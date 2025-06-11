/*
Copyright 2019 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package agent

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	runpprof "runtime/pprof"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"k8s.io/klog/v2"

	commonmetrics "sigs.k8s.io/apiserver-network-proxy/konnectivity-client/pkg/common/metrics"
	"sigs.k8s.io/apiserver-network-proxy/konnectivity-client/proto/client"
	"sigs.k8s.io/apiserver-network-proxy/pkg/agent/metrics"
	"sigs.k8s.io/apiserver-network-proxy/proto/agent"
	"sigs.k8s.io/apiserver-network-proxy/proto/header"
)

const dialTimeout = 5 * time.Second

// endpointConn tracks a connection from agent to node network.
type endpointConn struct {
	conn      net.Conn
	connID    int64
	cleanFunc func()
	dataCh    chan []byte
	cleanOnce sync.Once
	warnChLim bool
	dialDone  chan struct{}
}

func (e *endpointConn) cleanup() {
	e.cleanOnce.Do(e.cleanFunc)
}

func (e *endpointConn) send(msg []byte) {
	// TODO (cheftako@): Get perf test working and compare this solution with a lock based solution.
	defer func() {
		// Handles the race condition where we write to a closed channel
		if err := recover(); err != nil {
			klog.InfoS("Recovered from attempt to write to closed channel")
		}
	}()
	if e.warnChLim && len(e.dataCh) >= cap(e.dataCh) {
		klog.V(2).InfoS("Data channel on agent is full", "connectionID", e.connID)
	}

	e.dataCh <- msg
}

type connectionManager struct {
	mu          sync.RWMutex
	connections map[int64]*endpointConn
}

func (cm *connectionManager) Add(connID int64, eConn *endpointConn) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	metrics.Metrics.EndpointConnectionInc()
	cm.connections[connID] = eConn
}

func (cm *connectionManager) Get(connID int64) (*endpointConn, bool) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	eConn, ok := cm.connections[connID]
	return eConn, ok
}

func (cm *connectionManager) Delete(connID int64) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	// Delete for a connID is called from cleanFunc, which is
	// protected by cleanOnce.
	metrics.Metrics.EndpointConnectionDec()
	delete(cm.connections, connID)
}

func (cm *connectionManager) List() []*endpointConn {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	endpointConns := make([]*endpointConn, 0, len(cm.connections))
	for _, eConn := range cm.connections {
		endpointConns = append(endpointConns, eConn)
	}
	return endpointConns
}

func newConnectionManager() *connectionManager {
	return &connectionManager{
		connections: make(map[int64]*endpointConn),
	}
}

// Client runs on the node network side. It connects to proxy server and establishes
// a stream connection from which it sends and receives network traffic.
type Client struct {
	nextConnID int64

	connManager *connectionManager

	cs *ClientSet // the clientset that includes this AgentClient.

	stream           agent.AgentService_ConnectClient
	agentID          string
	agentIdentifiers string
	serverID         string // the id of the proxy server this client connects to.

	// connect opts
	address string
	opts    []grpc.DialOption
	conn    *grpc.ClientConn

	drainCh   <-chan struct{}
	drainOnce sync.Once
	stopCh    chan struct{}

	// locks
	sendLock      sync.Mutex
	recvLock      sync.Mutex
	probeInterval time.Duration // interval between probe pings

	// file path contains service account token.
	// token's value is auto-rotated by kubernetes, based on projected volume configuration.
	serviceAccountTokenPath string

	warnOnChannelLimit bool

	// API request filtering configuration
	denyList       []string // List of URI patterns to deny
	logAPIRequests bool     // Whether to log API requests

	// TLS inspection configuration
	tlsInspector *TLSInspector // For inspecting TLS traffic
}

// TLSInspector handles TLS traffic inspection without modifying the original packet
type TLSInspector struct {
	certFile   string
	keyFile    string
	clientCert *tls.Certificate
	enabled    bool
}

// NewTLSInspector creates a new TLS inspector using kubelet certificates
func NewTLSInspector(certFile, keyFile string) (*TLSInspector, error) {
	if certFile == "" || keyFile == "" {
		return &TLSInspector{enabled: false}, nil
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load kubelet certificates: %v", err)
	}

	return &TLSInspector{
		certFile:   certFile,
		keyFile:    keyFile,
		clientCert: &cert,
		enabled:    true,
	}, nil
}

// TryDecryptAndInspect attempts to decrypt a TLS packet and inspect the HTTP request
// Returns: shouldDeny, method, uri, error
func (t *TLSInspector) TryDecryptAndInspect(data []byte) (bool, string, string, error) {
	if !t.enabled {
		return false, "", "", nil
	}

	// Check if this is the beginning of a TLS handshake
	if !isTLSClientHello(data) {
		// Not a TLS handshake starting packet, could be application data
		// or continuation of previous TLS session
		return false, "", "", nil
	}

	// Create a memory buffer with the TLS client hello
	clientHelloBuf := bytes.NewBuffer(data)

	// Setup server side of TLS connection to analyze client hello
	config := &tls.Config{
		Certificates: []tls.Certificate{*t.clientCert},
		ClientAuth:   tls.RequestClientCert,
	}

	// Create a pipe for our mock connection
	clientConn, serverConn := net.Pipe()

	// Record what we capture from the TLS session
	var method, uri string
	var shouldDeny bool
	var captureErr error

	// Start a goroutine to handle the server side
	go func() {
		defer clientConn.Close()

		// Create TLS server connection
		tlsConn := tls.Server(serverConn, config)

		// Try to handshake
		if err := tlsConn.Handshake(); err != nil {
			captureErr = fmt.Errorf("TLS handshake error: %v", err)
			return
		}

		// Read the first HTTP request
		bufReader := bufio.NewReader(tlsConn)
		req, err := http.ReadRequest(bufReader)
		if err != nil {
			captureErr = fmt.Errorf("failed to read HTTP request: %v", err)
			return
		}

		// Capture the request details
		method = req.Method
		uri = req.URL.Path
	}()

	// Send the client hello to our mock server connection
	if _, err := io.Copy(clientConn, clientHelloBuf); err != nil {
		return false, "", "", fmt.Errorf("error sending client hello: %v", err)
	}

	// Close our connection to signal end of data
	serverConn.Close()

	// Check if we successfully captured the request
	if captureErr != nil {
		// This is expected for many cases - we're trying to catch just the initial request
		return false, "", "", nil
	}

	return shouldDeny, method, uri, nil
}

// isTLSClientHello checks if the packet appears to be a TLS Client Hello
func isTLSClientHello(data []byte) bool {
	// TLS handshakes typically start with byte 0x16 (22 decimal) for handshake
	// followed by 0x03 0x01 or higher for TLS version
	// and the handshake type for Client Hello is 0x01
	return len(data) >= 6 &&
		data[0] == 0x16 && // handshake
		data[1] >= 0x03 && // TLS version major
		data[5] == 0x01 // Client Hello
}

func isTLSHandshake(data []byte) bool {
	// TLS handshakes typically start with byte 0x16 (22 decimal)
	return len(data) >= 3 && data[0] == 0x16 && data[1] >= 0x03
}

// parseHTTPRequest attempts to parse data as an HTTP request
func parseHTTPRequest(data []byte) (method, uri string, ok bool) {
	// Check if this appears to be TLS data
	if isTLSHandshake(data) {
		return "TLS", "handshake", true
	}

	// Try to parse as plaintext HTTP
	str := string(data)
	lines := strings.Split(str, "\r\n")
	if len(lines) == 0 {
		return "", "", false
	}

	// Parse the request line
	parts := strings.Split(lines[0], " ")
	if len(parts) < 2 {
		// Try to extract something meaningful for non-HTTP protocol data
		if len(str) > 0 {
			// For non-HTTP protocol data, just return a generic identifier
			// and the first few bytes as hex for identification
			maxLen := 20
			if len(str) < maxLen {
				maxLen = len(str)
			}
			return "BINARY", fmt.Sprintf("protocol-data[%x...]", str[:maxLen]), true
		}
		return "", "", false
	}

	// This is a proper HTTP request
	return parts[0], parts[1], true
}

// extractHTTPHeaders parses out the headers from an HTTP request
func extractHTTPHeaders(data []byte) map[string]string {
	headers := make(map[string]string)

	str := string(data)
	lines := strings.Split(str, "\r\n")

	// Skip first line (request line) and parse headers
	for i := 1; i < len(lines); i++ {
		line := lines[i]
		if line == "" {
			break // End of headers
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}

	return headers
}

// shouldDenyRequest checks if a request URI matches any pattern in the deny list
func (a *Client) shouldDenyRequest(uri string) bool {
	// Currently we can only filter unencrypted HTTP traffic
	// TLS traffic cannot be inspected without a TLS intercepting proxy

	if len(a.denyList) == 0 {
		return false
	}

	// Don't try to filter TLS handshakes or binary data
	if uri == "handshake" || strings.HasPrefix(uri, "protocol-data") {
		// We cannot filter TLS content without implementing TLS interception
		klog.V(4).InfoS("Cannot filter TLS/encrypted traffic", "uri", uri)
		return false
	}

	for _, pattern := range a.denyList {
		if strings.HasPrefix(uri, pattern) {
			klog.V(2).InfoS("Request denied based on deny list", "uri", uri, "pattern", pattern)
			return true
		}
	}

	return false
}

// logRequestIfNeeded logs API request details if enabled
func (a *Client) logRequestIfNeeded(data []byte) {
	if !a.logAPIRequests {
		return
	}

	method, uri, ok := parseHTTPRequest(data)
	if ok {
		if method == "TLS" {
			klog.V(2).InfoS("TLS traffic detected (encrypted)", "type", uri)
			if klog.V(4).Enabled() {
				klog.V(4).InfoS("Note: TLS traffic cannot be inspected without TLS interception")
			}
			return
		}

		if method == "BINARY" {
			klog.V(2).InfoS("Binary protocol data", "preview", uri)
			return
		}

		// For regular HTTP requests
		klog.V(2).InfoS("API request", "method", method, "uri", uri)

		// Only log full request details at higher verbosity
		if klog.V(5).Enabled() {
			// Extract headers for better debugging
			headers := extractHTTPHeaders(data)
			klog.V(5).InfoS("API request details",
				"method", method,
				"uri", uri,
				"headers", headers,
				"size", len(data))
		}
	}
}

func newAgentClient(address, agentID, agentIdentifiers string, cs *ClientSet, opts ...grpc.DialOption) (*Client, int, error) {
	tlsInspector, err := NewTLSInspector(cs.kubeletCertFile, cs.kubeletKeyFile)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to initialize TLS inspector: %v", err)
	}

	a := &Client{
		cs:                      cs,
		address:                 address,
		agentID:                 agentID,
		agentIdentifiers:        agentIdentifiers,
		opts:                    opts,
		probeInterval:           cs.probeInterval,
		drainCh:                 cs.drainCh,
		stopCh:                  make(chan struct{}),
		serviceAccountTokenPath: cs.serviceAccountTokenPath,
		connManager:             newConnectionManager(),
		warnOnChannelLimit:      cs.warnOnChannelLimit,
		denyList:                cs.denyList,
		logAPIRequests:          cs.logAPIRequests,
		tlsInspector:            tlsInspector,
	}
	serverCount, err := a.Connect()
	if err != nil {
		return nil, 0, err
	}
	return a, serverCount, nil
}

// Connect makes the grpc dial to the proxy server. It returns the count
// of the number of servers this agent should connected to.
func (a *Client) Connect() (int, error) {
	conn, err := grpc.Dial(a.address, a.opts...)
	if err != nil {
		return 0, err
	}
	ctx := metadata.AppendToOutgoingContext(context.Background(),
		header.AgentID, a.agentID,
		header.AgentIdentifiers, a.agentIdentifiers)
	if a.serviceAccountTokenPath != "" {
		if ctx, err = a.initializeAuthContext(ctx); err != nil {
			err := conn.Close()
			if err != nil {
				klog.ErrorS(err, "failed to close gRPC connection", "agentID", a.agentID)
			}
			return 0, err
		}
	}
	stream, err := agent.NewAgentServiceClient(conn).Connect(ctx)
	if err != nil {
		conn.Close() /* #nosec G104 */
		return 0, err
	}
	serverID, err := serverID(stream)
	if err != nil {
		conn.Close() /* #nosec G104 */
		return 0, err
	}
	serverCount, err := serverCount(stream)
	if err != nil {
		conn.Close() /* #nosec G104 */
		return 0, err
	}
	a.conn = conn
	a.stream = stream
	a.serverID = serverID
	klog.V(2).InfoS("Connect to server", "serverID", serverID)
	return serverCount, nil
}

// Close closes the Connect gRPC connection.
func (a *Client) Close() {
	if a.conn == nil {
		klog.Errorln("Unexpected empty AgentClient.conn")
	}
	err := a.conn.Close()
	if err != nil {
		klog.ErrorS(err, "failed to close gRPC connection", "serverID", a.serverID, "agentID", a.agentID)
	}
	close(a.stopCh)
}

func (a *Client) Send(pkt *client.Packet) error {
	a.sendLock.Lock()
	defer a.sendLock.Unlock()

	const segment = commonmetrics.SegmentFromAgent
	metrics.Metrics.ObservePacket(segment, pkt.Type)
	err := a.stream.Send(pkt)
	if err != nil && err != io.EOF {
		metrics.Metrics.ObserveServerFailureDeprecated(metrics.DirectionToServer)
		metrics.Metrics.ObserveStreamError(segment, err, pkt.Type)
		a.cs.RemoveClient(a.serverID)
	}
	return err
}

func (a *Client) Recv() (*client.Packet, error) {
	a.recvLock.Lock()
	defer a.recvLock.Unlock()

	const segment = commonmetrics.SegmentToAgent
	pkt, err := a.stream.Recv()
	if err != nil {
		if err != io.EOF {
			metrics.Metrics.ObserveServerFailureDeprecated(metrics.DirectionFromServer)
			metrics.Metrics.ObserveStreamErrorNoPacket(segment, err)
		}
		return nil, err
	}
	metrics.Metrics.ObservePacket(segment, pkt.Type)
	return pkt, nil
}

func serverCount(stream agent.AgentService_ConnectClient) (int, error) {
	md, err := stream.Header()
	if err != nil {
		return 0, err
	}
	scounts := md.Get(header.ServerCount)
	if len(scounts) != 1 {
		return 0, fmt.Errorf("expected one server count, got %d", len(scounts))
	}
	scount := scounts[0]
	return strconv.Atoi(scount)
}

func serverID(stream agent.AgentService_ConnectClient) (string, error) {
	// TODO: this is a blocking call. Add a timeout?
	md, err := stream.Header()
	if err != nil {
		return "", err
	}
	sids := md.Get(header.ServerID)
	if len(sids) != 1 {
		return "", fmt.Errorf("expected one server ID in the context, got %v", sids)
	}
	return sids[0], nil
}

func (a *Client) initializeAuthContext(ctx context.Context) (context.Context, error) {
	var err error
	var b []byte

	// load current service account's token value
	if b, err = os.ReadFile(a.serviceAccountTokenPath); err != nil {
		klog.ErrorS(err, "Failed to read token", "path", a.serviceAccountTokenPath)
		return nil, err
	}
	ctx = metadata.AppendToOutgoingContext(ctx, header.AuthenticationTokenContextKey, header.AuthenticationTokenContextSchemePrefix+string(b))

	return ctx, nil
}

// Connect connects to proxy server to establish a gRPC stream,
// on which the proxied traffic is multiplexed through the stream
// and piped to the local connection. It register itself as a
// backend from proxy server, so proxy server will route traffic
// to this agent.
//
// The caller needs to call Serve to start serving proxy requests
// coming from proxy server.

// Serve starts to serve proxied requests from proxy server over the
// gRPC stream. Successful Connect is required before Serve. The
// The requests include things like opening a connection to a server,
// streaming data and close the connection.
func (a *Client) Serve() {
	defer a.cs.RemoveClient(a.serverID)
	defer func() {
		// close all of conns with remote when Client exits
		for _, eConn := range a.connManager.List() {
			eConn.cleanup()
		}
		klog.V(2).InfoS("cleanup all of conn contexts when client exits")
	}()

	klog.V(2).InfoS("Start serving", "serverID", a.serverID, "agentID", a.agentID)
	go a.probe()
	for {
		select {
		case <-a.stopCh:
			klog.V(2).InfoS("stop agent client.")
			return
		case <-a.drainCh:
			a.drainOnce.Do(func() {
				klog.V(2).InfoS("drain agent client", "serverID", a.serverID, "agentID", a.agentID)
				drainPkt := &client.Packet{
					Type: client.PacketType_DRAIN,
					Payload: &client.Packet_Drain{
						Drain: &client.Drain{},
					},
				}
				if err := a.Send(drainPkt); err != nil {
					klog.ErrorS(err, "drain failure", "")
				}
			})
		default:
		}

		pkt, err := a.Recv()
		if err != nil {
			if err == io.EOF {
				klog.V(2).InfoS("received EOF, exit", "serverID", a.serverID, "agentID", a.agentID)
				return
			}
			if status.Code(err) == codes.Canceled {
				klog.V(2).InfoS("stream canceled", "serverID", a.serverID, "agentID", a.agentID)
			} else {
				klog.ErrorS(err, "could not read stream", "serverID", a.serverID, "agentID", a.agentID)
			}
			return
		}

		if pkt == nil {
			klog.V(3).InfoS("empty packet received")
			continue
		}

		klog.V(5).InfoS("[tracing] recv packet", "type", pkt.Type)
		switch pkt.Type {
		case client.PacketType_DIAL_REQ:
			dialReq := pkt.GetDialRequest()
			klog.V(3).InfoS("Received DIAL_REQ", "serverID", a.serverID, "agentID", a.agentID, "dialID", dialReq.Random, "dialAddress", dialReq.Address)
			dialResp := &client.Packet{
				Type:    client.PacketType_DIAL_RSP,
				Payload: &client.Packet_DialResponse{DialResponse: &client.DialResponse{}},
			}
			dialResp.GetDialResponse().Random = dialReq.Random

			connID := atomic.AddInt64(&a.nextConnID, 1)
			dataCh := make(chan []byte, a.cs.xfrChannelSize)
			dialDone := make(chan struct{})
			eConn := &endpointConn{
				dataCh:    dataCh,
				dialDone:  dialDone,
				warnChLim: a.warnOnChannelLimit,
			}
			eConn.cleanFunc = func() {
				// block on purpose
				<-dialDone
				if eConn.conn == nil {
					// TODO: move this guard lower
					klog.ErrorS(fmt.Errorf("remote connection is nil"), "could not send CLOSE_RESP to nil connection")
					return
				}
				klog.V(4).InfoS("close connection", "dialID", dialReq.Random, "connectionID", connID, "dialAddress", dialReq.Address)
				var closePkt *client.Packet
				if connID == 0 {
					closePkt = &client.Packet{
						Type:    client.PacketType_DIAL_CLS,
						Payload: &client.Packet_CloseDial{CloseDial: &client.CloseDial{}},
					}
					closePkt.GetCloseDial().Random = dialReq.Random
				} else {
					closePkt = &client.Packet{
						Type:    client.PacketType_CLOSE_RSP,
						Payload: &client.Packet_CloseResponse{CloseResponse: &client.CloseResponse{}},
					}
					closePkt.GetCloseResponse().ConnectID = connID
				}
				if err := a.Send(closePkt); err != nil {
					klog.ErrorS(err, "close response failure", "")
				}
				close(dataCh)
				a.connManager.Delete(connID)
				if err := eConn.conn.Close(); err != nil {
					klog.ErrorS(err, "failed to close connection to remote", "dialID", dialReq.Random, "connectionID", connID)
				}
			}
			labels := runpprof.Labels(
				"agentID", a.agentID,
				"agentIdentifiers", a.agentIdentifiers,
				"serverAddress", a.address,
				"serverID", a.serverID,
				"dialID", strconv.FormatInt(dialReq.Random, 10),
				"dialAddress", dialReq.Address,
			)
			go runpprof.Do(context.Background(), labels, func(context.Context) {
				defer close(dialDone)
				start := time.Now()
				conn, err := net.DialTimeout(dialReq.Protocol, dialReq.Address, dialTimeout)
				if err != nil {
					reason := metrics.DialFailureUnknown
					if neterr, ok := err.(net.Error); ok && neterr.Timeout() {
						reason = metrics.DialFailureTimeout
					}
					metrics.Metrics.ObserveDialFailure(reason)
					// Do not log agent errors for remote unavailable.
					klog.V(1).InfoS("error dialing backend", "error", err, "dialID", dialReq.Random, "connectionID", connID, "dialAddress", dialReq.Address)
					dialResp.GetDialResponse().Error = err.Error()
					if err := a.Send(dialResp); err != nil {
						klog.ErrorS(err, "could not send DIAL_RSP with error", "dialID", dialReq.Random, "connectionID", connID, "dialAddress", dialReq.Address)
					}
					// Cannot invoke clean up as we have no conn yet.
					return
				}
				metrics.Metrics.ObserveDialLatency(time.Since(start))
				klog.V(3).InfoS("Endpoint connection established", "dialID", dialReq.Random, "connectionID", connID, "dialAddress", dialReq.Address)
				eConn.conn = conn
				a.connManager.Add(connID, eConn)
				dialResp.GetDialResponse().ConnectID = connID
				labels := runpprof.Labels(
					"agentID", a.agentID,
					"agentIdentifiers", a.agentIdentifiers,
					"serverAddress", a.address,
					"serverID", a.serverID,
					"connectionID", strconv.FormatInt(connID, 10),
					"dialAddress", dialReq.Address,
				)
				if err := a.Send(dialResp); err != nil {
					klog.ErrorS(err, "could not send DIAL_RSP", "dialID", dialReq.Random, "connectionID", connID, "dialAddress", dialReq.Address)
					// clean-up is normally called from remoteToProxy which we will never invoke.
					// So we are invoking it here to force the clean-up to occur.
					// However, cleanup will block until dialDone is closed.
					// So placing cleanup on its own goroutine to wait for the deferred close(dialDone) to kick in.
					go runpprof.Do(context.Background(), labels, func(context.Context) { eConn.cleanup() })
					return
				}
				go runpprof.Do(context.Background(), labels, func(context.Context) { a.remoteToProxy(connID, eConn) })
				go runpprof.Do(context.Background(), labels, func(context.Context) { a.proxyToRemote(connID, eConn) })
			})

		case client.PacketType_DATA:
			data := pkt.GetData()
			klog.V(4).InfoS("received DATA", "connectionID", data.ConnectID)
			if data.ConnectID == 0 {
				klog.ErrorS(nil, "Received packet missing ConnectID from frontend", "packetType", "DATA")
				continue
			}

			eConn, ok := a.connManager.Get(data.ConnectID)
			if ok {
				eConn.send(data.Data)
			} else {
				klog.V(2).InfoS("received DATA for unrecognized connection", "connectionID", data.ConnectID)
				a.Send(&client.Packet{
					Type: client.PacketType_CLOSE_RSP,
					Payload: &client.Packet_CloseResponse{
						CloseResponse: &client.CloseResponse{
							ConnectID: data.ConnectID,
							Error:     "unrecognized connectID",
						},
					},
				})
				continue
			}

		case client.PacketType_CLOSE_REQ:
			closeReq := pkt.GetCloseRequest()
			connID := closeReq.ConnectID

			klog.V(4).InfoS("received CLOSE_REQ", "connectionID", connID)

			eConn, ok := a.connManager.Get(connID)
			if ok {
				eConn.cleanup()
			} else {
				klog.V(4).InfoS("Failed to find connection context for close", "connectionID", connID)
				resp := &client.Packet{
					Type:    client.PacketType_CLOSE_RSP,
					Payload: &client.Packet_CloseResponse{CloseResponse: &client.CloseResponse{}},
				}
				resp.GetCloseResponse().ConnectID = connID
				resp.GetCloseResponse().Error = "Unknown connectID"
				if err := a.Send(resp); err != nil {
					klog.ErrorS(err, "could not send CLOSE_RSP", err, "connectionID", connID)
					continue
				}
			}

		default:
			klog.V(5).InfoS("unrecognized packet", "type", pkt)
		}
	}
}

func (a *Client) remoteToProxy(connID int64, eConn *endpointConn) {
	defer func() {
		if panicInfo := recover(); panicInfo != nil {
			klog.V(2).InfoS("Exiting remoteToProxy with recovery", "panicInfo", panicInfo, "connectionID", connID)
		} else {
			klog.V(4).InfoS("Exiting remoteToProxy", "connectionID", connID)
		}
	}()
	defer eConn.cleanup()

	var buf [1 << 12]byte
	resp := &client.Packet{
		Type: client.PacketType_DATA,
	}

	for {
		n, err := eConn.conn.Read(buf[:])
		klog.V(5).InfoS("received data from remote", "bytes", n, "connectionID", connID)

		if err == io.EOF {
			klog.V(2).InfoS("remote connection EOF", "connectionID", connID)
			return
		} else if err != nil {
			// "use of closed network connection" errors are expected upon receiving CLOSE_REQ
			// If connID doesn't exist in connManager, we assume the connection was meant to be closed.
			if _, ok := a.connManager.Get(connID); !ok {
				klog.V(5).InfoS("reading from a closed connection", "connectionID", connID, "err", err)
			} else {
				klog.ErrorS(err, "connection read failure", "connectionID", connID)
			}
			return
		}

		resp.Payload = &client.Packet_Data{Data: &client.Data{
			Data:      buf[:n],
			ConnectID: connID,
		}}
		if err := a.Send(resp); err != nil {
			klog.ErrorS(err, "could not send DATA", "connectionID", connID)
		}
	}
}

func (a *Client) proxyToRemote(connID int64, eConn *endpointConn) {
	defer func() {
		if panicInfo := recover(); panicInfo != nil {
			klog.V(2).InfoS("Exiting proxyToRemote with recovery", "panicInfo", panicInfo, "connectionID", connID)
		} else {
			klog.V(4).InfoS("Exiting proxyToRemote", "connectionID", connID)
		}
	}()
	// Not safe to call cleanup here, as cleanup() closes the dataCh
	// and we are the receiver for the dataCh. Also we now have a later
	// defer which will block until dataCh is closed.
	defer func() {
		// As the read side of the dataCh channel, we cannot close it.
		// However serve() may be blocked writing to the channel,
		// so we need to consume the channel until it is closed.
		discardedPktCount := 0
		for range eConn.dataCh {
			// Ignore values as this indicates there was a problem
			// with the remote connection.
			discardedPktCount++
		}
		if discardedPktCount > 0 {
			klog.V(2).InfoS("Discard packets while exiting proxyToRemote", "pktCount", discardedPktCount, "connectionID", connID)
		}
	}()

	// Track connections to determine if they've been examined for TLS content
	connectionInspected := false

	for d := range eConn.dataCh {
		// Handle the initial packet which might be a TLS handshake
		if !connectionInspected && len(d) > 0 && isTLSHandshake(d) {
			// This might be the start of a TLS session, try to inspect
			shouldDeny, method, uri, err := a.tlsInspector.TryDecryptAndInspect(d)
			connectionInspected = true

			if err != nil {
				// Log error but continue (we'll pass the traffic through)
				klog.V(4).InfoS("Failed to inspect TLS traffic", "error", err, "connectionID", connID)
			}

			// Log the request if we could decrypt it and logging is enabled
			if a.logAPIRequests && method != "" && uri != "" {
				klog.V(2).InfoS("TLS API request", "method", method, "uri", uri, "connectionID", connID)
			}

			// Check if this request should be denied
			if shouldDeny {
				klog.V(2).InfoS("Denying TLS API request", "method", method, "uri", uri, "connectionID", connID)

				// Close the connection to deny the request
				eConn.cleanup()
				return
			}
		} else if !connectionInspected {
			// Not a TLS connection or couldn't inspect
			connectionInspected = true
		}

		// For plaintext HTTP, continue with the existing logic
		if !isTLSHandshake(d) {
			// Log API request if enabled
			a.logRequestIfNeeded(d)

			// Check if request should be denied
			if method, uri, ok := parseHTTPRequest(d); ok && a.shouldDenyRequest(uri) {
				klog.V(2).InfoS("Denying API request", "method", method, "uri", uri, "connectionID", connID)

				// Send an HTTP 403 Forbidden response
				forbiddenResp := []byte("HTTP/1.1 403 Forbidden\r\nContent-Length: 9\r\n\r\nForbidden")
				resp := &client.Packet{
					Type: client.PacketType_DATA,
					Payload: &client.Packet_Data{Data: &client.Data{
						Data:      forbiddenResp,
						ConnectID: connID,
					}},
				}

				if err := a.Send(resp); err != nil {
					klog.ErrorS(err, "could not send forbidden response", "connectionID", connID)
				}

				// Skip forwarding this request to the remote
				continue
			}
		}

		// Forward the original packet unchanged
		pos := 0
		for {
			n, err := eConn.conn.Write(d[pos:])
			if err == nil {
				klog.V(4).InfoS("write to remote", "connectionID", connID, "lastData", n, "dataSize", len(d))
				break
			} else if n > 0 {
				// https://golang.org/pkg/io/#Writer specifies return non nil error if n < len(d)
				klog.ErrorS(err, "write to remote with failure", "connectionID", connID, "lastData", n)
				pos += n
			} else {
				// "use of closed network connection" errors are expected upon receiving CLOSE_REQ
				// If connID doesn't exist in connManager, we assume the connection was meant to be closed.
				if _, ok := a.connManager.Get(connID); !ok {
					klog.V(5).InfoS("writing to a closed connection", "connectionID", connID, "err", err)
				} else {
					klog.ErrorS(err, "conn write failure", "connectionID", connID)
				}

				return
			}
		}
	}
}

func (a *Client) probe() {
	for {
		select {
		case <-a.stopCh:
			return
		case <-time.After(a.probeInterval):
			if a.conn == nil {
				continue
			}
			// health check
			if a.conn.GetState() == connectivity.Ready {
				continue
			}
		}
		klog.V(1).InfoS("Removing client used for server connection", "state", a.conn.GetState(), "serverID", a.serverID)
		a.cs.RemoveClient(a.serverID)
		return
	}
}
