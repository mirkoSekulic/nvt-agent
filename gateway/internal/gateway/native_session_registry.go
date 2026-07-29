package gateway

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment"
)

const (
	maxNativeSessionConnections = 128
)

var (
	nativeSessionHandshakeLimit    = 5 * time.Second
	nativeSessionFrameTimeout      = 5 * time.Second
	nativeSessionHeartbeatInterval = 5 * time.Second

	ErrNativeSessionUnavailable = errors.New("native session unavailable")
	ErrNativeSessionProtocol    = errors.New("native session protocol failed")
	ErrNativeSessionCapacity    = errors.New("native session capacity exceeded")
)

// NativeSessionRelay is the implementation-neutral internal boundary used by
// later gateway routing work. V1 sends one existing bounded agentd request at
// a time; it does not define browser or HTTP reverse-tunnel behavior.
type NativeSessionRelay interface {
	RelayAgentd(context.Context, guestenrollment.Binding, json.RawMessage) (json.RawMessage, error)
	Ready(guestenrollment.Binding) bool
}

// NativeSessionServer accepts the provider-neutral outbound guest transport.
// The browser HTTP server remains a separate listener and routing path.
type NativeSessionServer struct {
	config          NativeSessionConfig
	tlsConfig       *tls.Config
	authenticator   nativeSessionAuthenticator
	registry        *nativeSessionRegistry
	connectionSlots chan struct{}

	lifetimeContext context.Context
	cancelLifetime  context.CancelFunc
	serveStarted    atomic.Bool
	shutdownStarted atomic.Bool

	listenerMu sync.Mutex
	listener   net.Listener
	handlers   sync.WaitGroup
	done       chan struct{}
	doneOnce   sync.Once
}

func NewNativeSessionServer(config NativeSessionConfig) (*NativeSessionServer, error) {
	if !config.Enabled {
		return nil, nil
	}
	if err := config.validate(); err != nil {
		return nil, err
	}
	certificate, err := tls.LoadX509KeyPair(config.TLSCertificateFile, config.TLSKeyFile)
	if err != nil {
		return nil, errors.New("load native session TLS identity failed")
	}
	authenticator, err := newBrokerNativeSessionAuthenticator(config)
	if err != nil {
		return nil, err
	}
	return newNativeSessionServer(config, &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{certificate},
	}, authenticator), nil
}

func newNativeSessionServer(config NativeSessionConfig, tlsConfig *tls.Config, authenticator nativeSessionAuthenticator) *NativeSessionServer {
	ctx, cancel := context.WithCancel(context.Background())
	registry := newNativeSessionRegistry()
	return &NativeSessionServer{
		config: config, tlsConfig: tlsConfig, authenticator: authenticator,
		registry: registry, connectionSlots: make(chan struct{}, maxNativeSessionConnections),
		lifetimeContext: ctx, cancelLifetime: cancel, done: make(chan struct{}),
	}
}

func (server *NativeSessionServer) Registry() NativeSessionRelay {
	if server == nil {
		return nil
	}
	return server.registry
}

func (server *NativeSessionServer) ListenAndServe() error {
	if server == nil {
		return nil
	}
	listener, err := net.Listen("tcp", server.config.ListenAddr)
	if err != nil {
		return errors.New("native session listener failed")
	}
	return server.Serve(listener)
}

func (server *NativeSessionServer) Serve(listener net.Listener) error {
	if server == nil || listener == nil || server.tlsConfig == nil || server.authenticator == nil || !server.serveStarted.CompareAndSwap(false, true) {
		if listener != nil {
			_ = listener.Close()
		}
		return errors.New("native session listener failed")
	}
	server.listenerMu.Lock()
	if server.shutdownStarted.Load() {
		server.listenerMu.Unlock()
		_ = listener.Close()
		server.finishServe()
		return nil
	}
	server.listener = listener
	server.listenerMu.Unlock()

	var serveError error
	for {
		connection, err := listener.Accept()
		if err != nil {
			if server.shutdownStarted.Load() || errors.Is(err, net.ErrClosed) {
				break
			}
			serveError = errors.New("native session listener failed")
			break
		}
		select {
		case server.connectionSlots <- struct{}{}:
			server.handlers.Add(1)
			go func() {
				defer server.handlers.Done()
				defer func() { <-server.connectionSlots }()
				server.handleConnection(connection)
			}()
		default:
			_ = connection.Close()
		}
	}
	server.cancelLifetime()
	server.registry.shutdown()
	server.handlers.Wait()
	server.finishServe()
	return serveError
}

func (server *NativeSessionServer) finishServe() {
	server.doneOnce.Do(func() { close(server.done) })
}

func (server *NativeSessionServer) Shutdown(ctx context.Context) error {
	if server == nil {
		return nil
	}
	if ctx == nil {
		return context.Canceled
	}
	if server.shutdownStarted.CompareAndSwap(false, true) {
		server.cancelLifetime()
		server.registry.shutdown()
		server.listenerMu.Lock()
		listener := server.listener
		server.listenerMu.Unlock()
		if listener != nil {
			_ = listener.Close()
		}
		if !server.serveStarted.Load() {
			server.finishServe()
		}
	}
	select {
	case <-server.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (server *NativeSessionServer) handleConnection(raw net.Conn) {
	connection := tls.Server(raw, server.tlsConfig.Clone())
	defer connection.Close()
	handshakeContext, cancelHandshake := context.WithTimeout(server.lifetimeContext, nativeSessionHandshakeLimit)
	_ = connection.SetDeadline(time.Now().Add(nativeSessionHandshakeLimit))
	err := connection.HandshakeContext(handshakeContext)
	cancelHandshake()
	if err != nil || server.lifetimeContext.Err() != nil {
		return
	}
	reader := newNativeSessionFrameReader(connection)
	hello, err := readNativeSessionFrame(reader, connection, time.Now().Add(nativeSessionFrameTimeout))
	if err != nil || hello.Type != guestenrollment.NativeSessionHello || hello.Binding == nil {
		return
	}
	binding := *hello.Binding
	credential := hello.Credential
	sequence, sequenceErr := nativeSessionCredentialSequence(credential)
	hello.Credential = ""
	hello.Binding = nil
	if sequenceErr != nil {
		credential = ""
		return
	}
	authenticationContext, cancelAuthentication := context.WithTimeout(server.lifetimeContext, server.config.AuthenticationTimeout)
	authenticated, err := server.authenticator.Authenticate(authenticationContext, credential, binding)
	cancelAuthentication()
	credential = ""
	if err != nil || authenticated.Binding != binding {
		_ = writeNativeSessionFrame(connection, guestenrollment.NativeSessionMessage{
			ContractVersion: guestenrollment.NativeSessionVersion,
			Type:            guestenrollment.NativeSessionHelloReject,
			Reason:          "unauthorized",
		}, time.Now().Add(nativeSessionFrameTimeout), nil)
		return
	}
	authenticated.Sequence = sequence
	session := newNativeSessionConnection(server.registry, connection, reader, authenticated, server.config.RevalidationInterval)
	if err := server.registry.reserve(session); err != nil {
		_ = writeNativeSessionFrame(connection, guestenrollment.NativeSessionMessage{
			ContractVersion: guestenrollment.NativeSessionVersion,
			Type:            guestenrollment.NativeSessionHelloReject,
			Reason:          "capacity-exceeded",
		}, time.Now().Add(nativeSessionFrameTimeout), nil)
		return
	}
	defer session.terminate()
	if err := session.write(guestenrollment.NativeSessionMessage{
		ContractVersion: guestenrollment.NativeSessionVersion,
		Type:            guestenrollment.NativeSessionHelloAck,
		Binding:         &binding,
		Audience:        guestenrollment.NativeGuestControlAudience,
	}, time.Now().Add(nativeSessionFrameTimeout)); err != nil {
		return
	}
	if !server.registry.activate(session) {
		return
	}
	session.run(server.lifetimeContext)
}

type nativeSessionRegistry struct {
	mu       sync.Mutex
	bindings map[guestenrollment.Binding]*nativeSessionBindingSlot
	closed   bool
}

type nativeSessionBindingSlot struct {
	active      *nativeSessionConnection
	replacement *nativeSessionConnection
}

func newNativeSessionRegistry() *nativeSessionRegistry {
	return &nativeSessionRegistry{bindings: make(map[guestenrollment.Binding]*nativeSessionBindingSlot)}
}

func (registry *nativeSessionRegistry) reserve(session *nativeSessionConnection) error {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if registry.closed {
		return ErrNativeSessionUnavailable
	}
	slot := registry.bindings[session.authenticated.Binding]
	if slot == nil {
		slot = &nativeSessionBindingSlot{}
		registry.bindings[session.authenticated.Binding] = slot
	}
	if slot.active == nil && slot.replacement == nil {
		slot.active = session
		return nil
	}
	if slot.active == nil || slot.replacement != nil {
		return ErrNativeSessionCapacity
	}
	if session.authenticated.Sequence <= slot.active.authenticated.Sequence {
		return ErrNativeSessionUnavailable
	}
	slot.replacement = session
	return nil
}

func (registry *nativeSessionRegistry) activate(session *nativeSessionConnection) bool {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if registry.closed || session.closed.Load() {
		return false
	}
	slot := registry.bindings[session.authenticated.Binding]
	if slot == nil || (slot.active != session && slot.replacement != session) {
		return false
	}
	session.ready = true
	if slot.active == nil && slot.replacement == session {
		slot.active = session
		slot.replacement = nil
	}
	return true
}

func (registry *nativeSessionRegistry) remove(session *nativeSessionConnection) {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	slot := registry.bindings[session.authenticated.Binding]
	if slot == nil {
		return
	}
	session.ready = false
	if slot.active == session {
		slot.active = nil
		if slot.replacement != nil && slot.replacement.ready && !slot.replacement.closed.Load() {
			slot.active = slot.replacement
			slot.replacement = nil
		}
	} else if slot.replacement == session {
		slot.replacement = nil
	}
	if slot.active == nil && slot.replacement == nil {
		delete(registry.bindings, session.authenticated.Binding)
	}
}

func (registry *nativeSessionRegistry) Ready(binding guestenrollment.Binding) bool {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	slot := registry.bindings[binding]
	return !registry.closed && slot != nil && slot.active != nil && slot.active.ready && !slot.active.closed.Load()
}

func (registry *nativeSessionRegistry) active(binding guestenrollment.Binding) *nativeSessionConnection {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	slot := registry.bindings[binding]
	if registry.closed || slot == nil || slot.active == nil || !slot.active.ready || slot.active.closed.Load() {
		return nil
	}
	return slot.active
}

func (registry *nativeSessionRegistry) isActive(session *nativeSessionConnection) bool {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	slot := registry.bindings[session.authenticated.Binding]
	return !registry.closed && slot != nil && slot.active == session && session.ready && !session.closed.Load()
}

func (registry *nativeSessionRegistry) RelayAgentd(ctx context.Context, binding guestenrollment.Binding, payload json.RawMessage) (json.RawMessage, error) {
	if ctx == nil || guestenrollment.ValidateBinding(binding) != nil {
		return nil, ErrNativeSessionUnavailable
	}
	session := registry.active(binding)
	if session == nil {
		return nil, ErrNativeSessionUnavailable
	}
	return session.relay(ctx, payload)
}

func (registry *nativeSessionRegistry) shutdown() {
	registry.mu.Lock()
	if registry.closed {
		registry.mu.Unlock()
		return
	}
	registry.closed = true
	connections := make([]*nativeSessionConnection, 0, len(registry.bindings)*2)
	for _, slot := range registry.bindings {
		if slot.active != nil {
			slot.active.ready = false
			connections = append(connections, slot.active)
		}
		if slot.replacement != nil {
			slot.replacement.ready = false
			connections = append(connections, slot.replacement)
		}
	}
	registry.bindings = make(map[guestenrollment.Binding]*nativeSessionBindingSlot)
	registry.mu.Unlock()
	for _, connection := range connections {
		connection.closeTransport()
	}
}

type nativeSessionConnection struct {
	registry      *nativeSessionRegistry
	connection    net.Conn
	reader        *bufio.Reader
	authenticated authenticatedNativeSession
	trustDeadline time.Time

	writeMu   sync.Mutex
	requestMu sync.Mutex
	pendingMu sync.Mutex
	pending   *nativeSessionPendingRequest
	seen      map[string]struct{}
	requests  int
	ready     bool // guarded by registry.mu
	closed    atomic.Bool
	closeOnce sync.Once
	closedCh  chan struct{}
}

type nativeSessionPendingRequest struct {
	id       string
	response chan nativeSessionResponse
}

type nativeSessionResponse struct {
	payload json.RawMessage
	err     error
}

func newNativeSessionConnection(registry *nativeSessionRegistry, connection net.Conn, reader *bufio.Reader, authenticated authenticatedNativeSession, revalidation time.Duration) *nativeSessionConnection {
	deadline := time.Now().Add(revalidation)
	if authenticated.LocalExpiresAt.Before(deadline) {
		deadline = authenticated.LocalExpiresAt
	}
	return &nativeSessionConnection{
		registry: registry, connection: connection, reader: reader, authenticated: authenticated,
		trustDeadline: deadline, seen: make(map[string]struct{}, guestenrollment.MaxNativeSessionRequestsPerConnection),
		closedCh: make(chan struct{}),
	}
}

func (session *nativeSessionConnection) run(ctx context.Context) {
	nextPing := time.Now().Add(nativeSessionHeartbeatInterval)
	var pongDeadline time.Time
	for ctx.Err() == nil && !session.closed.Load() {
		now := time.Now()
		if session.expired(now) || !now.Before(session.trustDeadline) {
			return
		}
		if !pongDeadline.IsZero() && !now.Before(pongDeadline) {
			return
		}
		if pongDeadline.IsZero() && !now.Before(nextPing) {
			deadline := minNativeSessionDeadline(now.Add(nativeSessionFrameTimeout), session.trustDeadline)
			if session.write(guestenrollment.NativeSessionMessage{ContractVersion: guestenrollment.NativeSessionVersion, Type: guestenrollment.NativeSessionPing}, deadline) != nil {
				return
			}
			pongDeadline = deadline
			continue
		}
		deadline := session.trustDeadline
		if !pongDeadline.IsZero() {
			deadline = minNativeSessionDeadline(deadline, pongDeadline)
		} else {
			deadline = minNativeSessionDeadline(deadline, nextPing)
		}
		frame, err := readNativeSessionFrame(session.reader, session.connection, deadline)
		if err != nil {
			if isNativeSessionTimeout(err) {
				continue
			}
			return
		}
		if session.expired(time.Now()) || !time.Now().Before(session.trustDeadline) {
			return
		}
		switch frame.Type {
		case guestenrollment.NativeSessionPing:
			writeDeadline := minNativeSessionDeadline(time.Now().Add(nativeSessionFrameTimeout), session.trustDeadline)
			if !pongDeadline.IsZero() {
				writeDeadline = minNativeSessionDeadline(writeDeadline, pongDeadline)
			}
			if session.write(guestenrollment.NativeSessionMessage{ContractVersion: guestenrollment.NativeSessionVersion, Type: guestenrollment.NativeSessionPong}, writeDeadline) != nil {
				return
			}
		case guestenrollment.NativeSessionPong:
			if pongDeadline.IsZero() {
				return
			}
			pongDeadline = time.Time{}
			nextPing = time.Now().Add(nativeSessionHeartbeatInterval)
		case guestenrollment.NativeSessionAgentdResponse:
			if !session.deliver(frame) {
				return
			}
		default:
			return
		}
	}
}

func (session *nativeSessionConnection) expired(now time.Time) bool {
	return !now.Before(session.authenticated.ExpiresAt) || !now.Before(session.authenticated.LocalExpiresAt)
}

func (session *nativeSessionConnection) write(frame guestenrollment.NativeSessionMessage, deadline time.Time) error {
	session.writeMu.Lock()
	defer session.writeMu.Unlock()
	if session.closed.Load() || deadline.IsZero() || !time.Now().Before(deadline) {
		return ErrNativeSessionUnavailable
	}
	return writeNativeSessionFrame(session.connection, frame, deadline, nil)
}

func (session *nativeSessionConnection) relay(ctx context.Context, payload json.RawMessage) (json.RawMessage, error) {
	session.requestMu.Lock()
	defer session.requestMu.Unlock()
	if !session.registry.isActive(session) || session.expired(time.Now()) {
		return nil, ErrNativeSessionUnavailable
	}
	if session.requests >= guestenrollment.MaxNativeSessionRequestsPerConnection {
		session.terminate()
		return nil, ErrNativeSessionCapacity
	}
	session.requests++
	requestID := "gateway-" + formatNativeSessionRequestID(session.requests)
	pending := &nativeSessionPendingRequest{id: requestID, response: make(chan nativeSessionResponse, 1)}
	session.pendingMu.Lock()
	if session.pending != nil {
		session.pendingMu.Unlock()
		session.terminate()
		return nil, ErrNativeSessionProtocol
	}
	session.pending = pending
	session.pendingMu.Unlock()

	deadline := minNativeSessionDeadline(time.Now().Add(nativeSessionFrameTimeout), session.trustDeadline)
	if contextDeadline, ok := ctx.Deadline(); ok {
		deadline = minNativeSessionDeadline(deadline, contextDeadline)
	}
	frame := guestenrollment.NativeSessionMessage{
		ContractVersion: guestenrollment.NativeSessionVersion,
		Type:            guestenrollment.NativeSessionAgentdRequest,
		RequestID:       requestID,
		Payload:         append(json.RawMessage(nil), payload...),
	}
	if err := session.write(frame, deadline); err != nil {
		session.clearPending(pending)
		session.terminate()
		return nil, ErrNativeSessionUnavailable
	}
	select {
	case result := <-pending.response:
		if result.err != nil {
			return nil, result.err
		}
		return result.payload, nil
	case <-ctx.Done():
		session.clearPending(pending)
		session.terminate()
		return nil, ErrNativeSessionUnavailable
	case <-session.closedCh:
		session.clearPending(pending)
		return nil, ErrNativeSessionUnavailable
	case <-time.After(time.Until(deadline)):
		session.clearPending(pending)
		session.terminate()
		return nil, ErrNativeSessionUnavailable
	}
}

func (session *nativeSessionConnection) deliver(frame guestenrollment.NativeSessionMessage) bool {
	session.pendingMu.Lock()
	pending := session.pending
	if pending == nil || pending.id != frame.RequestID {
		session.pendingMu.Unlock()
		return false
	}
	if _, duplicate := session.seen[frame.RequestID]; duplicate || len(session.seen) >= guestenrollment.MaxNativeSessionRequestsPerConnection {
		session.pendingMu.Unlock()
		return false
	}
	session.pending = nil
	session.seen[frame.RequestID] = struct{}{}
	session.pendingMu.Unlock()
	pending.response <- nativeSessionResponse{payload: append(json.RawMessage(nil), frame.Payload...)}
	return true
}

func (session *nativeSessionConnection) clearPending(pending *nativeSessionPendingRequest) {
	session.pendingMu.Lock()
	if session.pending == pending {
		session.pending = nil
	}
	session.pendingMu.Unlock()
}

func (session *nativeSessionConnection) terminate() {
	session.closeOnce.Do(func() {
		session.registry.remove(session)
		session.closeTransport()
	})
}

func (session *nativeSessionConnection) closeTransport() {
	if session.closed.CompareAndSwap(false, true) {
		close(session.closedCh)
		_ = session.connection.Close()
		session.failPending()
	}
}

func (session *nativeSessionConnection) failPending() {
	session.pendingMu.Lock()
	pending := session.pending
	session.pending = nil
	session.pendingMu.Unlock()
	if pending != nil {
		select {
		case pending.response <- nativeSessionResponse{err: ErrNativeSessionUnavailable}:
		default:
		}
	}
}

func newNativeSessionFrameReader(connection net.Conn) *bufio.Reader {
	return bufio.NewReaderSize(connection, guestenrollment.MaxNativeSessionFrameBytes)
}

func readNativeSessionFrame(reader *bufio.Reader, connection net.Conn, deadline time.Time) (guestenrollment.NativeSessionMessage, error) {
	if reader == nil || connection == nil || deadline.IsZero() || !time.Now().Before(deadline) {
		return guestenrollment.NativeSessionMessage{}, ErrNativeSessionUnavailable
	}
	if err := connection.SetReadDeadline(deadline); err != nil {
		return guestenrollment.NativeSessionMessage{}, ErrNativeSessionUnavailable
	}
	line, err := reader.ReadSlice('\n')
	if err != nil {
		zeroNativeSessionBytes(line)
		return guestenrollment.NativeSessionMessage{}, err
	}
	if !time.Now().Before(deadline) || len(line) == 0 || len(line) > guestenrollment.MaxNativeSessionFrameBytes {
		zeroNativeSessionBytes(line)
		return guestenrollment.NativeSessionMessage{}, ErrNativeSessionProtocol
	}
	frame, err := guestenrollment.DecodeNativeSessionMessage(line)
	zeroNativeSessionBytes(line)
	if err != nil {
		return guestenrollment.NativeSessionMessage{}, ErrNativeSessionProtocol
	}
	return frame, nil
}

func writeNativeSessionFrame(connection net.Conn, frame guestenrollment.NativeSessionMessage, deadline time.Time, lock *sync.Mutex) error {
	if lock != nil {
		lock.Lock()
		defer lock.Unlock()
	}
	if deadline.IsZero() || !time.Now().Before(deadline) || connection.SetWriteDeadline(deadline) != nil {
		return ErrNativeSessionUnavailable
	}
	encoded, err := guestenrollment.EncodeNativeSessionMessage(frame)
	if err != nil {
		return ErrNativeSessionProtocol
	}
	defer zeroNativeSessionBytes(encoded)
	for len(encoded) > 0 {
		written, writeErr := connection.Write(encoded)
		if writeErr != nil || written <= 0 {
			return ErrNativeSessionUnavailable
		}
		encoded = encoded[written:]
	}
	if !time.Now().Before(deadline) {
		return ErrNativeSessionUnavailable
	}
	return nil
}

func isNativeSessionTimeout(err error) bool {
	var netError net.Error
	return errors.As(err, &netError) && netError.Timeout()
}

func minNativeSessionDeadline(left, right time.Time) time.Time {
	if left.IsZero() || (!right.IsZero() && right.Before(left)) {
		return right
	}
	return left
}

func formatNativeSessionRequestID(value int) string {
	if value == 0 {
		return "0"
	}
	var buffer [20]byte
	index := len(buffer)
	for value > 0 {
		index--
		buffer[index] = byte('0' + value%10)
		value /= 10
	}
	return string(buffer[index:])
}

var _ NativeSessionRelay = (*nativeSessionRegistry)(nil)
