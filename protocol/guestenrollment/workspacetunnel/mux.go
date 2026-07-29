package workspacetunnel

import (
	"context"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment"
)

// StreamOpener is the implementation-neutral gateway data-plane boundary.
// Production routing may depend on this interface without importing yamux.
type StreamOpener interface {
	OpenStream(context.Context) (net.Conn, error)
	Binding() guestenrollment.Binding
	Sequence() uint64
	Close() error
}

type GatewaySession struct {
	binding       guestenrollment.Binding
	sequence      uint64
	mux           *yamux.Session
	base          io.ReadWriteCloser
	trustDeadline time.Time
	pending       chan struct{}
	active        chan struct{}

	lifetime context.Context
	cancel   context.CancelFunc
	timer    *time.Timer
	closed   atomic.Bool
	once     sync.Once
	streams  map[*managedConn]struct{}
	mu       sync.Mutex
	workerMu sync.Mutex
	workers  sync.WaitGroup
}

// GuestForwarder accepts only gateway-opened streams and dials only the fixed,
// trusted loopback endpoint supplied at construction time.
type GuestForwarder struct {
	binding       guestenrollment.Binding
	endpoint      string
	mux           *yamux.Session
	base          io.ReadWriteCloser
	trustDeadline time.Time
	active        chan struct{}

	lifetime     context.Context
	cancel       context.CancelFunc
	timer        *time.Timer
	closed       atomic.Bool
	serveStarted atomic.Bool
	once         sync.Once
	streams      map[*forwardedStream]struct{}
	mu           sync.Mutex
	workerMu     sync.Mutex
	workers      sync.WaitGroup
}

type managedConn struct {
	net.Conn
	owner *GatewaySession
	once  sync.Once
}

type forwardedStream struct {
	stream net.Conn
	local  net.Conn
}

type streamOpenResult struct {
	stream net.Conn
	err    error
}

func NewGatewaySession(connection io.ReadWriteCloser, authentication Authentication) (*GatewaySession, error) {
	if connection == nil || validateAcceptedAuthentication(authentication, time.Now()) != nil {
		return nil, ErrProtocol
	}
	multiplexer, err := yamux.Client(connection, yamuxConfig())
	if err != nil {
		return nil, ErrUnavailable
	}
	ctx, cancel := context.WithCancel(context.Background())
	value := &GatewaySession{
		binding: authentication.Binding, sequence: authentication.Sequence, mux: multiplexer, base: connection, trustDeadline: authentication.LocalExpiresAt,
		pending: make(chan struct{}, MaxPendingStreamOpens), active: make(chan struct{}, MaxActiveStreams),
		lifetime: ctx, cancel: cancel, streams: make(map[*managedConn]struct{}, MaxActiveStreams),
	}
	value.timer = time.NewTimer(time.Until(authentication.LocalExpiresAt))
	value.workers.Add(3)
	go func() {
		defer value.workers.Done()
		select {
		case <-value.timer.C:
			value.shutdown()
		case <-value.lifetime.Done():
		}
	}()
	go func() {
		defer value.workers.Done()
		<-value.mux.CloseChan()
		value.shutdown()
	}()
	go value.rejectGuestStreams()
	return value, nil
}

func NewGuestForwarder(connection io.ReadWriteCloser, binding guestenrollment.Binding, localTrustDeadline time.Time, endpoint string) (*GuestForwarder, error) {
	if connection == nil || guestenrollment.ValidateBinding(binding) != nil || validateLocalTrustDeadline(localTrustDeadline, time.Now()) != nil || ValidateLoopbackEndpoint(endpoint) != nil {
		return nil, ErrProtocol
	}
	multiplexer, err := yamux.Server(connection, yamuxConfig())
	if err != nil {
		return nil, ErrUnavailable
	}
	ctx, cancel := context.WithCancel(context.Background())
	value := &GuestForwarder{
		binding: binding, endpoint: endpoint, mux: multiplexer, base: connection, trustDeadline: localTrustDeadline,
		active: make(chan struct{}, MaxActiveStreams), lifetime: ctx, cancel: cancel,
		streams: make(map[*forwardedStream]struct{}, MaxActiveStreams),
	}
	value.timer = time.NewTimer(time.Until(localTrustDeadline))
	value.workers.Add(2)
	go func() {
		defer value.workers.Done()
		select {
		case <-value.timer.C:
			value.shutdown()
		case <-value.lifetime.Done():
		}
	}()
	go func() {
		defer value.workers.Done()
		<-value.mux.CloseChan()
		value.shutdown()
	}()
	return value, nil
}

func (session *GatewaySession) Binding() guestenrollment.Binding {
	if session == nil {
		return guestenrollment.Binding{}
	}
	return session.binding
}

func (session *GatewaySession) Sequence() uint64 {
	if session == nil {
		return 0
	}
	return session.sequence
}

func (session *GuestForwarder) Binding() guestenrollment.Binding {
	if session == nil {
		return guestenrollment.Binding{}
	}
	return session.binding
}

// Done closes as soon as the authenticated workspace lifetime begins
// teardown. Callers use it to withdraw external readiness before closing
// another required transport in the same lifecycle.
func (session *GuestForwarder) Done() <-chan struct{} {
	if session == nil {
		return nil
	}
	return session.lifetime.Done()
}

// CheckDestination verifies that the one trusted configured loopback service
// is reachable before a caller publishes session readiness. It neither sends
// application data nor accepts a caller-selected destination.
func (session *GuestForwarder) CheckDestination(ctx context.Context) error {
	if session == nil || ctx == nil || ctx.Err() != nil || session.closed.Load() || !time.Now().Before(session.trustDeadline) {
		return ErrUnavailable
	}
	dialContext, cancel := context.WithTimeout(ctx, LocalDialTimeout)
	defer cancel()
	connection, err := (&net.Dialer{}).DialContext(dialContext, "tcp", session.endpoint)
	if err != nil {
		return ErrUnavailable
	}
	return connection.Close()
}

func (session *GatewaySession) OpenStream(ctx context.Context) (net.Conn, error) {
	if session == nil || ctx == nil || ctx.Err() != nil || session.closed.Load() || !time.Now().Before(session.trustDeadline) {
		return nil, ErrUnavailable
	}
	select {
	case session.pending <- struct{}{}:
	case <-ctx.Done():
		return nil, ErrUnavailable
	default:
		return nil, ErrCapacity
	}
	if ctx.Err() != nil {
		<-session.pending
		return nil, ErrUnavailable
	}
	select {
	case session.active <- struct{}{}:
	case <-ctx.Done():
		<-session.pending
		return nil, ErrUnavailable
	default:
		<-session.pending
		return nil, ErrCapacity
	}
	resultChannel := make(chan streamOpenResult)
	abandon := make(chan struct{})
	session.workerMu.Lock()
	if session.closed.Load() {
		session.workerMu.Unlock()
		<-session.active
		<-session.pending
		return nil, ErrUnavailable
	}
	session.workers.Add(1)
	session.workerMu.Unlock()
	go func() {
		defer session.workers.Done()
		stream, err := session.mux.OpenStream()
		select {
		case resultChannel <- streamOpenResult{stream: stream, err: err}:
		case <-abandon:
			if stream != nil {
				_ = stream.Close()
			}
			<-session.active
			<-session.pending
		}
	}()
	var result streamOpenResult
	select {
	case result = <-resultChannel:
		<-session.pending
	case <-ctx.Done():
		close(abandon)
		return nil, ErrUnavailable
	case <-session.lifetime.Done():
		close(abandon)
		return nil, ErrUnavailable
	}
	if result.err != nil {
		<-session.active
		return nil, ErrUnavailable
	}
	stream := result.stream
	if ctx.Err() != nil || session.closed.Load() {
		_ = stream.Close()
		<-session.active
		return nil, ErrUnavailable
	}
	connection := &managedConn{Conn: &idleConn{Conn: stream, timeout: StreamIdleTimeout}, owner: session}
	session.mu.Lock()
	if session.closed.Load() {
		session.mu.Unlock()
		_ = stream.Close()
		<-session.active
		return nil, ErrUnavailable
	}
	session.streams[connection] = struct{}{}
	session.mu.Unlock()
	return connection, nil
}

func (connection *managedConn) Close() error {
	if connection == nil {
		return nil
	}
	var result error
	connection.once.Do(func() {
		result = connection.Conn.Close()
		owner := connection.owner
		owner.mu.Lock()
		if _, present := owner.streams[connection]; present {
			delete(owner.streams, connection)
			<-owner.active
		}
		owner.mu.Unlock()
	})
	return result
}

func (session *GatewaySession) rejectGuestStreams() {
	defer session.workers.Done()
	violations := 0
	for !session.closed.Load() {
		stream, err := session.mux.AcceptStreamWithContext(session.lifetime)
		if err != nil {
			return
		}
		_ = stream.Close()
		violations++
		if violations >= MaxGuestInitiatedStreams {
			session.shutdown()
			return
		}
	}
}

func (session *GuestForwarder) Serve(ctx context.Context) error {
	if session == nil || ctx == nil || session.closed.Load() || !time.Now().Before(session.trustDeadline) || !session.serveStarted.CompareAndSwap(false, true) {
		return ErrUnavailable
	}
	defer session.Close()
	serveContext, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		select {
		case <-session.lifetime.Done():
			cancel()
		case <-serveContext.Done():
		}
	}()
	for {
		stream, err := session.mux.AcceptStreamWithContext(serveContext)
		if err != nil {
			if serveContext.Err() != nil || session.closed.Load() {
				return nil
			}
			return ErrUnavailable
		}
		select {
		case session.active <- struct{}{}:
			session.workerMu.Lock()
			if session.closed.Load() {
				session.workerMu.Unlock()
				<-session.active
				_ = stream.Close()
				return nil
			}
			session.workers.Add(1)
			session.workerMu.Unlock()
			go session.forward(stream)
		default:
			_ = stream.Close()
		}
	}
}

func (session *GuestForwarder) forward(stream net.Conn) {
	defer session.workers.Done()
	defer func() { <-session.active }()
	dialContext, cancel := context.WithTimeout(session.lifetime, LocalDialTimeout)
	local, err := (&net.Dialer{}).DialContext(dialContext, "tcp", session.endpoint)
	cancel()
	if err != nil {
		_ = stream.Close()
		return
	}
	pair := &forwardedStream{stream: stream, local: local}
	session.mu.Lock()
	if session.closed.Load() {
		session.mu.Unlock()
		_ = stream.Close()
		_ = local.Close()
		return
	}
	session.streams[pair] = struct{}{}
	session.mu.Unlock()
	defer func() {
		_ = stream.Close()
		_ = local.Close()
		session.mu.Lock()
		delete(session.streams, pair)
		session.mu.Unlock()
	}()
	bridge(&idleConn{Conn: stream, timeout: StreamIdleTimeout}, &idleConn{Conn: local, timeout: StreamIdleTimeout})
}

func bridge(stream net.Conn, local net.Conn) {
	type copyResult struct {
		toLocal bool
		err     error
	}
	results := make(chan copyResult, 2)
	go func() {
		buffer := make([]byte, CopyBufferBytes)
		_, err := io.CopyBuffer(local, stream, buffer)
		zero(buffer)
		results <- copyResult{toLocal: true, err: err}
	}()
	go func() {
		buffer := make([]byte, CopyBufferBytes)
		_, err := io.CopyBuffer(stream, local, buffer)
		zero(buffer)
		results <- copyResult{err: err}
	}()
	first := <-results
	if first.err != nil {
		_ = stream.Close()
		_ = local.Close()
	} else if first.toLocal {
		closeWrite(local)
	} else {
		_ = stream.Close()
	}
	<-results
}

func closeWrite(connection net.Conn) {
	if value, ok := connection.(interface{ CloseWrite() error }); ok {
		_ = value.CloseWrite()
		return
	}
	_ = connection.Close()
}

func (session *GatewaySession) Close() error {
	if session == nil {
		return nil
	}
	session.shutdown()
	session.workerMu.Lock()
	session.workerMu.Unlock()
	session.workers.Wait()
	return nil
}

func (session *GatewaySession) shutdown() {
	session.once.Do(func() {
		session.closed.Store(true)
		if session.timer != nil {
			session.timer.Stop()
		}
		session.cancel()
		session.mu.Lock()
		streams := make([]*managedConn, 0, len(session.streams))
		for stream := range session.streams {
			streams = append(streams, stream)
		}
		session.mu.Unlock()
		for _, stream := range streams {
			_ = stream.Close()
		}
		_ = session.mux.Close()
		_ = session.base.Close()
	})
}

func (session *GuestForwarder) Close() error {
	if session == nil {
		return nil
	}
	session.shutdown()
	session.workerMu.Lock()
	session.workerMu.Unlock()
	session.workers.Wait()
	return nil
}

func (session *GuestForwarder) shutdown() {
	session.once.Do(func() {
		session.closed.Store(true)
		if session.timer != nil {
			session.timer.Stop()
		}
		session.cancel()
		session.mu.Lock()
		streams := make([]*forwardedStream, 0, len(session.streams))
		for stream := range session.streams {
			streams = append(streams, stream)
		}
		session.mu.Unlock()
		for _, stream := range streams {
			_ = stream.stream.Close()
			_ = stream.local.Close()
		}
		_ = session.mux.Close()
		_ = session.base.Close()
	})
}

type idleConn struct {
	net.Conn
	timeout time.Duration
}

func (connection *idleConn) Read(value []byte) (int, error) {
	if connection.Conn.SetDeadline(time.Now().Add(connection.timeout)) != nil {
		return 0, ErrUnavailable
	}
	count, err := connection.Conn.Read(value)
	if count > 0 && connection.Conn.SetDeadline(time.Now().Add(connection.timeout)) != nil {
		return count, ErrUnavailable
	}
	return count, err
}

func (connection *idleConn) Write(value []byte) (int, error) {
	if connection.Conn.SetDeadline(time.Now().Add(connection.timeout)) != nil {
		return 0, ErrUnavailable
	}
	count, err := connection.Conn.Write(value)
	if count > 0 && connection.Conn.SetDeadline(time.Now().Add(connection.timeout)) != nil {
		return count, ErrUnavailable
	}
	return count, err
}

func (connection *idleConn) CloseWrite() error {
	if value, ok := connection.Conn.(interface{ CloseWrite() error }); ok {
		return value.CloseWrite()
	}
	return connection.Conn.Close()
}

// ValidateLoopbackEndpoint validates the sole canonical fixed-destination
// form accepted by the guest forwarder.
func ValidateLoopbackEndpoint(endpoint string) error {
	host, portValue, err := net.SplitHostPort(endpoint)
	if err != nil || (host != "127.0.0.1" && host != "::1") || net.JoinHostPort(host, portValue) != endpoint {
		return ErrProtocol
	}
	port, err := strconv.Atoi(portValue)
	if err != nil || port < 1 || port > 65535 || strconv.Itoa(port) != portValue {
		return ErrProtocol
	}
	return nil
}

func yamuxConfig() *yamux.Config {
	return &yamux.Config{
		AcceptBacklog: AcceptBacklog, EnableKeepAlive: true, KeepAliveInterval: KeepAliveInterval,
		ConnectionWriteTimeout: ConnectionWriteTimeout, MaxStreamWindowSize: StreamWindowBytes,
		StreamOpenTimeout: StreamOpenTimeout, StreamCloseTimeout: StreamCloseTimeout,
		LogOutput: io.Discard,
	}
}

func (*GatewaySession) String() string   { return "[native workspace gateway session]" }
func (*GatewaySession) GoString() string { return "[native workspace gateway session]" }
func (*GuestForwarder) String() string   { return "[native workspace guest forwarder]" }
func (*GuestForwarder) GoString() string { return "[native workspace guest forwarder]" }
