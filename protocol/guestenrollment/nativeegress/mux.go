package nativeegress

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/yamux"
)

// FlowOpener is the implementation-neutral trusted guest boundary. No yamux
// type, credential, target, or provider endpoint crosses it.
type FlowOpener interface {
	OpenFlow(context.Context, Destination) (net.Conn, error)
	Done() <-chan struct{}
	Close() error
}

type transportProfile struct {
	flowIdleTimeout time.Duration
	shutdownTimeout time.Duration
	maxFlowIDs      uint64
}

func defaultTransportProfile() transportProfile {
	return transportProfile{
		flowIdleTimeout: FlowIdleTimeout,
		shutdownTimeout: ShutdownTimeout,
		maxFlowIDs:      MaxFlowIDsPerSession,
	}
}

func (profile transportProfile) valid() bool {
	return profile.flowIdleTimeout > 0 && profile.flowIdleTimeout <= FlowIdleTimeout &&
		profile.shutdownTimeout > 0 && profile.shutdownTimeout <= ShutdownTimeout &&
		profile.maxFlowIDs > 0 && profile.maxFlowIDs <= MaxFlowIDsPerSession
}

// GuestFlowTransport opens one guest-originated logical stream per outbound
// TCP flow. It owns no runtime identity or egress credential.
type GuestFlowTransport struct {
	mux     *yamux.Session
	base    io.ReadWriteCloser
	profile transportProfile
	pending chan struct{}
	active  chan struct{}
	nextID  atomic.Uint64
	closed  atomic.Bool
	once    sync.Once

	lifetime context.Context
	cancel   context.CancelFunc

	mu      sync.Mutex
	streams map[*guestFlowConn]struct{}

	workerMu sync.Mutex
	workers  sync.WaitGroup

	closeFinished chan struct{}
}

// RelayFlowTransport accepts guest-opened streams and routes each validated
// flow only through the already-authenticated exact-binding Session.
type RelayFlowTransport struct {
	mux      *yamux.Session
	base     io.ReadWriteCloser
	session  *Session
	profile  transportProfile
	handlers chan struct{}
	closed   atomic.Bool
	started  atomic.Bool
	once     sync.Once

	lifetime context.Context
	cancel   context.CancelFunc

	flowIDsMu sync.Mutex
	flowIDs   map[string]struct{}

	workerMu sync.Mutex
	workers  sync.WaitGroup

	closeFinished chan struct{}
}

type streamOpenResult struct {
	stream net.Conn
	err    error
}

type guestFlowConn struct {
	net.Conn
	reader *bufio.Reader
	owner  *GuestFlowTransport
	once   sync.Once
}

type activityConn struct {
	net.Conn
	timeout time.Duration
}

func NewGuestFlowTransport(connection io.ReadWriteCloser) (*GuestFlowTransport, error) {
	return newGuestFlowTransport(connection, defaultTransportProfile())
}

func newGuestFlowTransport(connection io.ReadWriteCloser, profile transportProfile) (*GuestFlowTransport, error) {
	if connection == nil || !profile.valid() {
		return nil, ErrProtocol
	}
	multiplexer, err := yamux.Client(connection, yamuxConfig())
	if err != nil {
		return nil, ErrUnavailable
	}
	lifetime, cancel := context.WithCancel(context.Background())
	transport := &GuestFlowTransport{
		mux: multiplexer, base: connection, profile: profile,
		pending: make(chan struct{}, MaxPendingFlowOpens), active: make(chan struct{}, MaxActiveFlows),
		lifetime: lifetime, cancel: cancel, streams: make(map[*guestFlowConn]struct{}, MaxActiveFlows),
		closeFinished: make(chan struct{}),
	}
	transport.workers.Add(1)
	go func() {
		defer transport.workers.Done()
		<-multiplexer.CloseChan()
		transport.beginShutdown()
	}()
	transport.workers.Add(1)
	go func() {
		defer transport.workers.Done()
		stream, err := multiplexer.AcceptStream()
		if err == nil && stream != nil {
			_ = stream.Close()
			transport.beginShutdown()
		}
	}()
	return transport, nil
}

func NewRelayFlowTransport(connection io.ReadWriteCloser, session *Session) (*RelayFlowTransport, error) {
	return newRelayFlowTransport(connection, session, defaultTransportProfile())
}

func newRelayFlowTransport(connection io.ReadWriteCloser, session *Session, profile transportProfile) (*RelayFlowTransport, error) {
	if connection == nil || session == nil || !session.Ready() || !profile.valid() {
		return nil, ErrProtocol
	}
	multiplexer, err := yamux.Server(connection, yamuxConfig())
	if err != nil {
		return nil, ErrUnavailable
	}
	lifetime, cancel := context.WithCancel(context.Background())
	transport := &RelayFlowTransport{
		mux: multiplexer, base: connection, session: session, profile: profile,
		handlers: make(chan struct{}, MaxActiveFlows+MaxPendingFlowOpens),
		lifetime: lifetime, cancel: cancel, flowIDs: make(map[string]struct{}, profile.maxFlowIDs),
		closeFinished: make(chan struct{}),
	}
	// Session callbacks run in registration order. The registry installs its
	// readiness withdrawal before the relay constructs this transport, so the
	// outer connection and streams close only after readiness is absent.
	if !session.addBeforeShutdown(transport.beginShutdown) {
		_ = multiplexer.Close()
		_ = connection.Close()
		return nil, ErrUnavailable
	}
	transport.workers.Add(1)
	go func() {
		defer transport.workers.Done()
		<-multiplexer.CloseChan()
		_ = session.Close()
	}()
	return transport, nil
}

func (transport *GuestFlowTransport) Done() <-chan struct{} {
	if transport == nil {
		closed := make(chan struct{})
		close(closed)
		return closed
	}
	return transport.lifetime.Done()
}

// AwaitReady proves that the authenticated peer has switched to the pinned
// yamux data plane. A hello acknowledgement alone is not transport readiness.
func (transport *GuestFlowTransport) AwaitReady(ctx context.Context) error {
	if transport == nil || ctx == nil || ctx.Err() != nil || transport.closed.Load() {
		return ErrUnavailable
	}
	stopCancellation := context.AfterFunc(ctx, transport.beginShutdown)
	defer stopCancellation()
	if _, err := transport.mux.Ping(); err != nil || ctx.Err() != nil || transport.closed.Load() {
		transport.beginShutdown()
		return ErrUnavailable
	}
	return nil
}

func (transport *GuestFlowTransport) OpenFlow(ctx context.Context, destination Destination) (net.Conn, error) {
	if transport == nil || ctx == nil || ValidateDestination(destination) != nil {
		return nil, ErrProtocol
	}
	if ctx.Err() != nil || transport.closed.Load() {
		return nil, ErrUnavailable
	}
	select {
	case transport.pending <- struct{}{}:
	case <-ctx.Done():
		return nil, ErrUnavailable
	default:
		return nil, ErrCapacity
	}
	select {
	case transport.active <- struct{}{}:
	case <-ctx.Done():
		<-transport.pending
		return nil, ErrUnavailable
	default:
		<-transport.pending
		return nil, ErrCapacity
	}
	stream, err := transport.openStream(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { <-transport.pending }()
	flowIDSequence := transport.nextID.Add(1)
	if flowIDSequence == 0 || flowIDSequence > transport.profile.maxFlowIDs {
		_ = stream.Close()
		<-transport.active
		transport.beginShutdown()
		return nil, ErrCapacity
	}
	flowID := "flow-" + strconv.FormatUint(flowIDSequence, 10)
	deadline := operationDeadline(ctx, FlowOpenTimeout)
	request := Message{ContractVersion: Version, Type: FlowOpen, FlowID: flowID, Destination: &destination}
	if err := writeMessage(stream, request, deadline); err != nil {
		_ = stream.Close()
		<-transport.active
		return nil, ErrUnavailable
	}
	response, reader, err := readFlowResponse(stream, deadline)
	if err != nil {
		_ = stream.Close()
		<-transport.active
		if errors.Is(err, ErrProtocol) {
			transport.beginShutdown()
		}
		return nil, err
	}
	if response.FlowID != flowID {
		_ = stream.Close()
		<-transport.active
		transport.beginShutdown()
		return nil, ErrProtocol
	}
	if response.Type == FlowOpenReject {
		_ = stream.Close()
		<-transport.active
		return nil, ErrDenied
	}
	if response.Type != FlowOpenAck {
		_ = stream.Close()
		<-transport.active
		transport.beginShutdown()
		return nil, ErrProtocol
	}
	_ = stream.SetDeadline(time.Time{})
	connection := &guestFlowConn{
		Conn:   &activityConn{Conn: stream, timeout: transport.profile.flowIdleTimeout},
		reader: reader, owner: transport,
	}
	transport.mu.Lock()
	if transport.closed.Load() {
		transport.mu.Unlock()
		_ = stream.Close()
		<-transport.active
		return nil, ErrUnavailable
	}
	transport.streams[connection] = struct{}{}
	transport.mu.Unlock()
	return connection, nil
}

func (transport *GuestFlowTransport) openStream(ctx context.Context) (net.Conn, error) {
	result := make(chan streamOpenResult)
	abandon := make(chan struct{})
	transport.workerMu.Lock()
	if transport.closed.Load() {
		transport.workerMu.Unlock()
		<-transport.active
		<-transport.pending
		return nil, ErrUnavailable
	}
	transport.workers.Add(1)
	transport.workerMu.Unlock()
	go func() {
		defer transport.workers.Done()
		stream, err := transport.mux.OpenStream()
		select {
		case result <- streamOpenResult{stream: stream, err: err}:
		case <-abandon:
			if stream != nil {
				_ = stream.Close()
			}
			<-transport.active
			<-transport.pending
		}
	}()
	select {
	case opened := <-result:
		if opened.err != nil || opened.stream == nil {
			<-transport.active
			<-transport.pending
			return nil, ErrUnavailable
		}
		return opened.stream, nil
	case <-ctx.Done():
		close(abandon)
		return nil, ErrUnavailable
	case <-transport.lifetime.Done():
		close(abandon)
		return nil, ErrUnavailable
	}
}

func (connection *guestFlowConn) Read(value []byte) (int, error) {
	if connection == nil {
		return 0, net.ErrClosed
	}
	if connection.reader != nil && connection.reader.Buffered() > 0 {
		return connection.reader.Read(value)
	}
	return connection.Conn.Read(value)
}

func (connection *guestFlowConn) CloseWrite() error {
	if connection == nil {
		return net.ErrClosed
	}
	return closeWrite(connection.Conn)
}

func (connection *guestFlowConn) Close() error {
	if connection == nil {
		return nil
	}
	var result error
	connection.once.Do(func() {
		_ = connection.Conn.SetDeadline(time.Now())
		result = connection.Conn.Close()
		connection.owner.mu.Lock()
		if _, present := connection.owner.streams[connection]; present {
			delete(connection.owner.streams, connection)
			<-connection.owner.active
		}
		connection.owner.mu.Unlock()
	})
	return result
}

func (transport *RelayFlowTransport) Serve(ctx context.Context) error {
	if transport == nil || ctx == nil || ctx.Err() != nil || transport.closed.Load() || !transport.started.CompareAndSwap(false, true) {
		return ErrUnavailable
	}
	defer transport.Close()
	serveContext, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		select {
		case <-transport.lifetime.Done():
			cancel()
		case <-serveContext.Done():
		}
	}()
	for {
		stream, err := transport.mux.AcceptStreamWithContext(serveContext)
		if err != nil {
			if serveContext.Err() != nil || transport.closed.Load() {
				return nil
			}
			return ErrUnavailable
		}
		select {
		case transport.handlers <- struct{}{}:
			transport.workerMu.Lock()
			if transport.closed.Load() {
				transport.workerMu.Unlock()
				<-transport.handlers
				_ = stream.Close()
				return nil
			}
			transport.workers.Add(1)
			transport.workerMu.Unlock()
			go transport.handleStream(stream)
		default:
			_ = stream.Close()
		}
	}
}

func (transport *RelayFlowTransport) handleStream(stream net.Conn) {
	defer transport.workers.Done()
	defer func() { <-transport.handlers }()
	defer stream.Close()
	deadline := operationDeadline(transport.lifetime, FlowOpenTimeout)
	message, reader, err := readFlowResponse(stream, deadline)
	if err != nil || reader.Buffered() != 0 || message.Type != FlowOpen || message.Destination == nil {
		_ = transport.session.Close()
		return
	}
	if !transport.reserveFlowID(message.FlowID) {
		_ = transport.session.Close()
		return
	}
	openContext, cancel := context.WithDeadline(transport.lifetime, deadline)
	target, err := transport.session.OpenFlow(openContext, *message.Destination)
	cancel()
	if err != nil {
		if errors.Is(err, ErrDenied) {
			_ = writeMessage(stream, Message{ContractVersion: Version, Type: FlowOpenReject, FlowID: message.FlowID, Reason: "denied"}, deadline)
		}
		return
	}
	defer target.Close()
	if err := writeMessage(stream, Message{ContractVersion: Version, Type: FlowOpenAck, FlowID: message.FlowID}, deadline); err != nil {
		return
	}
	_ = stream.SetDeadline(time.Time{})
	bridgeFlow(
		&activityConn{Conn: stream, timeout: transport.profile.flowIdleTimeout},
		target,
	)
}

func (transport *RelayFlowTransport) reserveFlowID(flowID string) bool {
	transport.flowIDsMu.Lock()
	defer transport.flowIDsMu.Unlock()
	if len(transport.flowIDs) >= int(transport.profile.maxFlowIDs) {
		return false
	}
	if _, present := transport.flowIDs[flowID]; present {
		return false
	}
	transport.flowIDs[flowID] = struct{}{}
	return true
}

func (connection *activityConn) Read(value []byte) (int, error) {
	if connection == nil || connection.Conn.SetDeadline(time.Now().Add(connection.timeout)) != nil {
		return 0, ErrUnavailable
	}
	count, err := connection.Conn.Read(value)
	if count > 0 && connection.Conn.SetDeadline(time.Now().Add(connection.timeout)) != nil {
		return count, ErrUnavailable
	}
	return count, err
}

func (connection *activityConn) Write(value []byte) (int, error) {
	if connection == nil || connection.Conn.SetDeadline(time.Now().Add(connection.timeout)) != nil {
		return 0, ErrUnavailable
	}
	count, err := connection.Conn.Write(value)
	if count > 0 && connection.Conn.SetDeadline(time.Now().Add(connection.timeout)) != nil {
		return count, ErrUnavailable
	}
	return count, err
}

func (connection *activityConn) CloseWrite() error {
	return closeWrite(connection.Conn)
}

func bridgeFlow(guest net.Conn, target net.Conn) {
	type copyResult struct {
		fromGuest bool
		err       error
	}
	results := make(chan copyResult, 2)
	go func() {
		buffer := make([]byte, CopyBufferBytes)
		_, err := io.CopyBuffer(target, guest, buffer)
		zero(buffer)
		results <- copyResult{fromGuest: true, err: err}
	}()
	go func() {
		buffer := make([]byte, CopyBufferBytes)
		_, err := io.CopyBuffer(guest, target, buffer)
		zero(buffer)
		results <- copyResult{err: err}
	}()
	first := <-results
	if first.err != nil {
		closeNow(guest)
		closeNow(target)
	} else if first.fromGuest {
		_ = closeWrite(target)
	} else {
		_ = closeWrite(guest)
	}
	<-results
	closeNow(guest)
	closeNow(target)
}

func closeWrite(connection net.Conn) error {
	if value, ok := connection.(interface{ CloseWrite() error }); ok {
		return value.CloseWrite()
	}
	return connection.Close()
}

func closeNow(connection net.Conn) {
	if connection == nil {
		return
	}
	_ = connection.SetDeadline(time.Now())
	_ = connection.Close()
}

func readFlowResponse(connection net.Conn, deadline time.Time) (Message, *bufio.Reader, error) {
	if deadline.IsZero() || !time.Now().Before(deadline) || connection.SetReadDeadline(deadline) != nil {
		return Message{}, nil, ErrUnavailable
	}
	reader := bufio.NewReaderSize(connection, MaxFrameBytes)
	line, err := reader.ReadSlice('\n')
	if err != nil {
		zero(line)
		if len(line) == 0 {
			return Message{}, nil, ErrUnavailable
		}
		return Message{}, nil, ErrProtocol
	}
	if len(line) == 0 || len(line) > MaxFrameBytes {
		zero(line)
		return Message{}, nil, ErrProtocol
	}
	defer zero(line)
	message, err := DecodeMessage(line)
	if err != nil {
		return Message{}, nil, err
	}
	return message, reader, nil
}

func (transport *GuestFlowTransport) beginShutdown() {
	if transport == nil {
		return
	}
	transport.once.Do(func() {
		transport.closed.Store(true)
		transport.cancel()
		transport.mu.Lock()
		streams := make([]*guestFlowConn, 0, len(transport.streams))
		for stream := range transport.streams {
			streams = append(streams, stream)
		}
		transport.mu.Unlock()
		go func() {
			var closing sync.WaitGroup
			closing.Add(len(streams) + 2)
			for _, stream := range streams {
				go func() {
					defer closing.Done()
					_ = stream.Close()
				}()
			}
			go func() { defer closing.Done(); _ = transport.mux.Close() }()
			go func() { defer closing.Done(); _ = transport.base.Close() }()
			closing.Wait()
			close(transport.closeFinished)
		}()
	})
}

func (transport *RelayFlowTransport) beginShutdown() {
	if transport == nil {
		return
	}
	transport.once.Do(func() {
		transport.closed.Store(true)
		transport.cancel()
		go func() {
			var closing sync.WaitGroup
			closing.Add(2)
			go func() { defer closing.Done(); _ = transport.mux.Close() }()
			go func() { defer closing.Done(); _ = transport.base.Close() }()
			closing.Wait()
			close(transport.closeFinished)
		}()
	})
}

func (transport *GuestFlowTransport) Close() error {
	if transport == nil {
		return nil
	}
	transport.beginShutdown()
	return transport.waitForShutdown()
}

func (transport *GuestFlowTransport) waitForShutdown() error {
	workersDone := make(chan struct{})
	go func() {
		transport.workerMu.Lock()
		transport.workerMu.Unlock()
		transport.workers.Wait()
		close(workersDone)
	}()
	timer := time.NewTimer(transport.profile.shutdownTimeout)
	defer timer.Stop()
	closed, workers := false, false
	closeFinished := (<-chan struct{})(transport.closeFinished)
	workersFinished := (<-chan struct{})(workersDone)
	for !closed || !workers {
		select {
		case <-closeFinished:
			closed = true
			closeFinished = nil
		case <-workersFinished:
			workers = true
			workersFinished = nil
		case <-timer.C:
			return ErrUnavailable
		}
	}
	return nil
}

func (transport *RelayFlowTransport) Close() error {
	if transport == nil {
		return nil
	}
	deadline := time.Now().Add(transport.profile.shutdownTimeout)
	_ = transport.session.closeWithin(transport.profile.shutdownTimeout)
	transport.beginShutdown()
	workersDone := make(chan struct{})
	go func() {
		transport.workerMu.Lock()
		transport.workerMu.Unlock()
		transport.workers.Wait()
		close(workersDone)
	}()
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return ErrUnavailable
	}
	timer := time.NewTimer(remaining)
	defer timer.Stop()
	closed, workers := false, false
	closeFinished := (<-chan struct{})(transport.closeFinished)
	workersFinished := (<-chan struct{})(workersDone)
	for !closed || !workers {
		select {
		case <-closeFinished:
			closed = true
			closeFinished = nil
		case <-workersFinished:
			workers = true
			workersFinished = nil
		case <-timer.C:
			return ErrUnavailable
		}
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

func (*GuestFlowTransport) String() string   { return "[native egress guest flow transport]" }
func (*GuestFlowTransport) GoString() string { return "[native egress guest flow transport]" }
func (*RelayFlowTransport) String() string   { return "[native egress relay flow transport]" }
func (*RelayFlowTransport) GoString() string { return "[native egress relay flow transport]" }

var _ FlowOpener = (*GuestFlowTransport)(nil)
