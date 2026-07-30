package relay

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment"
	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment/nativeegress"
)

var tlsHandshakeTimeout = nativeegress.HandshakeTimeout

// SessionLookup is the exact-only in-process registry seam. It cannot list or
// search bindings.
type SessionLookup interface {
	Active(guestenrollment.Binding) (*nativeegress.Session, bool)
}

type exactSessionLookup struct {
	registry *nativeegress.SessionRegistry
}

func (lookup *exactSessionLookup) Active(binding guestenrollment.Binding) (*nativeegress.Session, bool) {
	if lookup == nil || lookup.registry == nil || guestenrollment.ValidateBinding(binding) != nil {
		return nil, false
	}
	return lookup.registry.Active(binding)
}

func (*exactSessionLookup) String() string   { return "[native egress exact session lookup]" }
func (*exactSessionLookup) GoString() string { return "[native egress exact session lookup]" }

// Server accepts the guest-initiated authenticated TLS session and switches the
// admitted connection to the bounded native-egress flow transport.
type Server struct {
	listenAddress        string
	revalidationInterval time.Duration
	tlsConfig            *tls.Config
	authenticator        nativeegress.Authenticator
	resolver             TargetResolver
	registry             *nativeegress.SessionRegistry
	lookup               *exactSessionLookup
	handshakeSlots       chan struct{}
	handshakeTimeout     time.Duration

	lifetimeContext context.Context
	cancelLifetime  context.CancelFunc
	serveStarted    atomic.Bool
	shutdownStarted atomic.Bool

	listenerMu    sync.Mutex
	listener      net.Listener
	connectionsMu sync.Mutex
	connections   map[net.Conn]struct{}
	handlers      sync.WaitGroup
	done          chan struct{}
	doneOnce      sync.Once
	stopFinished  chan struct{}
}

func NewServer(config Configuration, resolver TargetResolver) (*Server, error) {
	if config.validate() != nil {
		return nil, errors.New("native egress relay configuration is invalid")
	}
	tlsConfig, err := loadServingTLS(config)
	if err != nil {
		return nil, err
	}
	authenticator, err := NewBrokerAuthenticator(config)
	if err != nil {
		return nil, err
	}
	if resolver == nil {
		resolver = DenyAllTargetResolver{}
	}
	server := newServer(
		config.ListenAddress,
		time.Duration(config.RevalidationIntervalSeconds)*time.Second,
		tlsConfig,
		authenticator,
		resolver,
		maxPendingTLSHandshakes,
	)
	if targetRegistry, ok := resolver.(*EgressdTargetRegistry); ok {
		if err := targetRegistry.bindSessionWithdrawal(server.registry.WithdrawBindings); err != nil {
			return nil, errors.New("native egress relay configuration is invalid")
		}
	}
	return server, nil
}

func newServer(listenAddress string, revalidationInterval time.Duration, tlsConfig *tls.Config, authenticator nativeegress.Authenticator, resolver TargetResolver, handshakeCapacity int) *Server {
	lifetime, cancelLifetime := context.WithCancel(context.Background())
	registry := nativeegress.NewSessionRegistry()
	return &Server{
		listenAddress: listenAddress, revalidationInterval: revalidationInterval, tlsConfig: tlsConfig,
		authenticator: authenticator, resolver: resolver, registry: registry,
		lookup: &exactSessionLookup{registry: registry}, handshakeSlots: make(chan struct{}, handshakeCapacity),
		handshakeTimeout: tlsHandshakeTimeout, lifetimeContext: lifetime, cancelLifetime: cancelLifetime,
		connections:  make(map[net.Conn]struct{}, nativeegress.MaxSessionBindings*2+maxPendingTLSHandshakes),
		done:         make(chan struct{}),
		stopFinished: make(chan struct{}),
	}
}

func (server *Server) Sessions() SessionLookup {
	if server == nil {
		return nil
	}
	return server.lookup
}

func (*Server) String() string   { return "[native egress relay server]" }
func (*Server) GoString() string { return "[native egress relay server]" }

func (server *Server) ListenAndServe() error {
	if server == nil {
		return errors.New("native egress relay unavailable")
	}
	listener, err := net.Listen("tcp", server.listenAddress)
	if err != nil {
		return errors.New("native egress relay unavailable")
	}
	return server.Serve(listener)
}

func (server *Server) Serve(listener net.Listener) error {
	if server == nil || listener == nil || server.tlsConfig == nil || server.authenticator == nil || server.resolver == nil ||
		server.revalidationInterval <= 0 || server.revalidationInterval > nativeegress.RevalidationInterval || server.handshakeTimeout <= 0 ||
		server.handshakeTimeout > nativeegress.HandshakeTimeout || cap(server.handshakeSlots) < 1 || !server.serveStarted.CompareAndSwap(false, true) {
		if listener != nil {
			_ = listener.Close()
		}
		return errors.New("native egress relay unavailable")
	}
	server.listenerMu.Lock()
	if server.shutdownStarted.Load() {
		server.listenerMu.Unlock()
		_ = listener.Close()
		<-server.stopFinished
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
			serveError = errors.New("native egress relay unavailable")
			break
		}
		select {
		case server.handshakeSlots <- struct{}{}:
			server.track(connection)
			server.handlers.Add(1)
			go func(raw net.Conn) {
				defer server.handlers.Done()
				defer server.untrack(raw)
				var releaseOnce sync.Once
				releaseHandshake := func() { releaseOnce.Do(func() { <-server.handshakeSlots }) }
				defer releaseHandshake()
				server.handleConnection(raw, releaseHandshake)
			}(connection)
		default:
			_ = connection.Close()
		}
	}
	server.stop()
	<-server.stopFinished
	server.handlers.Wait()
	server.finishServe()
	return serveError
}

func (server *Server) Shutdown(ctx context.Context) error {
	if server == nil {
		return nil
	}
	if ctx == nil {
		return context.Canceled
	}
	server.stop()
	if !server.serveStarted.Load() {
		go func() {
			<-server.stopFinished
			server.finishServe()
		}()
	}
	select {
	case <-server.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (server *Server) stop() {
	if !server.shutdownStarted.CompareAndSwap(false, true) {
		return
	}
	go server.finishStop()
}

func (server *Server) finishStop() {
	defer close(server.stopFinished)
	server.cancelLifetime()
	server.listenerMu.Lock()
	listener := server.listener
	server.listenerMu.Unlock()
	if listener != nil {
		_ = listener.Close()
	}
	// The shared registry withdraws every ready session before transports are
	// closed. Its own shutdown is bounded by the frozen contract.
	_ = server.registry.Close()
	server.closeTrackedConnections()
}

func (server *Server) finishServe() {
	server.doneOnce.Do(func() { close(server.done) })
}

func (server *Server) track(connection net.Conn) {
	server.connectionsMu.Lock()
	server.connections[connection] = struct{}{}
	server.connectionsMu.Unlock()
}

func (server *Server) untrack(connection net.Conn) {
	server.connectionsMu.Lock()
	delete(server.connections, connection)
	server.connectionsMu.Unlock()
}

func (server *Server) closeTrackedConnections() {
	server.connectionsMu.Lock()
	connections := make([]net.Conn, 0, len(server.connections))
	for connection := range server.connections {
		connections = append(connections, connection)
	}
	server.connectionsMu.Unlock()
	for _, connection := range connections {
		_ = connection.Close()
	}
}

func (server *Server) handleConnection(raw net.Conn, releaseHandshake func()) {
	connection := tls.Server(raw, server.tlsConfig.Clone())
	connectionOwned := true
	defer func() {
		if connectionOwned {
			_ = connection.Close()
		}
	}()
	tlsContext, cancelTLS := context.WithTimeout(server.lifetimeContext, server.handshakeTimeout)
	_ = connection.SetDeadline(time.Now().Add(server.handshakeTimeout))
	err := connection.HandshakeContext(tlsContext)
	cancelTLS()
	if err != nil || server.lifetimeContext.Err() != nil {
		return
	}
	admission := &sessionAdmission{authenticator: server.authenticator, resolver: server.resolver}
	handshakeContext, cancelHandshake := context.WithTimeout(server.lifetimeContext, nativeegress.HandshakeTimeout)
	pending, err := nativeegress.BeginAccept(handshakeContext, connection, admission)
	if err != nil || admission.target == nil || server.lifetimeContext.Err() != nil {
		cancelHandshake()
		return
	}
	authentication, err := pending.Authentication()
	if err != nil {
		cancelHandshake()
		return
	}
	localDeadline := time.Now().Add(server.revalidationInterval)
	if localDeadline.Before(authentication.LocalExpiresAt) {
		authentication.LocalExpiresAt = localDeadline
	}
	session, err := nativeegress.NewSession(authentication, admission.target)
	if err != nil {
		cancelHandshake()
		return
	}
	releaseTargetAdmission, targetReady := acquireTargetAdmission(admission.target)
	if !targetReady {
		cancelHandshake()
		_ = session.Close()
		return
	}
	targetAdmissionHeld := true
	defer func() {
		if targetAdmissionHeld {
			releaseTargetAdmission()
		}
	}()
	reservation, err := server.registry.Reserve(session)
	if err != nil {
		cancelHandshake()
		_ = session.Close()
		return
	}
	if err := pending.Acknowledge(); err != nil {
		cancelHandshake()
		reservation.Remove()
		return
	}
	cancelHandshake()
	transport, err := nativeegress.NewRelayFlowTransport(connection, session)
	if err != nil {
		reservation.Remove()
		return
	}
	connectionOwned = false
	// Session callbacks withdraw the exact registry reservation before the
	// transport callback closes the outer connection and target flows. Close
	// owns one shared absolute shutdown deadline across all of that work.
	defer transport.Close()
	if !reservation.Activate() {
		return
	}
	watchTargetLifecycle(session, admission.target)
	releaseTargetAdmission()
	targetAdmissionHeld = false
	releaseHandshake()
	_ = transport.Serve(server.lifetimeContext)
}

var _ SessionLookup = (*exactSessionLookup)(nil)
