package gateway

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment"
	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment/workspacetunnel"
)

const maxNativeWorkspacePendingHandshakes = 32

var nativeWorkspaceTLSHandshakeLimit = 5 * time.Second

// NativeWorkspaceConfig is the additive listener-only configuration. Serving
// identity, broker authority, and bounded trust settings are inherited from
// the required NativeSessionConfig rather than duplicated.
type NativeWorkspaceConfig struct {
	Enabled    bool
	ListenAddr string
}

func (config NativeWorkspaceConfig) validate(nativeSession NativeSessionConfig) error {
	if !config.Enabled {
		return nil
	}
	if !nativeSession.Enabled {
		return errors.New("nativeWorkspace requires nativeSession")
	}
	if validateNativeSessionListenAddress(config.ListenAddr) != nil {
		return errors.New("nativeWorkspace.listenAddr must be a TCP host and port between 1 and 65535")
	}
	return nil
}

// NativeWorkspaceStreams is the implementation-neutral routing seam for a
// later browser proxy. StreamOpener retains only the complete binding and the
// validated non-secret issuance sequence in addition to bounded stream open.
type NativeWorkspaceStreams interface {
	Lookup(guestenrollment.Binding) (workspacetunnel.StreamOpener, bool)
}

type nativeWorkspaceStreams struct {
	registry *workspacetunnel.SessionRegistry
}

func (streams *nativeWorkspaceStreams) Lookup(binding guestenrollment.Binding) (workspacetunnel.StreamOpener, bool) {
	if streams == nil || streams.registry == nil || guestenrollment.ValidateBinding(binding) != nil {
		return nil, false
	}
	return streams.registry.Active(binding)
}

func (*nativeWorkspaceStreams) String() string   { return "[native workspace streams]" }
func (*nativeWorkspaceStreams) GoString() string { return "[native workspace streams]" }

// NativeWorkspaceServer accepts the separate native workspace TLS/yamux data
// plane. It intentionally exposes no HTTP/browser route.
type NativeWorkspaceServer struct {
	config               NativeWorkspaceConfig
	revalidationInterval time.Duration
	tlsConfig            *tls.Config
	authenticator        workspacetunnel.Authenticator
	registry             *workspacetunnel.SessionRegistry
	streams              *nativeWorkspaceStreams
	handshakeSlots       chan struct{}

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

func NewNativeWorkspaceServer(config NativeWorkspaceConfig, nativeSession NativeSessionConfig) (*NativeWorkspaceServer, error) {
	if !config.Enabled {
		return nil, nil
	}
	if err := nativeSession.validate(); err != nil {
		return nil, err
	}
	if err := config.validate(nativeSession); err != nil {
		return nil, err
	}
	certificate, err := tls.LoadX509KeyPair(nativeSession.TLSCertificateFile, nativeSession.TLSKeyFile)
	if err != nil {
		return nil, errors.New("load native workspace TLS identity failed")
	}
	authenticator, err := newBrokerNativeSessionAuthenticator(nativeSession)
	if err != nil {
		return nil, err
	}
	return newNativeWorkspaceServer(config, nativeSession.RevalidationInterval, &tls.Config{
		MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate},
	}, authenticator), nil
}

func newNativeWorkspaceServer(config NativeWorkspaceConfig, revalidationInterval time.Duration, tlsConfig *tls.Config, authenticator workspacetunnel.Authenticator) *NativeWorkspaceServer {
	ctx, cancel := context.WithCancel(context.Background())
	registry := workspacetunnel.NewSessionRegistry()
	return &NativeWorkspaceServer{
		config: config, revalidationInterval: revalidationInterval, tlsConfig: tlsConfig, authenticator: authenticator,
		registry: registry, streams: &nativeWorkspaceStreams{registry: registry},
		handshakeSlots:  make(chan struct{}, maxNativeWorkspacePendingHandshakes),
		lifetimeContext: ctx, cancelLifetime: cancel, done: make(chan struct{}),
	}
}

func (server *NativeWorkspaceServer) Registry() NativeWorkspaceStreams {
	if server == nil {
		return nil
	}
	return server.streams
}

func (*NativeWorkspaceServer) String() string   { return "[native workspace server]" }
func (*NativeWorkspaceServer) GoString() string { return "[native workspace server]" }

func (server *NativeWorkspaceServer) ListenAndServe() error {
	if server == nil {
		return nil
	}
	listener, err := net.Listen("tcp", server.config.ListenAddr)
	if err != nil {
		return errors.New("native workspace listener failed")
	}
	return server.Serve(listener)
}

func (server *NativeWorkspaceServer) Serve(listener net.Listener) error {
	if server == nil || listener == nil || server.tlsConfig == nil || server.authenticator == nil ||
		server.revalidationInterval <= 0 || !server.serveStarted.CompareAndSwap(false, true) {
		if listener != nil {
			_ = listener.Close()
		}
		return errors.New("native workspace listener failed")
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
			serveError = errors.New("native workspace listener failed")
			break
		}
		select {
		case server.handshakeSlots <- struct{}{}:
			server.handlers.Add(1)
			go func() {
				defer server.handlers.Done()
				var releaseOnce sync.Once
				releaseHandshake := func() { releaseOnce.Do(func() { <-server.handshakeSlots }) }
				defer releaseHandshake()
				server.handleConnection(connection, releaseHandshake)
			}()
		default:
			_ = connection.Close()
		}
	}
	server.cancelLifetime()
	_ = server.registry.Close()
	server.handlers.Wait()
	server.finishServe()
	return serveError
}

func (server *NativeWorkspaceServer) Shutdown(ctx context.Context) error {
	if server == nil {
		return nil
	}
	if ctx == nil {
		return context.Canceled
	}
	if server.shutdownStarted.CompareAndSwap(false, true) {
		server.cancelLifetime()
		_ = server.registry.Close()
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

func (server *NativeWorkspaceServer) finishServe() {
	server.doneOnce.Do(func() { close(server.done) })
}

func (server *NativeWorkspaceServer) handleConnection(raw net.Conn, releaseHandshake func()) {
	connection := tls.Server(raw, server.tlsConfig.Clone())
	defer connection.Close()
	tlsContext, cancelTLS := context.WithTimeout(server.lifetimeContext, nativeWorkspaceTLSHandshakeLimit)
	_ = connection.SetDeadline(time.Now().Add(nativeWorkspaceTLSHandshakeLimit))
	err := connection.HandshakeContext(tlsContext)
	cancelTLS()
	if err != nil || server.lifetimeContext.Err() != nil {
		return
	}

	handshakeContext, cancelHandshake := context.WithTimeout(server.lifetimeContext, workspacetunnel.HandshakeTimeout)
	authentication, err := workspacetunnel.Accept(handshakeContext, connection, server.authenticator)
	cancelHandshake()
	if err != nil || server.lifetimeContext.Err() != nil {
		return
	}
	localDeadline := time.Now().Add(server.revalidationInterval)
	if localDeadline.Before(authentication.LocalExpiresAt) {
		authentication.LocalExpiresAt = localDeadline
	}
	session, err := workspacetunnel.NewGatewaySession(connection, authentication)
	if err != nil {
		return
	}
	defer session.Close()
	reservation, err := server.registry.Reserve(session)
	if err != nil {
		return
	}
	defer reservation.Remove()
	if !reservation.Activate() {
		return
	}
	releaseHandshake()
	select {
	case <-server.lifetimeContext.Done():
	case <-session.Done():
	}
}

var _ NativeWorkspaceStreams = (*nativeWorkspaceStreams)(nil)
