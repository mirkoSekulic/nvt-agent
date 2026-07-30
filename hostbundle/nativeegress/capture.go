package nativeegress

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	protocol "github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment/nativeegress"
	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment/nativeegress/captureinspect"
)

const captureInspectTimeout = 2 * time.Second

// OriginalDestinationResolver recovers trusted kernel redirect metadata from
// an accepted TCP connection. It is injectable so providers and hermetic tests
// can supply an equivalent Linux-native capture mechanism without changing
// the egress transport or destination contract.
type OriginalDestinationResolver func(*net.TCPConn) (string, error)

// CaptureLifecycle is the narrow runtime boundary between captured guest TCP
// traffic and the current authenticated native-egress flow transport.
type CaptureLifecycle interface {
	Start(context.Context) error
	Activate(protocol.FlowOpener) bool
	Withdraw()
	Done() <-chan error
	Close() error
}

// CaptureServer accepts only loopback TCP redirected by provider-owned guest
// plumbing. It never dials a destination directly: every accepted connection
// either enters the current FlowOpener or is closed.
type CaptureServer struct {
	configuration CaptureConfiguration
	original      OriginalDestinationResolver

	mu          sync.Mutex
	listener    net.Listener
	connections map[net.Conn]struct{}
	opener      protocol.FlowOpener
	generation  uint64
	closed      bool
	workers     sync.WaitGroup
	admission   chan struct{}
	done        chan error
	closeOnce   sync.Once
	closeDone   chan struct{}
	lifetime    context.Context
	cancel      context.CancelFunc
}

// NewCaptureServer uses Linux SO_ORIGINAL_DST for the production capture
// boundary. Call NewCaptureServerWithResolver only when an equivalent trusted
// redirect mechanism owns destination recovery.
func NewCaptureServer(configuration CaptureConfiguration) (*CaptureServer, error) {
	return NewCaptureServerWithResolver(configuration, captureinspect.OriginalDestination)
}

func NewCaptureServerWithResolver(configuration CaptureConfiguration, resolver OriginalDestinationResolver) (*CaptureServer, error) {
	if validateCaptureConfiguration(&configuration) != nil || resolver == nil {
		return nil, fail(ReasonConfiguration, false, false)
	}
	return &CaptureServer{
		configuration: configuration,
		original:      resolver,
		connections:   make(map[net.Conn]struct{}, CaptureMaxConnections*2),
		admission:     make(chan struct{}, CaptureMaxConnections),
		done:          make(chan error, 1),
		closeDone:     make(chan struct{}),
	}, nil
}

func (server *CaptureServer) Start(ctx context.Context) error {
	if server == nil || ctx == nil || ctx.Err() != nil {
		return fail(ReasonCaptureUnavailable, false, false)
	}
	listener, err := net.Listen("tcp", server.configuration.ListenAddress)
	if err != nil {
		return fail(ReasonCaptureUnavailable, false, false)
	}
	server.mu.Lock()
	if server.closed || server.listener != nil {
		server.mu.Unlock()
		_ = listener.Close()
		return fail(ReasonCaptureUnavailable, false, false)
	}
	server.listener = listener
	server.lifetime, server.cancel = context.WithCancel(ctx)
	server.mu.Unlock()
	server.workers.Add(1)
	go server.serve()
	go func() {
		select {
		case <-ctx.Done():
			_ = server.Close()
		case <-server.closeDone:
		}
	}()
	return nil
}

func (server *CaptureServer) Activate(opener protocol.FlowOpener) bool {
	if server == nil || opener == nil || channelClosed(opener.Done()) {
		return false
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	if server.closed || server.listener == nil {
		return false
	}
	server.generation++
	server.opener = opener
	return true
}

func (server *CaptureServer) Withdraw() {
	if server == nil {
		return
	}
	server.mu.Lock()
	server.generation++
	server.opener = nil
	server.mu.Unlock()
}

func (server *CaptureServer) Done() <-chan error {
	if server == nil {
		closed := make(chan error)
		close(closed)
		return closed
	}
	return server.done
}

func (server *CaptureServer) Close() error {
	if server == nil {
		return nil
	}
	server.closeOnce.Do(func() {
		server.mu.Lock()
		server.closed = true
		if server.cancel != nil {
			server.cancel()
		}
		server.generation++
		server.opener = nil
		listener := server.listener
		server.listener = nil
		connections := make([]net.Conn, 0, len(server.connections))
		for connection := range server.connections {
			connections = append(connections, connection)
		}
		server.mu.Unlock()
		if listener != nil {
			_ = listener.Close()
		}
		for _, connection := range connections {
			closeCaptureConnection(connection)
		}
		finished := make(chan struct{})
		go func() {
			server.workers.Wait()
			close(finished)
		}()
		select {
		case <-finished:
		case <-time.After(protocol.ShutdownTimeout):
		}
		close(server.closeDone)
	})
	<-server.closeDone
	return nil
}

func (server *CaptureServer) String() string   { return "[native egress capture]" }
func (server *CaptureServer) GoString() string { return "[native egress capture]" }

func (server *CaptureServer) serve() {
	defer server.workers.Done()
	for {
		server.mu.Lock()
		listener, closed := server.listener, server.closed
		server.mu.Unlock()
		if closed || listener == nil {
			return
		}
		connection, err := listener.Accept()
		if err != nil {
			server.mu.Lock()
			closed = server.closed
			server.mu.Unlock()
			if !closed {
				select {
				case server.done <- fail(ReasonCaptureUnavailable, false, false):
				default:
				}
			}
			return
		}
		select {
		case server.admission <- struct{}{}:
			if !server.track(connection) {
				<-server.admission
				closeCaptureConnection(connection)
				continue
			}
			server.workers.Add(1)
			go server.handle(connection)
		default:
			closeCaptureConnection(connection)
		}
	}
}

func (server *CaptureServer) handle(connection net.Conn) {
	defer server.workers.Done()
	defer func() { <-server.admission }()
	defer server.untrack(connection)
	defer closeCaptureConnection(connection)
	tcp, ok := connection.(*net.TCPConn)
	if !ok {
		return
	}
	original, err := server.original(tcp)
	if err != nil {
		return
	}
	host, portText, err := net.SplitHostPort(original)
	port, portErr := strconv.Atoi(portText)
	if err != nil || portErr != nil || port < 1 || port > 65535 || portText != strconv.Itoa(port) {
		return
	}
	reader := bufio.NewReaderSize(connection, CaptureInspectBytes)
	_ = connection.SetReadDeadline(time.Now().Add(captureInspectTimeout))
	detected, inspectionErr := captureinspect.InspectHostname(reader, CaptureInspectBytes)
	_ = connection.SetReadDeadline(time.Time{})
	if inspectionErr != nil && !errors.Is(inspectionErr, captureinspect.ErrHostnameUnavailable) {
		return
	}
	if detected != "" {
		host = detected
	}
	destination := protocol.Destination{
		Network: protocol.NetworkTCP, Host: host, Port: uint16(port),
		CapabilityHint: server.configuration.CapabilityHint,
	}
	if protocol.ValidateDestination(destination) != nil {
		return
	}
	opener, generation := server.current()
	if opener == nil {
		return
	}
	server.mu.Lock()
	lifetime := server.lifetime
	server.mu.Unlock()
	if lifetime == nil {
		return
	}
	openContext, cancel := context.WithTimeout(lifetime, protocol.FlowOpenTimeout)
	stopOpener := make(chan struct{})
	go func() {
		select {
		case <-opener.Done():
			cancel()
		case <-openContext.Done():
		case <-stopOpener:
		}
	}()
	stop := context.AfterFunc(openContext, func() { closeCaptureConnection(connection) })
	upstream, err := opener.OpenFlow(openContext, destination)
	stop()
	cancel()
	close(stopOpener)
	if err != nil || upstream == nil {
		if upstream != nil {
			closeCaptureConnection(upstream)
		}
		return
	}
	if !server.track(upstream) {
		closeCaptureConnection(upstream)
		return
	}
	defer server.untrack(upstream)
	defer closeCaptureConnection(upstream)
	if !server.currentMatches(generation) {
		return
	}
	relayCaptured(connection, reader, upstream, opener.Done(), server.closeDone)
}

func (server *CaptureServer) current() (protocol.FlowOpener, uint64) {
	server.mu.Lock()
	defer server.mu.Unlock()
	return server.opener, server.generation
}

func (server *CaptureServer) currentMatches(generation uint64) bool {
	server.mu.Lock()
	defer server.mu.Unlock()
	return !server.closed && server.generation == generation && server.opener != nil
}

func (server *CaptureServer) track(connection net.Conn) bool {
	server.mu.Lock()
	defer server.mu.Unlock()
	if server.closed {
		return false
	}
	server.connections[connection] = struct{}{}
	return true
}

func (server *CaptureServer) untrack(connection net.Conn) {
	server.mu.Lock()
	delete(server.connections, connection)
	server.mu.Unlock()
}

func relayCaptured(client net.Conn, reader io.Reader, upstream net.Conn, openerDone <-chan struct{}, serverDone <-chan struct{}) {
	type copyResult struct {
		fromClient bool
		err        error
	}
	results := make(chan copyResult, 2)
	go func() {
		buffer := make([]byte, protocol.CopyBufferBytes)
		_, err := io.CopyBuffer(upstream, reader, buffer)
		zero(buffer)
		results <- copyResult{fromClient: true, err: err}
	}()
	go func() {
		buffer := make([]byte, protocol.CopyBufferBytes)
		_, err := io.CopyBuffer(client, upstream, buffer)
		zero(buffer)
		results <- copyResult{err: err}
	}()
	select {
	case first := <-results:
		if first.err != nil {
			closeCaptureConnection(client)
			closeCaptureConnection(upstream)
		} else if first.fromClient {
			closeCaptureWrite(upstream)
		} else {
			closeCaptureWrite(client)
		}
	case <-openerDone:
		closeCaptureConnection(client)
		closeCaptureConnection(upstream)
		<-results
	case <-serverDone:
		closeCaptureConnection(client)
		closeCaptureConnection(upstream)
		<-results
	}
	<-results
}

func closeCaptureWrite(connection net.Conn) {
	if closer, ok := connection.(interface{ CloseWrite() error }); ok {
		_ = closer.CloseWrite()
		return
	}
	_ = connection.Close()
}

func closeCaptureConnection(connection net.Conn) {
	if connection == nil {
		return
	}
	_ = connection.SetDeadline(time.Now())
	_ = connection.Close()
}

func channelClosed(channel <-chan struct{}) bool {
	if channel == nil {
		return true
	}
	select {
	case <-channel:
		return true
	default:
		return false
	}
}
