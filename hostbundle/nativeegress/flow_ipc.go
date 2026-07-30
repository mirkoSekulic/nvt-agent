package nativeegress

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/mirkoSekulic/nvt-agent/hostbundle/nativeegressipc"
	protocol "github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment/nativeegress"
)

const maxLocalFlowHandlers = protocol.MaxActiveFlows + protocol.MaxPendingFlowOpens + 8

// FlowLifecycle is the credential-bearing daemon's narrow local boundary. It
// exposes only destination intent and a liveness lease; credentials and the
// exact binding are not representable by nativeegressipc.
type FlowLifecycle interface {
	Start(context.Context) error
	Activate(protocol.FlowOpener) bool
	Withdraw()
	Done() <-chan error
	Close() error
}

type FlowServer struct {
	socketPath string
	ownerUID   uint32

	mu          sync.Mutex
	listener    *net.UnixListener
	connections map[net.Conn]struct{}
	opener      protocol.FlowOpener
	epoch       uint64
	readyDone   chan struct{}
	closed      bool
	workers     sync.WaitGroup
	admission   chan struct{}
	done        chan error
	closeOnce   sync.Once
	closeDone   chan struct{}
	lifetime    context.Context
	cancel      context.CancelFunc
}

func NewFlowServer(socketPath string) (*FlowServer, error) {
	if !validFile(socketPath) {
		return nil, fail(ReasonConfiguration, false, false)
	}
	return &FlowServer{
		socketPath: socketPath, ownerUID: uint32(os.Geteuid()),
		connections: make(map[net.Conn]struct{}, maxLocalFlowHandlers*2),
		admission:   make(chan struct{}, maxLocalFlowHandlers), done: make(chan error, 1), closeDone: make(chan struct{}),
	}, nil
}

func (server *FlowServer) Start(ctx context.Context) error {
	if server == nil || ctx == nil || ctx.Err() != nil || server.prepareSocket() != nil {
		return fail(ReasonCaptureUnavailable, false, false)
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: server.socketPath, Net: "unix"})
	if err != nil {
		return fail(ReasonCaptureUnavailable, false, false)
	}
	listener.SetUnlinkOnClose(false)
	if err := os.Chmod(server.socketPath, 0o600); err != nil {
		_ = listener.Close()
		_ = os.Remove(server.socketPath)
		return fail(ReasonCaptureUnavailable, false, false)
	}
	server.mu.Lock()
	if server.closed || server.listener != nil {
		server.mu.Unlock()
		_ = listener.Close()
		_ = os.Remove(server.socketPath)
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

func (server *FlowServer) prepareSocket() error {
	info, err := os.Lstat(server.socketPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o600 || !ownedByProcess(info) {
		return errors.New("local native egress socket is unsafe")
	}
	return os.Remove(server.socketPath)
}

func (server *FlowServer) Activate(opener protocol.FlowOpener) bool {
	if server == nil || opener == nil || channelClosed(opener.Done()) {
		return false
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	if server.closed || server.listener == nil {
		return false
	}
	server.epoch++
	if server.epoch == 0 {
		server.epoch++
	}
	if server.opener == nil {
		server.readyDone = make(chan struct{})
	}
	server.opener = opener
	return true
}

func (server *FlowServer) Withdraw() {
	if server == nil {
		return
	}
	server.mu.Lock()
	server.epoch++
	if server.opener != nil && server.readyDone != nil {
		close(server.readyDone)
	}
	server.opener = nil
	server.readyDone = nil
	server.mu.Unlock()
}

func (server *FlowServer) Done() <-chan error {
	if server == nil {
		closed := make(chan error)
		close(closed)
		return closed
	}
	return server.done
}

func (server *FlowServer) Close() error {
	if server == nil {
		return nil
	}
	server.closeOnce.Do(func() {
		server.mu.Lock()
		server.closed = true
		if server.cancel != nil {
			server.cancel()
		}
		server.epoch++
		if server.opener != nil && server.readyDone != nil {
			close(server.readyDone)
		}
		server.opener = nil
		server.readyDone = nil
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
			closeFlowConnection(connection)
		}
		finished := make(chan struct{})
		go func() { server.workers.Wait(); close(finished) }()
		select {
		case <-finished:
		case <-time.After(protocol.ShutdownTimeout):
		}
		_ = os.Remove(server.socketPath)
		close(server.closeDone)
	})
	<-server.closeDone
	return nil
}

func (server *FlowServer) String() string   { return "[credential-free local native egress flow server]" }
func (server *FlowServer) GoString() string { return server.String() }

func (server *FlowServer) serve() {
	defer server.workers.Done()
	for {
		server.mu.Lock()
		listener, closed := server.listener, server.closed
		server.mu.Unlock()
		if closed || listener == nil {
			return
		}
		connection, err := listener.AcceptUnix()
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
				closeFlowConnection(connection)
				continue
			}
			server.workers.Add(1)
			go server.handle(connection)
		default:
			closeFlowConnection(connection)
		}
	}
}

func (server *FlowServer) handle(connection *net.UnixConn) {
	defer server.workers.Done()
	defer func() { <-server.admission }()
	defer server.untrack(connection)
	defer closeFlowConnection(connection)
	if uid, err := unixPeerUID(connection); err != nil || uid != server.ownerUID {
		return
	}
	deadline := time.Now().Add(nativeegressipc.Deadline)
	_ = connection.SetDeadline(deadline)
	reader := bufio.NewReaderSize(connection, nativeegressipc.MaxMessageBytes)
	line, err := reader.ReadBytes('\n')
	if err != nil || len(line) > nativeegressipc.MaxMessageBytes {
		return
	}
	request, err := nativeegressipc.DecodeRequest(line)
	if err != nil {
		return
	}
	opener, epoch, readyDone := server.current()
	if opener == nil {
		return
	}
	switch request.Type {
	case nativeegressipc.Health:
		if reader.Buffered() != 0 || server.writeResponse(connection, nativeegressipc.Response{Version: nativeegressipc.Version, Type: nativeegressipc.Ready, Epoch: epoch}) != nil {
			return
		}
		_ = connection.SetDeadline(time.Time{})
		clientClosed := make(chan struct{})
		go func() {
			_, _ = io.Copy(io.Discard, io.LimitReader(connection, 1))
			close(clientClosed)
		}()
		select {
		case <-readyDone:
		case <-server.closeDone:
		case <-clientClosed:
		}
	case nativeegressipc.Open:
		server.open(connection, reader, opener, epoch, *request.Destination, deadline)
	}
}

func (server *FlowServer) open(connection net.Conn, reader *bufio.Reader, opener protocol.FlowOpener, epoch uint64, destination protocol.Destination, deadline time.Time) {
	server.mu.Lock()
	lifetime := server.lifetime
	server.mu.Unlock()
	if lifetime == nil {
		return
	}
	openContext, cancel := context.WithDeadline(lifetime, deadline)
	stop := context.AfterFunc(openContext, func() { closeFlowConnection(connection) })
	upstream, err := opener.OpenFlow(openContext, destination)
	stop()
	cancel()
	if err != nil || upstream == nil {
		if upstream != nil {
			closeFlowConnection(upstream)
		}
		if errors.Is(err, protocol.ErrDenied) {
			_ = server.writeResponse(connection, nativeegressipc.Response{Version: nativeegressipc.Version, Type: nativeegressipc.OpenReject, Reason: "denied"})
		}
		return
	}
	if !server.track(upstream) {
		closeFlowConnection(upstream)
		return
	}
	defer server.untrack(upstream)
	defer closeFlowConnection(upstream)
	if !server.currentMatches(opener, epoch) || server.writeResponse(connection, nativeegressipc.Response{Version: nativeegressipc.Version, Type: nativeegressipc.OpenAck, Epoch: epoch}) != nil {
		return
	}
	_ = connection.SetDeadline(time.Time{})
	relayLocalFlow(connection, reader, upstream, opener.Done(), server.closeDone)
}

func (server *FlowServer) writeResponse(connection net.Conn, response nativeegressipc.Response) error {
	data, err := nativeegressipc.EncodeResponse(response)
	if err != nil {
		return err
	}
	_, err = connection.Write(data)
	return err
}

func (server *FlowServer) current() (protocol.FlowOpener, uint64, <-chan struct{}) {
	server.mu.Lock()
	defer server.mu.Unlock()
	return server.opener, server.epoch, server.readyDone
}

func (server *FlowServer) currentMatches(opener protocol.FlowOpener, epoch uint64) bool {
	server.mu.Lock()
	defer server.mu.Unlock()
	return !server.closed && server.opener == opener && server.epoch == epoch
}

func (server *FlowServer) track(connection net.Conn) bool {
	server.mu.Lock()
	defer server.mu.Unlock()
	if server.closed {
		return false
	}
	server.connections[connection] = struct{}{}
	return true
}

func (server *FlowServer) untrack(connection net.Conn) {
	server.mu.Lock()
	delete(server.connections, connection)
	server.mu.Unlock()
}

func relayLocalFlow(client net.Conn, reader io.Reader, upstream net.Conn, openerDone <-chan struct{}, serverDone <-chan struct{}) {
	type result struct {
		client bool
		err    error
	}
	results := make(chan result, 2)
	go func() {
		buffer := make([]byte, protocol.CopyBufferBytes)
		_, err := io.CopyBuffer(upstream, reader, buffer)
		zero(buffer)
		results <- result{client: true, err: err}
	}()
	go func() {
		buffer := make([]byte, protocol.CopyBufferBytes)
		_, err := io.CopyBuffer(client, upstream, buffer)
		zero(buffer)
		results <- result{err: err}
	}()
	select {
	case first := <-results:
		if first.err != nil {
			closeFlowConnection(client)
			closeFlowConnection(upstream)
		} else if first.client {
			closeFlowWrite(upstream)
		} else {
			closeFlowWrite(client)
		}
	case <-openerDone:
		closeFlowConnection(client)
		closeFlowConnection(upstream)
		<-results
	case <-serverDone:
		closeFlowConnection(client)
		closeFlowConnection(upstream)
		<-results
	}
	<-results
}

func closeFlowWrite(connection net.Conn) {
	if closer, ok := connection.(interface{ CloseWrite() error }); ok {
		_ = closer.CloseWrite()
		return
	}
	_ = connection.Close()
}

func closeFlowConnection(connection net.Conn) {
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
