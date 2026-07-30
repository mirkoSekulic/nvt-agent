package nativecapture

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/mirkoSekulic/nvt-agent/hostbundle/nativeegressipc"
	protocol "github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment/nativeegress"
	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment/nativeegress/captureinspect"
)

const inspectTimeout = 2 * time.Second

type OriginalDestinationResolver func(*net.TCPConn) (string, error)

type boundedPrefaceReader struct {
	reader  io.Reader
	maximum int
	read    int
	bounded bool
}

func (reader *boundedPrefaceReader) Read(destination []byte) (int, error) {
	if reader.bounded {
		remaining := reader.maximum + 1 - reader.read
		if remaining <= 0 {
			return 0, errors.New("native capture preface is oversized")
		}
		if len(destination) > remaining {
			destination = destination[:remaining]
		}
	}
	count, err := reader.reader.Read(destination)
	if reader.bounded {
		reader.read += count
	}
	return count, err
}

type Server struct {
	Configuration Configuration
	Original      OriginalDestinationResolver
	FlowClient    nativeegressipc.Client

	mu          sync.Mutex
	listeners   []net.Listener
	connections map[net.Conn]struct{}
	closed      bool
	workers     sync.WaitGroup
	admission   chan struct{}
	healthLease chan struct{}
	done        chan error
	closeOnce   sync.Once
	closeDone   chan struct{}
	lifetime    context.Context
	cancel      context.CancelFunc
}

func NewServer(configuration Configuration) (*Server, error) {
	return NewServerWithResolver(configuration, captureinspect.OriginalDestination)
}

func NewServerWithResolver(configuration Configuration, resolver OriginalDestinationResolver) (*Server, error) {
	if ValidateConfiguration(configuration) != nil || resolver == nil {
		return nil, errors.New("native capture configuration is invalid")
	}
	return &Server{
		Configuration: configuration, Original: resolver,
		FlowClient:  nativeegressipc.Client{SocketPath: configuration.FlowSocketPath, OwnerUID: uint32(os.Geteuid())},
		connections: make(map[net.Conn]struct{}, MaxConnections+1), admission: make(chan struct{}, MaxConnections),
		healthLease: make(chan struct{}, 1),
		done:        make(chan error, 1), closeDone: make(chan struct{}),
	}, nil
}

func (server *Server) Start(ctx context.Context) error {
	if server == nil || ctx == nil || ctx.Err() != nil || ensureRuntimeDirectory(server.Configuration.RuntimeDirectory) != nil || server.prepareReadinessSocket() != nil {
		return errors.New("native capture unavailable")
	}
	transparent, err := net.Listen("tcp", server.Configuration.TransparentListenAddress)
	if err != nil {
		return errors.New("native capture unavailable")
	}
	explicit, err := net.Listen("tcp", server.Configuration.ExplicitListenAddress)
	if err != nil {
		_ = transparent.Close()
		return errors.New("native capture unavailable")
	}
	readiness, err := net.ListenUnix("unix", &net.UnixAddr{Name: server.Configuration.ReadinessSocketPath, Net: "unix"})
	if err != nil {
		_ = transparent.Close()
		_ = explicit.Close()
		return errors.New("native capture unavailable")
	}
	readiness.SetUnlinkOnClose(false)
	if err := os.Chmod(server.Configuration.ReadinessSocketPath, 0o660); err != nil {
		_ = transparent.Close()
		_ = explicit.Close()
		_ = readiness.Close()
		_ = os.Remove(server.Configuration.ReadinessSocketPath)
		return errors.New("native capture unavailable")
	}
	server.mu.Lock()
	if server.closed || len(server.listeners) != 0 {
		server.mu.Unlock()
		_ = transparent.Close()
		_ = explicit.Close()
		_ = readiness.Close()
		_ = os.Remove(server.Configuration.ReadinessSocketPath)
		return errors.New("native capture unavailable")
	}
	server.listeners = []net.Listener{transparent, explicit, readiness}
	server.lifetime, server.cancel = context.WithCancel(ctx)
	server.mu.Unlock()
	server.workers.Add(3)
	go server.serveTCP(transparent, true)
	go server.serveTCP(explicit, false)
	go server.serveHealth(readiness)
	go func() {
		select {
		case <-ctx.Done():
			_ = server.Close()
		case <-server.closeDone:
		}
	}()
	return nil
}

func (server *Server) Done() <-chan error { return server.done }

func (server *Server) Close() error {
	if server == nil {
		return nil
	}
	server.closeOnce.Do(func() {
		server.mu.Lock()
		server.closed = true
		if server.cancel != nil {
			server.cancel()
		}
		listeners := append([]net.Listener(nil), server.listeners...)
		server.listeners = nil
		connections := make([]net.Conn, 0, len(server.connections))
		for connection := range server.connections {
			connections = append(connections, connection)
		}
		server.mu.Unlock()
		for _, listener := range listeners {
			_ = listener.Close()
		}
		for _, connection := range connections {
			closeConnection(connection)
		}
		finished := make(chan struct{})
		go func() { server.workers.Wait(); close(finished) }()
		select {
		case <-finished:
		case <-time.After(protocol.ShutdownTimeout):
		}
		_ = os.Remove(server.Configuration.ReadinessSocketPath)
		close(server.closeDone)
	})
	<-server.closeDone
	return nil
}

func (server *Server) String() string   { return "[credential-less native guest capture]" }
func (server *Server) GoString() string { return server.String() }

func (server *Server) prepareReadinessSocket() error {
	info, err := os.Lstat(server.Configuration.ReadinessSocketPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o660 || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("native capture readiness socket is unsafe")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || stat.Gid != uint32(os.Getegid()) || stat.Nlink != 1 {
		return errors.New("native capture readiness socket is unsafe")
	}
	return os.Remove(server.Configuration.ReadinessSocketPath)
}

func (server *Server) serveTCP(listener net.Listener, transparent bool) {
	defer server.workers.Done()
	for {
		connection, err := listener.Accept()
		if err != nil {
			server.report(err)
			return
		}
		if !server.admit(connection) {
			closeConnection(connection)
			continue
		}
		server.workers.Add(1)
		go func() {
			defer server.workers.Done()
			defer func() { <-server.admission }()
			defer server.untrack(connection)
			defer closeConnection(connection)
			if transparent {
				server.handleTransparent(connection)
			} else {
				server.handleExplicit(connection)
			}
		}()
	}
}

func (server *Server) admitHealth(connection net.Conn) bool {
	select {
	case server.healthLease <- struct{}{}:
	default:
		return false
	}
	if !server.track(connection) {
		<-server.healthLease
		return false
	}
	return true
}

func (server *Server) handleTransparent(connection net.Conn) {
	tcp, ok := connection.(*net.TCPConn)
	if !ok {
		return
	}
	original, err := server.Original(tcp)
	if err != nil {
		return
	}
	host, portText, err := net.SplitHostPort(original)
	port, portErr := strconv.Atoi(portText)
	if err != nil || portErr != nil || port < 1 || port > 65535 || portText != strconv.Itoa(port) {
		return
	}
	reader := bufio.NewReaderSize(connection, InspectBytes)
	_ = connection.SetReadDeadline(time.Now().Add(inspectTimeout))
	detected, inspectionErr := captureinspect.InspectHostname(reader, InspectBytes)
	_ = connection.SetReadDeadline(time.Time{})
	if inspectionErr != nil && !errors.Is(inspectionErr, captureinspect.ErrHostnameUnavailable) {
		return
	}
	if detected != "" {
		host = detected
	}
	server.openAndRelay(connection, reader, protocol.Destination{Network: protocol.NetworkTCP, Host: host, Port: uint16(port)}, false)
}

func (server *Server) handleExplicit(connection net.Conn) {
	source := &boundedPrefaceReader{reader: connection, maximum: InspectBytes, bounded: true}
	reader := bufio.NewReaderSize(source, InspectBytes)
	_ = connection.SetReadDeadline(time.Now().Add(inspectTimeout))
	request, err := http.ReadRequest(reader)
	_ = connection.SetReadDeadline(time.Time{})
	if err != nil || source.read > InspectBytes || request == nil || request.Method != http.MethodConnect || request.ProtoMajor != 1 || request.ProtoMinor != 1 ||
		request.URL == nil || request.URL.Scheme != "" || request.URL.Host != request.RequestURI || request.Host != request.RequestURI ||
		request.ContentLength > 0 || len(request.TransferEncoding) != 0 || reader.Buffered() > InspectBytes {
		writeProxyResponse(connection, http.StatusBadRequest)
		return
	}
	source.bounded = false
	host, portText, err := net.SplitHostPort(request.RequestURI)
	port, portErr := strconv.Atoi(portText)
	hint, hintOK := captureinspect.CapabilityHintFromConnect(request)
	destination := protocol.Destination{Network: protocol.NetworkTCP, Host: strings.ToLower(host), Port: uint16(port), CapabilityHint: hint}
	if err != nil || portErr != nil || port < 1 || port > 65535 || portText != strconv.Itoa(port) || !hintOK || protocol.ValidateDestination(destination) != nil {
		writeProxyResponse(connection, http.StatusBadRequest)
		return
	}
	server.openAndRelay(connection, reader, destination, true)
}

func (server *Server) openAndRelay(connection net.Conn, reader io.Reader, destination protocol.Destination, explicit bool) {
	server.mu.Lock()
	lifetime := server.lifetime
	server.mu.Unlock()
	if lifetime == nil {
		return
	}
	ctx, cancel := context.WithTimeout(lifetime, protocol.FlowOpenTimeout)
	upstream, _, err := server.FlowClient.OpenFlow(ctx, destination)
	cancel()
	if err != nil || upstream == nil {
		if upstream != nil {
			closeConnection(upstream)
		}
		if explicit {
			if errors.Is(err, protocol.ErrDenied) {
				writeProxyResponse(connection, http.StatusForbidden)
			} else {
				writeProxyResponse(connection, http.StatusServiceUnavailable)
			}
		}
		return
	}
	if !server.track(upstream) {
		closeConnection(upstream)
		return
	}
	defer server.untrack(upstream)
	defer closeConnection(upstream)
	if explicit && !writeProxyResponse(connection, http.StatusOK) {
		return
	}
	relay(connection, reader, upstream, server.closeDone)
}

func writeProxyResponse(connection net.Conn, status int) bool {
	reason := "Connection Established"
	if status != http.StatusOK {
		reason = http.StatusText(status)
	}
	_, err := io.WriteString(connection, fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Length: 0\r\n\r\n", status, reason))
	return err == nil
}

func (server *Server) serveHealth(listener *net.UnixListener) {
	defer server.workers.Done()
	for {
		connection, err := listener.AcceptUnix()
		if err != nil {
			server.report(err)
			return
		}
		if !server.admitHealth(connection) {
			closeConnection(connection)
			continue
		}
		server.workers.Add(1)
		go func() {
			defer server.workers.Done()
			defer func() { <-server.healthLease }()
			defer server.untrack(connection)
			defer closeConnection(connection)
			server.handleHealth(connection)
		}()
	}
}

func (server *Server) handleHealth(connection *net.UnixConn) {
	uid, gid, err := unixPeerCredentials(connection)
	if err != nil || (uid != uint32(os.Geteuid()) && gid != uint32(os.Getegid())) {
		return
	}
	deadline := time.Now().Add(nativeegressipc.Deadline)
	_ = connection.SetDeadline(deadline)
	reader := bufio.NewReaderSize(connection, nativeegressipc.MaxMessageBytes)
	line, err := reader.ReadBytes('\n')
	if err != nil {
		return
	}
	request, err := nativeegressipc.DecodeRequest(line)
	if err != nil || request.Type != nativeegressipc.Health || reader.Buffered() != 0 {
		return
	}
	server.mu.Lock()
	lifetime := server.lifetime
	server.mu.Unlock()
	if lifetime == nil {
		return
	}
	ctx, cancel := context.WithDeadline(lifetime, deadline)
	upstream, epoch, err := server.FlowClient.OpenHealth(ctx)
	cancel()
	if err != nil {
		return
	}
	defer upstream.Close()
	response, _ := nativeegressipc.EncodeResponse(nativeegressipc.Response{Version: nativeegressipc.Version, Type: nativeegressipc.Ready, Epoch: epoch})
	if _, err := connection.Write(response); err != nil {
		return
	}
	_ = connection.SetDeadline(time.Time{})
	closed := make(chan struct{}, 2)
	go func() { nativeegressipc.WaitClosed(upstream); closed <- struct{}{} }()
	go func() { nativeegressipc.WaitClosed(connection); closed <- struct{}{} }()
	select {
	case <-closed:
	case <-server.closeDone:
	}
}

func (server *Server) admit(connection net.Conn) bool {
	select {
	case server.admission <- struct{}{}:
	default:
		return false
	}
	if !server.track(connection) {
		<-server.admission
		return false
	}
	return true
}

func (server *Server) track(connection net.Conn) bool {
	server.mu.Lock()
	defer server.mu.Unlock()
	if server.closed {
		return false
	}
	server.connections[connection] = struct{}{}
	return true
}

func (server *Server) untrack(connection net.Conn) {
	server.mu.Lock()
	delete(server.connections, connection)
	server.mu.Unlock()
}

func (server *Server) report(err error) {
	server.mu.Lock()
	closed := server.closed
	server.mu.Unlock()
	if !closed && !errors.Is(err, net.ErrClosed) {
		select {
		case server.done <- errors.New("native capture unavailable"):
		default:
		}
	}
}

func relay(client net.Conn, reader io.Reader, upstream net.Conn, done <-chan struct{}) {
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
			closeConnection(client)
			closeConnection(upstream)
		} else if first.client {
			closeWrite(upstream)
		} else {
			closeWrite(client)
		}
	case <-done:
		closeConnection(client)
		closeConnection(upstream)
		<-results
	}
	<-results
}

func closeWrite(connection net.Conn) {
	if closer, ok := connection.(interface{ CloseWrite() error }); ok {
		_ = closer.CloseWrite()
		return
	}
	_ = connection.Close()
}
func closeConnection(connection net.Conn) {
	if connection != nil {
		_ = connection.SetDeadline(time.Now())
		_ = connection.Close()
	}
}
