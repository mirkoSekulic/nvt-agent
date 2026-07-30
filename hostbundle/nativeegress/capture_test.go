package nativeegress

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	protocol "github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment/nativeegress"
)

type captureOpen struct {
	destination protocol.Destination
	peer        net.Conn
}

type captureOpener struct {
	mu     sync.Mutex
	done   chan struct{}
	opens  chan captureOpen
	err    error
	closed bool
	pair   func() (net.Conn, net.Conn, error)
}

func newCaptureOpener() *captureOpener {
	return &captureOpener{done: make(chan struct{}), opens: make(chan captureOpen, CaptureMaxConnections+1)}
}

func (opener *captureOpener) OpenFlow(_ context.Context, destination protocol.Destination) (net.Conn, error) {
	opener.mu.Lock()
	err, closed := opener.err, opener.closed
	opener.mu.Unlock()
	if err != nil || closed {
		if err == nil {
			err = protocol.ErrUnavailable
		}
		return nil, err
	}
	var guest, peer net.Conn
	var pairErr error
	if opener.pair == nil {
		guest, peer = net.Pipe()
	} else {
		guest, peer, pairErr = opener.pair()
	}
	if pairErr != nil {
		return nil, pairErr
	}
	opener.opens <- captureOpen{destination: destination, peer: peer}
	return guest, nil
}

func (opener *captureOpener) Done() <-chan struct{} { return opener.done }

func (opener *captureOpener) Close() error {
	opener.mu.Lock()
	if !opener.closed {
		opener.closed = true
		close(opener.done)
	}
	opener.mu.Unlock()
	return nil
}

func TestCaptureRoutesOnlyThroughCurrentFlowOpener(t *testing.T) {
	address := unusedCaptureAddress(t)
	server, err := NewCaptureServerWithResolver(CaptureConfiguration{
		ListenAddress: address, CapabilityHint: "provider-main",
	}, func(*net.TCPConn) (string, error) { return "192.0.2.10:443", nil })
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := server.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })

	// Before an authenticated transport is current, capture is deny-only.
	unready, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(unready, "GET /blocked HTTP/1.1\r\nHost: blocked.example\r\n\r\n")
	_ = unreadinessDeadline(unready)
	if _, err := bufio.NewReader(unready).ReadByte(); err == nil {
		t.Fatal("capture relayed before a flow opener was active")
	}
	_ = unready.Close()

	opener := newCaptureOpener()
	if !server.Activate(opener) {
		t.Fatal("current flow opener was not accepted")
	}
	client, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	request := "POST /stream?q=1 HTTP/1.1\r\nHost: Workspace.Example:443\r\nContent-Length: 5\r\n\r\nhello"
	if _, err := io.WriteString(client, request); err != nil {
		t.Fatal(err)
	}
	opened := waitCaptureOpen(t, opener.opens)
	defer opened.peer.Close()
	if opened.destination != (protocol.Destination{
		Network: protocol.NetworkTCP, Host: "workspace.example", Port: 443, CapabilityHint: "provider-main",
	}) {
		t.Fatalf("destination=%#v", opened.destination)
	}
	upstreamRequest := make([]byte, len(request))
	if _, err := io.ReadFull(opened.peer, upstreamRequest); err != nil || string(upstreamRequest) != request {
		t.Fatalf("captured request mismatch error=%v", err)
	}
	response := "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nworld"
	if _, err := io.WriteString(opened.peer, response); err != nil {
		t.Fatal(err)
	}
	clientResponse := make([]byte, len(response))
	if _, err := io.ReadFull(client, clientResponse); err != nil || string(clientResponse) != response {
		t.Fatalf("captured response mismatch error=%v", err)
	}

	server.Withdraw()
	blocked, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(blocked, "GET / HTTP/1.1\r\nHost: blocked.example\r\n\r\n")
	_ = unreadinessDeadline(blocked)
	if _, err := bufio.NewReader(blocked).ReadByte(); err == nil {
		t.Fatal("capture relayed after readiness withdrawal")
	}
	_ = blocked.Close()
	select {
	case unexpected := <-opener.opens:
		_ = unexpected.peer.Close()
		t.Fatal("withdrawn capture opened another flow")
	default:
	}
}

func TestCaptureRecoversTLSSNIWithoutConsumingClientHello(t *testing.T) {
	address := unusedCaptureAddress(t)
	server, err := NewCaptureServerWithResolver(CaptureConfiguration{ListenAddress: address}, func(*net.TCPConn) (string, error) {
		return "192.0.2.11:443", nil
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := server.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	opener := newCaptureOpener()
	server.Activate(opener)
	connection, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	hello := captureTLSClientHello(t, "tls.capture.example")
	go func() { _, _ = connection.Write(hello) }()
	opened := waitCaptureOpen(t, opener.opens)
	defer opened.peer.Close()
	if opened.destination.Host != "tls.capture.example" || opened.destination.Port != 443 {
		t.Fatalf("TLS destination=%#v", opened.destination)
	}
	observed := make([]byte, len(hello))
	if _, err := io.ReadFull(opened.peer, observed); err != nil || !bytes.Equal(observed, hello) {
		t.Fatalf("TLS ClientHello changed error=%v match=%t", err, bytes.Equal(observed, hello))
	}
}

func TestCaptureRejectsUnavailableMalformedAndNonCanonicalInputs(t *testing.T) {
	for name, original := range map[string]string{
		"malformed original": "192.0.2.1:0443",
		"zero port":          "192.0.2.1:0",
	} {
		t.Run(name, func(t *testing.T) {
			address := unusedCaptureAddress(t)
			server, err := NewCaptureServerWithResolver(CaptureConfiguration{ListenAddress: address}, func(*net.TCPConn) (string, error) {
				return original, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if err := server.Start(ctx); err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			opener := newCaptureOpener()
			server.Activate(opener)
			connection, err := net.Dial("tcp", address)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = io.WriteString(connection, "GET / HTTP/1.1\r\nHost: valid.example\r\n\r\n")
			_ = unreadinessDeadline(connection)
			if _, err := bufio.NewReader(connection).ReadByte(); err == nil {
				t.Fatal("invalid destination remained open")
			}
			_ = connection.Close()
			select {
			case opened := <-opener.opens:
				_ = opened.peer.Close()
				t.Fatal("invalid destination reached flow opener")
			default:
			}
		})
	}

	address := unusedCaptureAddress(t)
	server, err := NewCaptureServerWithResolver(CaptureConfiguration{ListenAddress: address}, func(*net.TCPConn) (string, error) {
		return "", errors.New("unavailable")
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := server.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	opener := newCaptureOpener()
	server.Activate(opener)
	connection, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(connection, "GET / HTTP/1.1\r\nHost: valid.example\r\n\r\n")
	_ = unreadinessDeadline(connection)
	if _, err := bufio.NewReader(connection).ReadByte(); err == nil {
		t.Fatal("unavailable kernel destination remained open")
	}
	_ = connection.Close()
}

func TestCapturePreservesTCPHalfCloseInBothDirections(t *testing.T) {
	address := unusedCaptureAddress(t)
	server, err := NewCaptureServerWithResolver(CaptureConfiguration{ListenAddress: address}, func(*net.TCPConn) (string, error) {
		return "192.0.2.20:8443", nil
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := server.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	opener := newCaptureOpener()
	opener.pair = func() (net.Conn, net.Conn, error) { return tcpCapturePair(t) }
	if !server.Activate(opener) {
		t.Fatal("capture did not activate")
	}
	connection, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	client := connection.(*net.TCPConn)
	defer client.Close()
	request := "POST /half-close HTTP/1.1\r\nHost: half-close.example\r\n\r\nrequest-body"
	if _, err := io.WriteString(client, request); err != nil || client.CloseWrite() != nil {
		t.Fatalf("client half-close error=%v", err)
	}
	opened := waitCaptureOpen(t, opener.opens)
	peer := opened.peer.(*net.TCPConn)
	defer peer.Close()
	observed, err := io.ReadAll(peer)
	if err != nil || string(observed) != request {
		t.Fatalf("request after half-close=%q error=%v", observed, err)
	}
	response := []byte("response-after-request-eof")
	if _, err := peer.Write(response); err != nil || peer.CloseWrite() != nil {
		t.Fatalf("upstream half-close error=%v", err)
	}
	observedResponse, err := io.ReadAll(client)
	if err != nil || string(observedResponse) != string(response) {
		t.Fatalf("response after half-close=%q error=%v", observedResponse, err)
	}
}

func TestCaptureReplacementNeverMigratesExistingFlows(t *testing.T) {
	address := unusedCaptureAddress(t)
	server, err := NewCaptureServerWithResolver(CaptureConfiguration{ListenAddress: address}, func(*net.TCPConn) (string, error) {
		return "192.0.2.30:443", nil
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := server.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	first := newCaptureOpener()
	second := newCaptureOpener()
	if !server.Activate(first) {
		t.Fatal("first opener was not activated")
	}
	firstClient, firstRequest := startCapturedRequest(t, address, "first.example")
	defer firstClient.Close()
	firstFlow := waitCaptureOpen(t, first.opens)
	defer firstFlow.peer.Close()
	readCapturedRequest(t, firstFlow.peer, firstRequest)

	if !server.Activate(second) {
		t.Fatal("replacement opener was not activated")
	}
	secondClient, secondRequest := startCapturedRequest(t, address, "second.example")
	defer secondClient.Close()
	secondFlow := waitCaptureOpen(t, second.opens)
	defer secondFlow.peer.Close()
	readCapturedRequest(t, secondFlow.peer, secondRequest)

	_ = first.Close()
	_ = firstClient.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := bufio.NewReader(firstClient).ReadByte(); err == nil {
		t.Fatal("retired session's existing flow remained open")
	}
	if _, err := io.WriteString(secondFlow.peer, "replacement-live"); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, len("replacement-live"))
	if _, err := io.ReadFull(secondClient, response); err != nil || string(response) != "replacement-live" {
		t.Fatalf("replacement response=%q error=%v", response, err)
	}

	server.Withdraw()
	_ = second.Close()
	_ = secondClient.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := bufio.NewReader(secondClient).ReadByte(); err == nil {
		t.Fatal("withdrawn replacement flow remained open")
	}
}

func TestCaptureConnectionAdmissionIsBounded(t *testing.T) {
	address := unusedCaptureAddress(t)
	entered := make(chan struct{}, CaptureMaxConnections)
	release := make(chan struct{})
	var calls atomic.Int32
	server, err := NewCaptureServerWithResolver(CaptureConfiguration{ListenAddress: address}, func(*net.TCPConn) (string, error) {
		calls.Add(1)
		entered <- struct{}{}
		<-release
		return "192.0.2.40:443", nil
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := server.Start(ctx); err != nil {
		t.Fatal(err)
	}
	opener := newCaptureOpener()
	server.Activate(opener)
	connections := make([]net.Conn, 0, CaptureMaxConnections+1)
	defer func() {
		for _, connection := range connections {
			_ = connection.Close()
		}
	}()
	for range CaptureMaxConnections {
		connection, err := net.Dial("tcp", address)
		if err != nil {
			t.Fatal(err)
		}
		connections = append(connections, connection)
	}
	for range CaptureMaxConnections {
		select {
		case <-entered:
		case <-time.After(2 * time.Second):
			t.Fatal("capture admissions did not fill")
		}
	}
	overflow, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	connections = append(connections, overflow)
	_ = overflow.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := bufio.NewReader(overflow).ReadByte(); err == nil {
		t.Fatal("overflow capture connection remained open")
	}
	if calls.Load() != CaptureMaxConnections {
		t.Fatalf("original destination lookups=%d want=%d", calls.Load(), CaptureMaxConnections)
	}
	close(release)
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestCaptureConfigurationIsCanonicalAndSecretFree(t *testing.T) {
	valid := &CaptureConfiguration{ListenAddress: "127.0.0.1:15001", CapabilityHint: "provider-main"}
	if err := validateCaptureConfiguration(valid); err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]*CaptureConfiguration{
		"hostname":        {ListenAddress: "localhost:15001"},
		"non loopback":    {ListenAddress: "192.0.2.1:15001"},
		"leading zero":    {ListenAddress: "127.0.0.1:015001"},
		"privileged port": {ListenAddress: "127.0.0.1:443"},
		"zone":            {ListenAddress: "[::1%lo]:15001"},
		"bad capability":  {ListenAddress: "127.0.0.1:15001", CapabilityHint: "Provider Secret"},
	} {
		t.Run(name, func(t *testing.T) {
			if validateCaptureConfiguration(value) == nil {
				t.Fatal("invalid capture configuration was accepted")
			}
		})
	}
	server, err := NewCaptureServerWithResolver(*valid, func(*net.TCPConn) (string, error) { return "127.0.0.1:443", nil })
	if err != nil {
		t.Fatal(err)
	}
	formatted := server.String() + server.GoString() + fail(ReasonCaptureUnavailable, false, false).Error()
	for _, canary := range []string{"nvt_ri_RUNTIME-IDENTITY-CANARY", "nvt_eg1_EGRESS-BEARER-CANARY", "BROKER-TOKEN-CANARY", "PROVIDER-CREDENTIAL-CANARY"} {
		if strings.Contains(formatted, canary) {
			t.Fatalf("capture formatting exposed secret canary %q", canary)
		}
	}
}

func TestCaptureFlowDenialAndUnavailabilityHaveNoFallback(t *testing.T) {
	for name, openErr := range map[string]error{
		"denied": protocol.ErrDenied, "unavailable": protocol.ErrUnavailable,
	} {
		t.Run(name, func(t *testing.T) {
			address := unusedCaptureAddress(t)
			server, err := NewCaptureServerWithResolver(CaptureConfiguration{ListenAddress: address}, func(*net.TCPConn) (string, error) {
				return "192.0.2.50:443", nil
			})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if err := server.Start(ctx); err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			opener := newCaptureOpener()
			opener.err = openErr
			server.Activate(opener)
			connection, request := startCapturedRequest(t, address, "denied.example")
			defer connection.Close()
			_ = connection.SetReadDeadline(time.Now().Add(time.Second))
			if _, err := bufio.NewReader(connection).ReadByte(); err == nil {
				t.Fatalf("%s flow remained open", name)
			}
			if strings.Contains(server.String(), request) || strings.Contains(server.String(), "denied.example") {
				t.Fatal("capture formatting exposed destination or payload")
			}
			select {
			case opened := <-opener.opens:
				_ = opened.peer.Close()
				t.Fatal("failed flow unexpectedly produced a connection")
			default:
			}
		})
	}
}

func unusedCaptureAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}

func tcpCapturePair(t *testing.T) (net.Conn, net.Conn, error) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, nil, err
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- connection
	}()
	guest, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		return nil, nil, err
	}
	select {
	case peer := <-accepted:
		return guest, peer, nil
	case err := <-acceptErr:
		_ = guest.Close()
		return nil, nil, err
	case <-time.After(time.Second):
		_ = guest.Close()
		return nil, nil, errors.New("TCP pair timed out")
	}
}

func captureTLSClientHello(t *testing.T, serverName string) []byte {
	t.Helper()
	client, server := net.Pipe()
	done := make(chan struct{})
	go func() {
		_ = tls.Client(client, &tls.Config{ServerName: serverName, InsecureSkipVerify: true}).Handshake() //nolint:gosec
		_ = client.Close()
		close(done)
	}()
	header := make([]byte, 5)
	if _, err := io.ReadFull(server, header); err != nil {
		t.Fatal(err)
	}
	length := int(header[3])<<8 | int(header[4])
	body := make([]byte, length)
	if _, err := io.ReadFull(server, body); err != nil {
		t.Fatal(err)
	}
	_ = server.Close()
	<-done
	return append(header, body...)
}

func waitCaptureOpen(t *testing.T, opens <-chan captureOpen) captureOpen {
	t.Helper()
	select {
	case opened := <-opens:
		return opened
	case <-time.After(5 * time.Second):
		t.Fatal("capture flow was not opened")
		return captureOpen{}
	}
}

func unreadinessDeadline(connection net.Conn) error {
	return connection.SetReadDeadline(time.Now().Add(time.Second))
}

func startCapturedRequest(t *testing.T, address, host string) (net.Conn, string) {
	t.Helper()
	connection, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	request := "GET / HTTP/1.1\r\nHost: " + host + "\r\n\r\n"
	if _, err := io.WriteString(connection, request); err != nil {
		_ = connection.Close()
		t.Fatal(err)
	}
	return connection, request
}

func readCapturedRequest(t *testing.T, peer net.Conn, want string) {
	t.Helper()
	value := make([]byte, len(want))
	if _, err := io.ReadFull(peer, value); err != nil || string(value) != want {
		t.Fatalf("captured request=%q error=%v", value, err)
	}
}
