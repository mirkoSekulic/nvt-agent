package capture

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"testing"
	"time"
)

func tlsClientHello(t *testing.T, serverName string) []byte {
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

func TestInspectHostnameHTTPAndTLS(t *testing.T) {
	host, err := inspectHostname(bufio.NewReader(strings.NewReader("GET / HTTP/1.1\r\nHost: Example.COM\r\nCookie: not-logged\r\n\r\n")), 4096)
	if err != nil || host != "example.com" {
		t.Fatalf("HTTP host=%q err=%v", host, err)
	}
	hello := tlsClientHello(t, "tls.example")
	host, err = inspectHostname(bufio.NewReaderSize(bytes.NewReader(hello), len(hello)+1), len(hello)+1)
	if err != nil || host != "tls.example" {
		t.Fatalf("TLS SNI=%q err=%v", host, err)
	}
}

func TestInspectHTTPHostDelimiterNearLimit(t *testing.T) {
	const limit = 16 << 10
	prefix := "GET / HTTP/1.1\r\nHost: near-limit.example\r\nX-Fill: "
	preface := prefix + strings.Repeat("a", limit-len(prefix)-6) + "\r\n\r\n"
	if len(preface) != limit-2 {
		t.Fatalf("fixture length = %d", len(preface))
	}
	host, err := inspectHTTPHost(bufio.NewReaderSize(strings.NewReader(preface), limit), limit)
	if err != nil || host != "near-limit.example" {
		t.Fatalf("near-limit host=%q err=%v", host, err)
	}
}

func TestInspectHTTPHostWithoutDelimiterAtLimit(t *testing.T) {
	const limit = 16 << 10
	preface := "GET / HTTP/1.1\r\nHost: no-end.example\r\nX-Fill: " + strings.Repeat("a", limit)
	_, err := inspectHTTPHost(bufio.NewReaderSize(strings.NewReader(preface), limit), limit)
	if err == nil || errors.Is(err, errHostnameUnavailable) {
		t.Fatalf("unterminated limit preface must hard-deny, err=%v", err)
	}
}

func BenchmarkInspectHTTPHostNearLimit(b *testing.B) {
	const limit = 16 << 10
	prefix := "GET / HTTP/1.1\r\nHost: benchmark.example\r\nX-Fill: "
	preface := prefix + strings.Repeat("a", limit-len(prefix)-4) + "\r\n\r\n"
	b.ReportAllocs()
	for range b.N {
		_, _ = inspectHTTPHost(bufio.NewReaderSize(strings.NewReader(preface), limit), limit)
	}
}

func fakeEgressProxy(t *testing.T, received chan<- string) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		var request strings.Builder
		for {
			line, readErr := reader.ReadString('\n')
			request.WriteString(line)
			if readErr != nil || line == "\r\n" {
				break
			}
		}
		received <- request.String()
		_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
		_, _ = io.Copy(conn, reader)
	}()
	return listener.Addr().String()
}

func TestTransparentRelayUsesSNIAndPreservesBytes(t *testing.T) {
	received := make(chan string, 1)
	proxy := fakeEgressProxy(t, received)
	var logs bytes.Buffer
	server := &Server{EgressProxy: proxy, InspectTimeout: time.Second, Logger: log.New(&logs, "", 0)}
	left, right := net.Pipe()
	done := make(chan struct{})
	go func() {
		server.relayTransparent(right, "93.184.216.34:443")
		_ = right.Close()
		close(done)
	}()
	hello := tlsClientHello(t, "captured.example")
	go func() { _, _ = left.Write(hello) }()
	echoed := make([]byte, len(hello))
	if _, err := io.ReadFull(left, echoed); err != nil {
		t.Fatal(err)
	}
	_ = left.Close()
	<-done
	if !bytes.Equal(echoed, hello) {
		t.Fatal("transparent relay changed inspected bytes")
	}
	if request := <-received; !strings.HasPrefix(request, "CONNECT captured.example:443 ") || strings.Contains(strings.ToLower(request), "x-nvt-transparent") {
		t.Fatalf("transparent CONNECT request = %q", request)
	}
	if strings.Contains(logs.String(), "Cookie") || strings.Contains(logs.String(), string(hello)) {
		t.Fatalf("logs contain inspected payload: %q", logs.String())
	}
}

func TestTransparentRelayShortHTTPIsPromptAndPreservesBytes(t *testing.T) {
	received := make(chan string, 1)
	proxy := fakeEgressProxy(t, received)
	const inspectTimeout = 1500 * time.Millisecond
	server := &Server{EgressProxy: proxy, InspectTimeout: inspectTimeout}
	left, right := net.Pipe()
	done := make(chan struct{})
	started := time.Now()
	go func() {
		server.relayTransparent(right, "93.184.216.34:80")
		_ = right.Close()
		close(done)
	}()
	request := "GET /package HTTP/1.1\r\nHost: packages.example\r\nUser-Agent: apt-like\r\n\r\n"
	go func() { _, _ = io.WriteString(left, request) }()
	echoed := make([]byte, len(request))
	if _, err := io.ReadFull(left, echoed); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed >= inspectTimeout/2 {
		t.Fatalf("short HTTP inspection took %s, want comfortably below %s deadline", elapsed, inspectTimeout)
	}
	_ = left.Close()
	<-done
	if string(echoed) != request {
		t.Fatalf("HTTP bytes changed: %q", echoed)
	}
	if connect := <-received; !strings.HasPrefix(connect, "CONNECT packages.example:80 ") {
		t.Fatalf("HTTP CONNECT request = %q", connect)
	}
}

func TestExplicitRelayPreservesProviderHint(t *testing.T) {
	received := make(chan string, 1)
	proxy := fakeEgressProxy(t, received)
	server := &Server{EgressProxy: proxy}
	left, right := net.Pipe()
	done := make(chan struct{})
	go func() { server.relayExplicit(right); close(done) }()
	request := "CONNECT api.example:443 HTTP/1.1\r\nHost: api.example:443\r\nX-NVT-Capability: provider-a\r\n\r\n"
	go func() { _, _ = io.WriteString(left, request) }()
	reader := bufio.NewReader(left)
	if line, _ := reader.ReadString('\n'); !strings.Contains(line, "200") {
		t.Fatalf("response status = %q", line)
	}
	_ = left.Close()
	<-done
	if got := <-received; !strings.Contains(got, "X-NVT-Capability: provider-a") {
		t.Fatalf("provider hint not preserved: %q", got)
	}
}

func TestRelayPreservesHalfClose(t *testing.T) {
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	go func() {
		conn, _ := upstream.Accept()
		defer conn.Close()
		body, _ := io.ReadAll(conn)
		_, _ = io.WriteString(conn, "reply:"+string(body))
	}()
	leftListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer leftListener.Close()
	go func() {
		left, _ := leftListener.Accept()
		right, _ := net.Dial("tcp", upstream.Addr().String())
		relay(left, right)
		_ = left.Close()
		_ = right.Close()
	}()
	clientRaw, err := net.Dial("tcp", leftListener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	client := clientRaw.(*net.TCPConn)
	_, _ = io.WriteString(client, "body")
	_ = client.CloseWrite()
	response, _ := io.ReadAll(client)
	_ = client.Close()
	if string(response) != "reply:body" {
		t.Fatalf("half-close response = %q", response)
	}
}

func TestInspectionTimeoutAndMalformedInputFailSanitized(t *testing.T) {
	for _, input := range [][]byte{{0x16, 0x03, 0x01, 0xff, 0xff}, []byte("GET / HTTP/1.1\r\nCookie: canary")} {
		t.Run(fmt.Sprintf("%x", input[:1]), func(t *testing.T) {
			var logs bytes.Buffer
			server := &Server{EgressProxy: "127.0.0.1:1", InspectLimit: 64, InspectTimeout: 20 * time.Millisecond, Logger: log.New(&logs, "", 0)}
			left, right := net.Pipe()
			done := make(chan struct{})
			go func() { server.relayTransparent(right, "93.184.216.34:443"); close(done) }()
			_, _ = left.Write(input)
			<-done
			_ = left.Close()
			if strings.Contains(logs.String(), "canary") || strings.Contains(logs.String(), "Cookie") {
				t.Fatalf("sanitized log leaked input: %q", logs.String())
			}
		})
	}
}

func TestServerRejectsRecursiveAndOverlappingListeners(t *testing.T) {
	for _, server := range []*Server{
		{ExplicitListen: "127.0.0.1:1", TransparentListen: "127.0.0.1:1", EgressProxy: "egressd:2"},
		{ExplicitListen: "127.0.0.1:1", TransparentListen: "127.0.0.1:2", EgressProxy: "127.0.0.1:1"},
	} {
		if err := server.Validate(); err == nil {
			t.Fatal("invalid recursive listener configuration accepted")
		}
	}
}

func TestRunStopsWithContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	server := &Server{ExplicitListen: "127.0.0.1:0", TransparentListen: "localhost:0", EgressProxy: "egressd:8473"}
	if err := server.Run(ctx); err != nil {
		t.Fatal(err)
	}
}
