package relay

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	guestcapture "github.com/mirkoSekulic/nvt-agent/hostbundle/nativecapture"
	guesttransport "github.com/mirkoSekulic/nvt-agent/hostbundle/nativeegress"
	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment"
	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment/nativeegress"
)

func TestGuestCaptureThroughAuthenticatedRelayAndEgressdTarget(t *testing.T) {
	binding := testBinding("guest-capture-e2e")
	credential := testCredential(t, 17)
	authenticator := &fakeAuthenticator{bindings: map[string]guestenrollment.Binding{credential: binding}}
	observed := make(chan *http.Request, 2)
	egressd := newEchoConnectFixture(t, observed)
	registry, err := NewEgressdTargetRegistry([]EgressdTargetDescriptor{targetDescriptor(binding, egressd)})
	if err != nil {
		t.Fatal(err)
	}
	server, relayAddress, pki, _ := startInjectedServer(t, authenticator, registry, time.Second, 4)
	guest, err := connectGuest(t, relayAddress, pki, binding, credential)
	if err != nil {
		t.Fatal(err)
	}
	defer guest.Close()
	waitActive(t, server.Sessions(), binding, true)

	directory, err := os.MkdirTemp("/tmp", "nvt-relay-cap-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	flowDirectory := filepath.Join(directory, "e")
	if err := os.Mkdir(flowDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	flowSocket := filepath.Join(flowDirectory, guesttransport.FlowSocketName)
	flow, err := guesttransport.NewFlowServer(flowSocket)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := flow.Start(ctx); err != nil || !flow.Activate(guest) {
		t.Fatalf("flow startup error=%v", err)
	}
	t.Cleanup(func() { _ = flow.Close() })
	captureDirectory := filepath.Join(directory, "c")
	captureAddress := unusedRelayCaptureAddress(t)
	explicitAddress := unusedRelayCaptureAddress(t)
	for explicitAddress == captureAddress {
		explicitAddress = unusedRelayCaptureAddress(t)
	}
	capture, err := guestcapture.NewServerWithResolver(guestcapture.Configuration{
		Version: guestcapture.ConfigurationVersion, RuntimeDirectory: captureDirectory,
		TransparentListenAddress: captureAddress, ExplicitListenAddress: explicitAddress,
		FlowSocketPath: flowSocket, ReadinessSocketPath: filepath.Join(captureDirectory, "ready.sock"),
	}, func(*net.TCPConn) (string, error) { return "192.0.2.44:443", nil })
	if err != nil {
		t.Fatal(err)
	}
	if err := capture.Start(ctx); err != nil {
		t.Fatalf("capture startup error=%v", err)
	}
	t.Cleanup(func() { _ = capture.Close() })

	client, err := net.Dial("tcp", explicitAddress)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	connect := []byte("CONNECT api.capture.example:443 HTTP/1.1\r\nHost: api.capture.example:443\r\nX-NVT-Capability: provider-main\r\n\r\n")
	header := []byte("POST /large HTTP/1.1\r\nHost: api.capture.example:443\r\nContent-Type: application/octet-stream\r\n\r\n")
	payload := bytes.Repeat([]byte("captured-native-egress"), (nativeegress.StreamWindowBytes/len("captured-native-egress"))+2048)
	want := append(append([]byte(nil), header...), payload...)
	writeDone := make(chan error, 1)
	go func() {
		_, err := client.Write(append(connect, want...))
		writeDone <- err
	}()
	clientReader := bufio.NewReader(client)
	for {
		line, readErr := clientReader.ReadString('\n')
		if readErr != nil {
			t.Fatal(readErr)
		}
		if line == "\r\n" {
			break
		}
		if strings.HasPrefix(line, "HTTP/") && !strings.Contains(line, " 200 ") {
			t.Fatalf("CONNECT response=%q", line)
		}
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(clientReader, got); err != nil {
		t.Fatal(err)
	}
	if err := <-writeDone; err != nil || !bytes.Equal(got, want) {
		t.Fatalf("captured large stream error=%v match=%t", err, bytes.Equal(got, want))
	}
	request := <-observed
	if request.Method != http.MethodConnect || request.URL.Host != "api.capture.example:443" || request.Host != "api.capture.example:443" ||
		request.Header.Get("X-NVT-Capability") != "provider-main" || request.Header.Get("Proxy-Authorization") != "" {
		t.Fatalf("egressd CONNECT request method=%q url=%q host=%q headers=%#v", request.Method, request.URL.Host, request.Host, request.Header)
	}

	// Withdrawal closes existing captured flows and prevents any new flow from
	// reaching the exact target. There is no direct-network fallback.
	flow.Withdraw()
	_ = guest.Close()
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	var one [1]byte
	if _, err := client.Read(one[:]); err == nil {
		t.Fatal("captured flow survived session withdrawal")
	}
	blocked, err := net.Dial("tcp", explicitAddress)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(blocked, "CONNECT api.capture.example:443 HTTP/1.1\r\nHost: api.capture.example:443\r\nX-NVT-Capability: provider-main\r\n\r\n")
	_ = blocked.SetReadDeadline(time.Now().Add(time.Second))
	line, _ := bufio.NewReader(blocked).ReadString('\n')
	if strings.Contains(line, " 200 ") {
		t.Fatal("capture used a fallback after withdrawal")
	}
	_ = blocked.Close()
	select {
	case extra := <-observed:
		t.Fatalf("withdrawn capture reached egressd: %#v", extra)
	default:
	}
}

func unusedRelayCaptureAddress(t *testing.T) string {
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
