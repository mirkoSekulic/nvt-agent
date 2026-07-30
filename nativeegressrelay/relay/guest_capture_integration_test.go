package relay

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	guestcapture "github.com/mirkoSekulic/nvt-agent/hostbundle/nativeegress"
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

	captureAddress := unusedRelayCaptureAddress(t)
	capture, err := guestcapture.NewCaptureServerWithResolver(guestcapture.CaptureConfiguration{
		ListenAddress: captureAddress, CapabilityHint: "provider-main",
	}, func(*net.TCPConn) (string, error) { return "192.0.2.44:443", nil })
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := capture.Start(ctx); err != nil || !capture.Activate(guest) {
		t.Fatalf("capture startup error=%v", err)
	}
	t.Cleanup(func() { _ = capture.Close() })

	client, err := net.Dial("tcp", captureAddress)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	header := []byte("POST /large HTTP/1.1\r\nHost: api.capture.example:443\r\nContent-Type: application/octet-stream\r\n\r\n")
	payload := bytes.Repeat([]byte("captured-native-egress"), (nativeegress.StreamWindowBytes/len("captured-native-egress"))+2048)
	want := append(append([]byte(nil), header...), payload...)
	writeDone := make(chan error, 1)
	go func() {
		_, err := client.Write(want)
		writeDone <- err
	}()
	got := make([]byte, len(want))
	if _, err := io.ReadFull(client, got); err != nil {
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
	capture.Withdraw()
	_ = guest.Close()
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	var one [1]byte
	if _, err := client.Read(one[:]); err == nil {
		t.Fatal("captured flow survived session withdrawal")
	}
	blocked, err := net.Dial("tcp", captureAddress)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(blocked, "GET / HTTP/1.1\r\nHost: api.capture.example\r\n\r\n")
	_ = blocked.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := bufio.NewReader(blocked).ReadByte(); err == nil {
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
