package nativecapture_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/mirkoSekulic/nvt-agent/hostbundle/nativecapture"
	"github.com/mirkoSekulic/nvt-agent/hostbundle/nativeegress"
	"github.com/mirkoSekulic/nvt-agent/hostbundle/nativeegressipc"
	protocol "github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment/nativeegress"
)

type openRecord struct {
	destination protocol.Destination
	peer        net.Conn
}

type opener struct {
	done  chan struct{}
	once  sync.Once
	opens chan openRecord
	pair  func() (net.Conn, net.Conn, error)
}

func newOpener() *opener {
	return &opener{done: make(chan struct{}), opens: make(chan openRecord, 128)}
}
func (value *opener) OpenFlow(_ context.Context, destination protocol.Destination) (net.Conn, error) {
	var client, peer net.Conn
	var err error
	if value.pair == nil {
		client, peer = net.Pipe()
	} else {
		client, peer, err = value.pair()
	}
	if err != nil {
		return nil, err
	}
	value.opens <- openRecord{destination: destination, peer: peer}
	return client, nil
}

func TestCaptureStreamsLargePayloadAndBothHalfCloses(t *testing.T) {
	harness := newHarness(t)
	harness.opener.pair = tcpPair
	clientRaw, err := net.Dial("tcp", harness.explicit)
	if err != nil {
		t.Fatal(err)
	}
	client := clientRaw.(*net.TCPConn)
	defer client.Close()
	_, _ = io.WriteString(client, "CONNECT stream.example:443 HTTP/1.1\r\nHost: stream.example:443\r\n\r\n")
	reader := bufio.NewReader(client)
	status, err := reader.ReadString('\n')
	if err != nil || !strings.Contains(status, " 200 ") {
		t.Fatalf("CONNECT status=%q error=%v", status, err)
	}
	for {
		line, readErr := reader.ReadString('\n')
		if readErr != nil {
			t.Fatal(readErr)
		}
		if line == "\r\n" {
			break
		}
	}
	opened := <-harness.opener.opens
	peer := opened.peer.(*net.TCPConn)
	defer peer.Close()
	payload := bytes.Repeat([]byte("large-native-egress-"), 1<<15)
	writeDone := make(chan error, 1)
	go func() {
		_, err := client.Write(payload)
		if err == nil {
			err = client.CloseWrite()
		}
		writeDone <- err
	}()
	observed, err := io.ReadAll(peer)
	if err != nil || !bytes.Equal(observed, payload) {
		t.Fatalf("client half-close payload=%d error=%v", len(observed), err)
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	reply := bytes.Repeat([]byte("reply-"), 1<<15)
	go func() { _, _ = peer.Write(reply); _ = peer.CloseWrite() }()
	got, err := io.ReadAll(reader)
	if err != nil || !bytes.Equal(got, reply) {
		t.Fatalf("upstream half-close reply=%d error=%v", len(got), err)
	}
}
func (value *opener) Done() <-chan struct{} { return value.done }
func (value *opener) Close() error          { value.once.Do(func() { close(value.done) }); return nil }

type harness struct {
	capture     *nativecapture.Server
	flow        *nativeegress.FlowServer
	opener      *opener
	flowPath    string
	transparent string
	explicit    string
	readiness   string
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	directory, err := os.MkdirTemp("/tmp", "nvt-cap-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	flowDirectory := filepath.Join(directory, "e")
	if err := os.Mkdir(flowDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	flowPath := filepath.Join(flowDirectory, nativeegress.FlowSocketName)
	flow, err := nativeegress.NewFlowServer(flowPath)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := flow.Start(ctx); err != nil {
		t.Fatal(err)
	}
	assertMode(t, flowDirectory, 0o700, os.ModeDir)
	assertMode(t, flowPath, 0o600, os.ModeSocket)
	t.Cleanup(func() { _ = flow.Close() })
	opener := newOpener()
	if !flow.Activate(opener) {
		t.Fatal("flow opener was not activated")
	}
	captureDirectory := filepath.Join(directory, "c")
	transparentAddress := unusedAddress(t)
	explicitAddress := unusedAddress(t)
	for explicitAddress == transparentAddress {
		explicitAddress = unusedAddress(t)
	}
	configuration := nativecapture.Configuration{
		Version: nativecapture.ConfigurationVersion, RuntimeDirectory: captureDirectory,
		TransparentListenAddress: transparentAddress, ExplicitListenAddress: explicitAddress,
		FlowSocketPath: flowPath, ReadinessSocketPath: filepath.Join(captureDirectory, "ready.sock"),
	}
	server, err := nativecapture.NewServerWithResolver(configuration, func(*net.TCPConn) (string, error) { return "192.0.2.10:443", nil })
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Start(ctx); err != nil {
		t.Fatal(err)
	}
	assertMode(t, captureDirectory, 0o750, os.ModeDir)
	assertMode(t, configuration.ReadinessSocketPath, 0o660, os.ModeSocket)
	t.Cleanup(func() { _ = server.Close() })
	return &harness{capture: server, flow: flow, opener: opener, flowPath: flowPath, transparent: configuration.TransparentListenAddress, explicit: configuration.ExplicitListenAddress, readiness: configuration.ReadinessSocketPath}
}

func TestCredentiallessCaptureSelectsCapabilityPerExplicitFlow(t *testing.T) {
	harness := newHarness(t)
	type request struct{ capability, authorization, payload string }
	requests := []request{
		{capability: "github-main-app", payload: "git-required-hint"},
		{authorization: "Basic " + base64.StdEncoding.EncodeToString([]byte("codex-main:provider-secret-canary")), payload: "codex-injectable"},
	}
	wantPayload := map[string]string{"github-main-app": "git-required-hint", "codex-main": "codex-injectable"}
	responses := make(chan string, len(requests))
	for _, value := range requests {
		value := value
		go func() {
			connection, err := net.Dial("tcp", harness.explicit)
			if err != nil {
				responses <- "dial"
				return
			}
			defer connection.Close()
			header := ""
			if value.capability != "" {
				header = "X-NVT-Capability: " + value.capability + "\r\n"
			}
			if value.authorization != "" {
				header = "Proxy-Authorization: " + value.authorization + "\r\n"
			}
			_, _ = io.WriteString(connection, "CONNECT api.github.com:443 HTTP/1.1\r\nHost: api.github.com:443\r\n"+header+"\r\n"+value.payload)
			response, err := bufio.NewReader(connection).ReadString('\n')
			if err != nil {
				responses <- "read"
				return
			}
			responses <- response
		}()
	}
	seen := map[string]string{}
	for range requests {
		select {
		case opened := <-harness.opener.opens:
			if opened.destination.Host != "api.github.com" || opened.destination.Port != 443 {
				t.Fatalf("destination=%#v", opened.destination)
			}
			expected, ok := wantPayload[opened.destination.CapabilityHint]
			if !ok {
				t.Fatalf("unexpected capability=%q", opened.destination.CapabilityHint)
			}
			payload := make([]byte, len(expected))
			_ = opened.peer.SetReadDeadline(time.Now().Add(time.Second))
			if _, err := io.ReadFull(opened.peer, payload); err != nil {
				t.Fatal(err)
			}
			value := string(payload)
			if strings.Contains(value, "CONNECT") || strings.Contains(value, "Proxy-Authorization") {
				t.Fatal("CONNECT preface entered the tunneled stream")
			}
			seen[opened.destination.CapabilityHint] = value
			_ = opened.peer.Close()
		case <-time.After(2 * time.Second):
			t.Fatal("explicit flow was not opened")
		}
	}
	if seen["github-main-app"] != wantPayload["github-main-app"] || seen["codex-main"] != wantPayload["codex-main"] {
		t.Fatalf("per-flow capabilities/payloads=%#v", seen)
	}
	for range requests {
		if response := <-responses; !strings.Contains(response, " 200 ") {
			t.Fatalf("proxy response=%q", response)
		}
	}

	transparent, err := net.Dial("tcp", harness.transparent)
	if err != nil {
		t.Fatal(err)
	}
	defer transparent.Close()
	transparentRequest := "GET / HTTP/1.1\r\nHost: transparent.example\r\n\r\n"
	_, _ = io.WriteString(transparent, transparentRequest)
	opened := <-harness.opener.opens
	defer opened.peer.Close()
	if opened.destination.CapabilityHint != "" || opened.destination.Host != "transparent.example" {
		t.Fatalf("transparent destination=%#v", opened.destination)
	}
	observed := make([]byte, len(transparentRequest))
	if _, err := io.ReadFull(opened.peer, observed); err != nil || string(observed) != transparentRequest {
		t.Fatalf("transparent payload=%q error=%v", observed, err)
	}
}

func TestExplicitCaptureRejectsMalformedOversizedAndConsumesPreface(t *testing.T) {
	harness := newHarness(t)
	for name, request := range map[string]string{
		"method":               "GET api.example:443 HTTP/1.1\r\nHost: api.example:443\r\n\r\n",
		"duplicate capability": "CONNECT api.example:443 HTTP/1.1\r\nHost: api.example:443\r\nX-NVT-Capability: one\r\nX-NVT-Capability: two\r\n\r\n",
		"oversized":            "CONNECT api.example:443 HTTP/1.1\r\nHost: api.example:443\r\nX-Fill: " + strings.Repeat("x", nativecapture.InspectBytes) + "\r\n\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			connection, err := net.Dial("tcp", harness.explicit)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = io.WriteString(connection, request)
			_ = connection.SetReadDeadline(time.Now().Add(time.Second))
			line, _ := bufio.NewReader(connection).ReadString('\n')
			_ = connection.Close()
			if line != "" && !strings.Contains(line, " 400 ") {
				t.Fatalf("malformed response=%q", line)
			}
			select {
			case opened := <-harness.opener.opens:
				_ = opened.peer.Close()
				t.Fatal("malformed request opened a flow")
			case <-time.After(50 * time.Millisecond):
			}
		})
	}
}

func TestCaptureConnectionAdmissionIsBounded(t *testing.T) {
	harness := newHarness(t)
	connections := make([]net.Conn, 0, nativecapture.MaxConnections)
	defer func() {
		for _, connection := range connections {
			_ = connection.Close()
		}
	}()
	for range nativecapture.MaxConnections {
		connection, err := net.Dial("tcp", harness.explicit)
		if err != nil {
			t.Fatal(err)
		}
		connections = append(connections, connection)
		_, _ = connection.Write([]byte("C"))
	}
	time.Sleep(300 * time.Millisecond)
	overflow, err := net.Dial("tcp", harness.explicit)
	if err != nil {
		t.Fatal(err)
	}
	defer overflow.Close()
	_, _ = io.WriteString(overflow, "CONNECT overflow.example:443 HTTP/1.1\r\nHost: overflow.example:443\r\n\r\n")
	_ = overflow.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	if _, err := bufio.NewReader(overflow).ReadByte(); err == nil {
		t.Fatal("overflow capture connection remained admitted")
	}
	select {
	case opened := <-harness.opener.opens:
		_ = opened.peer.Close()
		t.Fatal("overflow capture connection opened a flow")
	default:
	}
}

func TestReadinessIsALiveLeaseAndStaleMarkersFailClosed(t *testing.T) {
	harness := newHarness(t)
	client := nativeegressipc.Client{SocketPath: harness.readiness, OwnerUID: uint32(os.Geteuid()), Shared: true}
	lease, _, err := client.OpenHealth(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	closed := make(chan struct{})
	go func() { nativeegressipc.WaitClosed(lease); close(closed) }()
	select {
	case <-closed:
		t.Fatal("current readiness lease closed")
	case <-time.After(50 * time.Millisecond):
	}
	secondAttempt, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if second, _, err := client.OpenHealth(secondAttempt); err == nil {
		_ = second.Close()
		t.Fatal("a second readiness lease was admitted")
	}
	replacement := newOpener()
	if !harness.flow.Activate(replacement) {
		t.Fatal("replacement opener was not activated")
	}
	_ = harness.opener.Close()
	select {
	case <-closed:
		t.Fatal("readiness lease flickered during atomic opener replacement")
	case <-time.After(50 * time.Millisecond):
	}
	harness.flow.Withdraw()
	_ = replacement.Close()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("readiness survived transport withdrawal")
	}
	_ = lease.Close()

	configuration := harness.capture.Configuration
	_ = harness.capture.Close()
	if err := os.WriteFile(configuration.ReadinessSocketPath, []byte("ready\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	restarted, err := nativecapture.NewServerWithResolver(configuration, func(*net.TCPConn) (string, error) { return "192.0.2.1:443", nil })
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.Start(context.Background()); err == nil {
		_ = restarted.Close()
		t.Fatal("stale readiness marker was accepted")
	}
	if _, _, err := client.OpenHealth(context.Background()); err == nil {
		t.Fatal("stale marker produced readiness")
	}
}

func TestCaptureConfigurationAndIPCAreCredentialFree(t *testing.T) {
	canaries := []string{"nvt_eg1_secret_canary", "nvt_ri_secret_canary", "broker-token-canary", "provider-secret-canary", "guest-instance-canary"}
	configuration := nativecapture.Configuration{Version: 1, RuntimeDirectory: "/run/nvt-agent-capture", TransparentListenAddress: "127.0.0.1:15001", ExplicitListenAddress: "127.0.0.1:15002", FlowSocketPath: "/run/nvt-agent-egress/flow.sock", ReadinessSocketPath: "/run/nvt-agent-capture/ready.sock"}
	request, err := nativeegressipc.EncodeRequest(nativeegressipc.Request{Version: nativeegressipc.Version, Type: nativeegressipc.Open, Destination: &protocol.Destination{Network: protocol.NetworkTCP, Host: "api.github.com", Port: 443, CapabilityHint: "github-main-app"}})
	if err != nil {
		t.Fatal(err)
	}
	formatted := fmt.Sprintf("%#v %s %s", configuration, configuration.String(), request)
	for _, canary := range canaries {
		if strings.Contains(formatted, canary) {
			t.Fatalf("capture surface contained %q", canary)
		}
	}
	if strings.Contains(formatted, "agent_run_uid") || strings.Contains(formatted, "guest_instance_id") || strings.Contains(formatted, "credential") {
		t.Fatal("local capture IPC can represent authority material")
	}
}

func TestCredentialBearingFlowSocketDeniesNonOwner(t *testing.T) {
	if path := os.Getenv("NVT_TEST_NATIVE_EGRESS_FLOW_SOCKET"); path != "" {
		connection, err := net.DialTimeout("unix", path, time.Second)
		if err != nil {
			return
		}
		defer connection.Close()
		request, _ := nativeegressipc.EncodeRequest(nativeegressipc.Request{Version: nativeegressipc.Version, Type: nativeegressipc.Health})
		_, _ = connection.Write(request)
		if unix, ok := connection.(*net.UnixConn); ok {
			_ = unix.CloseWrite()
		}
		_ = connection.SetReadDeadline(time.Now().Add(time.Second))
		if line, _ := bufio.NewReader(connection).ReadBytes('\n'); len(line) != 0 {
			os.Exit(2)
		}
		return
	}
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		t.Skip("Linux root is required to exercise a distinct Unix peer UID")
	}
	harness := newHarness(t)
	source, err := os.Open(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	helper, err := os.CreateTemp("/tmp", "nvt-native-capture-peer-*")
	if err != nil {
		t.Fatal(err)
	}
	helperPath := helper.Name()
	defer os.Remove(helperPath)
	if _, err := io.Copy(helper, source); err != nil || helper.Chmod(0o755) != nil || helper.Close() != nil {
		t.Fatal("prepare non-owner flow IPC helper")
	}
	command := exec.Command(helperPath, "-test.run=^TestCredentialBearingFlowSocketDeniesNonOwner$")
	command.Env = append(os.Environ(), "NVT_TEST_NATIVE_EGRESS_FLOW_SOCKET="+harness.flowPath)
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65532, Gid: 65532}}
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("non-owner flow IPC peer was not denied cleanly: %v %s", err, output)
	}
}

func unusedAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	return address
}

func assertMode(t *testing.T, path string, permission os.FileMode, kind os.FileMode) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil || info.Mode().Perm() != permission || info.Mode()&kind == 0 || info.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("mode for %s = %v, %v; want %v and %v", path, info, err, permission, kind)
	}
}

func tcpPair() (net.Conn, net.Conn, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, nil, err
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	errs := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			errs <- acceptErr
		} else {
			accepted <- connection
		}
	}()
	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		return nil, nil, err
	}
	select {
	case server := <-accepted:
		return client, server, nil
	case err := <-errs:
		_ = client.Close()
		return nil, nil, err
	}
}
