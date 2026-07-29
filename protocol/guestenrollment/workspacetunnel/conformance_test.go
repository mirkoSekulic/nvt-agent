package workspacetunnel

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/yamux"
)

type tunnelHarness struct {
	gateway   *GatewaySession
	guest     *GuestForwarder
	guestDone chan error
}

func newTunnelHarness(t *testing.T, endpoint string) *tunnelHarness {
	t.Helper()
	gatewayConnection, guestConnection := net.Pipe()
	binding := testBinding()
	credential := testCredential(t, 1)
	deadline := time.Now().Add(time.Minute)
	type gatewayResult struct {
		session *GatewaySession
		err     error
	}
	gatewayResultChannel := make(chan gatewayResult, 1)
	go func() {
		authenticated, err := Accept(t.Context(), gatewayConnection, testAuthenticator{credential: credential, binding: binding})
		if err != nil {
			_ = gatewayConnection.Close()
			gatewayResultChannel <- gatewayResult{err: err}
			return
		}
		session, err := NewGatewaySession(gatewayConnection, binding, authenticated.LocalExpiresAt)
		gatewayResultChannel <- gatewayResult{session: session, err: err}
	}()
	if err := Establish(t.Context(), guestConnection, binding, credential); err != nil {
		_ = guestConnection.Close()
		t.Fatal(err)
	}
	result := <-gatewayResultChannel
	if result.err != nil {
		_ = guestConnection.Close()
		t.Fatal(result.err)
	}
	gateway := result.session
	guest, err := NewGuestForwarder(guestConnection, binding, deadline, endpoint)
	if err != nil {
		_ = gateway.Close()
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- guest.Serve(t.Context()) }()
	harness := &tunnelHarness{gateway: gateway, guest: guest, guestDone: done}
	t.Cleanup(func() {
		_ = gateway.Close()
		_ = guest.Close()
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, ErrUnavailable) {
				t.Errorf("guest forwarder stopped: %v", err)
			}
		case <-time.After(time.Second):
			t.Error("guest forwarder did not stop")
		}
	})
	return harness
}

func TestYamuxHTTPReverseProxyUpgradeAndLargePayload(t *testing.T) {
	const headerCanary = "authorization-header-canary"
	largePayload := bytes.Repeat([]byte("nvt-workspace-window-proof-"), 48<<10)
	backend := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/large":
			if request.Header.Get("Authorization") != "Bearer "+headerCanary {
				http.Error(response, "missing", http.StatusUnauthorized)
				return
			}
			response.WriteHeader(http.StatusOK)
			_, _ = response.Write(largePayload)
		case "/upgrade":
			connection, buffer, err := response.(http.Hijacker).Hijack()
			if err != nil {
				return
			}
			defer connection.Close()
			_, _ = buffer.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: nvt-test\r\n\r\n")
			_ = buffer.Flush()
			line, err := buffer.ReadString('\n')
			if err == nil {
				_, _ = buffer.WriteString("echo:" + line)
				_ = buffer.Flush()
			}
		default:
			http.NotFound(response, request)
		}
	}))
	defer backend.Close()
	harness := newTunnelHarness(t, strings.TrimPrefix(backend.URL, "http://"))

	target, _ := url.Parse("http://workspace.invalid")
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.Transport = &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return harness.gateway.OpenStream(ctx)
		},
	}
	frontend := httptest.NewServer(proxy)
	defer frontend.Close()

	request, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, frontend.URL+"/large", nil)
	request.Header.Set("Authorization", "Bearer "+headerCanary)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil || response.StatusCode != http.StatusOK || !bytes.Equal(body, largePayload) || len(body) <= StreamWindowBytes {
		t.Fatalf("large response status=%d size=%d error=%v", response.StatusCode, len(body), err)
	}

	frontendAddress := strings.TrimPrefix(frontend.URL, "http://")
	upgrade, err := net.DialTimeout("tcp", frontendAddress, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer upgrade.Close()
	_, _ = io.WriteString(upgrade, "GET /upgrade HTTP/1.1\r\nHost: workspace.invalid\r\nConnection: Upgrade\r\nUpgrade: nvt-test\r\n\r\n")
	reader := bufio.NewReader(upgrade)
	status, err := reader.ReadString('\n')
	if err != nil || !strings.Contains(status, "101") {
		t.Fatalf("upgrade status=%q error=%v", status, err)
	}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if line == "\r\n" {
			break
		}
	}
	_, _ = io.WriteString(upgrade, "bidirectional\n")
	echo, err := reader.ReadString('\n')
	if err != nil || echo != "echo:bidirectional\n" {
		t.Fatalf("upgrade echo=%q error=%v", echo, err)
	}
}

func TestYamuxConcurrentIndependentStreamsAndLimits(t *testing.T) {
	var concurrent atomic.Int32
	var maximum atomic.Int32
	release := make(chan struct{})
	backend := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		current := concurrent.Add(1)
		defer concurrent.Add(-1)
		for {
			observed := maximum.Load()
			if current <= observed || maximum.CompareAndSwap(observed, current) {
				break
			}
		}
		<-release
		_, _ = io.WriteString(response, request.URL.Query().Get("value"))
	}))
	defer backend.Close()
	harness := newTunnelHarness(t, strings.TrimPrefix(backend.URL, "http://"))
	transport := &http.Transport{DisableKeepAlives: true, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return harness.gateway.OpenStream(ctx)
	}}
	client := &http.Client{Transport: transport}
	const requests = MaxPendingStreamOpens
	results := make(chan error, requests)
	for index := range requests {
		go func() {
			value := fmt.Sprintf("stream-%d", index)
			response, err := client.Get("http://workspace.invalid/?value=" + value)
			if err != nil {
				results <- err
				return
			}
			body, readErr := io.ReadAll(response.Body)
			_ = response.Body.Close()
			if readErr != nil || string(body) != value {
				results <- fmt.Errorf("response=%q error=%v", body, readErr)
				return
			}
			results <- nil
		}()
	}
	deadline := time.Now().Add(3 * time.Second)
	for maximum.Load() < requests && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	close(release)
	for range requests {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	if maximum.Load() != requests {
		t.Fatalf("maximum concurrent streams=%d want=%d", maximum.Load(), requests)
	}

	hold := make([]net.Conn, 0, MaxActiveStreams)
	for range MaxActiveStreams {
		stream, err := harness.gateway.OpenStream(t.Context())
		if err != nil {
			t.Fatalf("open bounded stream %d: %v", len(hold), err)
		}
		hold = append(hold, stream)
	}
	if _, err := harness.gateway.OpenStream(t.Context()); !errors.Is(err, ErrCapacity) {
		t.Fatalf("active stream overflow error=%v", err)
	}
	_ = hold[0].Close()
	replacement, err := harness.gateway.OpenStream(t.Context())
	if err != nil {
		t.Fatalf("capacity did not release: %v", err)
	}
	_ = replacement.Close()
	for _, stream := range hold[1:] {
		_ = stream.Close()
	}
}

func TestYamuxPendingOpenBoundAndCancellationRelease(t *testing.T) {
	gatewayConnection, peer := net.Pipe()
	gateway, err := NewGatewaySession(gatewayConnection, testBinding(), time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := gateway.OpenStream(cancelled); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("cancelled open error=%v", err)
	}
	if len(gateway.pending) != 0 || len(gateway.active) != 0 {
		t.Fatalf("cancelled open retained pending=%d active=%d", len(gateway.pending), len(gateway.active))
	}
	results := make(chan error, MaxPendingStreamOpens)
	for range MaxPendingStreamOpens {
		go func() {
			stream, err := gateway.OpenStream(t.Context())
			if stream != nil {
				_ = stream.Close()
			}
			results <- err
		}()
	}
	deadline := time.Now().Add(time.Second)
	for len(gateway.pending) != MaxPendingStreamOpens && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(gateway.pending) != MaxPendingStreamOpens {
		t.Fatalf("pending opens=%d want=%d", len(gateway.pending), MaxPendingStreamOpens)
	}
	if _, err := gateway.OpenStream(t.Context()); !errors.Is(err, ErrCapacity) {
		t.Fatalf("pending overflow error=%v", err)
	}
	_ = gateway.Close()
	for range MaxPendingStreamOpens {
		<-results
	}
	if len(gateway.pending) != 0 || len(gateway.active) != 0 {
		t.Fatalf("closed opens retained pending=%d active=%d", len(gateway.pending), len(gateway.active))
	}
}

func TestYamuxCancellationReturnsPromptlyAndReleasesAfterBoundedOpen(t *testing.T) {
	gatewayConnection, peer := net.Pipe()
	gateway, err := NewGatewaySession(gatewayConnection, testBinding(), time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	result := make(chan error, 1)
	go func() {
		stream, err := gateway.OpenStream(ctx)
		if stream != nil {
			_ = stream.Close()
		}
		result <- err
	}()
	deadline := time.Now().Add(time.Second)
	for len(gateway.pending) != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(gateway.pending) != 1 {
		t.Fatal("open did not enter bounded pending state")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, ErrUnavailable) {
			t.Fatalf("cancelled open error=%v", err)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("cancelled open did not return promptly")
	}
	// The pending/active reservations remain held by the one bounded yamux
	// open until its transport operation exits; this prevents cancellation
	// from creating an unbounded detached-goroutine path.
	if len(gateway.pending) != 1 || len(gateway.active) != 1 {
		t.Fatalf("bounded cancelled open pending=%d active=%d", len(gateway.pending), len(gateway.active))
	}
	_ = peer.Close()
	deadline = time.Now().Add(time.Second)
	for (len(gateway.pending) != 0 || len(gateway.active) != 0) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(gateway.pending) != 0 || len(gateway.active) != 0 {
		t.Fatalf("cancelled open retained pending=%d active=%d", len(gateway.pending), len(gateway.active))
	}
	_ = gateway.Close()
}

func TestPinnedYamuxConfigurationIsExplicit(t *testing.T) {
	config := yamuxConfig()
	if YamuxVersion != "github.com/hashicorp/yamux/v0.1.2" ||
		config.AcceptBacklog != AcceptBacklog || !config.EnableKeepAlive || config.KeepAliveInterval != KeepAliveInterval ||
		config.ConnectionWriteTimeout != ConnectionWriteTimeout || config.MaxStreamWindowSize != StreamWindowBytes ||
		config.StreamOpenTimeout != StreamOpenTimeout || config.StreamCloseTimeout != StreamCloseTimeout ||
		config.LogOutput != io.Discard || config.Logger != nil {
		t.Fatalf("unexpected yamux profile: %#v", config)
	}
	if MaxPendingStreamOpens > AcceptBacklog || MaxActiveStreams <= MaxPendingStreamOpens ||
		CopyBufferBytes > StreamWindowBytes || StreamIdleTimeout <= KeepAliveInterval {
		t.Fatal("workspace bounds are internally inconsistent")
	}
}

func TestYamuxRejectsGuestInitiatedStreamWithoutBreakingGatewayStream(t *testing.T) {
	gatewayConnection, guestConnection := net.Pipe()
	gateway, err := NewGatewaySession(gatewayConnection, testBinding(), time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	defer gateway.Close()
	guest, err := yamux.Server(guestConnection, yamuxConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer guest.Close()

	forbidden, err := guest.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	_ = forbidden.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := forbidden.Read(make([]byte, 1)); err == nil {
		t.Fatal("guest-initiated stream was not rejected")
	}

	echoDone := make(chan error, 1)
	go func() {
		stream, err := guest.AcceptStream()
		if err == nil {
			_, err = io.Copy(stream, stream)
			_ = stream.Close()
		}
		echoDone <- err
	}()
	allowed, err := gateway.OpenStream(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	_ = allowed.SetDeadline(time.Now().Add(time.Second))
	_, _ = allowed.Write([]byte("allowed"))
	response := make([]byte, len("allowed"))
	if _, err := io.ReadFull(allowed, response); err != nil || string(response) != "allowed" {
		t.Fatalf("allowed response=%q error=%v", response, err)
	}
	_ = allowed.Close()
	if err := <-echoDone; err != nil {
		t.Fatal(err)
	}
}

func TestYamuxDisconnectExpiryAndReplacementCloseStreams(t *testing.T) {
	backend := startEchoBackend(t)
	first := newTunnelHarness(t, backend)
	stream, err := first.gateway.OpenStream(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	_ = first.gateway.Close()
	_ = stream.SetDeadline(time.Now().Add(time.Second))
	if _, err := stream.Write([]byte("closed")); err == nil {
		t.Fatal("session close retained outstanding stream")
	}

	replacement := newTunnelHarness(t, backend)
	replacementStream, err := replacement.gateway.OpenStream(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	_ = replacementStream.SetDeadline(time.Now().Add(time.Second))
	_, _ = replacementStream.Write([]byte("replacement"))
	response := make([]byte, len("replacement"))
	if _, err := io.ReadFull(replacementStream, response); err != nil || string(response) != "replacement" {
		t.Fatalf("replacement response=%q error=%v", response, err)
	}
	_ = replacementStream.Close()

	gatewayConnection, guestConnection := net.Pipe()
	expires := time.Now().Add(80 * time.Millisecond)
	expiringGateway, err := NewGatewaySession(gatewayConnection, testBinding(), expires)
	if err != nil {
		t.Fatal(err)
	}
	expiringGuest, err := NewGuestForwarder(guestConnection, testBinding(), expires, backend)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- expiringGuest.Serve(t.Context()) }()
	expiringStream, err := expiringGateway.OpenStream(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(120 * time.Millisecond)
	_ = expiringStream.SetDeadline(time.Now().Add(time.Second))
	if _, err := expiringStream.Write([]byte("expired")); err == nil {
		t.Fatal("trust expiry retained outstanding stream")
	}
	_ = expiringGateway.Close()
	_ = expiringGuest.Close()
	<-done
}

func TestYamuxContractMetadataAndErrorsExcludeCanaries(t *testing.T) {
	credentialCanary := testCredential(t, 99)
	headerCanary := "authorization-header-canary"
	binding := testBinding()
	gatewayConnection, peer := net.Pipe()
	gateway, err := NewGatewaySession(gatewayConnection, binding, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	defer gateway.Close()
	defer peer.Close()
	values := []string{
		fmt.Sprint(gateway), fmt.Sprintf("%#v", gateway), fmt.Sprint(gateway.Binding()),
		ErrUnavailable.Error(), ErrDenied.Error(), ErrProtocol.Error(), ErrCapacity.Error(),
	}
	for _, value := range values {
		if strings.Contains(value, credentialCanary) || strings.Contains(value, headerCanary) {
			t.Fatalf("observable value disclosed canary: %q", value)
		}
	}
	config := yamuxConfig()
	if config.LogOutput != io.Discard || config.Logger != nil {
		t.Fatal("yamux logging is not disabled")
	}
	if gateway.Binding() != binding {
		t.Fatal("non-secret binding metadata changed")
	}
}

func startEchoBackend(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer connection.Close()
				_, _ = io.Copy(connection, connection)
			}()
		}
	}()
	return listener.Addr().String()
}

func TestLoopbackEndpointIsFixedAndStrict(t *testing.T) {
	for _, valid := range []string{"127.0.0.1:4090", "[::1]:4090"} {
		if err := validateLoopbackEndpoint(valid); err != nil {
			t.Fatalf("valid endpoint %q: %v", valid, err)
		}
	}
	for _, invalid := range []string{"localhost:4090", "0.0.0.0:4090", "127.0.0.1:0", "127.0.0.1:99999", "http://127.0.0.1:4090", "/tmp/workspace.sock"} {
		if err := validateLoopbackEndpoint(invalid); err == nil {
			t.Fatalf("invalid endpoint %q accepted", invalid)
		}
	}
}

var _ StreamOpener = (*GatewaySession)(nil)
