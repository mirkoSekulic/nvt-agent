package nativeegress

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment"
)

type testFlowPair struct {
	guest   *GuestFlowTransport
	relay   *RelayFlowTransport
	session *Session
	cancel  context.CancelFunc
	done    <-chan error
}

func newTestFlowPair(t *testing.T, target EgressTarget, profile transportProfile) testFlowPair {
	t.Helper()
	relayConnection, guestConnection := net.Pipe()
	session, err := newSession(testAuthentication(target.Binding(), 1, time.Minute), target, profile.flowIdleTimeout)
	if err != nil {
		t.Fatal(err)
	}
	relay, err := newRelayFlowTransport(relayConnection, session, profile)
	if err != nil {
		_ = session.Close()
		t.Fatal(err)
	}
	guest, err := newGuestFlowTransport(guestConnection, profile)
	if err != nil {
		_ = relay.Close()
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- relay.Serve(ctx) }()
	readyContext, cancelReady := context.WithTimeout(context.Background(), time.Second)
	if err := guest.AwaitReady(readyContext); err != nil {
		cancelReady()
		cancel()
		_ = guest.Close()
		_ = relay.Close()
		t.Fatal(err)
	}
	cancelReady()
	pair := testFlowPair{guest: guest, relay: relay, session: session, cancel: cancel, done: done}
	t.Cleanup(func() {
		cancel()
		_ = guest.Close()
		_ = relay.Close()
		select {
		case <-done:
		case <-time.After(ShutdownTimeout):
			t.Error("flow transport did not stop")
		}
	})
	return pair
}

func TestYamuxFlowTransportSuccessConcurrentAndLargePayload(t *testing.T) {
	binding := testBinding("mux-success")
	target := &fakeTarget{binding: binding, echo: true}
	defer target.closePeers()
	pair := newTestFlowPair(t, target, defaultTransportProfile())
	destination := Destination{Network: NetworkTCP, Host: "api.example", Port: 443, CapabilityHint: "codex-main"}

	const concurrent = MaxPendingFlowOpens
	errorsSeen := make(chan error, concurrent)
	for index := range concurrent {
		go func() {
			flow, err := pair.guest.OpenFlow(t.Context(), destination)
			if err != nil {
				errorsSeen <- err
				return
			}
			defer flow.Close()
			payload := []byte(fmt.Sprintf("flow-%d", index))
			if _, err := flow.Write(payload); err != nil {
				errorsSeen <- err
				return
			}
			response := make([]byte, len(payload))
			_, err = io.ReadFull(flow, response)
			if err == nil && !bytes.Equal(response, payload) {
				err = errors.New("flow response mismatch")
			}
			errorsSeen <- err
		}()
	}
	for range concurrent {
		if err := <-errorsSeen; err != nil {
			t.Fatal(err)
		}
	}

	flow, err := pair.guest.OpenFlow(t.Context(), destination)
	if err != nil {
		t.Fatal(err)
	}
	defer flow.Close()
	payload := bytes.Repeat([]byte("bounded-backpressure-payload"), (StreamWindowBytes/(len("bounded-backpressure-payload")))+2048)
	written := make(chan error, 1)
	go func() {
		_, err := flow.Write(payload)
		written <- err
	}()
	response := make([]byte, len(payload))
	if _, err := io.ReadFull(flow, response); err != nil {
		t.Fatal(err)
	}
	if err := <-written; err != nil || !bytes.Equal(response, payload) {
		t.Fatalf("large flow write=%v match=%t", err, bytes.Equal(response, payload))
	}
	target.mu.Lock()
	seen := append([]Destination(nil), target.seen...)
	target.mu.Unlock()
	if len(seen) != concurrent+1 {
		t.Fatalf("target flow count=%d", len(seen))
	}
	for _, observed := range seen {
		if observed != destination {
			t.Fatalf("target received mutated destination: %#v", observed)
		}
	}
}

func TestYamuxFlowTransportDenialFailureAndPendingCapacity(t *testing.T) {
	binding := testBinding("mux-bounds")
	release := make(chan struct{})
	target := &fakeTarget{binding: binding, block: release, deny: func(destination Destination) bool {
		return destination.Host == "denied.example"
	}}
	defer target.closePeers()
	pair := newTestFlowPair(t, target, defaultTransportProfile())
	if _, err := pair.guest.OpenFlow(t.Context(), Destination{Network: NetworkTCP, Host: "denied.example", Port: 443}); !errors.Is(err, ErrDenied) {
		t.Fatalf("destination denial=%v", err)
	}

	destination := Destination{Network: NetworkTCP, Host: "api.example", Port: 443}
	type openResult struct {
		flow net.Conn
		err  error
	}
	results := make(chan openResult, MaxPendingFlowOpens)
	for range MaxPendingFlowOpens {
		go func() {
			flow, err := pair.guest.OpenFlow(t.Context(), destination)
			results <- openResult{flow: flow, err: err}
		}()
	}
	deadline := time.Now().Add(time.Second)
	for target.calls.Load() < MaxPendingFlowOpens+1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if _, err := pair.guest.OpenFlow(t.Context(), destination); !errors.Is(err, ErrCapacity) {
		t.Fatalf("pending capacity error=%v target calls=%d", err, target.calls.Load())
	}
	close(release)
	for range MaxPendingFlowOpens {
		result := <-results
		if result.err != nil {
			t.Fatal(result.err)
		}
		_ = result.flow.Close()
	}

	failing := &fakeTarget{binding: testBinding("mux-target-failure"), err: errors.New("target-internal-canary")}
	failurePair := newTestFlowPair(t, failing, defaultTransportProfile())
	_, err := failurePair.guest.OpenFlow(t.Context(), destination)
	if !errors.Is(err, ErrUnavailable) || strings.Contains(err.Error(), "target-internal-canary") {
		t.Fatalf("target failure=%v", err)
	}
}

func TestYamuxFlowTransportOpenDeadlineAndActiveCapacity(t *testing.T) {
	destination := Destination{Network: NetworkTCP, Host: "api.example", Port: 443}
	binding := testBinding("mux-deadline")
	release := make(chan struct{})
	target := &fakeTarget{binding: binding, block: release}
	pair := newTestFlowPair(t, target, defaultTransportProfile())
	ctx, cancel := context.WithTimeout(t.Context(), 35*time.Millisecond)
	defer cancel()
	if _, err := pair.guest.OpenFlow(ctx, destination); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("flow-open timeout=%v", err)
	}
	close(release)
	flow, err := pair.guest.OpenFlow(t.Context(), destination)
	if err != nil {
		t.Fatalf("capacity not released after timeout: %v", err)
	}
	_ = flow.Close()

	activeTarget := &fakeTarget{binding: testBinding("mux-active")}
	defer activeTarget.closePeers()
	activePair := newTestFlowPair(t, activeTarget, defaultTransportProfile())
	flows := make([]net.Conn, 0, MaxActiveFlows)
	for index := range MaxActiveFlows {
		flow, err := activePair.guest.OpenFlow(t.Context(), destination)
		if err != nil {
			t.Fatalf("active flow %d: %v", index, err)
		}
		flows = append(flows, flow)
	}
	if _, err := activePair.guest.OpenFlow(t.Context(), destination); !errors.Is(err, ErrCapacity) {
		t.Fatalf("active flow overflow=%v", err)
	}
	for _, flow := range flows {
		_ = flow.Close()
	}
}

func TestYamuxFlowIDHistoryIsBoundedWithoutEviction(t *testing.T) {
	binding := testBinding("mux-flow-id-bound")
	target := &fakeTarget{binding: binding}
	defer target.closePeers()
	profile := defaultTransportProfile()
	profile.maxFlowIDs = 2
	pair := newTestFlowPair(t, target, profile)
	destination := Destination{Network: NetworkTCP, Host: "api.example", Port: 443}
	for range profile.maxFlowIDs {
		flow, err := pair.guest.OpenFlow(t.Context(), destination)
		if err != nil {
			t.Fatal(err)
		}
		_ = flow.Close()
	}
	if flow, err := pair.guest.OpenFlow(t.Context(), destination); !errors.Is(err, ErrCapacity) {
		if flow != nil {
			_ = flow.Close()
		}
		t.Fatalf("flow ID history overflow=%v", err)
	}
	select {
	case <-pair.guest.Done():
	case <-time.After(time.Second):
		t.Fatal("flow ID exhaustion did not require session replacement")
	}
	if target.calls.Load() != int32(profile.maxFlowIDs) {
		t.Fatalf("flow ID exhaustion reached target %d times", target.calls.Load())
	}
}

func TestYamuxFlowTransportOneWayActivityAndTrueIdle(t *testing.T) {
	binding := testBinding("mux-idle")
	target := &fakeTarget{binding: binding}
	defer target.closePeers()
	profile := defaultTransportProfile()
	profile.flowIdleTimeout = 50 * time.Millisecond
	pair := newTestFlowPair(t, target, profile)
	flow, err := pair.guest.OpenFlow(t.Context(), Destination{Network: NetworkTCP, Host: "api.example", Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	defer flow.Close()
	target.mu.Lock()
	peer := target.peers[len(target.peers)-1]
	target.mu.Unlock()
	for index := range 6 {
		if _, err := peer.Write([]byte{byte(index)}); err != nil {
			t.Fatal(err)
		}
		var one [1]byte
		if _, err := io.ReadFull(flow, one[:]); err != nil || one[0] != byte(index) {
			t.Fatalf("one-way byte=%d error=%v", one[0], err)
		}
		time.Sleep(profile.flowIdleTimeout / 2)
	}
	started := time.Now()
	var one [1]byte
	if _, err := flow.Read(one[:]); err == nil {
		t.Fatal("truly idle flow remained open")
	}
	if elapsed := time.Since(started); elapsed > profile.flowIdleTimeout*4 {
		t.Fatalf("idle close exceeded bound: %s", elapsed)
	}
}

func TestCanceledPreFrameStreamIsLocalAndPreservesSession(t *testing.T) {
	binding := testBinding("mux-empty-canceled")
	target := &fakeTarget{binding: binding, echo: true}
	defer target.closePeers()
	pair := newTestFlowPair(t, target, defaultTransportProfile())
	destination := Destination{Network: NetworkTCP, Host: "api.example", Port: 443}
	active, err := pair.guest.OpenFlow(t.Context(), destination)
	if err != nil {
		t.Fatal(err)
	}
	defer active.Close()
	assertEcho := func(flow net.Conn, payload string) {
		t.Helper()
		if _, err := flow.Write([]byte(payload)); err != nil {
			t.Fatal(err)
		}
		response := make([]byte, len(payload))
		if _, err := io.ReadFull(flow, response); err != nil || string(response) != payload {
			t.Fatalf("echo response=%q error=%v", response, err)
		}
	}
	assertEcho(active, "before-cancellation")

	baselineHandlers := len(pair.relay.handlers)
	empty, err := pair.guest.mux.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for len(pair.relay.handlers) != baselineHandlers+1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(pair.relay.handlers) != baselineHandlers+1 {
		t.Fatal("relay did not begin reading the empty pre-frame stream")
	}
	_ = empty.Close()
	deadline = time.Now().Add(time.Second)
	for len(pair.relay.handlers) != baselineHandlers && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(pair.relay.handlers) != baselineHandlers {
		t.Fatal("relay did not finish the canceled pre-frame stream locally")
	}
	if !pair.session.Ready() {
		t.Fatal("empty canceled stream closed the authenticated session")
	}
	select {
	case <-pair.guest.Done():
		t.Fatal("empty canceled stream closed the guest transport")
	default:
	}
	assertEcho(active, "after-cancellation")

	subsequent, err := pair.guest.OpenFlow(t.Context(), destination)
	if err != nil {
		t.Fatalf("subsequent valid flow failed: %v", err)
	}
	defer subsequent.Close()
	assertEcho(subsequent, "subsequent-flow")
}

type dialingTarget struct {
	binding guestenrollment.Binding
	address string
}

func (target dialingTarget) Binding() guestenrollment.Binding { return target.binding }
func (target dialingTarget) OpenFlow(ctx context.Context, _ Destination) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "tcp", target.address)
}

func TestYamuxFlowTransportPreservesTCPHalfClose(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverDone := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer connection.Close()
		request, err := io.ReadAll(connection)
		if err == nil && string(request) != "request-before-half-close" {
			err = errors.New("half-close request mismatch")
		}
		if err == nil {
			_, err = connection.Write([]byte("response-after-half-close"))
		}
		serverDone <- err
	}()
	binding := testBinding("mux-half-close")
	pair := newTestFlowPair(t, dialingTarget{binding: binding, address: listener.Addr().String()}, defaultTransportProfile())
	flow, err := pair.guest.OpenFlow(t.Context(), Destination{Network: NetworkTCP, Host: "api.example", Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	defer flow.Close()
	if _, err := flow.Write([]byte("request-before-half-close")); err != nil {
		t.Fatal(err)
	}
	halfCloser, ok := flow.(interface{ CloseWrite() error })
	if !ok || halfCloser.CloseWrite() != nil {
		t.Fatal("guest flow does not support half-close")
	}
	response, err := io.ReadAll(flow)
	if err != nil || string(response) != "response-after-half-close" {
		t.Fatalf("half-close response=%q error=%v", response, err)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func TestYamuxFlowTransportPreservesReverseTCPHalfClose(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverDone := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer connection.Close()
		if _, err = connection.Write([]byte("response-before-request")); err == nil {
			if halfCloser, ok := connection.(interface{ CloseWrite() error }); !ok {
				err = errors.New("target connection lacks half-close")
			} else {
				err = halfCloser.CloseWrite()
			}
		}
		var request []byte
		if err == nil {
			request, err = io.ReadAll(connection)
		}
		if err == nil && string(request) != "request-after-response-half-close" {
			err = errors.New("reverse half-close request mismatch")
		}
		serverDone <- err
	}()
	binding := testBinding("mux-reverse-half-close")
	pair := newTestFlowPair(t, dialingTarget{binding: binding, address: listener.Addr().String()}, defaultTransportProfile())
	flow, err := pair.guest.OpenFlow(t.Context(), Destination{Network: NetworkTCP, Host: "api.example", Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	defer flow.Close()
	response, err := io.ReadAll(flow)
	if err != nil || string(response) != "response-before-request" {
		t.Fatalf("reverse half-close response=%q error=%v", response, err)
	}
	if _, err := flow.Write([]byte("request-after-response-half-close")); err != nil {
		t.Fatal(err)
	}
	halfCloser, ok := flow.(interface{ CloseWrite() error })
	if !ok || halfCloser.CloseWrite() != nil {
		t.Fatal("guest flow does not support reverse half-close completion")
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func TestRelayRejectsMalformedOversizedAndDuplicateFlowOpen(t *testing.T) {
	for name, exercise := range map[string]func(*testing.T, *yamux.Session){
		"malformed": func(t *testing.T, mux *yamux.Session) {
			stream, err := mux.OpenStream()
			if err != nil {
				t.Fatal(err)
			}
			_, _ = stream.Write([]byte("{not-json}\n"))
		},
		"partial": func(t *testing.T, mux *yamux.Session) {
			stream, err := mux.OpenStream()
			if err != nil {
				t.Fatal(err)
			}
			_, _ = stream.Write([]byte("{"))
			_ = stream.Close()
		},
		"oversized": func(t *testing.T, mux *yamux.Session) {
			stream, err := mux.OpenStream()
			if err != nil {
				t.Fatal(err)
			}
			_, _ = stream.Write(append(bytes.Repeat([]byte{'x'}, MaxFrameBytes), '\n'))
		},
		"second-frame": func(t *testing.T, mux *yamux.Session) {
			stream, err := mux.OpenStream()
			if err != nil {
				t.Fatal(err)
			}
			destination := Destination{Network: NetworkTCP, Host: "api.example", Port: 443}
			frame, err := EncodeMessage(Message{ContractVersion: Version, Type: FlowOpen, FlowID: "one-frame-only", Destination: &destination})
			if err != nil {
				t.Fatal(err)
			}
			_, _ = stream.Write(append(frame, frame...))
		},
		"duplicate": func(t *testing.T, mux *yamux.Session) {
			destination := Destination{Network: NetworkTCP, Host: "api.example", Port: 443}
			for index := range 2 {
				stream, err := mux.OpenStream()
				if err != nil {
					t.Fatal(err)
				}
				deadline := time.Now().Add(time.Second)
				if err := writeMessage(stream, Message{ContractVersion: Version, Type: FlowOpen, FlowID: "replayed-flow", Destination: &destination}, deadline); err != nil {
					if index == 0 {
						t.Fatal(err)
					}
					return
				}
				if index == 0 {
					response, _, err := readFlowResponse(stream, deadline)
					if err != nil || response.Type != FlowOpenAck {
						t.Fatalf("first flow response=%#v error=%v", response, err)
					}
					_ = stream.Close()
				}
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			binding := testBinding("mux-invalid-" + name)
			target := &fakeTarget{binding: binding}
			defer target.closePeers()
			relayConnection, guestConnection := net.Pipe()
			session, err := NewSession(testAuthentication(binding, 1, time.Minute), target)
			if err != nil {
				t.Fatal(err)
			}
			relay, err := NewRelayFlowTransport(relayConnection, session)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go func() { _ = relay.Serve(ctx) }()
			guestMux, err := yamux.Client(guestConnection, yamuxConfig())
			if err != nil {
				t.Fatal(err)
			}
			exercise(t, guestMux)
			select {
			case <-session.Done():
			case <-time.After(time.Second):
				t.Fatal("protocol violation did not close exact session")
			}
			_ = guestMux.Close()
			_ = relay.Close()
		})
	}
}

func TestGuestRejectsWrongFlowResponseID(t *testing.T) {
	relayConnection, guestConnection := net.Pipe()
	guest, err := NewGuestFlowTransport(guestConnection)
	if err != nil {
		t.Fatal(err)
	}
	defer guest.Close()
	relayMux, err := yamux.Server(relayConnection, yamuxConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer relayMux.Close()
	go func() {
		stream, err := relayMux.AcceptStream()
		if err != nil {
			return
		}
		message, err := readMessage(stream, time.Now().Add(time.Second))
		if err == nil {
			_ = writeMessage(stream, Message{ContractVersion: Version, Type: FlowOpenAck, FlowID: message.FlowID + "-wrong"}, time.Now().Add(time.Second))
		}
	}()
	_, err = guest.OpenFlow(t.Context(), Destination{Network: NetworkTCP, Host: "api.example", Port: 443})
	if !errors.Is(err, ErrProtocol) {
		t.Fatalf("wrong response ID=%v", err)
	}
	select {
	case <-guest.Done():
	case <-time.After(time.Second):
		t.Fatal("wrong response ID did not close guest transport")
	}
}

func TestGuestRejectsRelayInitiatedStream(t *testing.T) {
	relayConnection, guestConnection := net.Pipe()
	guest, err := NewGuestFlowTransport(guestConnection)
	if err != nil {
		t.Fatal(err)
	}
	defer guest.Close()
	relayMux, err := yamux.Server(relayConnection, yamuxConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer relayMux.Close()
	stream, err := relayMux.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	_ = stream.Close()
	select {
	case <-guest.Done():
	case <-time.After(time.Second):
		t.Fatal("relay-initiated stream did not close guest transport")
	}
}

type blockingCloseFlowConn struct {
	net.Conn
	release <-chan struct{}
}

func (connection *blockingCloseFlowConn) Close() error {
	<-connection.release
	return connection.Conn.Close()
}

func TestFlowTransportShutdownIsBoundedAndSecretFree(t *testing.T) {
	client, server := net.Pipe()
	release := make(chan struct{})
	profile := defaultTransportProfile()
	profile.shutdownTimeout = 40 * time.Millisecond
	guest, err := newGuestFlowTransport(&blockingCloseFlowConn{Conn: client, release: release}, profile)
	if err != nil {
		t.Fatal(err)
	}
	peer, err := yamux.Server(server, yamuxConfig())
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if err := guest.Close(); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("blocking shutdown=%v", err)
	}
	if elapsed := time.Since(started); elapsed > profile.shutdownTimeout*4 {
		t.Fatalf("blocking shutdown exceeded bound: %s", elapsed)
	}
	close(release)
	_ = peer.Close()
	credential, err := guestenrollment.GenerateNativeEgressCredential(77)
	if err != nil {
		t.Fatal(err)
	}
	for _, formatted := range []string{fmt.Sprint(guest), fmt.Sprintf("%#v", guest), fmt.Sprint(&RelayFlowTransport{})} {
		if strings.Contains(formatted, credential) || strings.Contains(formatted, "api.example") {
			t.Fatalf("transport formatting leaked state: %q", formatted)
		}
	}
}

func TestNativeEgressYamuxProfileIsPinnedAndBounded(t *testing.T) {
	configuration := yamuxConfig()
	if YamuxVersion != "github.com/hashicorp/yamux/v0.1.2" || configuration.AcceptBacklog != MaxPendingFlowOpens ||
		configuration.MaxStreamWindowSize != StreamWindowBytes || configuration.ConnectionWriteTimeout != ConnectionWriteTimeout ||
		configuration.StreamOpenTimeout != FlowOpenTimeout || configuration.StreamCloseTimeout != ShutdownTimeout ||
		configuration.KeepAliveInterval != KeepAliveInterval || !configuration.EnableKeepAlive || configuration.LogOutput != io.Discard ||
		MaxFlowIDsPerSession < MaxActiveFlows || MaxFlowIDsPerSession > 4096 {
		t.Fatalf("unexpected native egress yamux profile: %#v", configuration)
	}
}
