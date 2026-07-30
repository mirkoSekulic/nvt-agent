package relay

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
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment"
	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment/nativeegress"
)

type connectFixture struct {
	listener net.Listener
	url      string
	done     chan struct{}
	mu       sync.Mutex
	conns    []net.Conn
	handler  func(net.Conn, *http.Request, *bufio.Reader)
}

func newConnectFixture(t *testing.T, handler func(net.Conn, *http.Request, *bufio.Reader)) *connectFixture {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fixture := &connectFixture{listener: listener, url: "http://" + listener.Addr().String(), done: make(chan struct{}), handler: handler}
	go fixture.serve()
	t.Cleanup(fixture.Close)
	return fixture
}

func newEchoConnectFixture(t *testing.T, observations chan<- *http.Request) *connectFixture {
	return newConnectFixture(t, func(connection net.Conn, request *http.Request, reader *bufio.Reader) {
		if observations != nil {
			observations <- request.Clone(context.Background())
		}
		if _, err := io.WriteString(connection, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			return
		}
		_, _ = io.Copy(connection, reader)
	})
}

func (fixture *connectFixture) serve() {
	defer close(fixture.done)
	for {
		connection, err := fixture.listener.Accept()
		if err != nil {
			return
		}
		fixture.mu.Lock()
		fixture.conns = append(fixture.conns, connection)
		fixture.mu.Unlock()
		go func() {
			defer connection.Close()
			reader := bufio.NewReader(connection)
			request, err := http.ReadRequest(reader)
			if err != nil {
				return
			}
			fixture.handler(connection, request, reader)
		}()
	}
}

func (fixture *connectFixture) Close() {
	_ = fixture.listener.Close()
	fixture.mu.Lock()
	connections := append([]net.Conn(nil), fixture.conns...)
	fixture.mu.Unlock()
	for _, connection := range connections {
		_ = connection.Close()
	}
	select {
	case <-fixture.done:
	case <-time.After(time.Second):
	}
}

func targetDescriptor(binding guestenrollment.Binding, fixture *connectFixture) EgressdTargetDescriptor {
	return EgressdTargetDescriptor{Binding: binding, ConnectURL: fixture.url}
}

func resolveTarget(t *testing.T, registry *EgressdTargetRegistry, binding guestenrollment.Binding) nativeegress.EgressTarget {
	t.Helper()
	target, err := registry.ResolveNativeEgressTarget(t.Context(), binding)
	if err != nil {
		t.Fatal(err)
	}
	return target
}

func assertFlowEcho(t *testing.T, flow net.Conn, payload []byte) {
	t.Helper()
	writeDone := make(chan error, 1)
	go func() {
		_, err := flow.Write(payload)
		writeDone <- err
	}()
	response := make([]byte, len(payload))
	if _, err := io.ReadFull(flow, response); err != nil {
		t.Fatal(err)
	}
	if err := <-writeDone; err != nil || !bytes.Equal(response, payload) {
		t.Fatalf("flow echo error=%v match=%t", err, bytes.Equal(response, payload))
	}
}

func TestEgressdTargetRegistryRoutesOnlyExactBindingAndCanonicalConnect(t *testing.T) {
	observedA := make(chan *http.Request, 1)
	observedB := make(chan *http.Request, 1)
	fixtureA := newEchoConnectFixture(t, observedA)
	fixtureB := newEchoConnectFixture(t, observedB)
	bindingA := testBinding("egressd-a")
	bindingB := testBinding("egressd-b")
	registry, err := NewEgressdTargetRegistry([]EgressdTargetDescriptor{
		targetDescriptor(bindingA, fixtureA), targetDescriptor(bindingB, fixtureB),
	})
	if err != nil {
		t.Fatal(err)
	}
	destination := nativeegress.Destination{Network: nativeegress.NetworkTCP, Host: "api.example", Port: 443, CapabilityHint: "codex-main"}
	for binding, observed := range map[guestenrollment.Binding]<-chan *http.Request{bindingA: observedA, bindingB: observedB} {
		target := resolveTarget(t, registry, binding)
		flow, err := target.OpenFlow(t.Context(), destination)
		if err != nil {
			t.Fatal(err)
		}
		assertFlowEcho(t, flow, []byte("exact-binding-"+binding.GuestInstanceID))
		_ = flow.Close()
		request := <-observed
		if request.Method != http.MethodConnect || request.URL.Host != "api.example:443" || request.Host != "api.example:443" {
			t.Fatalf("CONNECT request method=%q url=%q host=%q", request.Method, request.URL.Host, request.Host)
		}
		if request.Header.Get("X-NVT-Capability") != destination.CapabilityHint || request.Header.Get("Proxy-Authorization") != "" {
			t.Fatalf("CONNECT headers=%#v", request.Header)
		}
	}

	mutations := []func(*guestenrollment.Binding){
		func(value *guestenrollment.Binding) { value.AgentRunUID += "-other" },
		func(value *guestenrollment.Binding) { value.ExecutionID += "-other" },
		func(value *guestenrollment.Binding) { value.DriverRegistration += "-other" },
		func(value *guestenrollment.Binding) { value.DesiredGeneration++ },
		func(value *guestenrollment.Binding) { value.GuestInstanceID += "-other" },
	}
	for _, mutate := range mutations {
		changed := bindingA
		mutate(&changed)
		if target, err := registry.ResolveNativeEgressTarget(t.Context(), changed); !errors.Is(err, ErrTargetUnavailable) || target != nil {
			t.Fatal("partial or stale binding resolved")
		}
	}
	for _, formatted := range []string{fmt.Sprint(registry), fmt.Sprintf("%#v", registry), fmt.Sprint(targetDescriptor(bindingA, fixtureA))} {
		if strings.Contains(formatted, bindingA.GuestInstanceID) || strings.Contains(formatted, fixtureA.url) {
			t.Fatalf("target formatting exposed mapping: %q", formatted)
		}
	}
}

func TestEgressdTargetSupportsLargeStreamingAndBothHalfCloseDirections(t *testing.T) {
	binding := testBinding("egressd-streaming")
	destination := nativeegress.Destination{Network: nativeegress.NetworkTCP, Host: "stream.example", Port: 443}
	t.Run("large bidirectional", func(t *testing.T) {
		fixture := newEchoConnectFixture(t, nil)
		registry, err := NewEgressdTargetRegistry([]EgressdTargetDescriptor{targetDescriptor(binding, fixture)})
		if err != nil {
			t.Fatal(err)
		}
		flow, err := resolveTarget(t, registry, binding).OpenFlow(t.Context(), destination)
		if err != nil {
			t.Fatal(err)
		}
		defer flow.Close()
		payload := bytes.Repeat([]byte("native-egress-stream"), (nativeegress.StreamWindowBytes/len("native-egress-stream"))+4096)
		assertFlowEcho(t, flow, payload)
	})

	t.Run("guest half close", func(t *testing.T) {
		fixture := newConnectFixture(t, func(connection net.Conn, _ *http.Request, reader *bufio.Reader) {
			_, _ = io.WriteString(connection, "HTTP/1.1 200 Connection Established\r\n\r\n")
			request, _ := io.ReadAll(reader)
			_, _ = connection.Write(append([]byte("response:"), request...))
		})
		registry, _ := NewEgressdTargetRegistry([]EgressdTargetDescriptor{targetDescriptor(binding, fixture)})
		flow, err := resolveTarget(t, registry, binding).OpenFlow(t.Context(), destination)
		if err != nil {
			t.Fatal(err)
		}
		defer flow.Close()
		_, _ = flow.Write([]byte("request"))
		writer, ok := flow.(interface{ CloseWrite() error })
		if !ok || writer.CloseWrite() != nil {
			t.Fatal("target flow does not preserve guest half-close")
		}
		response, err := io.ReadAll(flow)
		if err != nil || string(response) != "response:request" {
			t.Fatalf("half-close response=%q error=%v", response, err)
		}
	})

	t.Run("egressd half close", func(t *testing.T) {
		fixture := newConnectFixture(t, func(connection net.Conn, _ *http.Request, reader *bufio.Reader) {
			_, _ = io.WriteString(connection, "HTTP/1.1 200 Connection Established\r\n\r\nresponse")
			if writer, ok := connection.(interface{ CloseWrite() error }); ok {
				_ = writer.CloseWrite()
			}
			_, _ = io.ReadAll(reader)
		})
		registry, _ := NewEgressdTargetRegistry([]EgressdTargetDescriptor{targetDescriptor(binding, fixture)})
		flow, err := resolveTarget(t, registry, binding).OpenFlow(t.Context(), destination)
		if err != nil {
			t.Fatal(err)
		}
		defer flow.Close()
		response, err := io.ReadAll(flow)
		if err != nil || string(response) != "response" {
			t.Fatalf("reverse half-close response=%q error=%v", response, err)
		}
		if _, err := flow.Write([]byte("request-after-response")); err != nil {
			t.Fatal(err)
		}
		if writer, ok := flow.(interface{ CloseWrite() error }); !ok || writer.CloseWrite() != nil {
			t.Fatal("reverse half-close could not finish request")
		}
	})
}

func TestEgressdTargetFailuresAreBoundedSanitizedAndReleaseSessionCapacity(t *testing.T) {
	binding := testBinding("egressd-failures")
	destination := nativeegress.Destination{Network: nativeegress.NetworkTCP, Host: "api.example", Port: 443}
	const diagnosticCanary = "SECRET-PROVIDER-DIAGNOSTIC-CANARY"
	for name, response := range map[string]string{
		"denied":    "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n",
		"non-2xx":   "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n",
		"malformed": "not-http " + diagnosticCanary + "\r\n\r\n",
		"oversized": "HTTP/1.1 200 OK\r\nX-Internal: " + strings.Repeat("x", maxEgressdConnectResponseBytes) + "\r\n\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newConnectFixture(t, func(connection net.Conn, _ *http.Request, _ *bufio.Reader) {
				_, _ = io.WriteString(connection, response)
			})
			registry, _ := NewEgressdTargetRegistry([]EgressdTargetDescriptor{targetDescriptor(binding, fixture)})
			_, err := resolveTarget(t, registry, binding).OpenFlow(t.Context(), destination)
			if name == "denied" {
				if !errors.Is(err, nativeegress.ErrDenied) {
					t.Fatalf("denial error=%v", err)
				}
			} else if !errors.Is(err, ErrTargetUnavailable) {
				t.Fatalf("failure error=%v", err)
			}
			if err != nil && strings.Contains(err.Error(), diagnosticCanary) {
				t.Fatal("target diagnostic leaked")
			}
		})
	}

	requestSeen := make(chan struct{})
	canceledFixture := newConnectFixture(t, func(connection net.Conn, _ *http.Request, _ *bufio.Reader) {
		close(requestSeen)
		buffer := make([]byte, 1)
		_, _ = connection.Read(buffer)
	})
	canceledRegistry, _ := NewEgressdTargetRegistry([]EgressdTargetDescriptor{targetDescriptor(binding, canceledFixture)})
	canceledTarget := resolveTarget(t, canceledRegistry, binding)
	canceledContext, cancel := context.WithCancel(t.Context())
	canceled := make(chan error, 1)
	go func() {
		_, err := canceledTarget.OpenFlow(canceledContext, destination)
		canceled <- err
	}()
	<-requestSeen
	cancel()
	select {
	case err := <-canceled:
		if !errors.Is(err, ErrTargetUnavailable) {
			t.Fatalf("canceled CONNECT error=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled CONNECT did not return promptly")
	}

	var calls int
	var callsMu sync.Mutex
	fixture := newConnectFixture(t, func(connection net.Conn, _ *http.Request, reader *bufio.Reader) {
		callsMu.Lock()
		calls++
		call := calls
		callsMu.Unlock()
		if call == 1 {
			time.Sleep(150 * time.Millisecond)
			return
		}
		_, _ = io.WriteString(connection, "HTTP/1.1 200 Connection Established\r\n\r\n")
		_, _ = io.Copy(connection, reader)
	})
	registry, _ := NewEgressdTargetRegistry([]EgressdTargetDescriptor{targetDescriptor(binding, fixture)})
	target := resolveTarget(t, registry, binding)
	now := time.Now()
	session, err := nativeegress.NewSession(nativeegress.Authentication{
		Binding: binding, Sequence: 1, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute), LocalExpiresAt: now.Add(20 * time.Second),
	}, target)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	firstContext, cancelFirst := context.WithTimeout(t.Context(), 40*time.Millisecond)
	if flow, err := session.OpenFlow(firstContext, destination); !errors.Is(err, nativeegress.ErrUnavailable) || flow != nil {
		t.Fatalf("timed-out flow=%v error=%v", flow, err)
	}
	cancelFirst()
	flow, err := session.OpenFlow(t.Context(), destination)
	if err != nil {
		t.Fatalf("capacity was not released after timeout: %v", err)
	}
	assertFlowEcho(t, flow, []byte("after-timeout"))
	_ = flow.Close()

	closedListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedURL := "http://" + closedListener.Addr().String()
	_ = closedListener.Close()
	unavailableRegistry, _ := NewEgressdTargetRegistry([]EgressdTargetDescriptor{{Binding: binding, ConnectURL: closedURL}})
	if _, err := resolveTarget(t, unavailableRegistry, binding).OpenFlow(t.Context(), destination); !errors.Is(err, ErrTargetUnavailable) {
		t.Fatalf("lost endpoint error=%v", err)
	}
}

func TestProductionRelayMapsRealEgressdHTTPDenialToFixedFlowRejection(t *testing.T) {
	const diagnosticCanary = "SECRET-EGRESSD-DENIAL-CANARY"
	egressd := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		http.Error(writer, diagnosticCanary, http.StatusForbidden)
	}))
	defer egressd.Close()
	binding := testBinding("egressd-real-denial")
	credential := testCredential(t, 7)
	registry, err := NewEgressdTargetRegistry([]EgressdTargetDescriptor{{Binding: binding, ConnectURL: egressd.URL}})
	if err != nil {
		t.Fatal(err)
	}
	authenticator := &fakeAuthenticator{bindings: map[string]guestenrollment.Binding{credential: binding}}
	server, address, pki, _ := startInjectedServer(t, authenticator, registry, nativeegress.RevalidationInterval, 4)
	guest, err := connectGuest(t, address, pki, binding, credential)
	if err != nil {
		t.Fatal(err)
	}
	defer guest.Close()
	waitActive(t, server.Sessions(), binding, true)
	flow, err := guest.OpenFlow(t.Context(), nativeegress.Destination{Network: nativeegress.NetworkTCP, Host: "denied.example", Port: 443})
	if flow != nil || !errors.Is(err, nativeegress.ErrDenied) {
		t.Fatalf("real egressd denial flow=%v error=%v", flow, err)
	}
	if strings.Contains(err.Error(), diagnosticCanary) {
		t.Fatal("egressd denial diagnostics reached the guest")
	}
	if _, ready := server.Sessions().Active(binding); !ready {
		t.Fatal("authoritative flow denial closed the authenticated session")
	}
}

func TestEgressdTargetSnapshotReplacementWithdrawsSessionsWithoutMigratingFlows(t *testing.T) {
	fixtureA := newEchoConnectFixture(t, nil)
	fixtureB := newEchoConnectFixture(t, nil)
	binding := testBinding("egressd-replace")
	descriptorA := targetDescriptor(binding, fixtureA)
	descriptorB := targetDescriptor(binding, fixtureB)
	registry, err := NewEgressdTargetRegistry([]EgressdTargetDescriptor{descriptorA})
	if err != nil {
		t.Fatal(err)
	}
	oldTarget := resolveTarget(t, registry, binding)
	oldLifecycle := oldTarget.(interface{ Done() <-chan struct{} })
	if err := registry.Reconcile([]EgressdTargetDescriptor{descriptorA}); err != nil {
		t.Fatal(err)
	}
	if unchanged := resolveTarget(t, registry, binding); unchanged != oldTarget {
		t.Fatal("unchanged level-triggered snapshot churned target identity")
	}
	select {
	case <-oldLifecycle.Done():
		t.Fatal("unchanged snapshot withdrew target")
	default:
	}
	destination := nativeegress.Destination{Network: nativeegress.NetworkTCP, Host: "api.example", Port: 443}
	activeFlow, err := oldTarget.OpenFlow(t.Context(), destination)
	if err != nil {
		t.Fatal(err)
	}
	defer activeFlow.Close()
	assertFlowEcho(t, activeFlow, []byte("old-before-replacement"))
	if err := registry.Reconcile([]EgressdTargetDescriptor{descriptorB}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-oldLifecycle.Done():
	case <-time.After(time.Second):
		t.Fatal("replaced target did not withdraw")
	}
	if flow, err := oldTarget.OpenFlow(t.Context(), destination); !errors.Is(err, ErrTargetUnavailable) || flow != nil {
		t.Fatal("withdrawn target admitted a new flow")
	}
	assertFlowEcho(t, activeFlow, []byte("old-flow-not-migrated"))
	newTarget := resolveTarget(t, registry, binding)
	if newTarget == oldTarget {
		t.Fatal("replacement retained stale target")
	}
	newFlow, err := newTarget.OpenFlow(t.Context(), destination)
	if err != nil {
		t.Fatal(err)
	}
	assertFlowEcho(t, newFlow, []byte("new-target-flow"))
	_ = newFlow.Close()
	if err := registry.Reconcile(nil); err != nil {
		t.Fatal(err)
	}
	if target, err := registry.ResolveNativeEgressTarget(t.Context(), binding); !errors.Is(err, ErrTargetUnavailable) || target != nil {
		t.Fatal("removed target remained resolvable")
	}
}

func TestProductionRelayEgressdAdapterWithdrawsAndRebindsExactSession(t *testing.T) {
	observedA := make(chan *http.Request, 1)
	observedB := make(chan *http.Request, 1)
	closedAfterWithdrawal := make(chan bool, 1)
	var server *Server
	var binding guestenrollment.Binding
	var address string
	var pki testPKI
	fixtureA := newConnectFixture(t, func(connection net.Conn, request *http.Request, reader *bufio.Reader) {
		observedA <- request.Clone(context.Background())
		_, _ = io.WriteString(connection, "HTTP/1.1 200 Connection Established\r\n\r\n")
		_, _ = io.Copy(connection, reader)
		_, ready := server.Sessions().Active(binding)
		closedAfterWithdrawal <- !ready
	})
	fixtureB := newEchoConnectFixture(t, observedB)
	binding = testBinding("egressd-production")
	credential := testCredential(t, 9)
	registry, err := NewEgressdTargetRegistry([]EgressdTargetDescriptor{targetDescriptor(binding, fixtureA)})
	if err != nil {
		t.Fatal(err)
	}
	authenticator := &fakeAuthenticator{bindings: map[string]guestenrollment.Binding{credential: binding}}
	server, address, pki, _ = startInjectedServer(t, authenticator, registry, nativeegress.RevalidationInterval, 4)
	destination := nativeegress.Destination{Network: nativeegress.NetworkTCP, Host: "api.example", Port: 443, CapabilityHint: "provider-main"}

	first, err := connectGuest(t, address, pki, binding, credential)
	if err != nil {
		t.Fatal(err)
	}
	waitActive(t, server.Sessions(), binding, true)
	oldFlow, err := first.OpenFlow(t.Context(), destination)
	if err != nil {
		t.Fatal(err)
	}
	assertFlowEcho(t, oldFlow, []byte("first-target"))
	if request := <-observedA; request.Header.Get("X-NVT-Capability") != destination.CapabilityHint {
		t.Fatal("first exact target did not receive capability hint")
	}

	if err := registry.Reconcile([]EgressdTargetDescriptor{targetDescriptor(binding, fixtureB)}); err != nil {
		t.Fatal(err)
	}
	waitActive(t, server.Sessions(), binding, false)
	waitGuestClosed(t, first)
	_ = oldFlow.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := oldFlow.Read(make([]byte, 1)); err == nil {
		t.Fatal("withdrawn session retained or migrated its active flow")
	}
	select {
	case withdrawn := <-closedAfterWithdrawal:
		if !withdrawn {
			t.Fatal("target flow closed before exact session readiness was withdrawn")
		}
	case <-time.After(time.Second):
		t.Fatal("withdrawn target flow did not close")
	}

	second, err := connectGuest(t, address, pki, binding, credential)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	waitActive(t, server.Sessions(), binding, true)
	newFlow, err := second.OpenFlow(t.Context(), destination)
	if err != nil {
		t.Fatal(err)
	}
	defer newFlow.Close()
	assertFlowEcho(t, newFlow, []byte("replacement-target"))
	if request := <-observedB; request.Host != "api.example:443" {
		t.Fatal("replacement exact target received the wrong destination")
	}
	authenticator.mu.Lock()
	authenticationCalls := len(authenticator.calls)
	authenticator.mu.Unlock()
	if authenticationCalls != 2 {
		t.Fatalf("target replacement authentication calls=%d", authenticationCalls)
	}
}

func TestEgressdTargetDescriptorsRejectMalformedDuplicateAndUnboundedInput(t *testing.T) {
	binding := testBinding("egressd-config")
	valid := EgressdTargetDescriptor{Binding: binding, ConnectURL: "http://egressd.example:8470"}
	invalidURLs := []string{
		"", "https://egressd.example:8470", "http://egressd.example", "http://egressd.example:08470",
		"http://user@egressd.example:8470", "http://egressd.example:8470/", "http://EGRESSD.example:8470",
		"http://[fe80::1%25eth0]:8470", "http://egressd.example:8470?target=other",
	}
	for _, value := range invalidURLs {
		descriptor := valid
		descriptor.ConnectURL = value
		if _, err := NewEgressdTargetRegistry([]EgressdTargetDescriptor{descriptor}); err == nil {
			t.Fatalf("invalid CONNECT URL %q was accepted", value)
		}
	}
	if _, err := NewEgressdTargetRegistry([]EgressdTargetDescriptor{valid, valid}); err == nil {
		t.Fatal("duplicate exact binding was accepted")
	}
	registry, err := NewEgressdTargetRegistry([]EgressdTargetDescriptor{valid})
	if err != nil {
		t.Fatal(err)
	}
	previous := resolveTarget(t, registry, binding)
	other := valid
	other.Binding = testBinding("egressd-config-other")
	if err := registry.Reconcile([]EgressdTargetDescriptor{valid, other}); err == nil {
		t.Fatal("duplicate canonical egressd endpoint across bindings was accepted")
	}
	if current := resolveTarget(t, registry, binding); current != previous {
		t.Fatal("rejected duplicate endpoint snapshot disturbed the previous mapping")
	}
	if target, err := registry.ResolveNativeEgressTarget(t.Context(), other.Binding); target != nil || !errors.Is(err, ErrTargetUnavailable) {
		t.Fatal("rejected duplicate endpoint snapshot partially installed another binding")
	}
	invalidBinding := valid
	invalidBinding.Binding.GuestInstanceID = ""
	if _, err := NewEgressdTargetRegistry([]EgressdTargetDescriptor{invalidBinding}); err == nil {
		t.Fatal("malformed binding was accepted")
	}
	overflow := make([]EgressdTargetDescriptor, nativeegress.MaxSessionBindings+1)
	for index := range overflow {
		overflow[index] = EgressdTargetDescriptor{Binding: testBinding("bounded-" + strconv.Itoa(index)), ConnectURL: "http://egressd.example:8470"}
	}
	if _, err := NewEgressdTargetRegistry(overflow); err == nil {
		t.Fatal("unbounded target snapshot was accepted")
	}
}
