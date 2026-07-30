package relay

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment"
	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment/nativeegress"
)

func TestProductionRelayAuthenticatesBrokerThenExactTargetAndForwardsFlow(t *testing.T) {
	binding := testBinding("production")
	credential := testCredential(t, 11)
	now := time.Now().UTC().Truncate(time.Second)
	var eventsMu sync.Mutex
	events := []string{}
	fixture := newBrokerFixture(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		eventsMu.Lock()
		events = append(events, "broker")
		eventsMu.Unlock()
		if request.URL.Path != guestenrollment.NativeEgressIdentityAuthenticatePath || request.Header.Get("Authorization") != "Bearer "+credential {
			response.WriteHeader(http.StatusUnauthorized)
			return
		}
		body, err := io.ReadAll(io.LimitReader(request.Body, guestenrollment.MaxNativeEgressIdentityRequestBytes+1))
		if err != nil || strings.Contains(string(body), credential) {
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		decoded, err := guestenrollment.DecodeNativeEgressAuthenticateRequest(body)
		if err != nil || decoded.Binding != binding {
			response.WriteHeader(http.StatusUnauthorized)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(guestenrollment.NativeEgressStatus{
			ContractVersion: guestenrollment.NativeEgressIdentityVersion, CredentialType: guestenrollment.NativeEgressCredentialType,
			Binding: binding, Audience: guestenrollment.NativeEgressAudience, Sequence: 11,
			IssuedAt: guestenrollment.FormatTimestamp(now.Add(-time.Minute)), ExpiresAt: guestenrollment.FormatTimestamp(now.Add(4 * time.Minute)),
		})
	}))
	target := &fakeTarget{binding: binding, echo: true}
	defer target.closePeers()
	resolver := &fakeResolver{targets: map[guestenrollment.Binding]*fakeTarget{binding: target}, events: &events, eventsMu: &eventsMu}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fixture.config.ListenAddress = listener.Addr().String()
	server, err := NewServer(fixture.config, resolver)
	if err != nil {
		t.Fatal(err)
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(listener) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), nativeegress.ShutdownTimeout)
		defer cancel()
		_ = server.Shutdown(ctx)
		<-serveDone
	})

	connection, err := connectGuest(t, listener.Addr().String(), fixture.pki, binding, credential)
	if err != nil {
		t.Fatal(err)
	}
	waitActive(t, server.Sessions(), binding, true)
	eventsMu.Lock()
	observedEvents := append([]string(nil), events...)
	eventsMu.Unlock()
	if len(observedEvents) != 2 || observedEvents[0] != "broker" || observedEvents[1] != "target" {
		_ = connection.Close()
		t.Fatalf("authority/target order=%v", observedEvents)
	}
	resolver.mu.Lock()
	resolved := append([]guestenrollment.Binding(nil), resolver.calls...)
	resolver.mu.Unlock()
	if len(resolved) != 1 || resolved[0] != binding {
		_ = connection.Close()
		t.Fatal("target resolver did not receive exactly the authenticated binding")
	}
	destination := nativeegress.Destination{Network: nativeegress.NetworkTCP, Host: "api.example", Port: 443, CapabilityHint: "codex-main"}
	flow, err := connection.OpenFlow(t.Context(), destination)
	if err != nil {
		_ = connection.Close()
		t.Fatal(err)
	}
	const payload = "native-egress-flow-payload"
	if _, err := flow.Write([]byte(payload)); err != nil {
		_ = flow.Close()
		_ = connection.Close()
		t.Fatal(err)
	}
	response := make([]byte, len(payload))
	if _, err := io.ReadFull(flow, response); err != nil || string(response) != payload {
		_ = flow.Close()
		_ = connection.Close()
		t.Fatalf("flow response=%q error=%v", response, err)
	}
	_ = flow.Close()
	target.mu.Lock()
	opens := target.opens
	destinations := append([]nativeegress.Destination(nil), target.destinations...)
	target.mu.Unlock()
	if opens != 1 || len(destinations) != 1 || destinations[0] != destination {
		t.Fatalf("relay target opens=%d destinations=%#v", opens, destinations)
	}
	_ = connection.Close()

	for _, formatted := range []string{fmt.Sprint(server), fmt.Sprintf("%#v", server), fmt.Sprint(server.Sessions())} {
		if strings.Contains(formatted, credential) || strings.Contains(formatted, binding.GuestInstanceID) || strings.Contains(formatted, fixture.config.BrokerURL) {
			t.Fatalf("relay formatting disclosed internals: %q", formatted)
		}
	}
	root := filepath.Dir(fixture.config.TLSCertificateFile)
	if treeContains(t, root, credential) {
		t.Fatal("native egress credential was persisted")
	}
}

func TestRelayFailsClosedBeforeTargetForAuthenticationAndTLSFailures(t *testing.T) {
	binding := testBinding("fail-closed")
	credential := testCredential(t, 1)
	authenticator := &fakeAuthenticator{bindings: map[string]guestenrollment.Binding{credential: binding}}
	resolver := &fakeResolver{targets: map[guestenrollment.Binding]*fakeTarget{binding: {binding: binding}}}
	server, address, pki, _ := startInjectedServer(t, authenticator, resolver, 500*time.Millisecond, 4)

	authenticator.mu.Lock()
	authenticator.temporary = true
	authenticator.mu.Unlock()
	if _, err := connectGuest(t, address, pki, binding, credential); err == nil || errors.Is(err, nativeegress.ErrDenied) {
		t.Fatalf("temporary authority failure was not a silent close: %v", err)
	}
	authenticator.mu.Lock()
	authenticator.temporary = false
	authenticator.denied = true
	authenticator.mu.Unlock()
	if _, err := connectGuest(t, address, pki, binding, credential); !errors.Is(err, nativeegress.ErrDenied) {
		t.Fatalf("definitive authority denial was not rejected: %v", err)
	}
	resolver.mu.Lock()
	if len(resolver.calls) != 0 {
		resolver.mu.Unlock()
		t.Fatal("target resolver ran before successful authentication")
	}
	resolver.mu.Unlock()
	authenticator.mu.Lock()
	authenticator.denied = false
	authenticator.mu.Unlock()

	otherBinding := binding
	otherBinding.GuestInstanceID = "other-guest"
	if _, err := connectGuest(t, address, pki, otherBinding, credential); !errors.Is(err, nativeegress.ErrDenied) {
		t.Fatalf("cross-binding credential was not denied: %v", err)
	}
	resolver.mu.Lock()
	if len(resolver.calls) != 0 {
		resolver.mu.Unlock()
		t.Fatal("cross-binding denial reached target resolution")
	}
	resolver.mu.Unlock()

	resolver.mu.Lock()
	resolver.targets = nil
	resolver.mu.Unlock()
	if _, err := connectGuest(t, address, pki, binding, credential); err == nil || errors.Is(err, nativeegress.ErrDenied) {
		t.Fatalf("absent target did not fail closed silently: %v", err)
	}
	if _, active := server.Sessions().Active(binding); active {
		t.Fatal("target-less session became active")
	}
	resolver.mu.Lock()
	resolver.targets = map[guestenrollment.Binding]*fakeTarget{binding: {binding: otherBinding}}
	resolver.mu.Unlock()
	if _, err := connectGuest(t, address, pki, binding, credential); err == nil || errors.Is(err, nativeegress.ErrDenied) {
		t.Fatalf("mismatched target did not fail closed silently: %v", err)
	}

	for name, tlsConfig := range map[string]*tls.Config{
		"untrusted CA":  {MinVersion: tls.VersionTLS12, RootCAs: x509.NewCertPool(), ServerName: "localhost"},
		"wrong SNI":     {MinVersion: tls.VersionTLS12, RootCAs: pki.rootPool, ServerName: "wrong.example"},
		"TLS downgrade": {MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS11, RootCAs: pki.rootPool, ServerName: "localhost"},
	} {
		t.Run(name, func(t *testing.T) {
			dialer := &tls.Dialer{Config: tlsConfig}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if connection, err := dialer.DialContext(ctx, "tcp", address); err == nil {
				_ = connection.Close()
				t.Fatal("invalid TLS trust established")
			}
		})
	}
}

func TestRelayRejectsMalformedPurposeCredentialAndFramesBeforeAuthority(t *testing.T) {
	binding := testBinding("framing")
	credential := testCredential(t, 1)
	authenticator := &fakeAuthenticator{bindings: map[string]guestenrollment.Binding{credential: binding}}
	resolver := &fakeResolver{targets: map[guestenrollment.Binding]*fakeTarget{binding: {binding: binding}}}
	_, address, pki, _ := startInjectedServer(t, authenticator, resolver, time.Second, 4)
	bindingJSON, err := json.Marshal(binding)
	if err != nil {
		t.Fatal(err)
	}
	validPrefix := `{"contract_version":"nvt.native-egress/v1","type":"hello","binding":` + string(bindingJSON)
	frames := map[string][]byte{
		"wrong purpose":    []byte(validPrefix + `,"audience":"nvt.native-guest-control/v1","credential":"` + credential + `"}` + "\n"),
		"wrong credential": []byte(validPrefix + `,"audience":"nvt.native-egress/v1","credential":"nvt_eg1_invalid"}` + "\n"),
		"duplicate key":    []byte(validPrefix + `,"audience":"nvt.native-egress/v1","credential":"` + credential + `","credential":"` + credential + `"}` + "\n"),
		"trailing JSON":    []byte(validPrefix + `,"audience":"nvt.native-egress/v1","credential":"` + credential + `"}{}` + "\n"),
		"oversized":        append(make([]byte, nativeegress.MaxFrameBytes), '\n'),
	}
	for name, frame := range frames {
		t.Run(name, func(t *testing.T) {
			dialer := &tls.Dialer{Config: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pki.rootPool, ServerName: "localhost"}}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			connection, err := dialer.DialContext(ctx, "tcp", address)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := connection.Write(frame); err != nil {
				_ = connection.Close()
				t.Fatal(err)
			}
			waitConnectionClosed(t, connection)
		})
	}
	authenticator.mu.Lock()
	authenticationCalls := len(authenticator.calls)
	authenticator.mu.Unlock()
	resolver.mu.Lock()
	targetCalls := len(resolver.calls)
	resolver.mu.Unlock()
	if authenticationCalls != 0 || targetCalls != 0 {
		t.Fatalf("invalid frames reached authority=%d target=%d", authenticationCalls, targetCalls)
	}
}

func TestRelayRegistryReconnectStandbyReplayCapacityAndPromotion(t *testing.T) {
	binding := testBinding("registry")
	credential1 := testCredential(t, 1)
	credential2 := testCredential(t, 2)
	credential3 := testCredential(t, 3)
	authenticator := &fakeAuthenticator{bindings: map[string]guestenrollment.Binding{
		credential1: binding, credential2: binding, credential3: binding,
	}}
	target := &fakeTarget{binding: binding, echo: true}
	defer target.closePeers()
	resolver := &fakeResolver{targets: map[guestenrollment.Binding]*fakeTarget{binding: target}}
	server, address, pki, _ := startInjectedServer(t, authenticator, resolver, time.Second, 8)
	destination := nativeegress.Destination{Network: nativeegress.NetworkTCP, Host: "api.example", Port: 443}

	activeConnection, err := connectGuest(t, address, pki, binding, credential1)
	if err != nil {
		t.Fatal(err)
	}
	active := waitActive(t, server.Sessions(), binding, true)
	equalStandby, err := connectGuest(t, address, pki, binding, credential1)
	if err != nil {
		t.Fatal(err)
	}
	if current := waitActive(t, server.Sessions(), binding, true); current != active {
		t.Fatal("equal reconnect preempted active")
	}
	if third, err := connectGuest(t, address, pki, binding, credential2); err == nil {
		_ = third.Close()
		t.Fatal("third session received hello_ack before capacity admission")
	} else if errors.Is(err, nativeegress.ErrDenied) {
		t.Fatalf("temporary capacity rejection became definitive denial: %v", err)
	}
	if current := waitActive(t, server.Sessions(), binding, true); current != active {
		t.Fatal("third session changed active authority")
	}
	_ = activeConnection.Close()
	promotedEqual := waitActiveReplacement(t, server.Sessions(), binding, active)
	if promotedEqual == active || promotedEqual.Sequence() != 1 {
		t.Fatal("equal reconnect did not promote after active loss")
	}
	_ = equalStandby.Close()
	waitActive(t, server.Sessions(), binding, false)

	sequenceTwo, err := connectGuest(t, address, pki, binding, credential2)
	if err != nil {
		t.Fatal(err)
	}
	activeTwo := waitActive(t, server.Sessions(), binding, true)
	if older, err := connectGuest(t, address, pki, binding, credential1); err == nil {
		_ = older.Close()
		t.Fatal("older replay received hello_ack before sequence admission")
	} else if errors.Is(err, nativeegress.ErrDenied) {
		t.Fatalf("registry replay rejection became authority denial: %v", err)
	}
	if current := waitActive(t, server.Sessions(), binding, true); current != activeTwo {
		t.Fatal("older replay changed active authority")
	}
	higherStandby, err := connectGuest(t, address, pki, binding, credential3)
	if err != nil {
		t.Fatal(err)
	}
	if current := waitActive(t, server.Sessions(), binding, true); current != activeTwo {
		t.Fatal("higher standby preempted active")
	}
	if flow, err := higherStandby.OpenFlow(t.Context(), destination); !errors.Is(err, nativeegress.ErrUnavailable) {
		if flow != nil {
			_ = flow.Close()
		}
		t.Fatalf("standby transported a flow before promotion: %v", err)
	}
	predecessorFlow, err := sequenceTwo.OpenFlow(t.Context(), destination)
	if err != nil {
		t.Fatal(err)
	}
	_ = sequenceTwo.Close()
	promotedHigher := waitActiveReplacement(t, server.Sessions(), binding, activeTwo)
	if promotedHigher == activeTwo || promotedHigher.Sequence() != 3 {
		t.Fatal("higher standby did not promote atomically")
	}
	_ = predecessorFlow.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := predecessorFlow.Read(make([]byte, 1)); err == nil {
		t.Fatal("predecessor flow migrated or survived session replacement")
	}
	replacementFlow, err := higherStandby.OpenFlow(t.Context(), destination)
	if err != nil {
		t.Fatalf("promoted replacement did not open a flow: %v", err)
	}
	if _, err := replacementFlow.Write([]byte("replacement-flow")); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, len("replacement-flow"))
	if _, err := io.ReadFull(replacementFlow, response); err != nil || string(response) != "replacement-flow" {
		t.Fatalf("replacement response=%q error=%v", response, err)
	}
	_ = replacementFlow.Close()
	_ = higherStandby.Close()
	waitActive(t, server.Sessions(), binding, false)
}

func TestRelayRevalidationReconnectRevocationConnectionLossAndShutdown(t *testing.T) {
	binding := testBinding("lifecycle")
	credential := testCredential(t, 4)
	authenticator := &fakeAuthenticator{bindings: map[string]guestenrollment.Binding{credential: binding}}
	target := &fakeTarget{binding: binding, echo: true}
	defer target.closePeers()
	resolver := &fakeResolver{targets: map[guestenrollment.Binding]*fakeTarget{binding: target}}
	server, address, pki, serveDone := startInjectedServer(t, authenticator, resolver, 120*time.Millisecond, 4)

	first, err := connectGuest(t, address, pki, binding, credential)
	if err != nil {
		t.Fatal(err)
	}
	waitActive(t, server.Sessions(), binding, true)
	expiringFlow, err := first.OpenFlow(t.Context(), nativeegress.Destination{Network: nativeegress.NetworkTCP, Host: "api.example", Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	waitActive(t, server.Sessions(), binding, false)
	waitGuestClosed(t, first)
	_ = expiringFlow.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := expiringFlow.Read(make([]byte, 1)); err == nil {
		t.Fatal("revalidation cutoff retained an active flow")
	}
	second, err := connectGuest(t, address, pki, binding, credential)
	if err != nil {
		t.Fatal(err)
	}
	waitActive(t, server.Sessions(), binding, true)
	authenticator.mu.Lock()
	if len(authenticator.calls) != 2 {
		authenticator.mu.Unlock()
		t.Fatal("same credential reconnect did not reauthenticate")
	}
	authenticator.mu.Unlock()
	_ = second.Close()
	waitActive(t, server.Sessions(), binding, false)

	authenticator.mu.Lock()
	authenticator.denied = true
	authenticator.mu.Unlock()
	if _, err := connectGuest(t, address, pki, binding, credential); !errors.Is(err, nativeegress.ErrDenied) {
		t.Fatalf("revoked reconnect was not denied: %v", err)
	}
	if _, active := server.Sessions().Active(binding); active {
		t.Fatal("revoked session retained readiness")
	}
	authenticator.mu.Lock()
	authenticator.denied = false
	authenticator.mu.Unlock()
	third, err := connectGuest(t, address, pki, binding, credential)
	if err != nil {
		t.Fatal(err)
	}
	waitActive(t, server.Sessions(), binding, true)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	started := time.Now()
	if err := server.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	if time.Since(started) > time.Second || func() bool { _, active := server.Sessions().Active(binding); return active }() {
		t.Fatal("bounded shutdown retained readiness")
	}
	waitGuestClosed(t, third)
	if err := <-serveDone; err != nil {
		t.Fatal(err)
	}
}

func TestRelayBoundsSlowTLSHandshakeAndReleasesAdmission(t *testing.T) {
	binding := testBinding("slow")
	credential := testCredential(t, 1)
	authenticator := &fakeAuthenticator{bindings: map[string]guestenrollment.Binding{credential: binding}}
	resolver := &fakeResolver{targets: map[guestenrollment.Binding]*fakeTarget{binding: {binding: binding}}}
	server, address, pki, _ := startInjectedServer(t, authenticator, resolver, time.Second, 1, 100*time.Millisecond)

	stalled, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer stalled.Close()
	waitForCondition(t, func() bool { return len(server.handshakeSlots) == 1 }, "stalled handshake admission")
	overflow, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	waitConnectionClosed(t, overflow)
	waitForCondition(t, func() bool { return len(server.handshakeSlots) == 0 }, "handshake deadline release")
	connection, err := connectGuest(t, address, pki, binding, credential)
	if err != nil {
		t.Fatal(err)
	}
	waitActive(t, server.Sessions(), binding, true)
	_ = connection.Close()
}

func treeContains(t *testing.T, root, needle string) bool {
	t.Helper()
	found := false
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || found || info.IsDir() {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr == nil && strings.Contains(string(data), needle) {
			found = true
		}
		return nil
	})
	return found
}

func waitForCondition(t *testing.T, condition func() bool, name string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", name)
}

func waitActiveReplacement(t *testing.T, lookup SessionLookup, binding guestenrollment.Binding, predecessor *nativeegress.Session) *nativeegress.Session {
	t.Helper()
	var replacement *nativeegress.Session
	waitForCondition(t, func() bool {
		current, active := lookup.Active(binding)
		if active && current != predecessor {
			replacement = current
			return true
		}
		return false
	}, "standby promotion")
	return replacement
}
