package relay

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment"
	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment/nativeegress"
)

func TestStalledGuestAcknowledgementDoesNotBlockUnrelatedTargetPublication(t *testing.T) {
	fixtureA := newEchoConnectFixture(t, nil)
	fixtureB := newEchoConnectFixture(t, nil)
	fixtureBReplacement := newEchoConnectFixture(t, nil)
	bindingA := testBinding("ack-stall-a")
	bindingB := testBinding("ack-stall-b")
	descriptorA := targetDescriptor(bindingA, fixtureA)
	descriptorB := targetDescriptor(bindingB, fixtureB)
	descriptorBReplacement := targetDescriptor(bindingB, fixtureBReplacement)
	registry, err := NewEgressdTargetRegistry([]EgressdTargetDescriptor{descriptorA, descriptorB})
	if err != nil {
		t.Fatal(err)
	}
	oldA := resolveTarget(t, registry, bindingA).(*egressdTarget)
	oldB := resolveTarget(t, registry, bindingB)
	credential := testCredential(t, 1)
	authenticator := &fakeAuthenticator{bindings: map[string]guestenrollment.Binding{credential: bindingA}}
	pki := newTestPKI(t, "localhost")
	server := newServer("pipe", time.Second, &tls.Config{
		MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pki.certificate},
	}, authenticator, registry, 2)
	if err := registry.bindSessionWithdrawal(server.registry.WithdrawBindings); err != nil {
		t.Fatal(err)
	}
	serverSide, guestSide := net.Pipe()
	handlerDone := make(chan struct{})
	go func() {
		server.handleConnection(serverSide, func() {})
		close(handlerDone)
	}()
	t.Cleanup(func() {
		_ = guestSide.Close()
		select {
		case <-handlerDone:
		case <-time.After(time.Second):
		}
		server.cancelLifetime()
	})

	guest := tls.Client(guestSide, &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pki.rootPool, ServerName: "localhost"})
	handshakeContext, cancelHandshake := context.WithTimeout(t.Context(), time.Second)
	defer cancelHandshake()
	if err := guest.HandshakeContext(handshakeContext); err != nil {
		t.Fatal(err)
	}
	hello, err := nativeegress.EncodeMessage(nativeegress.Message{
		ContractVersion: nativeegress.Version, Type: nativeegress.Hello, Binding: &bindingA,
		Audience: guestenrollment.NativeEgressAudience, Credential: credential,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := guest.Write(hello); err != nil {
		t.Fatal(err)
	}
	waitForCondition(t, func() bool { return egressdTargetAdmissions(oldA) == 1 }, "stalled target acknowledgement")
	if _, ready := server.Sessions().Active(bindingA); ready {
		t.Fatal("stalled acknowledgement became registry-ready")
	}

	publicationDone := make(chan error, 1)
	go func() {
		publicationDone <- registry.Reconcile([]EgressdTargetDescriptor{descriptorA, descriptorBReplacement})
	}()
	select {
	case err := <-publicationDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("unrelated target publication blocked behind guest acknowledgement")
	}
	if current := resolveTarget(t, registry, bindingA); current != oldA {
		t.Fatal("unrelated publication churned stalled target")
	}
	if current := resolveTarget(t, registry, bindingB); current == oldB {
		t.Fatal("unrelated replacement was not published")
	}

	removalDone := make(chan error, 1)
	go func() { removalDone <- registry.Reconcile([]EgressdTargetDescriptor{descriptorBReplacement}) }()
	waitForCondition(t, func() bool { return !oldA.isActive() }, "stalled acknowledgement target draining")
	// Let the peer consume any TLS record only after withdrawal has blocked the
	// admission epoch. Whether the ACK write completed or failed, the reserved
	// session must be unable to activate before the snapshot commits.
	_ = guest.SetReadDeadline(time.Now().Add(time.Second))
	_, _ = guest.Read(make([]byte, nativeegress.MaxFrameBytes))
	select {
	case err := <-removalDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("target withdrawal did not cancel the stalled acknowledgement")
	}
	if _, ready := server.Sessions().Active(bindingA); ready {
		t.Fatal("withdrawn acknowledgement activated a late session")
	}
	if target, err := registry.ResolveNativeEgressTarget(t.Context(), bindingA); target != nil || !errors.Is(err, ErrTargetUnavailable) {
		t.Fatal("withdrawn target remained resolvable")
	}
	assertEgressdTargetLifecycle(t, oldA, egressdTargetClosed, 0)
	// tls.Conn.Close writes close_notify; release the deliberately non-reading
	// net.Pipe peer before requiring the handler's outer close to return.
	_ = guest.Close()
	select {
	case <-handlerDone:
	case <-time.After(time.Second):
		t.Fatal("stalled acknowledgement handler did not terminate")
	}
}

func TestStalledTargetConnectIsPerBindingAndCannotActivateAfterReplacement(t *testing.T) {
	fixtureAReplacement := newEchoConnectFixture(t, nil)
	fixtureB := newEchoConnectFixture(t, nil)
	bindingA := testBinding("connect-stall-a")
	bindingB := testBinding("connect-stall-b")
	descriptorA := EgressdTargetDescriptor{Binding: bindingA, ConnectURL: "http://stall-a.example:8470"}
	descriptorAReplacement := targetDescriptor(bindingA, fixtureAReplacement)
	descriptorB := targetDescriptor(bindingB, fixtureB)
	started := make(chan struct{})
	release := make(chan struct{})
	var startedOnce sync.Once
	dialer := &net.Dialer{}
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != "stall-a.example:8470" {
			return dialer.DialContext(ctx, network, address)
		}
		startedOnce.Do(func() { close(started) })
		<-release // Deliberately model target I/O that ignores cancellation.
		client, peer := net.Pipe()
		_ = peer.Close()
		return client, nil
	}
	registry, err := newEgressdTargetRegistry([]EgressdTargetDescriptor{descriptorA, descriptorB}, dial)
	if err != nil {
		t.Fatal(err)
	}
	oldA := resolveTarget(t, registry, bindingA).(*egressdTarget)
	destination := nativeegress.Destination{Network: nativeegress.NetworkTCP, Host: "api.example", Port: 443}
	flowResult := make(chan error, 1)
	go func() {
		flow, openErr := oldA.OpenFlow(t.Context(), destination)
		if flow != nil {
			_ = flow.Close()
		}
		flowResult <- openErr
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("stalled target dial did not start")
	}

	replacementDone := make(chan error, 1)
	go func() {
		replacementDone <- registry.Reconcile([]EgressdTargetDescriptor{descriptorAReplacement, descriptorB})
	}()
	waitForCondition(t, func() bool { return !oldA.isActive() }, "target draining")

	// The changed target is draining, but the unchanged binding remains fully
	// independent while publication waits for the bounded exact admission.
	flowB, err := resolveTarget(t, registry, bindingB).OpenFlow(t.Context(), destination)
	if err != nil {
		t.Fatalf("unrelated target admission was blocked: %v", err)
	}
	assertFlowEcho(t, flowB, []byte("unrelated-binding"))
	_ = flowB.Close()
	select {
	case err := <-replacementDone:
		t.Fatalf("replacement committed before stalled exact admission released: %v", err)
	default:
	}

	close(release)
	if err := <-flowResult; !errors.Is(err, ErrTargetUnavailable) {
		t.Fatalf("drained target returned a late flow: %v", err)
	}
	select {
	case err := <-replacementDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("replacement did not commit after exact admission released")
	}
	assertEgressdTargetLifecycle(t, oldA, egressdTargetClosed, 0)
	newA := resolveTarget(t, registry, bindingA)
	if newA == oldA {
		t.Fatal("replacement retained the drained target epoch")
	}
	flowA, err := newA.OpenFlow(t.Context(), destination)
	if err != nil {
		t.Fatal(err)
	}
	assertFlowEcho(t, flowA, []byte("replacement-binding"))
	_ = flowA.Close()
}

func TestCanceledTargetDrainRollsBackWithoutLeakingAdmission(t *testing.T) {
	fixtureA := newEchoConnectFixture(t, nil)
	fixtureAReplacement := newEchoConnectFixture(t, nil)
	binding := testBinding("drain-rollback")
	descriptor := targetDescriptor(binding, fixtureA)
	replacement := targetDescriptor(binding, fixtureAReplacement)
	registry, err := NewEgressdTargetRegistry([]EgressdTargetDescriptor{descriptor})
	if err != nil {
		t.Fatal(err)
	}
	target := resolveTarget(t, registry, binding).(*egressdTarget)
	admission, ok := target.acquireAdmission()
	if !ok {
		t.Fatal("target admission was unavailable")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 25*time.Millisecond)
	defer cancel()
	if err := registry.ReconcileContext(ctx, []EgressdTargetDescriptor{replacement}); err == nil {
		t.Fatal("canceled drain committed a replacement")
	}
	if current := resolveTarget(t, registry, binding); current != target {
		t.Fatal("canceled drain disturbed the prior snapshot")
	}
	if admission.Active() {
		t.Fatal("canceled epoch became valid again after rollback")
	}
	admission.Release()
	assertEgressdTargetLifecycle(t, target, egressdTargetActive, 0)
	if err := registry.Reconcile([]EgressdTargetDescriptor{replacement}); err != nil {
		t.Fatalf("target could not reconcile after rollback: %v", err)
	}
	assertEgressdTargetLifecycle(t, target, egressdTargetClosed, 0)
}

func egressdTargetAdmissions(target *egressdTarget) int {
	if target == nil {
		return 0
	}
	target.lifecycleMu.Lock()
	defer target.lifecycleMu.Unlock()
	return target.admissions
}

func assertEgressdTargetLifecycle(t *testing.T, target *egressdTarget, state egressdTargetState, admissions int) {
	t.Helper()
	target.lifecycleMu.Lock()
	defer target.lifecycleMu.Unlock()
	if target.state != state || target.admissions != admissions {
		t.Fatalf("target lifecycle state=%d admissions=%d, want state=%d admissions=%d", target.state, target.admissions, state, admissions)
	}
}
