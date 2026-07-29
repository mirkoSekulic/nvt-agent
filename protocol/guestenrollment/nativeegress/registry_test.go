package nativeegress

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment"
)

func TestRegistryMakeBeforeBreakMonotonicPromotionAndCleanup(t *testing.T) {
	binding := testBinding("run-registry")
	registry := NewSessionRegistry()
	defer registry.Close()
	active := mustSession(t, binding, 2)
	activeReservation, err := registry.Reserve(active)
	if err != nil || !activeReservation.Activate() {
		t.Fatalf("activate initial: %v", err)
	}
	if got, ok := registry.Active(binding); !ok || got != active {
		t.Fatal("initial session not active")
	}

	older := mustSession(t, binding, 1)
	if _, err := registry.Reserve(older); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("older replay error=%v", err)
	}
	_ = older.Close()
	standby := mustSession(t, binding, 2)
	standbyReservation, err := registry.Reserve(standby)
	if err != nil || !standbyReservation.Activate() {
		t.Fatalf("activate equal reconnect: %v", err)
	}
	if got, _ := registry.Active(binding); got != active {
		t.Fatal("standby preempted active")
	}
	third := mustSession(t, binding, 3)
	if _, err := registry.Reserve(third); !errors.Is(err, ErrCapacity) {
		t.Fatalf("third session error=%v", err)
	}
	_ = third.Close()

	activeReservation.Remove()
	if got, ok := registry.Active(binding); !ok || got != standby || got.Sequence() != 2 {
		t.Fatalf("standby was not promoted: %#v %t", got, ok)
	}
	select {
	case <-active.Done():
	case <-time.After(time.Second):
		t.Fatal("obsolete active session was not closed")
	}
	standbyReservation.Remove()
	if _, ok := registry.Active(binding); ok {
		t.Fatal("removed binding remained ready")
	}
}

func TestRegistryNewerReplacementExpiryShutdownAndBound(t *testing.T) {
	binding := testBinding("run-newer")
	registry := NewSessionRegistry()
	active := mustSession(t, binding, 1)
	activeReservation, err := registry.Reserve(active)
	if err != nil || !activeReservation.Activate() {
		t.Fatal(err)
	}
	newer := mustSession(t, binding, 2)
	newerReservation, err := registry.Reserve(newer)
	if err != nil || !newerReservation.Activate() {
		t.Fatal(err)
	}
	activeReservation.Remove()
	if got, ok := registry.Active(binding); !ok || got != newer {
		t.Fatal("newer standby not promoted")
	}
	if err := registry.Close(); err != nil {
		t.Fatal(err)
	}
	if _, ok := registry.Active(binding); ok {
		t.Fatal("closed registry remained ready")
	}
	select {
	case <-newer.Done():
	case <-time.After(time.Second):
		t.Fatal("registry shutdown retained session")
	}
	newerReservation.Remove()

	bounded := NewSessionRegistry()
	defer bounded.Close()
	for index := range MaxSessionBindings {
		candidateBinding := testBinding(fmt.Sprintf("run-bound-%d", index))
		session := mustSession(t, candidateBinding, 1)
		reservation, err := bounded.Reserve(session)
		if err != nil || !reservation.Activate() {
			t.Fatalf("reserve binding %d: %v", index, err)
		}
	}
	overflowBinding := testBinding("run-overflow")
	overflow := mustSession(t, overflowBinding, 1)
	if _, err := bounded.Reserve(overflow); !errors.Is(err, ErrCapacity) {
		t.Fatalf("binding overflow error=%v", err)
	}
	_ = overflow.Close()
}

func TestRegistryWithdrawsReadinessBeforeClosingFlows(t *testing.T) {
	binding := testBinding("run-order")
	registry := NewSessionRegistry()
	closedAfterWithdrawal := make(chan bool, 1)
	target := &fakeTarget{binding: binding}
	target.onClose = func() {
		_, ready := registry.Active(binding)
		closedAfterWithdrawal <- !ready
	}
	session, err := NewSession(testAuthentication(binding, 1, time.Minute), target)
	if err != nil {
		t.Fatal(err)
	}
	reservation, err := registry.Reserve(session)
	if err != nil || !reservation.Activate() {
		t.Fatal(err)
	}
	flow, err := session.OpenFlow(t.Context(), Destination{Network: NetworkTCP, Host: "api.example", Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	reservation.Remove()
	select {
	case withdrawn := <-closedAfterWithdrawal:
		if !withdrawn {
			t.Fatal("flow closed before readiness withdrawal")
		}
	case <-time.After(time.Second):
		t.Fatal("active flow was not closed")
	}
	_ = flow.Close()
	_ = registry.Close()
	target.closePeers()
}

func TestCredentialDeadlineRemovesSessionAndFlows(t *testing.T) {
	binding := testBinding("run-expiry")
	registry := NewSessionRegistry()
	target := &fakeTarget{binding: binding}
	session, err := NewSession(testAuthentication(binding, 1, 80*time.Millisecond), target)
	if err != nil {
		t.Fatal(err)
	}
	reservation, err := registry.Reserve(session)
	if err != nil || !reservation.Activate() {
		t.Fatal(err)
	}
	flow, err := session.OpenFlow(t.Context(), Destination{Network: NetworkTCP, Host: "api.example", Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-session.Done():
	case <-time.After(time.Second):
		t.Fatal("credential deadline did not close session")
	}
	deadline := time.Now().Add(time.Second)
	for {
		if _, ready := registry.Active(binding); !ready {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("expired session remained registered")
		}
		time.Sleep(time.Millisecond)
	}
	if _, err := flow.Read(make([]byte, 1)); err == nil {
		t.Fatal("expired session retained flow")
	}
	_ = registry.Close()
	target.closePeers()
}

func mustSession(t *testing.T, binding guestenrollment.Binding, sequence uint64) *Session {
	t.Helper()
	target := &fakeTarget{binding: binding}
	session, err := NewSession(testAuthentication(binding, sequence, time.Minute), target)
	if err != nil {
		t.Fatal(err)
	}
	return session
}
