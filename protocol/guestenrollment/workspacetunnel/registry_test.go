package workspacetunnel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment"
)

type registryTestSession struct {
	binding  guestenrollment.Binding
	sequence uint64
	closed   atomic.Bool
}

func (session *registryTestSession) OpenStream(context.Context) (net.Conn, error) {
	return nil, ErrUnavailable
}

func (session *registryTestSession) Binding() guestenrollment.Binding { return session.binding }
func (session *registryTestSession) Sequence() uint64                 { return session.sequence }
func (session *registryTestSession) Close() error {
	session.closed.Store(true)
	return nil
}

func TestSessionRegistryPinsOlderEqualNewerStandbyAndPromotion(t *testing.T) {
	binding := testBinding()
	registry := NewSessionRegistry()
	t.Cleanup(func() { _ = registry.Close() })

	active := &registryTestSession{binding: binding, sequence: 10}
	activeReservation, err := registry.Reserve(active)
	if err != nil || !activeReservation.Activate() {
		t.Fatalf("activate first session: reservation=%v error=%v", activeReservation, err)
	}
	if selected, ready := registry.Active(binding); !ready || selected != active {
		t.Fatal("first session is not authoritative")
	}

	older := &registryTestSession{binding: binding, sequence: 9}
	if _, err := registry.Reserve(older); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("older sequence error=%v", err)
	}
	equal := &registryTestSession{binding: binding, sequence: 10}
	equalReservation, err := registry.Reserve(equal)
	if err != nil || !equalReservation.Activate() {
		t.Fatalf("activate equal standby: reservation=%v error=%v", equalReservation, err)
	}
	if selected, ready := registry.Active(binding); !ready || selected != active {
		t.Fatal("equal standby preempted the active session")
	}
	if _, err := registry.Reserve(&registryTestSession{binding: binding, sequence: 11}); !errors.Is(err, ErrCapacity) {
		t.Fatalf("third session error=%v", err)
	}

	activeReservation.Remove()
	if selected, ready := registry.Active(binding); !ready || selected != equal {
		t.Fatal("ready equal standby was not promoted")
	}
	newer := &registryTestSession{binding: binding, sequence: 11}
	newerReservation, err := registry.Reserve(newer)
	if err != nil || !newerReservation.Activate() {
		t.Fatalf("activate newer standby: reservation=%v error=%v", newerReservation, err)
	}
	if selected, _ := registry.Active(binding); selected != equal {
		t.Fatal("newer standby preempted the active session")
	}
	equalReservation.Remove()
	if selected, ready := registry.Active(binding); !ready || selected != newer {
		t.Fatal("ready newer standby was not promoted")
	}
}

func TestSessionRegistryBoundsBindingsAndClosesSessions(t *testing.T) {
	registry := NewSessionRegistry()
	sessions := make([]*registryTestSession, 0, MaxWorkspaceSessionBindings)
	for index := range MaxWorkspaceSessionBindings {
		binding := testBinding()
		binding.ExecutionID = fmt.Sprintf("execution-workspace-%d", index)
		binding.GuestInstanceID = fmt.Sprintf("guest-workspace-%d", index)
		session := &registryTestSession{binding: binding, sequence: 1}
		reservation, err := registry.Reserve(session)
		if err != nil || !reservation.Activate() {
			t.Fatalf("reserve binding %d: reservation=%v error=%v", index, reservation, err)
		}
		sessions = append(sessions, session)
	}
	extraBinding := testBinding()
	extraBinding.ExecutionID = "execution-workspace-overflow"
	extraBinding.GuestInstanceID = "guest-workspace-overflow"
	if _, err := registry.Reserve(&registryTestSession{binding: extraBinding, sequence: 1}); !errors.Is(err, ErrCapacity) {
		t.Fatalf("binding overflow error=%v", err)
	}
	if err := registry.Close(); err != nil {
		t.Fatal(err)
	}
	for index, session := range sessions {
		if !session.closed.Load() {
			t.Fatalf("session %d was not closed", index)
		}
	}
	if _, ready := registry.Active(sessions[0].binding); ready {
		t.Fatal("closed registry retained readiness")
	}
}

func TestSessionRegistryConcurrentStandbyAdmissionIsBounded(t *testing.T) {
	binding := testBinding()
	registry := NewSessionRegistry()
	t.Cleanup(func() { _ = registry.Close() })
	active := &registryTestSession{binding: binding, sequence: 1}
	activeReservation, err := registry.Reserve(active)
	if err != nil || !activeReservation.Activate() {
		t.Fatalf("activate first session: reservation=%v error=%v", activeReservation, err)
	}

	type result struct {
		reservation *SessionReservation
		session     *registryTestSession
		err         error
	}
	const attempts = 16
	start := make(chan struct{})
	results := make(chan result, attempts)
	var workers sync.WaitGroup
	for range attempts {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			session := &registryTestSession{binding: binding, sequence: 2}
			reservation, err := registry.Reserve(session)
			results <- result{reservation: reservation, session: session, err: err}
		}()
	}
	close(start)
	workers.Wait()
	close(results)
	var admitted result
	admittedCount := 0
	for candidate := range results {
		if candidate.err == nil {
			admitted = candidate
			admittedCount++
			continue
		}
		if !errors.Is(candidate.err, ErrCapacity) {
			t.Fatalf("concurrent standby error=%v", candidate.err)
		}
	}
	if admittedCount != 1 || admitted.reservation == nil || !admitted.reservation.Activate() {
		t.Fatalf("admitted standby count=%d reservation=%v", admittedCount, admitted.reservation)
	}
	if selected, _ := registry.Active(binding); selected != active {
		t.Fatal("concurrent standby preempted active")
	}
	activeReservation.Remove()
	if selected, ready := registry.Active(binding); !ready || selected != admitted.session {
		t.Fatal("concurrent standby was not promoted")
	}
}

var _ StreamOpener = (*registryTestSession)(nil)
