package nativeegress

import (
	"sync"
	"time"

	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment"
)

// SessionRegistry stores one active and one already-authenticated standby per
// exact binding. It has no list/enumeration or partial-binding lookup API.
type SessionRegistry struct {
	mu           sync.Mutex
	slots        map[guestenrollment.Binding]*sessionSlot
	closed       bool
	shutdownDone chan struct{}
	shutdownErr  error
}

type sessionSlot struct {
	active  *SessionReservation
	standby *SessionReservation
}

type SessionReservation struct {
	registry *SessionRegistry
	session  *Session
	binding  guestenrollment.Binding
	sequence uint64
	ready    bool
	removed  bool
}

func NewSessionRegistry() *SessionRegistry {
	return &SessionRegistry{
		slots:        make(map[guestenrollment.Binding]*sessionSlot, MaxSessionBindings),
		shutdownDone: make(chan struct{}),
	}
}

func (registry *SessionRegistry) Reserve(session *Session) (*SessionReservation, error) {
	if registry == nil || session == nil || !session.Ready() {
		return nil, ErrProtocol
	}
	binding := session.Binding()
	sequence := session.Sequence()
	if guestenrollment.ValidateBinding(binding) != nil || sequence == 0 || sequence > guestenrollment.MaxGuestSessionIssuanceSequence {
		return nil, ErrProtocol
	}
	reservation := &SessionReservation{registry: registry, session: session, binding: binding, sequence: sequence}
	registry.mu.Lock()
	if registry.closed {
		registry.mu.Unlock()
		return nil, ErrUnavailable
	}
	slot := registry.slots[binding]
	if slot == nil {
		if len(registry.slots) >= MaxSessionBindings {
			registry.mu.Unlock()
			return nil, ErrCapacity
		}
		slot = &sessionSlot{}
	} else if slot.active == nil || slot.standby != nil {
		registry.mu.Unlock()
		return nil, ErrCapacity
	} else if sequence < slot.active.sequence {
		registry.mu.Unlock()
		return nil, ErrUnavailable
	}
	if !session.addBeforeShutdown(func() { reservation.withdraw() }) {
		registry.mu.Unlock()
		return nil, ErrUnavailable
	}
	if !session.setFlowAuthority(false) {
		registry.mu.Unlock()
		return nil, ErrUnavailable
	}
	if registry.slots[binding] == nil {
		registry.slots[binding] = slot
	}
	if slot.active == nil && slot.standby == nil {
		slot.active = reservation
	} else {
		slot.standby = reservation
	}
	registry.mu.Unlock()
	go reservation.removeWhenClosed()
	return reservation, nil
}

func (reservation *SessionReservation) Activate() bool {
	if reservation == nil || reservation.registry == nil || reservation.session == nil || !reservation.session.Ready() {
		return false
	}
	registry := reservation.registry
	registry.mu.Lock()
	if registry.closed || reservation.removed {
		registry.mu.Unlock()
		return false
	}
	slot := registry.slots[reservation.binding]
	if slot == nil || (slot.active != reservation && slot.standby != reservation) {
		registry.mu.Unlock()
		return false
	}
	reservation.ready = true
	if slot.active == nil && slot.standby == reservation {
		slot.active = reservation
		slot.standby = nil
	}
	if slot.active == reservation && !reservation.session.setFlowAuthority(true) {
		registry.mu.Unlock()
		return false
	}
	registry.mu.Unlock()
	return true
}

// Remove withdraws readiness under the registry lock before closing flows.
// An already-ready standby is promoted atomically; it never preempts active.
func (reservation *SessionReservation) Remove() {
	if reservation == nil || reservation.registry == nil {
		return
	}
	if !reservation.withdraw() {
		return
	}
	_ = reservation.session.Close()
}

func (reservation *SessionReservation) withdraw() bool {
	registry := reservation.registry
	registry.mu.Lock()
	if reservation.removed {
		registry.mu.Unlock()
		return false
	}
	reservation.removed = true
	reservation.ready = false
	reservation.session.setFlowAuthority(false)
	slot := registry.slots[reservation.binding]
	if slot != nil {
		if slot.active == reservation {
			slot.active = nil
			if slot.standby != nil && slot.standby.ready && !slot.standby.removed && slot.standby.session.Ready() {
				slot.active = slot.standby
				slot.standby = nil
				slot.active.session.setFlowAuthority(true)
			}
		} else if slot.standby == reservation {
			slot.standby = nil
		}
		if slot.active == nil && slot.standby == nil {
			delete(registry.slots, reservation.binding)
		}
	}
	registry.mu.Unlock()
	return true
}

func (reservation *SessionReservation) removeWhenClosed() {
	<-reservation.session.Done()
	reservation.Remove()
}

func (registry *SessionRegistry) Active(binding guestenrollment.Binding) (*Session, bool) {
	if registry == nil || guestenrollment.ValidateBinding(binding) != nil {
		return nil, false
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	slot := registry.slots[binding]
	if registry.closed || slot == nil || slot.active == nil || !slot.active.ready || slot.active.removed || !slot.active.session.Ready() {
		return nil, false
	}
	return slot.active.session, true
}

// WithdrawBindings synchronously removes flow authority and registry
// readiness for each complete binding, then closes the finite affected
// sessions concurrently. The returned channel closes when teardown finishes
// or the single bounded shutdown budget elapses. Callers may safely make a
// replacement target snapshot visible immediately after this method returns:
// no withdrawn session can open another flow or remain registry-ready.
func (registry *SessionRegistry) WithdrawBindings(bindings []guestenrollment.Binding) (<-chan struct{}, error) {
	if registry == nil || len(bindings) > MaxSessionBindings {
		return nil, ErrProtocol
	}
	canonical := append([]guestenrollment.Binding(nil), bindings...)
	seen := make(map[guestenrollment.Binding]struct{}, len(canonical))
	for _, binding := range canonical {
		if guestenrollment.ValidateBinding(binding) != nil {
			return nil, ErrProtocol
		}
		if _, exists := seen[binding]; exists {
			return nil, ErrProtocol
		}
		seen[binding] = struct{}{}
	}

	registry.mu.Lock()
	if registry.closed {
		registry.mu.Unlock()
		return nil, ErrUnavailable
	}
	reservations := make([]*SessionReservation, 0, len(canonical)*2)
	for _, binding := range canonical {
		slot := registry.slots[binding]
		if slot == nil {
			continue
		}
		for _, reservation := range []*SessionReservation{slot.active, slot.standby} {
			if reservation == nil || reservation.removed {
				continue
			}
			reservation.removed = true
			reservation.ready = false
			reservation.session.setFlowAuthority(false)
			reservations = append(reservations, reservation)
		}
		delete(registry.slots, binding)
	}
	registry.mu.Unlock()

	done := make(chan struct{})
	go finishWithdrawals(reservations, done)
	return done, nil
}

func finishWithdrawals(reservations []*SessionReservation, done chan<- struct{}) {
	defer close(done)
	results := make(chan struct{}, len(reservations))
	for _, reservation := range reservations {
		go func() {
			_ = reservation.session.Close()
			results <- struct{}{}
		}()
	}
	timer := time.NewTimer(ShutdownTimeout)
	defer timer.Stop()
	for range reservations {
		select {
		case <-results:
		case <-timer.C:
			return
		}
	}
}

func (registry *SessionRegistry) Close() error {
	return registry.closeWithin(ShutdownTimeout)
}

func (registry *SessionRegistry) closeWithin(timeout time.Duration) error {
	if registry == nil {
		return nil
	}
	if timeout <= 0 || timeout > ShutdownTimeout {
		return ErrProtocol
	}
	registry.mu.Lock()
	if !registry.closed {
		registry.closed = true
		reservations := make([]*SessionReservation, 0, len(registry.slots)*2)
		for _, slot := range registry.slots {
			for _, reservation := range []*SessionReservation{slot.active, slot.standby} {
				if reservation == nil || reservation.removed {
					continue
				}
				reservation.removed = true
				reservation.ready = false
				reservation.session.setFlowAuthority(false)
				reservations = append(reservations, reservation)
			}
		}
		registry.slots = nil
		go registry.finishShutdown(reservations, timeout)
	}
	done := registry.shutdownDone
	registry.mu.Unlock()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-done:
		registry.mu.Lock()
		err := registry.shutdownErr
		registry.mu.Unlock()
		return err
	case <-timer.C:
		return ErrUnavailable
	}
}

func (registry *SessionRegistry) finishShutdown(reservations []*SessionReservation, timeout time.Duration) {
	results := make(chan error, len(reservations))
	for _, reservation := range reservations {
		go func() { results <- reservation.session.closeWithin(timeout) }()
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	err := error(nil)
	for range reservations {
		select {
		case result := <-results:
			if result != nil {
				err = ErrUnavailable
			}
		case <-timer.C:
			err = ErrUnavailable
			goto complete
		}
	}

complete:
	registry.mu.Lock()
	registry.shutdownErr = err
	close(registry.shutdownDone)
	registry.mu.Unlock()
}

func (*SessionRegistry) String() string   { return "[native egress session registry]" }
func (*SessionRegistry) GoString() string { return "[native egress session registry]" }
