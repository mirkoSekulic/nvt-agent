package workspacetunnel

import (
	"sync"

	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment"
)

const MaxWorkspaceSessionBindings = 128

// SessionRegistry proves the implementation-neutral active/standby selection
// contract. It stores only non-secret binding/sequence metadata and
// StreamOpener values; no credential or yamux type crosses the boundary.
type SessionRegistry struct {
	mu     sync.Mutex
	slots  map[guestenrollment.Binding]*sessionSlot
	closed bool
}

type sessionSlot struct {
	active  *SessionReservation
	standby *SessionReservation
}

// SessionReservation represents one bounded registry position. Activation
// makes a first session ready but never lets a standby preempt the active
// session. Remove promotes an already-ready standby atomically.
type SessionReservation struct {
	registry *SessionRegistry
	session  StreamOpener
	binding  guestenrollment.Binding
	sequence uint64
	ready    bool
	removed  bool
}

func NewSessionRegistry() *SessionRegistry {
	return &SessionRegistry{slots: make(map[guestenrollment.Binding]*sessionSlot, MaxWorkspaceSessionBindings)}
}

func (registry *SessionRegistry) Reserve(session StreamOpener) (*SessionReservation, error) {
	if registry == nil || session == nil {
		return nil, ErrProtocol
	}
	binding := session.Binding()
	sequence := session.Sequence()
	if guestenrollment.ValidateBinding(binding) != nil || sequence == 0 || sequence > guestenrollment.MaxGuestSessionIssuanceSequence {
		return nil, ErrProtocol
	}
	reservation := &SessionReservation{registry: registry, session: session, binding: binding, sequence: sequence}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if registry.closed {
		return nil, ErrUnavailable
	}
	slot := registry.slots[binding]
	if slot == nil {
		if len(registry.slots) >= MaxWorkspaceSessionBindings {
			return nil, ErrCapacity
		}
		slot = &sessionSlot{}
		registry.slots[binding] = slot
	}
	if slot.active == nil && slot.standby == nil {
		slot.active = reservation
		return reservation, nil
	}
	if slot.active == nil || slot.standby != nil {
		return nil, ErrCapacity
	}
	if sequence < slot.active.sequence {
		return nil, ErrUnavailable
	}
	slot.standby = reservation
	return reservation, nil
}

func (reservation *SessionReservation) Activate() bool {
	if reservation == nil || reservation.registry == nil {
		return false
	}
	registry := reservation.registry
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if registry.closed || reservation.removed {
		return false
	}
	slot := registry.slots[reservation.binding]
	if slot == nil || (slot.active != reservation && slot.standby != reservation) {
		return false
	}
	reservation.ready = true
	if slot.active == nil && slot.standby == reservation {
		slot.active = reservation
		slot.standby = nil
	}
	return true
}

func (reservation *SessionReservation) Remove() {
	if reservation == nil || reservation.registry == nil {
		return
	}
	registry := reservation.registry
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if reservation.removed {
		return
	}
	reservation.removed = true
	reservation.ready = false
	slot := registry.slots[reservation.binding]
	if slot == nil {
		return
	}
	if slot.active == reservation {
		slot.active = nil
		if slot.standby != nil && slot.standby.ready && !slot.standby.removed {
			slot.active = slot.standby
			slot.standby = nil
		}
	} else if slot.standby == reservation {
		slot.standby = nil
	}
	if slot.active == nil && slot.standby == nil {
		delete(registry.slots, reservation.binding)
	}
}

func (registry *SessionRegistry) Active(binding guestenrollment.Binding) (StreamOpener, bool) {
	if registry == nil {
		return nil, false
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	slot := registry.slots[binding]
	if registry.closed || slot == nil || slot.active == nil || !slot.active.ready || slot.active.removed {
		return nil, false
	}
	return slot.active.session, true
}

func (registry *SessionRegistry) Close() error {
	if registry == nil {
		return nil
	}
	registry.mu.Lock()
	if registry.closed {
		registry.mu.Unlock()
		return nil
	}
	registry.closed = true
	sessions := make([]StreamOpener, 0, len(registry.slots)*2)
	for _, slot := range registry.slots {
		for _, reservation := range []*SessionReservation{slot.active, slot.standby} {
			if reservation == nil || reservation.removed {
				continue
			}
			reservation.removed = true
			reservation.ready = false
			sessions = append(sessions, reservation.session)
		}
	}
	registry.slots = nil
	registry.mu.Unlock()
	for _, session := range sessions {
		_ = session.Close()
	}
	return nil
}

func (*SessionRegistry) String() string   { return "[native workspace session registry]" }
func (*SessionRegistry) GoString() string { return "[native workspace session registry]" }
