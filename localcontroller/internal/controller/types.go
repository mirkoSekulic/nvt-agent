package controller

import (
	"encoding/json"
	"errors"
	"time"
)

const (
	APIVersion             = "nvt.local-runs/v1"
	MaxRequestBytes        = 1088 << 10
	MaxIdempotencyKeyBytes = 256
	MaxOwnerBytes          = 128
	MaxReasonBytes         = 128
	MaxListLimit           = 500
)

type State string

const (
	StatePending   State = "pending"
	StatePreparing State = "preparing"
	StateRunning   State = "running"
	StateStopping  State = "stopping"
	StateCompleted State = "completed"
	StateFailed    State = "failed"
	StateExpired   State = "expired"
)

var (
	ErrInvalidRequest    = errors.New("invalid local-run request")
	ErrNotFound          = errors.New("local run not found")
	ErrGone              = errors.New("local run was deleted")
	ErrConflict          = errors.New("local run conflict")
	ErrCapacityExceeded  = errors.New("local run capacity exceeded")
	ErrInvalidTransition = errors.New("invalid local-run state transition")
	ErrOwnershipConflict = errors.New("local-run reconciliation ownership conflict")
	ErrStoreUnavailable  = errors.New("local-run store unavailable")
)

func (state State) valid() bool {
	switch state {
	case StatePending, StatePreparing, StateRunning, StateStopping, StateCompleted, StateFailed, StateExpired:
		return true
	default:
		return false
	}
}

func (state State) terminal() bool {
	return state == StateCompleted || state == StateFailed || state == StateExpired
}

func (state State) active() bool {
	return state.valid() && !state.terminal()
}

func transitionAllowed(from, to State) bool {
	switch from {
	case StatePending:
		return to == StatePreparing || to == StateStopping
	case StatePreparing:
		return to == StateRunning || to == StateStopping
	case StateRunning:
		return to == StatePreparing || to == StateStopping
	case StateStopping:
		return to == StateCompleted || to == StateFailed || to == StateExpired
	default:
		return false
	}
}

type CreateInput struct {
	IdempotencyKey string
	ResolvedRun    json.RawMessage
}

type ClaimInput struct {
	RunID            string
	Owner            string
	ExpectedRevision int64
	Lease            time.Duration
}

type StatusInput struct {
	RunID            string
	Owner            string
	ExpectedRevision int64
	State            State
	TerminalTarget   State
	Reason           string
}

type Run struct {
	APIVersion        string     `json:"api_version"`
	RunID             string     `json:"run_id"`
	State             State      `json:"state"`
	Revision          int64      `json:"revision"`
	SnapshotDigest    string     `json:"snapshot_digest"`
	Issuer            string     `json:"issuer"`
	Subject           string     `json:"subject"`
	Profile           string     `json:"profile"`
	Workflow          string     `json:"workflow"`
	Retention         string     `json:"retention"`
	Persistent        bool       `json:"persistent"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
	DeadlineAt        *time.Time `json:"deadline_at,omitempty"`
	TerminalExpiresAt *time.Time `json:"terminal_expires_at,omitempty"`
	DeleteRequested   bool       `json:"delete_requested,omitempty"`
	TerminalTarget    State      `json:"terminal_target,omitempty"`
	LastReason        string     `json:"last_reason,omitempty"`
	ReconcileOwner    string     `json:"reconcile_owner,omitempty"`
	ReconcileUntil    *time.Time `json:"reconcile_until,omitempty"`
}

type ListResult struct {
	APIVersion string `json:"api_version"`
	Runs       []Run  `json:"runs"`
	NextAfter  string `json:"next_after,omitempty"`
}

type CreateResult struct {
	Run     Run
	Created bool
}

func persistentRun(workspace, runtimeState, dockerData bool) bool {
	return workspace || runtimeState || dockerData
}
