package guestenrollment

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

type handoffStore struct {
	ExecutionScope ExecutionScope `json:"execution_scope"`
	Generation     int64          `json:"generation"`
	GuestID        string         `json:"guest_instance_id"`
	Accepted       bool           `json:"accepted"`
}

type conformanceHandoff struct {
	store            *handoffStore
	loseDeliverReply bool
}

func (h *conformanceHandoff) Prepare(_ context.Context, request HandoffPrepareRequest) (HandoffPrepareResult, error) {
	if ValidateHandoffPrepareRequest(request) != nil {
		return HandoffPrepareResult{}, NewFailure(ReasonInvalidRequest)
	}
	fresh := h.store.GuestID == ""
	if fresh {
		h.store.ExecutionScope = request.ExecutionScope
		h.store.Generation = request.DesiredGeneration
		h.store.GuestID = "guest-1"
	} else if h.store.ExecutionScope != request.ExecutionScope || h.store.Generation != request.DesiredGeneration {
		return HandoffPrepareResult{}, NewFailure(ReasonBindingMismatch)
	}
	state := HandoffStatePrepared
	if h.store.Accepted {
		state = HandoffStateAccepted
		fresh = false
	}
	return HandoffPrepareResult{ContractVersion: HandoffVersion, GuestInstanceID: h.store.GuestID, State: state, NewlyPrepared: fresh}, nil
}

func (h *conformanceHandoff) Replace(_ context.Context, request HandoffReplaceRequest) (HandoffPrepareResult, error) {
	if ValidateHandoffReplaceRequest(request) != nil || request.Binding.ExecutionScope() != h.store.ExecutionScope ||
		request.Binding.DesiredGeneration != h.store.Generation || request.Binding.GuestInstanceID != h.store.GuestID {
		return HandoffPrepareResult{}, NewFailure(ReasonBindingMismatch)
	}
	h.store.GuestID = "guest-2"
	h.store.Accepted = false
	return HandoffPrepareResult{ContractVersion: HandoffVersion, GuestInstanceID: h.store.GuestID, State: HandoffStatePrepared, NewlyPrepared: true}, nil
}

func (h *conformanceHandoff) Deliver(_ context.Context, request HandoffDeliverRequest) error {
	if ValidateHandoffDeliverRequest(request) != nil || request.Envelope.Binding.ExecutionScope() != h.store.ExecutionScope ||
		request.Envelope.Binding.DesiredGeneration != h.store.Generation || request.Envelope.Binding.GuestInstanceID != h.store.GuestID {
		return NewFailure(ReasonBindingMismatch)
	}
	// Acceptance is durable before the acknowledgement can be lost. The token
	// is deliberately not copied into the durable provider snapshot.
	h.store.Accepted = true
	if h.loseDeliverReply {
		return errors.New("sanitized response lost")
	}
	return nil
}

func TestHandoffConformanceRestartAndResponseLoss(t *testing.T) {
	store := &handoffStore{}
	handoff := &conformanceHandoff{store: store, loseDeliverReply: true}
	scope := ExecutionScope{AgentRunUID: "uid", ExecutionID: "execution", DriverRegistration: "fake"}
	request := HandoffPrepareRequest{ContractVersion: HandoffVersion, ExecutionScope: scope, DesiredGeneration: 4}
	prepared, err := handoff.Prepare(context.Background(), request)
	if err != nil || !prepared.NewlyPrepared || prepared.State != HandoffStatePrepared {
		t.Fatalf("fresh prepare=%#v err=%v", prepared, err)
	}
	repeated, err := handoff.Prepare(context.Background(), request)
	if err != nil || repeated.NewlyPrepared || repeated.GuestInstanceID != prepared.GuestInstanceID {
		t.Fatalf("repeat prepare=%#v err=%v", repeated, err)
	}
	binding := Binding{AgentRunUID: scope.AgentRunUID, ExecutionID: scope.ExecutionID, DriverRegistration: scope.DriverRegistration, DesiredGeneration: request.DesiredGeneration, GuestInstanceID: prepared.GuestInstanceID}
	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	token := opaqueValue(TokenBytes, 0x77)
	err = handoff.Deliver(context.Background(), HandoffDeliverRequest{ContractVersion: HandoffVersion, Envelope: BootstrapEnvelope{
		ContractVersion: Version, Binding: binding, ExchangeURL: "https://issuer.example/v1/guest-enrollment/exchange",
		Token: token, IssuedAt: FormatTimestamp(now), ExpiresAt: FormatTimestamp(now.Add(time.Minute)),
	}})
	if err == nil {
		t.Fatal("response-loss seam did not fire")
	}

	restarted := &conformanceHandoff{store: store}
	accepted, err := restarted.Prepare(context.Background(), request)
	if err != nil || accepted.State != HandoffStateAccepted || accepted.NewlyPrepared {
		t.Fatalf("restart did not recover acceptance: %#v err=%v", accepted, err)
	}
	snapshot, err := json.Marshal(store)
	if err != nil || strings.Contains(string(snapshot), token) || strings.Contains(string(snapshot), "exchange_url") {
		t.Fatalf("ordinary durable state disclosed envelope: %s err=%v", snapshot, err)
	}
}
