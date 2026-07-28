package driver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/mirkoSekulic/nvt-agent/executiondrivers/qemu/internal/config"
	"github.com/mirkoSekulic/nvt-agent/executiondrivers/qemu/internal/wire"
	"github.com/mirkoSekulic/nvt-agent/operator/executiondriver"
	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment"
)

type MachineObservation struct {
	Running  bool
	Enrolled bool
	Ready    bool
}

type MachineManager interface {
	GuestImageDigest() (string, error)
	Ensure(context.Context, *State) error
	Observe(context.Context, *State) (MachineObservation, error)
	Configure(context.Context, *State, wire.BootConfiguration) error
	Deliver(context.Context, *State, guestenrollment.BootstrapEnvelope) (MachineObservation, error)
	Replace(context.Context, *State) error
	Delete(context.Context, *State) error
	Shutdown(context.Context) error
}

type Driver struct {
	store        Store
	machines     MachineManager
	registration string
	mu           sync.Mutex
}

type Error struct{ Failure executiondriver.Failure }

func (failure *Error) Error() string { return "QEMU execution driver request failed" }

func New(storeRoot, registration string, machines MachineManager) (*Driver, error) {
	if storeRoot == "" || machines == nil || executiondriver.ValidateInitializeParams(executiondriver.InitializeParams{
		ProtocolVersion: executiondriver.ProtocolVersion, DriverInstanceName: registration,
	}) != nil {
		return nil, errors.New("QEMU driver configuration is invalid")
	}
	if err := os.MkdirAll(storeRoot, 0o700); err != nil {
		return nil, errors.New("QEMU driver state is unavailable")
	}
	return &Driver{store: Store{Root: storeRoot}, machines: machines, registration: registration}, nil
}

func (driver *Driver) Reconcile(ctx context.Context, desired executiondriver.DesiredExecution) (executiondriver.Status, error) {
	driver.mu.Lock()
	defer driver.mu.Unlock()
	if executiondriver.ValidateReconcileParams(executiondriver.ReconcileParams{Desired: desired}) != nil || desired.WorkloadKind != executiondriver.WorkloadKindVM {
		return executiondriver.Status{}, reject("invalid-desired", "resolved QEMU desired state is invalid")
	}
	resolved, err := config.Decode(desired.Configuration)
	if err != nil {
		return executiondriver.Status{}, reject("invalid-configuration", "QEMU execution class configuration is invalid")
	}
	imageDigest, err := driver.machines.GuestImageDigest()
	if err != nil || imageDigest != resolved.GuestImage.Digest {
		return executiondriver.Status{}, reject("guest-image-mismatch", "QEMU guest image digest does not match the execution class")
	}
	state, err := driver.store.Load(desired.ExecutionID)
	if errors.Is(err, os.ErrNotExist) {
		hostPort, allocationErr := driver.store.AllocateHostPort(desired.ExecutionID)
		if allocationErr != nil {
			return executiondriver.Status{}, retry("capacity-unavailable", "QEMU local health capacity is unavailable")
		}
		state = State{
			Version: stateVersion, ExecutionID: desired.ExecutionID, Generation: desired.Generation,
			DesiredFingerprint: desired.DesiredFingerprint, ClassName: desired.ClassName, Configuration: resolved,
			Attempt: 1, GuestInstanceID: guestInstanceID(desired.ExecutionID, desired.Generation, 1), HostPort: hostPort,
		}
		if err := driver.store.Save(state); err != nil {
			return executiondriver.Status{}, retry("state-unavailable", "QEMU durable state is unavailable")
		}
	} else if err != nil {
		return executiondriver.Status{}, retry("state-invalid", "QEMU durable state could not be validated")
	} else {
		if desired.Generation < state.Generation {
			return executiondriver.Status{}, reject("generation-regression", "QEMU desired generation regressed")
		}
		if desired.Generation == state.Generation && desired.DesiredFingerprint != state.DesiredFingerprint {
			return executiondriver.Status{}, reject("desired-conflict", "QEMU desired fingerprint conflicts with its generation")
		}
		if desired.Generation > state.Generation {
			if state.ExecutionScope != nil {
				return executiondriver.Status{}, reject("replacement-required", "QEMU enrolled desired state is immutable")
			}
			if err := driver.machines.Delete(ctx, &state); err != nil || driver.store.Remove(state.ExecutionID) != nil {
				return executiondriver.Status{}, retry("replacement-pending", "QEMU prior desired state cleanup is pending")
			}
			hostPort, allocationErr := driver.store.AllocateHostPort(desired.ExecutionID)
			if allocationErr != nil {
				return executiondriver.Status{}, retry("capacity-unavailable", "QEMU local health capacity is unavailable")
			}
			state = State{
				Version: stateVersion, ExecutionID: desired.ExecutionID, Generation: desired.Generation,
				DesiredFingerprint: desired.DesiredFingerprint, ClassName: desired.ClassName, Configuration: resolved,
				Attempt: 1, GuestInstanceID: guestInstanceID(desired.ExecutionID, desired.Generation, 1), HostPort: hostPort,
			}
			if err := driver.store.Save(state); err != nil {
				return executiondriver.Status{}, retry("state-unavailable", "QEMU durable state is unavailable")
			}
		}
	}
	if err := driver.machines.Ensure(ctx, &state); err != nil {
		return statusFor(state, MachineObservation{}), retry("vm-unavailable", "QEMU guest convergence is pending")
	}
	if state.ExecutionScope != nil {
		if err := driver.machines.Configure(ctx, &state, bootConfiguration(state)); err != nil {
			return statusFor(state, MachineObservation{Running: true}), nil
		}
	}
	observation, err := driver.machines.Observe(ctx, &state)
	if err != nil {
		return statusFor(state, MachineObservation{Running: true}), nil
	}
	if observation.Enrolled && !state.EnrollmentAccepted {
		state.EnrollmentAccepted = true
		if err := driver.store.Save(state); err != nil {
			return executiondriver.Status{}, retry("state-unavailable", "QEMU durable state is unavailable")
		}
	}
	return statusFor(state, observation), nil
}

func (driver *Driver) Observe(ctx context.Context, executionID string) (executiondriver.Status, error) {
	driver.mu.Lock()
	defer driver.mu.Unlock()
	if executiondriver.ValidateExecutionParams(executiondriver.ExecutionParams{ExecutionID: executionID}) != nil {
		return executiondriver.Status{}, reject("invalid-execution", "QEMU execution identity is invalid")
	}
	state, err := driver.store.Load(executionID)
	if errors.Is(err, os.ErrNotExist) {
		return executiondriver.Status{Phase: executiondriver.PhaseUnknown}, nil
	}
	if err != nil {
		return executiondriver.Status{}, retry("state-invalid", "QEMU durable state could not be validated")
	}
	observation, err := driver.machines.Observe(ctx, &state)
	if err != nil {
		return statusFor(state, MachineObservation{}), nil
	}
	return statusFor(state, observation), nil
}

func (driver *Driver) Delete(ctx context.Context, executionID string) (executiondriver.Status, error) {
	driver.mu.Lock()
	defer driver.mu.Unlock()
	if executiondriver.ValidateExecutionParams(executiondriver.ExecutionParams{ExecutionID: executionID}) != nil {
		return executiondriver.Status{}, reject("invalid-execution", "QEMU execution identity is invalid")
	}
	state, err := driver.store.Load(executionID)
	if errors.Is(err, os.ErrNotExist) {
		return executiondriver.Status{Phase: executiondriver.PhaseDeleted}, nil
	}
	if err != nil {
		return executiondriver.Status{}, retry("state-invalid", "QEMU durable state could not be validated")
	}
	if err := driver.machines.Delete(ctx, &state); err != nil {
		retryAfter := int32(5)
		return executiondriver.Status{Phase: executiondriver.PhaseDeleting, ObservedGeneration: state.Generation, RetryAfterSeconds: &retryAfter}, nil
	}
	if err := driver.store.Remove(executionID); err != nil {
		return executiondriver.Status{}, retry("cleanup-pending", "QEMU durable resource cleanup is pending")
	}
	return executiondriver.Status{Phase: executiondriver.PhaseDeleted, ObservedGeneration: state.Generation}, nil
}

func (driver *Driver) Prepare(ctx context.Context, request guestenrollment.HandoffPrepareRequest) (guestenrollment.HandoffPrepareResult, error) {
	driver.mu.Lock()
	defer driver.mu.Unlock()
	if guestenrollment.ValidateHandoffPrepareRequest(request) != nil || request.ExecutionScope.DriverRegistration != driver.registration {
		return guestenrollment.HandoffPrepareResult{}, errors.New("QEMU enrollment handoff was rejected")
	}
	state, err := driver.store.Load(request.ExecutionScope.ExecutionID)
	if err != nil || state.Generation != request.DesiredGeneration {
		return guestenrollment.HandoffPrepareResult{}, errors.New("QEMU enrollment handoff is unavailable")
	}
	fresh := false
	if state.ExecutionScope == nil {
		scope := request.ExecutionScope
		state.ExecutionScope = &scope
		fresh = true
	} else if *state.ExecutionScope != request.ExecutionScope {
		return guestenrollment.HandoffPrepareResult{}, errors.New("QEMU enrollment handoff was rejected")
	}
	if err := driver.machines.Ensure(ctx, &state); err != nil || driver.machines.Configure(ctx, &state, bootConfiguration(state)) != nil {
		return guestenrollment.HandoffPrepareResult{}, errors.New("QEMU enrollment handoff is unavailable")
	}
	// Persist the prepared obligation only after this exact guest is able to
	// accept the envelope. Before that point a retry is still the same fresh,
	// deterministic attempt; recording it early would make the orchestrator
	// conservatively revoke and replace a guest that was merely still booting.
	if fresh && driver.store.Save(state) != nil {
		return guestenrollment.HandoffPrepareResult{}, errors.New("QEMU enrollment handoff is unavailable")
	}
	if observation, observeErr := driver.machines.Observe(ctx, &state); observeErr == nil && observation.Enrolled && !state.EnrollmentAccepted {
		state.EnrollmentAccepted = true
		if driver.store.Save(state) != nil {
			return guestenrollment.HandoffPrepareResult{}, errors.New("QEMU enrollment handoff is unavailable")
		}
	}
	handoffState := guestenrollment.HandoffStatePrepared
	if state.EnrollmentAccepted {
		handoffState = guestenrollment.HandoffStateAccepted
		fresh = false
	}
	return guestenrollment.HandoffPrepareResult{ContractVersion: guestenrollment.HandoffVersion, GuestInstanceID: state.GuestInstanceID, State: handoffState, NewlyPrepared: fresh}, nil
}

func (driver *Driver) Replace(ctx context.Context, request guestenrollment.HandoffReplaceRequest) (guestenrollment.HandoffPrepareResult, error) {
	driver.mu.Lock()
	defer driver.mu.Unlock()
	if guestenrollment.ValidateHandoffReplaceRequest(request) != nil || request.Binding.DriverRegistration != driver.registration {
		return guestenrollment.HandoffPrepareResult{}, errors.New("QEMU enrollment replacement was rejected")
	}
	state, err := driver.store.Load(request.Binding.ExecutionID)
	if err != nil || state.ExecutionScope == nil || *state.ExecutionScope != request.Binding.ExecutionScope() || state.Generation != request.Binding.DesiredGeneration || state.GuestInstanceID != request.Binding.GuestInstanceID {
		return guestenrollment.HandoffPrepareResult{}, errors.New("QEMU enrollment replacement was rejected")
	}
	if err := driver.machines.Replace(ctx, &state); err != nil {
		return guestenrollment.HandoffPrepareResult{}, errors.New("QEMU enrollment replacement is unavailable")
	}
	state.Attempt++
	state.GuestInstanceID = guestInstanceID(state.ExecutionID, state.Generation, state.Attempt)
	state.EnrollmentAccepted = false
	if err := driver.store.Save(state); err != nil || driver.machines.Ensure(ctx, &state) != nil || driver.machines.Configure(ctx, &state, bootConfiguration(state)) != nil {
		return guestenrollment.HandoffPrepareResult{}, errors.New("QEMU enrollment replacement is unavailable")
	}
	return guestenrollment.HandoffPrepareResult{ContractVersion: guestenrollment.HandoffVersion, GuestInstanceID: state.GuestInstanceID, State: guestenrollment.HandoffStatePrepared, NewlyPrepared: true}, nil
}

func (driver *Driver) Deliver(ctx context.Context, request guestenrollment.HandoffDeliverRequest) error {
	driver.mu.Lock()
	defer driver.mu.Unlock()
	if guestenrollment.ValidateHandoffDeliverRequest(request) != nil || request.Envelope.Binding.DriverRegistration != driver.registration {
		return errors.New("QEMU enrollment delivery was rejected")
	}
	binding := request.Envelope.Binding
	state, err := driver.store.Load(binding.ExecutionID)
	if err != nil || state.ExecutionScope == nil || *state.ExecutionScope != binding.ExecutionScope() || state.Generation != binding.DesiredGeneration || state.GuestInstanceID != binding.GuestInstanceID {
		return errors.New("QEMU enrollment delivery was rejected")
	}
	if state.EnrollmentAccepted {
		return nil
	}
	observation, err := driver.machines.Deliver(ctx, &state, request.Envelope)
	if err != nil || !observation.Enrolled {
		return errors.New("QEMU enrollment delivery is unavailable")
	}
	state.EnrollmentAccepted = true
	if err := driver.store.Save(state); err != nil {
		return errors.New("QEMU enrollment delivery is unavailable")
	}
	return nil
}

func (driver *Driver) Shutdown(ctx context.Context) error {
	driver.mu.Lock()
	defer driver.mu.Unlock()
	return driver.machines.Shutdown(ctx)
}

func bootConfiguration(state State) wire.BootConfiguration {
	return wire.BootConfiguration{
		ContractVersion: wire.Version,
		Binding: guestenrollment.Binding{
			AgentRunUID: state.ExecutionScope.AgentRunUID, ExecutionID: state.ExecutionID, DriverRegistration: state.ExecutionScope.DriverRegistration,
			DesiredGeneration: state.Generation, GuestInstanceID: state.GuestInstanceID,
		},
		HostBundle: state.Configuration.HostBundle, RegistryCAPEM: state.Configuration.RegistryCAPEM, EnrollmentCAPEM: state.Configuration.EnrollmentCAPEM,
		NativeSessionEndpoint: state.Configuration.NativeSessionEndpoint, NativeSessionCAPEM: state.Configuration.NativeSessionCAPEM,
	}
}

func statusFor(state State, observation MachineObservation) executiondriver.Status {
	retryAfter := int32(2)
	status := executiondriver.Status{
		Phase: executiondriver.PhaseProvisioning, ObservedGeneration: state.Generation,
		ExternalResourceID: "qemu-vm/" + state.GuestInstanceID, RetryAfterSeconds: &retryAfter,
	}
	if observation.Ready && state.EnrollmentAccepted {
		status.Phase = executiondriver.PhaseRunning
		status.Ready = true
		status.Endpoint = &executiondriver.Endpoint{Scheme: executiondriver.EndpointSchemeHTTP, Host: "127.0.0.1", Port: uint16(state.HostPort)}
		status.RetryAfterSeconds = nil
	}
	return status
}

func reject(reason, message string) error {
	return &Error{Failure: executiondriver.Failure{Reason: reason, Message: message, Retryable: false}}
}

func retry(reason, message string) error {
	return &Error{Failure: executiondriver.Failure{Reason: reason, Message: message, Retryable: true}}
}

func MarshalStateForTest(state State) []byte {
	value, _ := json.Marshal(state)
	return value
}

func (driver *Driver) String() string { return fmt.Sprintf("QEMU driver %s", driver.registration) }

var _ guestenrollment.Handoff = (*Driver)(nil)
