package driver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"sync"

	"github.com/mirkoSekulic/nvt-agent/executiondrivers/azure/internal/config"
	"github.com/mirkoSekulic/nvt-agent/operator/executiondriver"
	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment"
)

type Driver struct {
	store        Store
	cloud        Cloud
	bootstrap    Bootstrapper
	resolver     Resolver
	registration string
	locksMu      sync.Mutex
	locks        map[string]*executionLock
}

type executionLock struct {
	mutex sync.Mutex
	refs  int
}

type Error struct{ Failure executiondriver.Failure }

func (*Error) Error() string { return "Azure execution driver request failed" }

func New(stateRoot, registration string, cloud Cloud, bootstrap Bootstrapper, resolver Resolver) (*Driver, error) {
	if stateRoot == "" || cloud == nil || bootstrap == nil || resolver == nil ||
		executiondriver.ValidateInitializeParams(executiondriver.InitializeParams{ProtocolVersion: executiondriver.ProtocolVersion, DriverInstanceName: registration}) != nil {
		return nil, errors.New("Azure driver configuration is invalid")
	}
	if err := os.MkdirAll(stateRoot, 0o700); err != nil || os.Chmod(stateRoot, 0o700) != nil {
		return nil, errors.New("Azure driver state is unavailable")
	}
	return &Driver{store: Store{Root: stateRoot}, cloud: cloud, bootstrap: bootstrap, resolver: resolver, registration: registration, locks: make(map[string]*executionLock)}, nil
}

func (driver *Driver) lock(executionID string) (func(), error) {
	driver.locksMu.Lock()
	value := driver.locks[executionID]
	if value == nil {
		if len(driver.locks) >= maxExecutions {
			driver.locksMu.Unlock()
			return nil, errors.New("Azure operation capacity is exhausted")
		}
		value = &executionLock{}
		driver.locks[executionID] = value
	}
	value.refs++
	driver.locksMu.Unlock()

	value.mutex.Lock()
	return func() {
		value.mutex.Unlock()
		driver.locksMu.Lock()
		value.refs--
		if value.refs == 0 {
			delete(driver.locks, executionID)
		}
		driver.locksMu.Unlock()
	}, nil
}

func (driver *Driver) Reconcile(ctx context.Context, desired executiondriver.DesiredExecution) (executiondriver.Status, error) {
	if executiondriver.ValidateReconcileParams(executiondriver.ReconcileParams{Desired: desired}) != nil || desired.WorkloadKind != executiondriver.WorkloadKindVM {
		return executiondriver.Status{}, reject("invalid-desired", "resolved Azure desired state is invalid")
	}
	configuration, err := config.Decode(desired.Configuration)
	if err != nil {
		return executiondriver.Status{}, reject("invalid-configuration", "Azure execution class configuration is invalid")
	}
	if configuration.SubscriptionID == "" || validateAttachmentAgainstConfig(configuration, desired.NativeEgressAttachment) != nil {
		return executiondriver.Status{}, reject("invalid-native-egress", "Azure native egress attachment is invalid")
	}
	unlock, err := driver.lock(desired.ExecutionID)
	if err != nil {
		return executiondriver.Status{}, retry("capacity-exhausted", "Azure operation capacity is unavailable")
	}
	defer unlock()
	state, err := driver.store.Load(desired.ExecutionID)
	if errors.Is(err, os.ErrNotExist) {
		destinations, resolveErr := resolveAttachment(ctx, driver.resolver, desired.NativeEgressAttachment)
		if resolveErr != nil {
			return executiondriver.Status{}, retry("network-resolution-pending", "Azure trusted endpoint resolution is unavailable")
		}
		state = newState(configuration, desired, 1, destinations)
		if err := driver.store.Create(desired.ExecutionID, state); err != nil {
			return executiondriver.Status{}, retry("state-unavailable", "Azure durable state is unavailable")
		}
		state, err = driver.store.Load(desired.ExecutionID)
		if err != nil {
			return executiondriver.Status{}, retry("state-unavailable", "Azure durable state is unavailable")
		}
	} else if err != nil {
		return executiondriver.Status{}, retry("state-invalid", "Azure durable state could not be validated")
	} else {
		if desired.Generation < state.Generation {
			return executiondriver.Status{}, reject("generation-regression", "Azure desired generation regressed")
		}
		if desired.Generation == state.Generation && desired.DesiredFingerprint != state.DesiredFingerprint {
			return executiondriver.Status{}, reject("desired-conflict", "Azure desired fingerprint conflicts with its generation")
		}
		if desired.Generation > state.Generation {
			if state.ExecutionScope != nil {
				return executiondriver.Status{}, reject("replacement-required", "Azure enrolled desired state is immutable")
			}
			if driver.cloud.Delete(ctx, state) != nil || driver.store.RemoveKey(state.ExecutionID) != nil || driver.store.Remove(state.ExecutionID) != nil {
				return deletingStatus(state), retry("replacement-pending", "Azure prior desired state cleanup is pending")
			}
			destinations, resolveErr := resolveAttachment(ctx, driver.resolver, desired.NativeEgressAttachment)
			if resolveErr != nil {
				return executiondriver.Status{}, retry("network-resolution-pending", "Azure trusted endpoint resolution is unavailable")
			}
			state = newState(configuration, desired, 1, destinations)
			if driver.store.Create(desired.ExecutionID, state) != nil {
				return executiondriver.Status{}, retry("state-unavailable", "Azure durable state is unavailable")
			}
			state, err = driver.store.Load(desired.ExecutionID)
			if err != nil {
				return executiondriver.Status{}, retry("state-unavailable", "Azure durable state is unavailable")
			}
		}
	}
	bootstrap := !state.BootstrapLocked
	if err := driver.cloud.Deploy(ctx, state, bootstrap); err != nil {
		if observation, observeErr := driver.cloud.Observe(ctx, state); observeErr != nil || !observation.Exact {
			return providerFailureStatus(state, observation, err), nil
		}
	}
	observation, err := driver.cloud.Observe(ctx, state)
	if err != nil {
		return providerFailureStatus(state, observation, err), nil
	}
	if !observation.Exact {
		return statusFor(state, observation), reject("resource-collision", "Azure resource ownership or configuration conflicts")
	}
	if observation.PrivateIP != state.PrivateIPAddress {
		state.PrivateIPAddress = observation.PrivateIP
		if driver.store.Save(state) != nil {
			return executiondriver.Status{}, retry("state-unavailable", "Azure durable state is unavailable")
		}
	}
	if state.BootstrapLocked && state.GuestEnrolled && !state.EnrollmentAccepted {
		if err := driver.finalizeEnrollment(ctx, &state, observation); err != nil {
			return statusFor(state, observation), nil
		}
		observation, _ = driver.cloud.Observe(ctx, state)
	}
	return statusFor(state, observation), nil
}

func (driver *Driver) Observe(ctx context.Context, executionID string) (executiondriver.Status, error) {
	if executiondriver.ValidateExecutionParams(executiondriver.ExecutionParams{ExecutionID: executionID}) != nil {
		return executiondriver.Status{}, reject("invalid-execution", "Azure execution identity is invalid")
	}
	unlock, lockErr := driver.lock(executionID)
	if lockErr != nil {
		return executiondriver.Status{}, retry("capacity-exhausted", "Azure operation capacity is unavailable")
	}
	defer unlock()
	state, err := driver.store.Load(executionID)
	if errors.Is(err, os.ErrNotExist) {
		return executiondriver.Status{Phase: executiondriver.PhaseUnknown}, nil
	}
	if err != nil {
		return executiondriver.Status{}, retry("state-invalid", "Azure durable state could not be validated")
	}
	observation, err := driver.cloud.Observe(ctx, state)
	if err != nil {
		return statusFor(state, observation), nil
	}
	return statusFor(state, observation), nil
}

func (driver *Driver) Delete(ctx context.Context, executionID string) (executiondriver.Status, error) {
	if executiondriver.ValidateExecutionParams(executiondriver.ExecutionParams{ExecutionID: executionID}) != nil {
		return executiondriver.Status{}, reject("invalid-execution", "Azure execution identity is invalid")
	}
	unlock, lockErr := driver.lock(executionID)
	if lockErr != nil {
		return executiondriver.Status{}, retry("capacity-exhausted", "Azure operation capacity is unavailable")
	}
	defer unlock()
	state, err := driver.store.Load(executionID)
	if errors.Is(err, os.ErrNotExist) {
		return executiondriver.Status{Phase: executiondriver.PhaseDeleted}, nil
	}
	if err != nil {
		return executiondriver.Status{}, retry("state-invalid", "Azure durable state could not be validated")
	}
	if err := driver.cloud.Delete(ctx, state); err != nil {
		return deletingStatus(state), nil
	}
	if err := driver.store.RemoveKey(executionID); err != nil || driver.store.Remove(executionID) != nil {
		return deletingStatus(state), nil
	}
	return executiondriver.Status{Phase: executiondriver.PhaseDeleted, ObservedGeneration: state.Generation}, nil
}

func (driver *Driver) Prepare(ctx context.Context, request guestenrollment.HandoffPrepareRequest) (guestenrollment.HandoffPrepareResult, error) {
	if guestenrollment.ValidateHandoffPrepareRequest(request) != nil || request.ExecutionScope.DriverRegistration != driver.registration {
		return guestenrollment.HandoffPrepareResult{}, errors.New("Azure enrollment handoff was rejected")
	}
	unlock, lockErr := driver.lock(request.ExecutionScope.ExecutionID)
	if lockErr != nil {
		return guestenrollment.HandoffPrepareResult{}, errors.New("Azure enrollment handoff is unavailable")
	}
	defer unlock()
	state, err := driver.store.Load(request.ExecutionScope.ExecutionID)
	if err != nil || state.Generation != request.DesiredGeneration {
		return guestenrollment.HandoffPrepareResult{}, errors.New("Azure enrollment handoff is unavailable")
	}
	observation, err := driver.cloud.Observe(ctx, state)
	if err != nil || !providerReadyForEnrollment(state, observation) {
		return guestenrollment.HandoffPrepareResult{}, errors.New("Azure enrollment handoff is unavailable")
	}
	if state.EnrollmentAccepted && state.ExecutionScope != nil && *state.ExecutionScope == request.ExecutionScope {
		return prepareResult(state, guestenrollment.HandoffStateAccepted, false), nil
	}
	fresh := false
	if state.ExecutionScope == nil {
		scope := request.ExecutionScope
		state.ExecutionScope = &scope
		fresh = true
	} else if *state.ExecutionScope != request.ExecutionScope {
		return guestenrollment.HandoffPrepareResult{}, errors.New("Azure enrollment handoff was rejected")
	}
	if !state.GuestConfigured {
		if driver.bootstrap.Configure(ctx, state) != nil {
			return guestenrollment.HandoffPrepareResult{}, errors.New("Azure enrollment handoff is unavailable")
		}
		state.GuestConfigured = true
		if driver.store.Save(state) != nil {
			return guestenrollment.HandoffPrepareResult{}, errors.New("Azure enrollment handoff is unavailable")
		}
	}
	guestState, statusErr := driver.bootstrap.Status(ctx, state)
	if statusErr == nil && (guestState == GuestEnrolled || guestState == GuestReady || guestState == GuestLocked) && !state.GuestEnrolled {
		state.GuestEnrolled = true
		if driver.store.Save(state) != nil {
			return guestenrollment.HandoffPrepareResult{}, errors.New("Azure enrollment handoff is unavailable")
		}
	}
	if state.GuestEnrolled {
		if state.DeliveryPending && statusErr != nil && !state.BootstrapLocked {
			// The guest may have accepted and locked the one-shot channel while
			// the response or subsequent state write was lost. Return the old
			// non-fresh prepared attempt so the orchestrator follows the frozen
			// revoke-and-replace path instead of guessing acceptance.
			return prepareResult(state, guestenrollment.HandoffStatePrepared, false), nil
		}
		if !state.BootstrapLocked {
			if driver.bootstrap.Lock(ctx, state) != nil {
				return guestenrollment.HandoffPrepareResult{}, errors.New("Azure enrollment handoff is unavailable")
			}
			state.BootstrapLocked = true
			if driver.store.Save(state) != nil {
				return guestenrollment.HandoffPrepareResult{}, errors.New("Azure enrollment handoff is unavailable")
			}
		}
		if driver.finalizeEnrollment(ctx, &state, CloudObservation{}) != nil {
			return guestenrollment.HandoffPrepareResult{}, errors.New("Azure enrollment handoff is unavailable")
		}
		return prepareResult(state, guestenrollment.HandoffStateAccepted, false), nil
	}
	return prepareResult(state, guestenrollment.HandoffStatePrepared, fresh), nil
}

func (driver *Driver) Deliver(ctx context.Context, request guestenrollment.HandoffDeliverRequest) error {
	if guestenrollment.ValidateHandoffDeliverRequest(request) != nil || request.Envelope.Binding.DriverRegistration != driver.registration {
		return errors.New("Azure enrollment delivery was rejected")
	}
	binding := request.Envelope.Binding
	unlock, lockErr := driver.lock(binding.ExecutionID)
	if lockErr != nil {
		return errors.New("Azure enrollment delivery is unavailable")
	}
	defer unlock()
	state, err := driver.store.Load(binding.ExecutionID)
	if err != nil || state.ExecutionScope == nil || *state.ExecutionScope != binding.ExecutionScope() || bindingFor(state) != binding {
		return errors.New("Azure enrollment delivery was rejected")
	}
	if state.EnrollmentAccepted {
		return nil
	}
	observation, err := driver.cloud.Observe(ctx, state)
	if err != nil || !providerReadyForEnrollment(state, observation) {
		return errors.New("Azure enrollment delivery is unavailable")
	}
	if !enrollmentEndpointAllowed(state, request.Envelope.ExchangeURL) {
		return errors.New("Azure enrollment delivery is unavailable")
	}
	if state.NativeEgressAttachment != nil {
		if guestenrollment.ValidateNativeEgressCAPEM(request.NativeEgressCAPEM) != nil {
			return errors.New("Azure enrollment delivery is unavailable")
		}
	} else if request.NativeEgressCAPEM != "" {
		return errors.New("Azure enrollment delivery was rejected")
	}
	if !state.GuestEnrolled {
		if !state.DeliveryPending {
			state.DeliveryPending = true
			if driver.store.Save(state) != nil {
				return errors.New("Azure enrollment delivery is unavailable")
			}
		}
		if driver.bootstrap.Deliver(ctx, state, request.Envelope, request.NativeEgressCAPEM) != nil {
			return errors.New("Azure enrollment delivery is unavailable")
		}
		state.GuestEnrolled = true
		if driver.store.Save(state) != nil {
			return errors.New("Azure enrollment delivery is unavailable")
		}
	}
	if !state.BootstrapLocked {
		if driver.bootstrap.Lock(ctx, state) != nil {
			return errors.New("Azure enrollment delivery is unavailable")
		}
		state.BootstrapLocked = true
		if driver.store.Save(state) != nil {
			return errors.New("Azure enrollment delivery is unavailable")
		}
	}
	if driver.finalizeEnrollment(ctx, &state, CloudObservation{}) != nil {
		return errors.New("Azure enrollment delivery is unavailable")
	}
	return nil
}

func (driver *Driver) Replace(ctx context.Context, request guestenrollment.HandoffReplaceRequest) (guestenrollment.HandoffPrepareResult, error) {
	if guestenrollment.ValidateHandoffReplaceRequest(request) != nil || request.Binding.DriverRegistration != driver.registration {
		return guestenrollment.HandoffPrepareResult{}, errors.New("Azure enrollment replacement was rejected")
	}
	unlock, lockErr := driver.lock(request.Binding.ExecutionID)
	if lockErr != nil {
		return guestenrollment.HandoffPrepareResult{}, errors.New("Azure enrollment replacement is unavailable")
	}
	defer unlock()
	state, err := driver.store.Load(request.Binding.ExecutionID)
	if err != nil || state.ExecutionScope == nil || bindingFor(state) != request.Binding {
		return guestenrollment.HandoffPrepareResult{}, errors.New("Azure enrollment replacement was rejected")
	}
	if driver.cloud.Delete(ctx, state) != nil || driver.store.RemoveKey(state.ExecutionID) != nil || driver.store.Remove(state.ExecutionID) != nil {
		return guestenrollment.HandoffPrepareResult{}, errors.New("Azure enrollment replacement is unavailable")
	}
	desired := executiondriver.DesiredExecution{ExecutionID: state.ExecutionID, Generation: state.Generation, DesiredFingerprint: state.DesiredFingerprint,
		WorkloadKind: executiondriver.WorkloadKindVM, ClassName: state.ClassName, Configuration: mustJSON(state.Configuration), NativeEgressAttachment: cloneAttachment(state.NativeEgressAttachment)}
	replacement := newState(state.Configuration, desired, state.Attempt+1, state.PinnedDestinations)
	scope := *state.ExecutionScope
	replacement.ExecutionScope = &scope
	if driver.store.Create(state.ExecutionID, replacement) != nil {
		return guestenrollment.HandoffPrepareResult{}, errors.New("Azure enrollment replacement is unavailable")
	}
	replacement, err = driver.store.Load(state.ExecutionID)
	if err != nil || driver.cloud.Deploy(ctx, replacement, true) != nil {
		return guestenrollment.HandoffPrepareResult{}, errors.New("Azure enrollment replacement is unavailable")
	}
	observation, err := driver.cloud.Observe(ctx, replacement)
	if err != nil || !providerReadyForEnrollment(replacement, observation) {
		return guestenrollment.HandoffPrepareResult{}, errors.New("Azure enrollment replacement is unavailable")
	}
	replacement.PrivateIPAddress = observation.PrivateIP
	if driver.bootstrap.Configure(ctx, replacement) != nil {
		return guestenrollment.HandoffPrepareResult{}, errors.New("Azure enrollment replacement is unavailable")
	}
	replacement.GuestConfigured = true
	if driver.store.Save(replacement) != nil {
		return guestenrollment.HandoffPrepareResult{}, errors.New("Azure enrollment replacement is unavailable")
	}
	return prepareResult(replacement, guestenrollment.HandoffStatePrepared, true), nil
}

func (driver *Driver) finalizeEnrollment(ctx context.Context, state *State, observation CloudObservation) error {
	if !state.GuestEnrolled || !state.BootstrapLocked {
		return errors.New("Azure enrollment finalization is unavailable")
	}
	if err := driver.cloud.Deploy(ctx, *state, false); err != nil {
		current, observeErr := driver.cloud.Observe(ctx, *state)
		if observeErr != nil || !current.SteadyFence {
			return err
		}
		observation = current
	}
	if !observation.Exact || !observation.SteadyFence || !observation.Running {
		var err error
		observation, err = driver.cloud.Observe(ctx, *state)
		if err != nil || !observation.Exact || !observation.SteadyFence || !observation.Running {
			return errors.New("Azure steady network fence is unavailable")
		}
	}
	if driver.store.RemoveKey(state.ExecutionID) != nil {
		return errors.New("Azure bootstrap key removal is pending")
	}
	state.EnrollmentAccepted = true
	state.DeliveryPending = false
	state.PrivateIPAddress = observation.PrivateIP
	return driver.store.Save(*state)
}

func providerReadyForEnrollment(state State, observation CloudObservation) bool {
	if !observation.Exists || !observation.Exact || !observation.Running || observation.PrivateIP == "" {
		return false
	}
	if state.NativeEgressAttachment == nil {
		return observation.BootstrapFence
	}
	return observation.BootstrapFence
}

func statusFor(state State, observation CloudObservation) executiondriver.Status {
	retryAfter := int32(5)
	status := executiondriver.Status{Phase: executiondriver.PhaseProvisioning, ObservedGeneration: state.Generation,
		ExternalResourceID: state.Resources.VM, RetryAfterSeconds: &retryAfter}
	if state.NativeEgressAttachment != nil {
		readyFence := observation.BootstrapFence
		if state.BootstrapLocked {
			readyFence = observation.SteadyFence
		}
		status.EgressConfinement = &executiondriver.EgressConfinementStatus{Boundary: executiondriver.EgressConfinementBoundaryInfrastructure,
			Ready: readyFence && observation.Exact, AttachmentGeneration: state.NativeEgressAttachment.Generation, AttachmentDigest: state.NativeEgressAttachment.Digest}
		if observation.Running && observation.Exact && readyFence {
			status.Phase, status.Ready, status.RetryAfterSeconds = executiondriver.PhaseRunning, true, nil
			status.Endpoint = &executiondriver.Endpoint{Scheme: executiondriver.EndpointSchemeHTTP, Host: observation.PrivateIP, Port: 4090}
		}
		return status
	}
	if observation.Running && observation.Exact && (state.EnrollmentAccepted || !state.GuestEnrolled) {
		if state.EnrollmentAccepted {
			status.Phase, status.Ready, status.RetryAfterSeconds = executiondriver.PhaseRunning, true, nil
			status.Endpoint = &executiondriver.Endpoint{Scheme: executiondriver.EndpointSchemeHTTP, Host: observation.PrivateIP, Port: 4090}
		}
	}
	return status
}

func deletingStatus(state State) executiondriver.Status {
	retryAfter := int32(5)
	return executiondriver.Status{Phase: executiondriver.PhaseDeleting, ObservedGeneration: state.Generation, RetryAfterSeconds: &retryAfter}
}

func prepareResult(state State, handoffState guestenrollment.HandoffState, fresh bool) guestenrollment.HandoffPrepareResult {
	return guestenrollment.HandoffPrepareResult{ContractVersion: guestenrollment.HandoffVersion, GuestInstanceID: state.GuestInstanceID, State: handoffState, NewlyPrepared: fresh}
}

func enrollmentEndpointAllowed(state State, exchangeURL string) bool {
	if state.NativeEgressAttachment == nil {
		return endpointMatches(exchangeURL, endpointHost(state.Configuration.EnrollmentEndpoint), endpointPortText(state.Configuration.EnrollmentEndpoint))
	}
	return endpointMatches(exchangeURL, endpointHost(state.Configuration.EnrollmentEndpoint), endpointPortText(state.Configuration.EnrollmentEndpoint)) &&
		endpointAllowedByAttachment(*state.NativeEgressAttachment, exchangeURL)
}

func endpointAllowedByAttachment(attachment executiondriver.NativeEgressAttachment, endpoint string) bool {
	for _, destination := range attachment.RequiredDestinations {
		if destination.Purpose == executiondriver.NativeEgressDestinationBootstrap && endpointMatches(endpoint, destination.Host, destination.Port) {
			return true
		}
	}
	return false
}

func endpointMatches(endpoint, host string, port uint16) bool {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() != host {
		return false
	}
	actual := 443
	if parsed.Port() != "" {
		actual, err = strconv.Atoi(parsed.Port())
		if err != nil {
			return false
		}
	}
	return actual == int(port)
}

func endpointHost(endpoint string) string {
	parsed, _ := url.Parse(endpoint)
	return parsed.Hostname()
}

func endpointPortText(endpoint string) uint16 {
	parsed, _ := url.Parse(endpoint)
	port := 443
	if parsed.Port() != "" {
		port, _ = strconv.Atoi(parsed.Port())
	}
	return uint16(port)
}

func providerFailureStatus(state State, observation CloudObservation, err error) executiondriver.Status {
	retryable := true
	var value *cloudError
	if errors.As(err, &value) {
		retryable = value.Retryable()
	}
	status := statusFor(state, observation)
	status.Phase = executiondriver.PhaseFailed
	status.Ready = false
	status.Endpoint = nil
	reason := "provider-unavailable"
	if !retryable {
		reason = "provider-rejected"
	}
	status.Failure = &executiondriver.Failure{Reason: reason, Message: "Azure control-plane convergence failed", Retryable: retryable}
	if !retryable {
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
func (driver *Driver) Shutdown(context.Context) error { return nil }
func (driver *Driver) String() string                 { return fmt.Sprintf("Azure driver %s", driver.registration) }

func mustJSON(value any) json.RawMessage { encoded, _ := json.Marshal(value); return encoded }

var _ guestenrollment.Handoff = (*Driver)(nil)
