package driver

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mirkoSekulic/nvt-agent/executiondrivers/qemu/internal/config"
	"github.com/mirkoSekulic/nvt-agent/executiondrivers/qemu/internal/wire"
	"github.com/mirkoSekulic/nvt-agent/operator/executiondriver"
	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment"
)

const (
	registration = "qemu-reference"
	secretCanary = "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE"
)

type fakeProvider struct {
	mu           sync.Mutex
	resources    map[string]MachineObservation
	creates      int
	deletes      int
	configs      int
	deliveries   int
	block        bool
	configureErr bool
	digest       string
}

type fakeMachines struct{ provider *fakeProvider }

func (machine *fakeMachines) GuestImageDigest() (string, error) { return machine.provider.digest, nil }
func (machine *fakeMachines) Ensure(ctx context.Context, state *State) error {
	if machine.provider.block {
		<-ctx.Done()
		return ctx.Err()
	}
	machine.provider.mu.Lock()
	defer machine.provider.mu.Unlock()
	if _, exists := machine.provider.resources[state.ExecutionID]; !exists {
		machine.provider.resources[state.ExecutionID] = MachineObservation{Running: true}
		machine.provider.creates++
	}
	return nil
}
func (machine *fakeMachines) Observe(_ context.Context, state *State) (MachineObservation, error) {
	machine.provider.mu.Lock()
	defer machine.provider.mu.Unlock()
	return machine.provider.resources[state.ExecutionID], nil
}
func (machine *fakeMachines) Configure(_ context.Context, _ *State, configuration wire.BootConfiguration) error {
	if guestenrollment.ValidateBinding(configuration.Binding) != nil || configuration.ContractVersion != wire.Version ||
		config.ValidateNativeSessionEndpoint(configuration.NativeSessionEndpoint) != nil || config.ValidateCAPEM(configuration.NativeSessionCAPEM) != nil {
		return errors.New("invalid boot configuration")
	}
	machine.provider.mu.Lock()
	if machine.provider.configureErr {
		machine.provider.mu.Unlock()
		return errors.New("injected unhealthy guest")
	}
	machine.provider.configs++
	machine.provider.mu.Unlock()
	return nil
}
func (machine *fakeMachines) Deliver(_ context.Context, state *State, envelope guestenrollment.BootstrapEnvelope) (MachineObservation, error) {
	if envelope.Token != secretCanary {
		return MachineObservation{}, errors.New("wrong token")
	}
	machine.provider.mu.Lock()
	defer machine.provider.mu.Unlock()
	machine.provider.deliveries++
	observation := machine.provider.resources[state.ExecutionID]
	observation.Running = true
	observation.Enrolled = true
	machine.provider.resources[state.ExecutionID] = observation
	return observation, nil
}
func (machine *fakeMachines) Replace(_ context.Context, state *State) error {
	machine.provider.mu.Lock()
	delete(machine.provider.resources, state.ExecutionID)
	machine.provider.mu.Unlock()
	return nil
}
func (machine *fakeMachines) Delete(_ context.Context, state *State) error {
	machine.provider.mu.Lock()
	delete(machine.provider.resources, state.ExecutionID)
	machine.provider.deletes++
	machine.provider.mu.Unlock()
	return nil
}
func (*fakeMachines) Shutdown(context.Context) error { return nil }

func TestExecutionDriverConformanceLifecycleAndRestart(t *testing.T) {
	root := t.TempDir()
	configuration := testConfiguration(t)
	provider := &fakeProvider{resources: map[string]MachineObservation{}, digest: configuration.GuestImage.Digest}
	first, err := New(root, registration, &fakeMachines{provider})
	if err != nil {
		t.Fatal(err)
	}
	desired := desiredExecution(t, configuration)
	status, err := first.Reconcile(context.Background(), desired)
	if err != nil || status.Phase != executiondriver.PhaseProvisioning || status.Ready {
		t.Fatalf("initial reconcile: %#v %v", status, err)
	}
	status, err = first.Reconcile(context.Background(), desired)
	if err != nil || provider.creates != 1 {
		t.Fatalf("idempotent reconcile recreated provider resource: %d %v", provider.creates, err)
	}
	observed, err := first.Observe(context.Background(), desired.ExecutionID)
	if err != nil || observed.Phase != executiondriver.PhaseProvisioning {
		t.Fatalf("observe did not report durable provisioning state: %#v %v", observed, err)
	}
	scope := guestenrollment.ExecutionScope{AgentRunUID: "11111111-1111-1111-1111-111111111111", ExecutionID: desired.ExecutionID, DriverRegistration: registration}
	prepared, err := first.Prepare(context.Background(), guestenrollment.HandoffPrepareRequest{ContractVersion: guestenrollment.HandoffVersion, ExecutionScope: scope, DesiredGeneration: desired.Generation})
	if err != nil || prepared.State != guestenrollment.HandoffStatePrepared || !prepared.NewlyPrepared {
		t.Fatalf("prepare: %#v %v", prepared, err)
	}
	binding := guestenrollment.Binding{AgentRunUID: scope.AgentRunUID, ExecutionID: scope.ExecutionID, DriverRegistration: scope.DriverRegistration, DesiredGeneration: desired.Generation, GuestInstanceID: prepared.GuestInstanceID}
	envelope := testEnvelope(binding)
	if err := first.Deliver(context.Background(), guestenrollment.HandoffDeliverRequest{ContractVersion: guestenrollment.HandoffVersion, Envelope: envelope}); err != nil {
		t.Fatal(err)
	}
	if provider.deliveries != 1 {
		t.Fatal("enrollment was not delivered exactly once")
	}
	if err := first.Deliver(context.Background(), guestenrollment.HandoffDeliverRequest{ContractVersion: guestenrollment.HandoffVersion, Envelope: envelope}); err != nil || provider.deliveries != 1 {
		t.Fatal("accepted delivery was not idempotent")
	}
	provider.mu.Lock()
	provider.resources[desired.ExecutionID] = MachineObservation{Running: true, Enrolled: true, Ready: true}
	provider.mu.Unlock()

	restarted, err := New(root, registration, &fakeMachines{provider})
	if err != nil {
		t.Fatal(err)
	}
	status, err = restarted.Reconcile(context.Background(), desired)
	if err != nil || !status.Ready || status.Phase != executiondriver.PhaseRunning || provider.creates != 1 {
		t.Fatalf("restart recovery: %#v creates=%d err=%v", status, provider.creates, err)
	}
	if status.Endpoint == nil || status.Endpoint.Host != "127.0.0.1" || status.ExternalResourceID == "" {
		t.Fatalf("portable ready status is incomplete: %#v", status)
	}
	observed, err = restarted.Observe(context.Background(), desired.ExecutionID)
	if err != nil || !observed.Ready || observed.Phase != executiondriver.PhaseRunning {
		t.Fatalf("observe lost recovered readiness: %#v %v", observed, err)
	}
	assertTreeExcludes(t, root, []byte(secretCanary))
	deleted, err := restarted.Delete(context.Background(), desired.ExecutionID)
	if err != nil || deleted.Phase != executiondriver.PhaseDeleted || provider.deletes != 1 {
		t.Fatalf("delete: %#v deletes=%d err=%v", deleted, provider.deletes, err)
	}
	if _, err := os.Stat((Store{Root: root}).RunDir(desired.ExecutionID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("driver-owned execution resources remain after deletion")
	}
	deleted, err = restarted.Delete(context.Background(), desired.ExecutionID)
	if err != nil || deleted.Phase != executiondriver.PhaseDeleted {
		t.Fatal("repeated deletion is not idempotent")
	}
}

func TestNativeEgressConfinementGatesEnrollmentAndGuestReadiness(t *testing.T) {
	root := t.TempDir()
	configuration := testConfiguration(t)
	configuration.NativeEgressProbe = &config.NativeEgressProbe{Host: "echo.example", Port: 443, Capability: "github-main"}
	provider := &fakeProvider{resources: map[string]MachineObservation{}, digest: configuration.GuestImage.Digest}
	implementation, err := New(root, registration, &fakeMachines{provider})
	if err != nil {
		t.Fatal(err)
	}
	desired := desiredExecution(t, configuration)
	attachment := testNativeEgressAttachment(t)
	desired.NativeEgressAttachment = &attachment
	status, err := implementation.Reconcile(context.Background(), desired)
	if err != nil || status.Ready || status.EgressConfinement != nil {
		t.Fatalf("unconfined reconcile = %#v, %v", status, err)
	}
	scope := guestenrollment.ExecutionScope{AgentRunUID: "abababab-abab-abab-abab-abababababab", ExecutionID: desired.ExecutionID, DriverRegistration: registration}
	prepare := guestenrollment.HandoffPrepareRequest{ContractVersion: guestenrollment.HandoffVersion, ExecutionScope: scope, DesiredGeneration: desired.Generation}
	if _, err := implementation.Prepare(context.Background(), prepare); err == nil || provider.configs != 0 || provider.deliveries != 0 {
		t.Fatal("missing provider confinement reached enrollment handoff")
	}
	state, err := implementation.store.Load(desired.ExecutionID)
	if err != nil || state.ExecutionScope != nil {
		t.Fatal("failed confinement created a durable enrollment binding")
	}

	provider.mu.Lock()
	provider.resources[desired.ExecutionID] = MachineObservation{Running: true, EgressConfinement: &executiondriver.EgressConfinementStatus{
		Boundary: "guest", Ready: true, AttachmentGeneration: attachment.Generation, AttachmentDigest: attachment.Digest,
	}}
	provider.mu.Unlock()
	if _, err := implementation.Prepare(context.Background(), prepare); err == nil || provider.configs != 0 {
		t.Fatal("guest-asserted confinement reached enrollment handoff")
	}

	provider.mu.Lock()
	provider.resources[desired.ExecutionID] = MachineObservation{Running: true, EgressConfinement: &executiondriver.EgressConfinementStatus{
		Boundary: executiondriver.EgressConfinementBoundaryInfrastructure, Ready: true,
		AttachmentGeneration: attachment.Generation - 1, AttachmentDigest: attachment.Digest,
	}}
	provider.mu.Unlock()
	if _, err := implementation.Prepare(context.Background(), prepare); err == nil || provider.configs != 0 {
		t.Fatal("stale provider confinement reached enrollment handoff")
	}

	provider.mu.Lock()
	provider.resources[desired.ExecutionID] = MachineObservation{Running: true, EgressConfinement: exactConfinement(attachment)}
	provider.mu.Unlock()
	status, err = implementation.Reconcile(context.Background(), desired)
	if err != nil || !status.Ready || status.Phase != executiondriver.PhaseRunning || status.EgressConfinement == nil || !status.EgressConfinement.Ready {
		t.Fatalf("exact pre-enrollment confinement = %#v, %v", status, err)
	}
	prepared, err := implementation.Prepare(context.Background(), prepare)
	if err != nil || !prepared.NewlyPrepared || provider.configs != 1 {
		t.Fatalf("exact confined preparation = %#v, configs=%d, %v", prepared, provider.configs, err)
	}
	binding := guestenrollment.Binding{
		AgentRunUID: scope.AgentRunUID, ExecutionID: scope.ExecutionID, DriverRegistration: scope.DriverRegistration,
		DesiredGeneration: desired.Generation, GuestInstanceID: prepared.GuestInstanceID,
	}
	wrongEndpoint := testEnvelope(binding)
	wrongEndpoint.ExchangeURL = "https://unlisted.example/v1/guest-enrollment/exchange"
	if err := implementation.Deliver(context.Background(), guestenrollment.HandoffDeliverRequest{ContractVersion: guestenrollment.HandoffVersion, Envelope: wrongEndpoint}); err == nil || provider.deliveries != 0 {
		t.Fatal("unlisted enrollment endpoint reached the confined guest")
	}
	if err := implementation.Deliver(context.Background(), guestenrollment.HandoffDeliverRequest{ContractVersion: guestenrollment.HandoffVersion, Envelope: testEnvelope(binding)}); err != nil || provider.deliveries != 1 {
		t.Fatalf("confined enrollment delivery = deliveries=%d, %v", provider.deliveries, err)
	}
	status, err = implementation.Reconcile(context.Background(), desired)
	if err != nil || !status.Ready || status.Phase != executiondriver.PhaseRunning {
		t.Fatalf("accepted guest lost its infrastructure-ready provider boundary: %#v, %v", status, err)
	}
	provider.mu.Lock()
	provider.configureErr = true
	provider.mu.Unlock()
	recovered, err := implementation.Prepare(context.Background(), prepare)
	if err != nil || recovered.State != guestenrollment.HandoffStateAccepted || recovered.NewlyPrepared {
		t.Fatalf("accepted mediated handoff depended on unpublished guest data plane: %#v, %v", recovered, err)
	}
	status, err = implementation.Reconcile(context.Background(), desired)
	if err != nil || !status.Ready || status.Phase != executiondriver.PhaseRunning || status.EgressConfinement == nil || !status.EgressConfinement.Ready {
		t.Fatalf("guest control failure erased live infrastructure confinement: %#v, %v", status, err)
	}
	provider.mu.Lock()
	provider.configureErr = false
	provider.mu.Unlock()
	provider.mu.Lock()
	observation := provider.resources[desired.ExecutionID]
	observation.Ready = true
	provider.resources[desired.ExecutionID] = observation
	provider.mu.Unlock()
	status, err = implementation.Reconcile(context.Background(), desired)
	if err != nil || !status.Ready || status.Endpoint == nil {
		t.Fatalf("live confined guest did not become ready: %#v, %v", status, err)
	}
	assertTreeExcludes(t, root, []byte(secretCanary))
}

func TestNativeEgressNetworkReadbackIsExactAndLegacyArgumentIsUnchanged(t *testing.T) {
	legacy, err := qemuNetworkArgument(State{HostPort: 23456})
	if err != nil || legacy != "user,id=nvtnet,hostfwd=tcp:127.0.0.1:23456-:8080" {
		t.Fatalf("legacy network argument changed: %q, %v", legacy, err)
	}
	attachment := testNativeEgressAttachment(t)
	state := State{HostPort: 23456, NativeEgressAttachment: &attachment}
	argument, err := qemuNetworkArgument(state)
	if err != nil || !strings.Contains(argument, ",restrict=on,") || strings.Contains(argument, attachment.Relay.CAPEM) || strings.Contains(argument, attachment.Digest) {
		t.Fatalf("mediated network argument is unsafe: %q, %v", argument, err)
	}
	for _, required := range []string{
		"hostfwd=tcp:127.0.0.1:23456-:8080",
		"guestfwd=tcp:10.0.2.100:443-cmd:/bin/busybox nc broker.example 443",
		"guestfwd=tcp:10.0.2.101:7443-cmd:/bin/busybox nc gateway.example 7443",
		"guestfwd=tcp:10.0.2.102:443-cmd:/bin/busybox nc registry.example 443",
		"guestfwd=tcp:10.0.2.103:7444-cmd:/bin/busybox nc relay.example 7444",
	} {
		if !strings.Contains(argument, required) {
			t.Fatalf("mediated network omitted %q: %q", required, argument)
		}
	}
	machine := &activeMachine{netdevArgument: argument, attachmentGeneration: attachment.Generation, attachmentDigest: attachment.Digest}
	exact := qemuConfinementStatus(state, machine, []string{"qemu-system-x86_64", "-netdev", argument})
	if exact == nil || !exact.Ready || exact.Boundary != executiondriver.EgressConfinementBoundaryInfrastructure {
		t.Fatalf("exact host readback was not ready: %#v", exact)
	}
	for name, arguments := range map[string][]string{
		"guest claim": nil,
		"relaxed":     {"qemu-system-x86_64", "-netdev", strings.Replace(argument, ",restrict=on,", ",", 1)},
		"duplicate":   {"qemu-system-x86_64", "-netdev", argument, "-netdev", argument},
		"stale":       {"qemu-system-x86_64", "-netdev", argument + ",guestfwd=tcp:10.0.2.200:443-cmd:/bin/busybox nc 192.0.2.10 443"},
	} {
		t.Run(name, func(t *testing.T) {
			status := qemuConfinementStatus(state, machine, arguments)
			if status == nil || status.Ready {
				t.Fatalf("non-exact host readback was accepted: %#v", status)
			}
		})
	}
	staleGeneration := *machine
	staleGeneration.attachmentGeneration--
	if status := qemuConfinementStatus(state, &staleGeneration, []string{"qemu-system-x86_64", "-netdev", argument}); status == nil || status.Ready {
		t.Fatalf("stale attachment generation was accepted: %#v", status)
	}
	staleDigest := *machine
	staleDigest.attachmentDigest = "sha256:" + strings.Repeat("0", 64)
	if status := qemuConfinementStatus(state, &staleDigest, []string{"qemu-system-x86_64", "-netdev", argument}); status == nil || status.Ready {
		t.Fatalf("stale attachment digest was accepted: %#v", status)
	}
	resolved, err := qemuNetworkArgumentWithResolver(context.Background(), state, func(_ context.Context, host string) (string, error) {
		addresses := map[string]string{
			"broker.example": "192.0.2.10", "gateway.example": "192.0.2.11",
			"registry.example": "192.0.2.12", "relay.example": "192.0.2.13",
		}
		return addresses[host], nil
	})
	if err != nil || strings.Contains(resolved, "-cmd:/bin/busybox nc relay.example ") ||
		!strings.Contains(resolved, "guestfwd=tcp:10.0.2.103:7444-cmd:/bin/busybox nc 192.0.2.13 7444") {
		t.Fatalf("provider did not resolve the exact forward targets: %q, %v", resolved, err)
	}
}

func TestNativeEgressAttachmentFailsBeforeProviderMutation(t *testing.T) {
	configuration := testConfiguration(t)
	provider := &fakeProvider{resources: map[string]MachineObservation{}, digest: configuration.GuestImage.Digest}
	implementation, err := New(t.TempDir(), registration, &fakeMachines{provider})
	if err != nil {
		t.Fatal(err)
	}
	desired := desiredExecution(t, configuration)
	attachment := testNativeEgressAttachment(t)
	attachment.Digest = "sha256:" + strings.Repeat("0", 64)
	desired.NativeEgressAttachment = &attachment
	if _, err := implementation.Reconcile(context.Background(), desired); err == nil || provider.creates != 0 {
		t.Fatal("malformed attachment reached provider mutation")
	}
	configuration.NativeEgressProbe = &config.NativeEgressProbe{Host: "relay.example", Port: 443, Capability: "provider-main"}
	desired = desiredExecution(t, configuration)
	attachment = testNativeEgressAttachment(t)
	desired.NativeEgressAttachment = &attachment
	if _, err := implementation.Reconcile(context.Background(), desired); err == nil || provider.creates != 0 {
		t.Fatal("probe overlapping trusted infrastructure reached provider mutation")
	}
}

func TestOptionalNativeEgressStateAndBootMembersRemainAbsentForLegacyRuns(t *testing.T) {
	configuration := testConfiguration(t)
	state := State{
		Version: stateVersion, ExecutionID: "legacy-execution", Generation: 3,
		DesiredFingerprint: "sha256:" + strings.Repeat("c", 64), ClassName: "qemu-small", Configuration: configuration,
		Attempt: 1, GuestInstanceID: guestInstanceID("legacy-execution", 3, 1), HostPort: 23456,
		ExecutionScope: &guestenrollment.ExecutionScope{
			AgentRunUID: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", ExecutionID: "legacy-execution", DriverRegistration: registration,
		},
	}
	encodedState, err := json.Marshal(state)
	if err != nil || bytes.Contains(encodedState, []byte("native_egress")) {
		t.Fatalf("legacy durable state changed: %s, %v", encodedState, err)
	}
	encodedBoot, err := wire.Encode(wire.Request{ContractVersion: wire.Version, Type: wire.RequestConfigure, Configuration: ptrBoot(bootConfiguration(state))})
	if err != nil || bytes.Contains(encodedBoot, []byte("native_egress")) {
		t.Fatalf("legacy guest control wire changed: %s, %v", encodedBoot, err)
	}
}

func ptrBoot(value wire.BootConfiguration) *wire.BootConfiguration { return &value }

func TestPreparedUnacceptedGuestRemainsReplaceableAfterBecomingUnhealthy(t *testing.T) {
	root := t.TempDir()
	configuration := testConfiguration(t)
	provider := &fakeProvider{resources: map[string]MachineObservation{}, digest: configuration.GuestImage.Digest}
	implementation, err := New(root, registration, &fakeMachines{provider})
	if err != nil {
		t.Fatal(err)
	}
	desired := desiredExecution(t, configuration)
	if _, err := implementation.Reconcile(context.Background(), desired); err != nil {
		t.Fatal(err)
	}
	scope := guestenrollment.ExecutionScope{
		AgentRunUID: "99999999-9999-9999-9999-999999999999", ExecutionID: desired.ExecutionID, DriverRegistration: registration,
	}
	prepared, err := implementation.Prepare(context.Background(), guestenrollment.HandoffPrepareRequest{
		ContractVersion: guestenrollment.HandoffVersion, ExecutionScope: scope, DesiredGeneration: desired.Generation,
	})
	if err != nil || prepared.State != guestenrollment.HandoffStatePrepared || !prepared.NewlyPrepared {
		t.Fatalf("initial prepared attempt = %#v %v", prepared, err)
	}
	provider.configureErr = true
	if _, err := implementation.Prepare(context.Background(), guestenrollment.HandoffPrepareRequest{
		ContractVersion: guestenrollment.HandoffVersion, ExecutionScope: scope, DesiredGeneration: desired.Generation,
	}); err == nil {
		t.Fatal("unhealthy guest was advertised as ready for a new enrollment envelope")
	}
	provider.configureErr = false
	binding := guestenrollment.Binding{
		AgentRunUID: scope.AgentRunUID, ExecutionID: scope.ExecutionID, DriverRegistration: scope.DriverRegistration,
		DesiredGeneration: desired.Generation, GuestInstanceID: prepared.GuestInstanceID,
	}
	replacement, err := implementation.Replace(context.Background(), guestenrollment.HandoffReplaceRequest{ContractVersion: guestenrollment.HandoffVersion, Binding: binding})
	if err != nil || !replacement.NewlyPrepared || replacement.GuestInstanceID == prepared.GuestInstanceID {
		t.Fatalf("unhealthy prepared attempt did not converge through replacement: %#v %v", replacement, err)
	}
}

func TestPrepareDoesNotPersistObligationBeforeGuestCanAcceptEnvelope(t *testing.T) {
	root := t.TempDir()
	configuration := testConfiguration(t)
	provider := &fakeProvider{resources: map[string]MachineObservation{}, digest: configuration.GuestImage.Digest, configureErr: true}
	implementation, err := New(root, registration, &fakeMachines{provider})
	if err != nil {
		t.Fatal(err)
	}
	desired := desiredExecution(t, configuration)
	if _, err := implementation.Reconcile(context.Background(), desired); err != nil {
		t.Fatal(err)
	}
	scope := guestenrollment.ExecutionScope{
		AgentRunUID: "88888888-8888-8888-8888-888888888888", ExecutionID: desired.ExecutionID, DriverRegistration: registration,
	}
	request := guestenrollment.HandoffPrepareRequest{
		ContractVersion: guestenrollment.HandoffVersion, ExecutionScope: scope, DesiredGeneration: desired.Generation,
	}
	if _, err := implementation.Prepare(context.Background(), request); err == nil {
		t.Fatal("unavailable guest was advertised as prepared")
	}
	state, err := implementation.store.Load(desired.ExecutionID)
	if err != nil {
		t.Fatal(err)
	}
	if state.ExecutionScope != nil {
		t.Fatal("unavailable guest created a durable enrollment obligation")
	}
	provider.configureErr = false
	prepared, err := implementation.Prepare(context.Background(), request)
	if err != nil || !prepared.NewlyPrepared || prepared.GuestInstanceID != state.GuestInstanceID {
		t.Fatalf("converged fresh preparation = %#v, %v", prepared, err)
	}
}

func TestDriverRejectsConflictMalformedHandoffAndCancels(t *testing.T) {
	configuration := testConfiguration(t)
	provider := &fakeProvider{resources: map[string]MachineObservation{}, digest: configuration.GuestImage.Digest}
	implementation, err := New(t.TempDir(), registration, &fakeMachines{provider})
	if err != nil {
		t.Fatal(err)
	}
	desired := desiredExecution(t, configuration)
	if _, err := implementation.Reconcile(context.Background(), desired); err != nil {
		t.Fatal(err)
	}
	conflict := desired
	conflict.DesiredFingerprint = "sha256:" + strings.Repeat("f", 64)
	if _, err := implementation.Reconcile(context.Background(), conflict); err == nil || strings.Contains(err.Error(), secretCanary) {
		t.Fatal("same-generation divergent desired state was not safely rejected")
	}
	lower := desired
	lower.Generation = desired.Generation - 1
	if _, err := implementation.Reconcile(context.Background(), lower); err == nil {
		t.Fatal("lower desired generation was accepted")
	}
	if err := implementation.Deliver(context.Background(), guestenrollment.HandoffDeliverRequest{}); err == nil {
		t.Fatal("malformed enrollment delivery was accepted")
	}
	scope := guestenrollment.ExecutionScope{AgentRunUID: "22222222-2222-2222-2222-222222222222", ExecutionID: desired.ExecutionID, DriverRegistration: registration}
	prepared, err := implementation.Prepare(context.Background(), guestenrollment.HandoffPrepareRequest{ContractVersion: guestenrollment.HandoffVersion, ExecutionScope: scope, DesiredGeneration: desired.Generation})
	if err != nil {
		t.Fatal(err)
	}
	wrongBinding := guestenrollment.Binding{AgentRunUID: scope.AgentRunUID, ExecutionID: scope.ExecutionID, DriverRegistration: registration, DesiredGeneration: desired.Generation, GuestInstanceID: "wrong-guest"}
	if err := implementation.Deliver(context.Background(), guestenrollment.HandoffDeliverRequest{ContractVersion: guestenrollment.HandoffVersion, Envelope: testEnvelope(wrongBinding)}); err == nil || strings.Contains(err.Error(), secretCanary) {
		t.Fatal("wrong-bootstrap-instance delivery was not safely rejected")
	}
	exact := guestenrollment.Binding{AgentRunUID: scope.AgentRunUID, ExecutionID: scope.ExecutionID, DriverRegistration: registration, DesiredGeneration: desired.Generation, GuestInstanceID: prepared.GuestInstanceID}
	replacement, err := implementation.Replace(context.Background(), guestenrollment.HandoffReplaceRequest{ContractVersion: guestenrollment.HandoffVersion, Binding: exact})
	if err != nil || replacement.GuestInstanceID == prepared.GuestInstanceID || !replacement.NewlyPrepared {
		t.Fatalf("replacement did not create an exact new bootstrap instance: %#v %v", replacement, err)
	}
	provider.block = true
	contextValue, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = implementation.Reconcile(contextValue, desired)
	if err == nil || time.Since(start) > time.Second || strings.Contains(err.Error(), secretCanary) {
		t.Fatalf("cancelled operation did not fail promptly and safely: %v", err)
	}
}

func TestStableResourceIdentity(t *testing.T) {
	if guestInstanceID("execution-a", 4, 2) != guestInstanceID("execution-a", 4, 2) || guestInstanceID("execution-a", 4, 2) == guestInstanceID("execution-a", 4, 3) {
		t.Fatal("guest resource identity is not stable and attempt-scoped")
	}
	if stableHostPort("execution-a") != stableHostPort("execution-a") || stableHostPort("execution-a") < 20000 || stableHostPort("execution-a") > 49999 {
		t.Fatal("host port selection is not stable and bounded")
	}
	if cpuModelForAcceleration("kvm") != "host" || cpuModelForAcceleration("tcg") != "max" {
		t.Fatal("QEMU acceleration did not select its compatible CPU model")
	}
}

func TestCollidingStablePortsReceiveDistinctDurableReservations(t *testing.T) {
	if stableHostPort("execution-51") != stableHostPort("execution-253") {
		t.Fatal("test fixture no longer exercises the known hash collision")
	}
	root := t.TempDir()
	configuration := testConfiguration(t)
	provider := &fakeProvider{resources: map[string]MachineObservation{}, digest: configuration.GuestImage.Digest}
	implementation, err := New(root, registration, &fakeMachines{provider})
	if err != nil {
		t.Fatal(err)
	}
	first := desiredExecution(t, configuration)
	first.ExecutionID = "execution-51"
	second := desiredExecution(t, configuration)
	second.ExecutionID = "execution-253"
	if _, err := implementation.Reconcile(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	if _, err := implementation.Reconcile(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	firstState, err := (Store{Root: root}).Load(first.ExecutionID)
	if err != nil {
		t.Fatal(err)
	}
	secondState, err := (Store{Root: root}).Load(second.ExecutionID)
	if err != nil {
		t.Fatal(err)
	}
	if firstState.HostPort == secondState.HostPort {
		t.Fatalf("colliding executions shared local health port %d", firstState.HostPort)
	}
}

func TestProductionStateRootUsesShortScratchSocket(t *testing.T) {
	manager := testQEMUManager(t, "/var/lib/nvt-execution-driver", "/tmp")
	path := manager.controlSocketPath("nvt-agentrun-" + strings.Repeat("a", 64))
	if len(path) > 107 || strings.HasPrefix(path, "/var/lib/nvt-execution-driver") {
		t.Fatalf("control socket path is not short scratch state: %q (%d bytes)", path, len(path))
	}
}

func TestRecoveredGuestControlExchangeUnwindsBeforeOuterHostDeadline(t *testing.T) {
	for _, test := range []struct {
		name     string
		accepted bool
		request  wire.Request
	}{
		{name: "status", request: wire.Request{ContractVersion: wire.Version, Type: wire.RequestStatus}},
		{name: "accepted configure", accepted: true, request: wire.Request{ContractVersion: wire.Version, Type: wire.RequestConfigure}},
	} {
		t.Run(test.name, func(t *testing.T) {
			manager := testQEMUManager(t, t.TempDir(), "/tmp")
			manager.recoveryControlTimeout = 40 * time.Millisecond
			state := State{
				ExecutionID:        "bounded-recovered-" + strings.ReplaceAll(test.name, " ", "-"),
				EnrollmentAccepted: test.accepted,
				Configuration:      config.Configuration{BootTimeoutSec: 30},
			}
			listener, err := net.Listen("unix", manager.controlSocketPath(state.ExecutionID))
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			release := make(chan struct{})
			defer close(release)
			go func() {
				connection, acceptErr := listener.Accept()
				if acceptErr != nil {
					return
				}
				defer connection.Close()
				<-release
			}()

			started := time.Now()
			if _, err := manager.call(context.Background(), &state, test.request); err == nil {
				t.Fatal("unresponsive recovered guest control exchange succeeded")
			}
			if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
				t.Fatalf("recovered guest control retained its owner for %s", elapsed)
			}
		})
	}
}

func TestAcceptedGuestNeverRecreatesMissingDisk(t *testing.T) {
	root := t.TempDir()
	manager := testQEMUManager(t, root, "/tmp")
	state := State{ExecutionID: "accepted-execution", EnrollmentAccepted: true}
	if err := manager.Ensure(context.Background(), &state); err == nil {
		t.Fatal("accepted durable state recreated a missing guest disk")
	}
	if _, err := os.Stat(filepath.Join((Store{Root: root}).RunDir(state.ExecutionID), "guest.qcow2")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("accepted missing disk was changed: %v", err)
	}
}

func TestDeleteRetainsResourcesUntilProcessIsConfirmedReaped(t *testing.T) {
	root := t.TempDir()
	manager := testQEMUManager(t, root, "/tmp")
	manager.terminateGrace = time.Millisecond
	manager.killGrace = time.Millisecond
	state := State{ExecutionID: "stuck-execution"}
	directory := (Store{Root: root}).RunDir(state.ExecutionID)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	resource := filepath.Join(directory, "guest.qcow2")
	if err := os.WriteFile(resource, []byte("durable"), 0o600); err != nil {
		t.Fatal(err)
	}
	manager.active[state.ExecutionID] = &activeMachine{command: &exec.Cmd{}, done: make(chan struct{})}
	if err := manager.Delete(context.Background(), &state); err == nil {
		t.Fatal("delete reported success without confirmed process reaping")
	}
	if _, err := os.Stat(resource); err != nil {
		t.Fatalf("delete removed resources before reaping: %v", err)
	}
}

func testQEMUManager(t *testing.T, stateRoot, scratchRoot string) *QEMUManager {
	t.Helper()
	directory := t.TempDir()
	paths := make([]string, 4)
	for index, name := range []string{"qemu", "kernel", "initramfs", "disk"} {
		paths[index] = filepath.Join(directory, name)
		if err := os.WriteFile(paths[index], []byte(name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	manager, err := NewQEMUManager(QEMUConfig{
		Binary: paths[0], Kernel: paths[1], Initramfs: paths[2], DiskTemplate: paths[3], StateRoot: stateRoot, ScratchRoot: scratchRoot,
	})
	if err != nil {
		t.Fatal(err)
	}
	return manager
}

func desiredExecution(t *testing.T, configuration config.Configuration) executiondriver.DesiredExecution {
	t.Helper()
	encoded, err := json.Marshal(configuration)
	if err != nil {
		t.Fatal(err)
	}
	return executiondriver.DesiredExecution{
		ExecutionID: "nvt-agentrun-" + strings.Repeat("a", 64), Generation: 3,
		DesiredFingerprint: "sha256:" + strings.Repeat("c", 64), WorkloadKind: executiondriver.WorkloadKindVM,
		ClassName: "qemu-small", Configuration: encoded,
	}
}

func testConfiguration(t *testing.T) config.Configuration {
	t.Helper()
	return config.Configuration{
		ContractVersion: config.Version,
		GuestImage:      config.GuestImage{Digest: "sha256:" + strings.Repeat("a", 64)},
		HostBundle:      config.Artifact{Repository: "https://registry.example/nvt/host-bundle", Digest: "sha256:" + strings.Repeat("b", 64)},
		EnrollmentCAPEM: testCertificate(t), NativeSessionEndpoint: "tls://gateway.example:7443", NativeSessionCAPEM: testCertificate(t),
		CPUs: 1, MemoryMiB: 512, Acceleration: "tcg", BootTimeoutSec: 30,
	}
}

func testEnvelope(binding guestenrollment.Binding) guestenrollment.BootstrapEnvelope {
	now := time.Now().UTC().Truncate(time.Second)
	return guestenrollment.BootstrapEnvelope{
		ContractVersion: guestenrollment.Version, Binding: binding,
		ExchangeURL: "https://broker.example/v1/guest-enrollment/exchange", Token: secretCanary,
		IssuedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(time.Minute).Format(time.RFC3339),
	}
}

func testNativeEgressAttachment(t *testing.T) executiondriver.NativeEgressAttachment {
	t.Helper()
	value, err := executiondriver.SealNativeEgressAttachment(executiondriver.NativeEgressAttachment{
		ContractVersion: executiondriver.NativeEgressAttachmentVersion,
		Generation:      7,
		Relay: executiondriver.NativeEgressRelayAttachment{
			Host: "relay.example", Port: 7444, ServerName: "relay.example", CAPEM: testCertificate(t),
		},
		RequiredDestinations: []executiondriver.NativeEgressRequiredDestination{
			{Purpose: executiondriver.NativeEgressDestinationBootstrap, Host: "broker.example", Port: 443},
			{Purpose: executiondriver.NativeEgressDestinationBootstrap, Host: "registry.example", Port: 443},
			{Purpose: executiondriver.NativeEgressDestinationControl, Host: "gateway.example", Port: 7443},
		},
		Redirect: executiondriver.NativeEgressRedirectIntent{
			Mode: executiondriver.NativeEgressRedirectModeCaptureTCP, LoopbackAddress: "127.0.0.1",
			TransparentTCPPort: 15001, ExplicitCONNECTPort: 15002,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func exactConfinement(attachment executiondriver.NativeEgressAttachment) *executiondriver.EgressConfinementStatus {
	return &executiondriver.EgressConfinementStatus{
		Boundary: executiondriver.EgressConfinementBoundaryInfrastructure, Ready: true,
		AttachmentGeneration: attachment.Generation, AttachmentDigest: attachment.Digest,
	}
}

func testCertificate(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-ca"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func assertTreeExcludes(t *testing.T, root string, canary []byte) {
	t.Helper()
	if err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() || !entry.Type().IsRegular() {
			return err
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(content, canary) {
			t.Fatalf("sensitive enrollment material persisted in %s", path)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
