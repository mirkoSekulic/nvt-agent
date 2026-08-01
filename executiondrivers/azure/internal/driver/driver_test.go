package driver

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mirkoSekulic/nvt-agent/executiondrivers/azure/internal/config"
	"github.com/mirkoSekulic/nvt-agent/operator/executiondriver"
	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment"
	"golang.org/x/crypto/ssh"
)

type fakeCloud struct {
	mu          sync.Mutex
	observation CloudObservation
	deployments []bool
	apply       bool
	deployError error
	startError  error
	starts      int
	deleteError error
	deleted     bool
}

func (cloud *fakeCloud) Deploy(_ context.Context, _ State, bootstrap bool) error {
	cloud.mu.Lock()
	defer cloud.mu.Unlock()
	cloud.deployments = append(cloud.deployments, bootstrap)
	if cloud.apply {
		cloud.observation = CloudObservation{Exists: true, Exact: true, Running: true, PrivateIP: "10.42.0.7", BootstrapFence: bootstrap, SteadyFence: !bootstrap}
	}
	err := cloud.deployError
	cloud.deployError = nil
	return err
}
func (cloud *fakeCloud) Observe(context.Context, State) (CloudObservation, error) {
	cloud.mu.Lock()
	defer cloud.mu.Unlock()
	return cloud.observation, nil
}
func (cloud *fakeCloud) Start(context.Context, State) error {
	cloud.mu.Lock()
	defer cloud.mu.Unlock()
	cloud.starts++
	if cloud.startError != nil {
		err := cloud.startError
		cloud.startError = nil
		return err
	}
	cloud.observation.Running = true
	return nil
}
func (cloud *fakeCloud) Delete(context.Context, State) error {
	cloud.mu.Lock()
	defer cloud.mu.Unlock()
	if cloud.deleteError != nil {
		err := cloud.deleteError
		cloud.deleteError = nil
		return err
	}
	cloud.deleted = true
	cloud.observation = CloudObservation{}
	return nil
}

type fakeBootstrap struct {
	mu           sync.Mutex
	configured   int
	delivered    int
	locked       int
	state        GuestState
	lostResponse bool
	binding      guestenrollment.Binding
}

func (value *fakeBootstrap) Configure(_ context.Context, state State) error {
	value.mu.Lock()
	defer value.mu.Unlock()
	value.configured++
	value.binding = bindingFor(state)
	if value.state == "" {
		value.state = GuestWaiting
	}
	return nil
}
func (value *fakeBootstrap) Status(context.Context, State) (GuestState, error) {
	value.mu.Lock()
	defer value.mu.Unlock()
	return value.state, nil
}
func (value *fakeBootstrap) Deliver(_ context.Context, state State, envelope guestenrollment.BootstrapEnvelope, _ string) error {
	value.mu.Lock()
	defer value.mu.Unlock()
	value.delivered++
	value.binding = envelope.Binding
	value.state = GuestEnrolled
	if value.lostResponse {
		value.lostResponse = false
		return errors.New("lost")
	}
	return nil
}
func (value *fakeBootstrap) Lock(context.Context, State) error {
	value.mu.Lock()
	defer value.mu.Unlock()
	value.locked++
	value.state = GuestLocked
	return nil
}

type fakeResolver struct {
	addresses map[string][]netip.Addr
	servers   []string
}

func (resolver *fakeResolver) LookupIPv4(_ context.Context, dnsServer, host string) ([]netip.Addr, error) {
	resolver.servers = append(resolver.servers, dnsServer)
	values := resolver.addresses[host]
	if len(values) == 0 {
		return nil, errors.New("missing")
	}
	return append([]netip.Addr(nil), values...), nil
}

func TestMediatedLifecycleEnrollmentSteadyFenceAndExactDeletion(t *testing.T) {
	root := t.TempDir()
	cloud := &fakeCloud{apply: true}
	bootstrap := &fakeBootstrap{}
	driver := newTestDriver(t, root, cloud, bootstrap)
	desired := testDesired(t, true)
	status, err := driver.Reconcile(context.Background(), desired)
	if err != nil || !status.Ready || status.Phase != executiondriver.PhaseRunning || status.EgressConfinement == nil || !status.EgressConfinement.Ready {
		t.Fatalf("mediated bootstrap fence not ready: %#v %v", status, err)
	}
	scope := guestenrollment.ExecutionScope{AgentRunUID: "run-uid", ExecutionID: desired.ExecutionID, DriverRegistration: "azure-prod"}
	prepared, err := driver.Prepare(context.Background(), guestenrollment.HandoffPrepareRequest{ContractVersion: guestenrollment.HandoffVersion, ExecutionScope: scope, DesiredGeneration: desired.Generation})
	if err != nil || prepared.State != guestenrollment.HandoffStatePrepared || !prepared.NewlyPrepared || bootstrap.configured != 1 {
		t.Fatalf("prepare failed: %#v %v", prepared, err)
	}
	binding := guestenrollment.Binding{AgentRunUID: scope.AgentRunUID, ExecutionID: scope.ExecutionID, DriverRegistration: scope.DriverRegistration, DesiredGeneration: desired.Generation, GuestInstanceID: prepared.GuestInstanceID}
	envelope := testEnvelope(t, binding)
	if err := driver.Deliver(context.Background(), guestenrollment.HandoffDeliverRequest{ContractVersion: guestenrollment.HandoffVersion, Envelope: envelope, NativeEgressCAPEM: testCAPEM(t)}); err != nil {
		t.Fatal(err)
	}
	state, err := (Store{Root: root}).Load(desired.ExecutionID)
	if err != nil || !state.EnrollmentAccepted || !state.BootstrapLocked {
		t.Fatalf("enrollment not durable: %#v %v", state, err)
	}
	if _, err := os.Stat((Store{Root: root}).KeyPath(desired.ExecutionID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("bootstrap private key remains after acceptance")
	}
	if len(cloud.deployments) < 2 || !cloud.deployments[0] || cloud.deployments[len(cloud.deployments)-1] {
		t.Fatalf("unexpected fence sequence: %#v", cloud.deployments)
	}
	content, _ := os.ReadFile(root + "/executions/" + strings.TrimPrefix((Store{Root: root}).RunDir(desired.ExecutionID), root+"/executions/") + "/state.json")
	for _, needle := range []string{envelope.Token, "nvt_eg1_", "PRIVATE KEY"} {
		if strings.Contains(string(content), needle) {
			t.Fatalf("durable state leaked %q", needle)
		}
	}
	cloud.deleteError = errors.New("temporary")
	deleting, err := driver.Delete(context.Background(), desired.ExecutionID)
	if err != nil || deleting.Phase != executiondriver.PhaseDeleting {
		t.Fatalf("uncertain delete completed: %#v %v", deleting, err)
	}
	if _, err := (Store{Root: root}).Load(desired.ExecutionID); err != nil {
		t.Fatal("cleanup obligation was lost")
	}
	deleted, err := driver.Delete(context.Background(), desired.ExecutionID)
	if err != nil || deleted.Phase != executiondriver.PhaseDeleted || !cloud.deleted {
		t.Fatalf("delete did not converge: %#v %v", deleted, err)
	}
}

func TestMediatedConfinementCannotDowngradeOrEnrollBeforeReadback(t *testing.T) {
	cloud := &fakeCloud{observation: CloudObservation{Exists: true, Exact: true, Running: true, PrivateIP: "10.42.0.7"}}
	bootstrap := &fakeBootstrap{}
	driver := newTestDriver(t, t.TempDir(), cloud, bootstrap)
	desired := testDesired(t, true)
	status, err := driver.Reconcile(context.Background(), desired)
	if err != nil {
		t.Fatal(err)
	}
	if status.Ready || status.EgressConfinement == nil || status.EgressConfinement.Ready {
		t.Fatalf("missing fence became ready: %#v", status)
	}
	scope := guestenrollment.ExecutionScope{AgentRunUID: "run-uid", ExecutionID: desired.ExecutionID, DriverRegistration: "azure-prod"}
	if _, err := driver.Prepare(context.Background(), guestenrollment.HandoffPrepareRequest{ContractVersion: guestenrollment.HandoffVersion, ExecutionScope: scope, DesiredGeneration: desired.Generation}); err == nil {
		t.Fatal("enrollment prepared before exact confinement")
	}
	if bootstrap.configured != 0 {
		t.Fatal("guest mutated before exact confinement")
	}
}

func TestReconcileStartsExactOwnedStoppedVMAndRetriesFailure(t *testing.T) {
	cloud := &fakeCloud{apply: true}
	driver := newTestDriver(t, t.TempDir(), cloud, &fakeBootstrap{})
	desired := testDesired(t, true)
	if status, err := driver.Reconcile(context.Background(), desired); err != nil || !status.Ready {
		t.Fatalf("initial Azure VM did not become ready: %#v %v", status, err)
	}
	cloud.mu.Lock()
	cloud.apply = false
	cloud.observation.Running = false
	cloud.startError = &cloudError{retryable: true}
	cloud.mu.Unlock()
	failed, err := driver.Reconcile(context.Background(), desired)
	if err != nil || failed.Phase != executiondriver.PhaseFailed || failed.Failure == nil || !failed.Failure.Retryable || failed.Ready {
		t.Fatalf("start failure was not a bounded retryable status: %#v %v", failed, err)
	}
	recovered, err := driver.Reconcile(context.Background(), desired)
	if err != nil || !recovered.Ready || recovered.Phase != executiondriver.PhaseRunning {
		t.Fatalf("exact stopped VM did not recover through Start: %#v %v", recovered, err)
	}
	cloud.mu.Lock()
	starts := cloud.starts
	cloud.mu.Unlock()
	if starts != 2 {
		t.Fatalf("unexpected Azure Start attempts: %d", starts)
	}
}

func TestLostARMAndEnrollmentResponsesRecoverFromDurableAuthority(t *testing.T) {
	root := t.TempDir()
	cloud := &fakeCloud{apply: true, deployError: &cloudError{retryable: true}}
	bootstrap := &fakeBootstrap{lostResponse: true}
	driver := newTestDriver(t, root, cloud, bootstrap)
	desired := testDesired(t, true)
	status, err := driver.Reconcile(context.Background(), desired)
	if err != nil || !status.Ready {
		t.Fatalf("lost ARM response was not recovered by readback: %#v %v", status, err)
	}
	scope := guestenrollment.ExecutionScope{AgentRunUID: "run-uid", ExecutionID: desired.ExecutionID, DriverRegistration: "azure-prod"}
	prepared, err := driver.Prepare(context.Background(), guestenrollment.HandoffPrepareRequest{ContractVersion: guestenrollment.HandoffVersion, ExecutionScope: scope, DesiredGeneration: desired.Generation})
	if err != nil {
		t.Fatal(err)
	}
	binding := guestenrollment.Binding{AgentRunUID: scope.AgentRunUID, ExecutionID: scope.ExecutionID, DriverRegistration: scope.DriverRegistration, DesiredGeneration: desired.Generation, GuestInstanceID: prepared.GuestInstanceID}
	request := guestenrollment.HandoffDeliverRequest{ContractVersion: guestenrollment.HandoffVersion, Envelope: testEnvelope(t, binding), NativeEgressCAPEM: testCAPEM(t)}
	if err := driver.Deliver(context.Background(), request); err == nil {
		t.Fatal("lost guest acknowledgement was accepted")
	}
	restarted := newTestDriver(t, root, cloud, bootstrap)
	recovered, err := restarted.Prepare(context.Background(), guestenrollment.HandoffPrepareRequest{ContractVersion: guestenrollment.HandoffVersion, ExecutionScope: scope, DesiredGeneration: desired.Generation})
	if err != nil || recovered.State != guestenrollment.HandoffStateAccepted || recovered.GuestInstanceID != prepared.GuestInstanceID || bootstrap.delivered != 1 {
		t.Fatalf("response-loss recovery failed: %#v %v", recovered, err)
	}
}

func TestDesiredReplayConflictCollisionAndReplacementAreFailClosed(t *testing.T) {
	root := t.TempDir()
	cloud := &fakeCloud{apply: true}
	bootstrap := &fakeBootstrap{}
	driver := newTestDriver(t, root, cloud, bootstrap)
	desired := testDesired(t, true)
	if _, err := driver.Reconcile(context.Background(), desired); err != nil {
		t.Fatal(err)
	}
	conflict := desired
	conflict.DesiredFingerprint = "sha256:" + strings.Repeat("c", 64)
	if _, err := driver.Reconcile(context.Background(), conflict); err == nil {
		t.Fatal("same-generation conflict accepted")
	}
	regressed := desired
	regressed.Generation = desired.Generation - 1
	if _, err := driver.Reconcile(context.Background(), regressed); err == nil {
		t.Fatal("generation regression accepted")
	}
	cloud.apply = false
	cloud.observation = CloudObservation{Exists: true, Exact: false, Running: true, PrivateIP: "10.42.0.7"}
	other := testDesired(t, true)
	other.ExecutionID = "nvt-exec-collision"
	if _, err := driver.Reconcile(context.Background(), other); err == nil {
		t.Fatal("foreign resource collision accepted")
	}
}

func TestDirectModeRemainsExplicitAndHasNoConfinementAssertion(t *testing.T) {
	cloud := &fakeCloud{apply: true}
	driver := newTestDriver(t, t.TempDir(), cloud, &fakeBootstrap{})
	desired := testDesired(t, false)
	status, err := driver.Reconcile(context.Background(), desired)
	if err != nil {
		t.Fatal(err)
	}
	if status.EgressConfinement != nil || status.Ready {
		t.Fatalf("direct provisioning changed semantics: %#v", status)
	}
	if len(cloud.deployments) != 1 || !cloud.deployments[0] {
		t.Fatal("direct bootstrap SSH was not explicit")
	}
}

func TestReplacementUsesNewGuestAndKeyAndRejectsWrongBinding(t *testing.T) {
	root := t.TempDir()
	cloud := &fakeCloud{apply: true}
	bootstrap := &fakeBootstrap{}
	driver := newTestDriver(t, root, cloud, bootstrap)
	desired := testDesired(t, true)
	if _, err := driver.Reconcile(context.Background(), desired); err != nil {
		t.Fatal(err)
	}
	scope := guestenrollment.ExecutionScope{AgentRunUID: "run-uid", ExecutionID: desired.ExecutionID, DriverRegistration: "azure-prod"}
	prepared, err := driver.Prepare(context.Background(), guestenrollment.HandoffPrepareRequest{ContractVersion: guestenrollment.HandoffVersion, ExecutionScope: scope, DesiredGeneration: desired.Generation})
	if err != nil {
		t.Fatal(err)
	}
	binding := guestenrollment.Binding{AgentRunUID: scope.AgentRunUID, ExecutionID: scope.ExecutionID, DriverRegistration: scope.DriverRegistration, DesiredGeneration: desired.Generation, GuestInstanceID: prepared.GuestInstanceID}
	wrong := binding
	wrong.GuestInstanceID = "another-guest"
	if _, err := driver.Replace(context.Background(), guestenrollment.HandoffReplaceRequest{ContractVersion: guestenrollment.HandoffVersion, Binding: wrong}); err == nil {
		t.Fatal("wrong binding replaced Azure VM")
	}
	prior, err := os.ReadFile((Store{Root: root}).KeyPath(desired.ExecutionID))
	if err != nil {
		t.Fatal(err)
	}
	replacement, err := driver.Replace(context.Background(), guestenrollment.HandoffReplaceRequest{ContractVersion: guestenrollment.HandoffVersion, Binding: binding})
	if err != nil || !replacement.NewlyPrepared || replacement.GuestInstanceID == binding.GuestInstanceID {
		t.Fatalf("replacement failed: %#v %v", replacement, err)
	}
	current, err := os.ReadFile((Store{Root: root}).KeyPath(desired.ExecutionID))
	if err != nil {
		t.Fatal(err)
	}
	if string(current) == string(prior) {
		t.Fatal("replacement reused bootstrap private key")
	}
}

func TestUnsupportedWorkloadAndAttachmentEndpointFailBeforeCloudMutation(t *testing.T) {
	cloud := &fakeCloud{apply: true}
	driver := newTestDriver(t, t.TempDir(), cloud, &fakeBootstrap{})
	desired := testDesired(t, true)
	desired.WorkloadKind = executiondriver.WorkloadKindPod
	if _, err := driver.Reconcile(context.Background(), desired); err == nil {
		t.Fatal("Pod workload accepted by Azure driver")
	}
	desired = testDesired(t, true)
	desired.NativeEgressAttachment.RequiredDestinations[2].Host = "other-gateway.example"
	sealed, err := executiondriver.SealNativeEgressAttachment(*desired.NativeEgressAttachment)
	if err != nil {
		t.Fatal(err)
	}
	desired.NativeEgressAttachment = &sealed
	if _, err := driver.Reconcile(context.Background(), desired); err == nil {
		t.Fatal("attachment missing configured endpoint was accepted")
	}
	desired = testDesired(t, true)
	desired.NativeEgressAttachment.Relay.Host = "2606:4700:4700::1111"
	sealed, err = executiondriver.SealNativeEgressAttachment(*desired.NativeEgressAttachment)
	if err != nil {
		t.Fatal(err)
	}
	desired.NativeEgressAttachment = &sealed
	if _, err := driver.Reconcile(context.Background(), desired); err == nil {
		t.Fatal("unsupported IPv6 Azure relay was accepted")
	}
	if len(cloud.deployments) != 0 {
		t.Fatal("Azure mutation occurred before desired validation")
	}
}

func TestResolverPreservesDistinctTrustedEndpointsSharingAddressAndPort(t *testing.T) {
	desired := testDesired(t, true)
	desired.NativeEgressAttachment.RequiredDestinations[2].Port = 443
	sealed, err := executiondriver.SealNativeEgressAttachment(*desired.NativeEgressAttachment)
	if err != nil {
		t.Fatal(err)
	}
	resolver := &fakeResolver{addresses: map[string][]netip.Addr{
		"relay.example": {netip.MustParseAddr("20.1.1.3")}, "broker.example": {netip.MustParseAddr("20.1.1.4")},
		"registry.example": {netip.MustParseAddr("20.1.1.9")}, "gateway.example": {netip.MustParseAddr("20.1.1.9")},
	}}
	pinned, err := resolveAttachment(context.Background(), resolver, "10.50.0.53", &sealed)
	if err != nil {
		t.Fatal(err)
	}
	if len(pinned) != 4 {
		t.Fatalf("co-located exact endpoints were collapsed: %#v", pinned)
	}
	for _, server := range resolver.servers {
		if server != "10.50.0.53" {
			t.Fatalf("resolution used a DNS server other than the VM's configured server: %q", server)
		}
	}

	resolver.addresses["relay.example"] = []netip.Addr{netip.MustParseAddr("20.1.1.3"), netip.MustParseAddr("169.254.169.254")}
	if _, err := resolveAttachment(context.Background(), resolver, "10.50.0.53", &sealed); err == nil {
		t.Fatal("mixed public and metadata answers did not fail closed")
	}
}

func TestWorkloadIdentityIsExplicitAndHasNoAmbientFallback(t *testing.T) {
	for _, name := range RequiredWorkloadIdentityEnvironment {
		t.Setenv(name, "")
	}
	if _, err := NewWorkloadIdentityCloud(); err == nil {
		t.Fatal("missing Workload Identity configuration fell back to ambient credentials")
	}
	if strings.Join(RequiredWorkloadIdentityEnvironment, ",") != "AZURE_TENANT_ID,AZURE_CLIENT_ID,AZURE_FEDERATED_TOKEN_FILE" {
		t.Fatal("Workload Identity environment contract drifted")
	}
	token := t.TempDir() + "/token"
	if err := os.WriteFile(token, []byte("projected-service-account-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AZURE_TENANT_ID", "11111111-1111-4111-8111-111111111111")
	t.Setenv("AZURE_CLIENT_ID", "22222222-2222-4222-8222-222222222222")
	t.Setenv("AZURE_FEDERATED_TOKEN_FILE", token)
	if _, err := NewWorkloadIdentityCloud(); err != nil {
		t.Fatalf("explicit Workload Identity rejected: %v", err)
	}
}

func TestSanitizedProviderFailuresContainNoAuthorityOrResourceDetails(t *testing.T) {
	needle := "provider-secret-resource-path"
	err := sanitizeAzureError(errors.New(needle))
	if strings.Contains(err.Error(), needle) || strings.Contains((&Error{Failure: executiondriver.Failure{Reason: "provider-unavailable"}}).Error(), needle) {
		t.Fatal("provider details entered diagnostics")
	}
}

func TestProviderFailuresMapToBoundedPortableStatuses(t *testing.T) {
	for name, providerError := range map[string]error{
		"temporary": &cloudError{retryable: true},
		"permanent": &cloudError{retryable: false},
	} {
		t.Run(name, func(t *testing.T) {
			cloud := &fakeCloud{deployError: providerError}
			driver := newTestDriver(t, t.TempDir(), cloud, &fakeBootstrap{})
			status, err := driver.Reconcile(context.Background(), testDesired(t, true))
			if err != nil || executiondriver.ValidateStatus(status) != nil || status.Phase != executiondriver.PhaseFailed ||
				status.Failure == nil || status.Failure.Retryable != (name == "temporary") || (status.RetryAfterSeconds != nil) != (name == "temporary") {
				t.Fatalf("provider failure was not mapped to a bounded status: %#v %v", status, err)
			}
			encoded, _ := json.Marshal(status)
			if strings.Contains(string(encoded), "provider-secret-resource-path") {
				t.Fatal("provider diagnostics entered portable status")
			}
		})
	}
}

func TestOperationLocksAreBoundedAndReleased(t *testing.T) {
	driver := newTestDriver(t, t.TempDir(), &fakeCloud{}, &fakeBootstrap{})
	releases := make([]func(), 0, maxExecutions)
	for index := 0; index < maxExecutions; index++ {
		release, err := driver.lock(fmt.Sprintf("nvt-exec-capacity-%d", index))
		if err != nil {
			t.Fatalf("bounded operation %d rejected: %v", index, err)
		}
		releases = append(releases, release)
	}
	if release, err := driver.lock("nvt-exec-capacity-overflow"); err == nil {
		release()
		t.Fatal("operation capacity exceeded its hard bound")
	}
	releases[0]()
	release, err := driver.lock("nvt-exec-capacity-reused")
	if err != nil {
		t.Fatalf("released operation capacity was not reusable: %v", err)
	}
	release()
	for _, release := range releases[1:] {
		release()
	}
	if len(driver.locks) != 0 {
		t.Fatal("operation lock references leaked")
	}
}

func TestPrepareStateRootPreservesVolumeRoot(t *testing.T) {
	volumeRoot := t.TempDir()
	if err := os.Chmod(volumeRoot, 0o770); err != nil {
		t.Fatal(err)
	}
	stateRoot, err := PrepareStateRoot(volumeRoot)
	if err != nil {
		t.Fatal(err)
	}
	if stateRoot != volumeRoot+"/azure" {
		t.Fatalf("unexpected owned state root %q", stateRoot)
	}
	volumeInfo, _ := os.Stat(volumeRoot)
	stateInfo, _ := os.Stat(stateRoot)
	if volumeInfo.Mode().Perm() != 0o770 || stateInfo.Mode().Perm() != 0o700 {
		t.Fatalf("state preparation changed the volume boundary: volume=%o child=%o", volumeInfo.Mode().Perm(), stateInfo.Mode().Perm())
	}
}

func newTestDriver(t *testing.T, root string, cloud Cloud, bootstrap Bootstrapper) *Driver {
	t.Helper()
	value, err := New(root, "azure-prod", cloud, bootstrap, &fakeResolver{addresses: map[string][]netip.Addr{
		"registry.example": {netip.MustParseAddr("20.1.1.1")}, "gateway.example": {netip.MustParseAddr("20.1.1.2")},
		"relay.example": {netip.MustParseAddr("20.1.1.3")}, "broker.example": {netip.MustParseAddr("20.1.1.4")},
	}})
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func testDesired(t *testing.T, mediated bool) executiondriver.DesiredExecution {
	t.Helper()
	configuration := testConfiguration(t)
	raw, _ := json.Marshal(configuration)
	desired := executiondriver.DesiredExecution{ExecutionID: "nvt-exec-azure-test", Generation: 7, DesiredFingerprint: "sha256:" + strings.Repeat("b", 64), WorkloadKind: executiondriver.WorkloadKindVM, ClassName: "azure-small", Configuration: raw}
	if mediated {
		attachment, err := executiondriver.SealNativeEgressAttachment(executiondriver.NativeEgressAttachment{ContractVersion: executiondriver.NativeEgressAttachmentVersion, Generation: 3, Relay: executiondriver.NativeEgressRelayAttachment{Host: "relay.example", Port: 7445, ServerName: "relay.example", CAPEM: testCAPEM(t)}, RequiredDestinations: []executiondriver.NativeEgressRequiredDestination{{Purpose: executiondriver.NativeEgressDestinationBootstrap, Host: "broker.example", Port: 7347}, {Purpose: executiondriver.NativeEgressDestinationBootstrap, Host: "registry.example", Port: 443}, {Purpose: executiondriver.NativeEgressDestinationControl, Host: "gateway.example", Port: 7443}}, Redirect: executiondriver.NativeEgressRedirectIntent{Mode: executiondriver.NativeEgressRedirectModeCaptureTCP, LoopbackAddress: "127.0.0.1", TransparentTCPPort: 15001, ExplicitCONNECTPort: 15002}})
		if err != nil {
			t.Fatal(err)
		}
		desired.NativeEgressAttachment = &attachment
	}
	return desired
}

func testConfiguration(t *testing.T) config.Configuration {
	t.Helper()
	return config.Configuration{ContractVersion: config.Version, SubscriptionID: "11111111-1111-4111-8111-111111111111", ResourceGroup: "nvt-rg", Location: "westeurope", SubnetResourceID: "/subscriptions/11111111-1111-4111-8111-111111111111/resourceGroups/net-rg/providers/Microsoft.Network/virtualNetworks/nvt-vnet/subnets/agents", VMImageResourceID: "/subscriptions/11111111-1111-4111-8111-111111111111/resourceGroups/image-rg/providers/Microsoft.Compute/galleries/nvtgallery/images/nvtguest/versions/1.2.3", GuestArchitecture: "amd64", VMSize: "Standard_D2s_v5", OSDisk: config.OSDisk{SizeGiB: 64, StorageAccountType: "Premium_LRS"}, HostBundle: config.Artifact{Repository: "https://registry.example/nvt/host-bundle", Digest: "sha256:" + strings.Repeat("a", 64)}, EnrollmentEndpoint: "https://broker.example:7347", EnrollmentCAPEM: testCAPEM(t), NativeSessionEndpoint: "tls://gateway.example:7443", NativeSessionCAPEM: testCAPEM(t), SSHHostPublicKey: testSSHKey(t), Network: config.BootstrapNetwork{DriverSourceCIDR: "10.40.0.0/24", DNSServer: "168.63.129.16"}, BootstrapTimeoutSec: 90}
}
func testCAPEM(t *testing.T) string {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ca"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}
func testSSHKey(t *testing.T) string {
	t.Helper()
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
}
func testEnvelope(t *testing.T, binding guestenrollment.Binding) guestenrollment.BootstrapEnvelope {
	t.Helper()
	token, err := guestenrollment.GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	return guestenrollment.BootstrapEnvelope{ContractVersion: guestenrollment.Version, Binding: binding, ExchangeURL: "https://broker.example:7347/v1/guest-enrollment/exchange", Token: token, IssuedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(5 * time.Minute).Format(time.RFC3339)}
}
