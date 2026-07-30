package controller

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	nvtv1alpha1 "github.com/mirkoSekulic/nvt-agent/operator/api/v1alpha1"
	"github.com/mirkoSekulic/nvt-agent/operator/executiondriver"
	publicationclient "github.com/mirkoSekulic/nvt-agent/operator/nativeegresspublication"
	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment/nativeegress"
)

type recordingTargetAuthority struct {
	status       nativeegress.TargetStatus
	snapshots    []nativeegress.TargetSnapshot
	conflictOnce bool
	responseLost bool
}

type namespaceRecordingReader struct {
	client.Reader
	listNamespaces []string
}

func (reader *namespaceRecordingReader) List(ctx context.Context, list client.ObjectList, options ...client.ListOption) error {
	resolved := (&client.ListOptions{}).ApplyOptions(options)
	reader.listNamespaces = append(reader.listNamespaces, resolved.Namespace)
	return reader.Reader.List(ctx, list, options...)
}

func (authority *recordingTargetAuthority) Status(context.Context) (nativeegress.TargetStatus, error) {
	return authority.status, nil
}

func (authority *recordingTargetAuthority) Publish(_ context.Context, snapshot nativeegress.TargetSnapshot) (nativeegress.TargetSnapshotAcknowledgement, error) {
	authority.snapshots = append(authority.snapshots, snapshot)
	if authority.conflictOnce {
		authority.conflictOnce = false
		authority.status = nativeegress.TargetStatus{ContractVersion: nativeegress.TargetPublicationVersion, Type: nativeegress.TargetPublicationStatusResponse, Published: true, Generation: snapshot.Generation, Digest: snapshot.Digest, TargetCount: len(snapshot.Targets)}
		return nativeegress.TargetSnapshotAcknowledgement{}, publicationclient.ErrConflict
	}
	authority.status = nativeegress.TargetStatus{ContractVersion: nativeegress.TargetPublicationVersion, Type: nativeegress.TargetPublicationStatusResponse, Published: true, Generation: snapshot.Generation, Digest: snapshot.Digest, TargetCount: len(snapshot.Targets)}
	if authority.responseLost {
		authority.responseLost = false
		return nativeegress.TargetSnapshotAcknowledgement{}, publicationclient.ErrUnavailable
	}
	return nativeegress.TargetSnapshotAcknowledgement{ContractVersion: nativeegress.TargetPublicationVersion, Type: nativeegress.TargetSnapshotAck, Generation: snapshot.Generation, Digest: snapshot.Digest, TargetCount: len(snapshot.Targets)}, nil
}

func TestNativeEgressCoordinatorPublishesCanonicalCompleteSnapshotAndWithdraws(t *testing.T) {
	ctx := context.Background()
	first := readyNativeEgressRun("first", "11111111-1111-1111-1111-111111111111", "guest-first")
	second := readyNativeEgressRun("second", "22222222-2222-2222-2222-222222222222", "guest-second")
	firstPod, firstService := readyTargetObjects(first)
	secondPod, secondService := readyTargetObjects(second)
	kubernetes := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(first, second, firstPod, firstService, secondPod, secondService).Build()
	authority := &recordingTargetAuthority{status: nativeegress.TargetStatus{ContractVersion: nativeegress.TargetPublicationVersion, Type: nativeegress.TargetPublicationStatusResponse}, conflictOnce: true}
	coordinator := mustNativeEgressTargetCoordinator(t, kubernetes, authority)
	if err := coordinator.Reconcile(ctx, nil, ""); err != nil {
		t.Fatal(err)
	}
	if len(authority.snapshots) != 2 || len(authority.snapshots[1].Targets) != 2 {
		t.Fatalf("unexpected snapshots: %#v", authority.snapshots)
	}
	if authority.snapshots[1].Generation != authority.snapshots[0].Generation || authority.snapshots[1].Digest != authority.snapshots[0].Digest {
		t.Fatal("conflict recovery did not retry the exact applied snapshot")
	}
	if err := coordinator.Reconcile(ctx, nil, ""); err != nil {
		t.Fatal(err)
	}
	if idempotent := authority.snapshots[len(authority.snapshots)-1]; idempotent.Generation != 1 || idempotent.Digest != authority.snapshots[0].Digest {
		t.Fatal("unchanged desired state churned publication generation")
	}
	if err := coordinator.Reconcile(ctx, nil, string(first.UID)); err != nil {
		t.Fatal(err)
	}
	last := authority.snapshots[len(authority.snapshots)-1]
	if len(last.Targets) != 1 || last.Targets[0].Binding.AgentRunUID != string(second.UID) || last.Generation != 2 {
		t.Fatalf("withdrawal did not publish the exact remaining set: %#v", last)
	}
}

func TestNativeEgressCoordinatorAlwaysListsOnlyInstallationNamespace(t *testing.T) {
	reader := &namespaceRecordingReader{Reader: fake.NewClientBuilder().WithScheme(testScheme(t)).Build()}
	authority := &recordingTargetAuthority{status: nativeegress.TargetStatus{ContractVersion: nativeegress.TargetPublicationVersion, Type: nativeegress.TargetPublicationStatusResponse}}
	coordinator := mustNativeEgressTargetCoordinator(t, reader, authority)
	if err := coordinator.Reconcile(context.Background(), nil, ""); err != nil {
		t.Fatal(err)
	}
	if len(reader.listNamespaces) != 1 || reader.listNamespaces[0] != "nvt" {
		t.Fatalf("list namespaces=%q, want only nvt", reader.listNamespaces)
	}
}

func TestNativeEgressCoordinatorRetriesExactSnapshotAfterLostAcknowledgement(t *testing.T) {
	run := readyNativeEgressRun("lost-ack", "77777777-7777-7777-7777-777777777777", "guest-lost-ack")
	pod, service := readyTargetObjects(run)
	kubernetes := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(run, pod, service).Build()
	authority := &recordingTargetAuthority{
		status:       nativeegress.TargetStatus{ContractVersion: nativeegress.TargetPublicationVersion, Type: nativeegress.TargetPublicationStatusResponse},
		responseLost: true,
	}
	coordinator := mustNativeEgressTargetCoordinator(t, kubernetes, authority)
	if err := coordinator.Reconcile(context.Background(), nil, ""); err != nil {
		t.Fatal(err)
	}
	if len(authority.snapshots) != 2 {
		t.Fatalf("publish calls=%d, want 2", len(authority.snapshots))
	}
	first, second := authority.snapshots[0], authority.snapshots[1]
	if first.Generation != second.Generation || first.Digest != second.Digest {
		t.Fatal("response-loss recovery did not retry the exact committed snapshot")
	}
}

type serializedTargetAuthority struct {
	mu         sync.Mutex
	active     int
	maxActive  int
	status     nativeegress.TargetStatus
	requestLag time.Duration
}

func (authority *serializedTargetAuthority) begin() func() {
	authority.mu.Lock()
	authority.active++
	if authority.active > authority.maxActive {
		authority.maxActive = authority.active
	}
	authority.mu.Unlock()
	time.Sleep(authority.requestLag)
	return func() {
		authority.mu.Lock()
		authority.active--
		authority.mu.Unlock()
	}
}

func (authority *serializedTargetAuthority) Status(context.Context) (nativeegress.TargetStatus, error) {
	done := authority.begin()
	defer done()
	authority.mu.Lock()
	defer authority.mu.Unlock()
	return authority.status, nil
}

func (authority *serializedTargetAuthority) Publish(_ context.Context, snapshot nativeegress.TargetSnapshot) (nativeegress.TargetSnapshotAcknowledgement, error) {
	done := authority.begin()
	defer done()
	authority.mu.Lock()
	defer authority.mu.Unlock()
	authority.status = nativeegress.TargetStatus{ContractVersion: nativeegress.TargetPublicationVersion, Type: nativeegress.TargetPublicationStatusResponse, Published: true, Generation: snapshot.Generation, Digest: snapshot.Digest, TargetCount: len(snapshot.Targets)}
	return nativeegress.TargetSnapshotAcknowledgement{ContractVersion: nativeegress.TargetPublicationVersion, Type: nativeegress.TargetSnapshotAck, Generation: snapshot.Generation, Digest: snapshot.Digest, TargetCount: len(snapshot.Targets)}, nil
}

func TestNativeEgressCoordinatorSerializesConcurrentCompleteSnapshots(t *testing.T) {
	authority := &serializedTargetAuthority{
		status:     nativeegress.TargetStatus{ContractVersion: nativeegress.TargetPublicationVersion, Type: nativeegress.TargetPublicationStatusResponse},
		requestLag: time.Millisecond,
	}
	coordinator := mustNativeEgressTargetCoordinator(t, fake.NewClientBuilder().WithScheme(testScheme(t)).Build(), authority)
	const reconciles = 12
	errorsSeen := make(chan error, reconciles)
	var group sync.WaitGroup
	for range reconciles {
		group.Add(1)
		go func() {
			defer group.Done()
			errorsSeen <- coordinator.Reconcile(context.Background(), nil, "")
		}()
	}
	group.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		if err != nil {
			t.Fatal(err)
		}
	}
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if authority.maxActive != 1 {
		t.Fatalf("concurrent relay operations=%d, want 1", authority.maxActive)
	}
	if !authority.status.Published || authority.status.Generation != 1 || authority.status.TargetCount != 0 {
		t.Fatalf("unexpected final status: %#v", authority.status)
	}
}

func TestNativeEgressCoordinatorRejectsMalformedCurrentWithoutAuthorityCall(t *testing.T) {
	authority := &recordingTargetAuthority{}
	coordinator := mustNativeEgressTargetCoordinator(t, fake.NewClientBuilder().WithScheme(testScheme(t)).Build(), authority)
	target := nativeegress.PublishedTarget{}
	if err := coordinator.Reconcile(context.Background(), &target, ""); err == nil {
		t.Fatal("expected malformed current target rejection")
	}
	if len(authority.snapshots) != 0 {
		t.Fatal("authority was called for malformed input")
	}
}

func TestNativeEgressPublicationOmittedLeavesControllerDisabled(t *testing.T) {
	reconciler := &AgentRunReconciler{}
	if err := ConfigureNativeEgressTargetPublication(reconciler, nil, fake.NewClientBuilder().WithScheme(testScheme(t)).Build(), ""); err != nil {
		t.Fatal(err)
	}
	if reconciler.nativeEgressTargets != nil {
		t.Fatal("omitted publication configuration installed an authority")
	}
	if err := BootstrapNativeEgressTargetPublication(context.Background(), reconciler); err != nil {
		t.Fatalf("disabled publication bootstrap failed: %v", err)
	}
}

func TestNativeEgressPublicationEnabledRequiresInstallationNamespace(t *testing.T) {
	reconciler := &AgentRunReconciler{}
	reader := fake.NewClientBuilder().WithScheme(testScheme(t)).Build()
	if err := ConfigureNativeEgressTargetPublication(reconciler, &publicationclient.Client{}, reader, ""); err == nil {
		t.Fatal("enabled publication accepted an empty installation namespace")
	}
	if reconciler.nativeEgressTargets != nil {
		t.Fatal("invalid enabled publication installed an authority")
	}
}

func mustNativeEgressTargetCoordinator(t *testing.T, reader client.Reader, authority publicationclient.Interface) nativeEgressTargetPublication {
	t.Helper()
	coordinator, err := newNativeEgressTargetCoordinator(reader, authority, "nvt")
	if err != nil {
		t.Fatal(err)
	}
	return coordinator
}

func TestNativeEgressCoordinatorFailsClosedOnAuthorityFailure(t *testing.T) {
	coordinator := &nativeEgressTargetCoordinator{client: fake.NewClientBuilder().WithScheme(testScheme(t)).Build(), authority: failingTargetAuthority{}}
	if err := coordinator.Reconcile(context.Background(), nil, ""); err == nil || err.Error() != "native egress publication is unavailable" {
		t.Fatalf("unexpected error: %v", err)
	}
}

type failingTargetAuthority struct{}

func (failingTargetAuthority) Status(context.Context) (nativeegress.TargetStatus, error) {
	return nativeegress.TargetStatus{}, errors.New("secret backend diagnostic")
}
func (failingTargetAuthority) Publish(context.Context, nativeegress.TargetSnapshot) (nativeegress.TargetSnapshotAcknowledgement, error) {
	panic("unexpected")
}

type recordingPublicationBoundary struct {
	calls int
	check func(*nativeegress.PublishedTarget, string) error
}

type failNthStatusClient struct {
	client.Client
	failAt  int
	updates int
}

func (kubernetes *failNthStatusClient) Status() client.SubResourceWriter {
	return &failNthStatusWriter{SubResourceWriter: kubernetes.Client.Status(), client: kubernetes}
}

type failNthStatusWriter struct {
	client.SubResourceWriter
	client *failNthStatusClient
}

func (writer *failNthStatusWriter) Update(ctx context.Context, object client.Object, options ...client.SubResourceUpdateOption) error {
	writer.client.updates++
	if writer.client.updates == writer.client.failAt {
		return errors.New("injected status conflict")
	}
	return writer.SubResourceWriter.Update(ctx, object, options...)
}

func (boundary *recordingPublicationBoundary) Reconcile(_ context.Context, target *nativeegress.PublishedTarget, exclude string) error {
	boundary.calls++
	if boundary.check != nil {
		return boundary.check(target, exclude)
	}
	return nil
}

func TestNativeEgressWithdrawalIsAcknowledgedBeforeBindingClear(t *testing.T) {
	ctx := context.Background()
	run := readyNativeEgressRun("withdraw", "33333333-3333-3333-3333-333333333333", "guest-withdraw")
	scheme := testScheme(t)
	kubernetes := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(run).WithObjects(run).Build()
	boundary := &recordingPublicationBoundary{}
	boundary.check = func(target *nativeegress.PublishedTarget, exclude string) error {
		if target != nil || exclude != string(run.UID) {
			t.Fatal("withdrawal did not exclude the exact binding")
		}
		current := &nvtv1alpha1.AgentRun{}
		if err := kubernetes.Get(ctx, client.ObjectKeyFromObject(run), current); err != nil {
			t.Fatal(err)
		}
		if current.Status.NativeGuestBinding == nil {
			t.Fatal("binding cleared before relay acknowledgement")
		}
		condition := meta.FindStatusCondition(current.Status.Conditions, ConditionNativeEgressReady)
		if condition == nil || condition.Status != metav1.ConditionFalse || condition.Reason != "NativeEgressWithdrawalPending" {
			t.Fatalf("withdrawal intent was not durable before relay mutation: %#v", condition)
		}
		return nil
	}
	reconciler := &AgentRunReconciler{Client: kubernetes, Scheme: scheme, nativeEgressTargets: boundary}
	current := &nvtv1alpha1.AgentRun{}
	if err := kubernetes.Get(ctx, client.ObjectKeyFromObject(run), current); err != nil {
		t.Fatal(err)
	}
	cleared, err := reconciler.clearNativeGuestBindingStatus(ctx, current)
	if err != nil || !cleared || boundary.calls != 1 {
		t.Fatalf("cleared=%v calls=%d err=%v", cleared, boundary.calls, err)
	}
	updated := &nvtv1alpha1.AgentRun{}
	if err := kubernetes.Get(ctx, client.ObjectKeyFromObject(run), updated); err != nil {
		t.Fatal(err)
	}
	if updated.Status.NativeGuestBinding != nil {
		t.Fatal("binding remained after acknowledged withdrawal")
	}
}

func TestNativeEgressWithdrawalCrashCannotResurrectTargetOnBootstrap(t *testing.T) {
	ctx := context.Background()
	run := readyNativeEgressRun("crash-withdraw", "88888888-8888-8888-8888-888888888888", "guest-crash-withdraw")
	pod, service := readyTargetObjects(run)
	scheme := testScheme(t)
	base := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(run).WithObjects(run, pod, service).Build()
	kubernetes := &failNthStatusClient{Client: base, failAt: 2}
	binding, err := exactNativeEgressBinding(run)
	if err != nil {
		t.Fatal(err)
	}
	initialTargets, initialDigest, err := nativeegress.CanonicalTargetSnapshot([]nativeegress.PublishedTarget{nativeEgressPublishedTarget(run, binding)})
	if err != nil || len(initialTargets) != 1 {
		t.Fatalf("initial target: %#v, %v", initialTargets, err)
	}
	authority := &recordingTargetAuthority{status: nativeegress.TargetStatus{
		ContractVersion: nativeegress.TargetPublicationVersion, Type: nativeegress.TargetPublicationStatusResponse,
		Published: true, Generation: 1, Digest: initialDigest, TargetCount: 1,
	}}
	coordinator := mustNativeEgressTargetCoordinator(t, kubernetes, authority)
	reconciler := &AgentRunReconciler{Client: kubernetes, Scheme: scheme, nativeEgressTargets: coordinator}
	current := &nvtv1alpha1.AgentRun{}
	if err := kubernetes.Get(ctx, client.ObjectKeyFromObject(run), current); err != nil {
		t.Fatal(err)
	}
	if err := reconciler.withdrawNativeEgressTarget(ctx, current); err == nil {
		t.Fatal("expected injected failure after relay acknowledgement")
	}
	stored := &nvtv1alpha1.AgentRun{}
	if err := base.Get(ctx, client.ObjectKeyFromObject(run), stored); err != nil {
		t.Fatal(err)
	}
	condition := meta.FindStatusCondition(stored.Status.Conditions, ConditionNativeEgressReady)
	if condition == nil || condition.Status != metav1.ConditionFalse || condition.Reason != "NativeEgressWithdrawalPending" {
		t.Fatalf("durable withdrawal intent was lost: %#v", condition)
	}
	if len(authority.snapshots) != 1 || len(authority.snapshots[0].Targets) != 0 {
		t.Fatalf("relay withdrawal was not acknowledged: %#v", authority.snapshots)
	}
	restarted := mustNativeEgressTargetCoordinator(t, base, authority)
	if err := restarted.Reconcile(ctx, nil, ""); err != nil {
		t.Fatal(err)
	}
	if last := authority.snapshots[len(authority.snapshots)-1]; len(last.Targets) != 0 {
		t.Fatalf("bootstrap resurrected withdrawn target: %#v", last)
	}
}

func TestNativeEgressTerminalEntryPersistsWithdrawalBeforeRelay(t *testing.T) {
	ctx := context.Background()
	run := readyNativeEgressRun("terminal", "99999999-9999-9999-9999-999999999999", "guest-terminal")
	scheme := testScheme(t)
	kubernetes := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(run).WithObjects(run).Build()
	boundary := &recordingPublicationBoundary{check: func(target *nativeegress.PublishedTarget, exclude string) error {
		current := &nvtv1alpha1.AgentRun{}
		if err := kubernetes.Get(ctx, client.ObjectKeyFromObject(run), current); err != nil {
			t.Fatal(err)
		}
		condition := meta.FindStatusCondition(current.Status.Conditions, ConditionNativeEgressReady)
		if target != nil || exclude != string(run.UID) || condition == nil || condition.Status != metav1.ConditionFalse || condition.Reason != "NativeEgressWithdrawalPending" {
			t.Fatalf("terminal withdrawal ordering is invalid: target=%#v exclude=%q condition=%#v", target, exclude, condition)
		}
		return nil
	}}
	reconciler := &AgentRunReconciler{Client: kubernetes, Scheme: scheme, nativeEgressTargets: boundary}
	current := &nvtv1alpha1.AgentRun{}
	if err := kubernetes.Get(ctx, client.ObjectKeyFromObject(run), current); err != nil {
		t.Fatal(err)
	}
	if _, err := reconciler.recordExternalExecutionStatus(ctx, current, executiondriver.Status{Phase: executiondriver.PhaseSucceeded, ObservedGeneration: 1}, 1); err != nil {
		t.Fatal(err)
	}
	if boundary.calls != 1 {
		t.Fatalf("terminal withdrawal calls=%d", boundary.calls)
	}
	stored := &nvtv1alpha1.AgentRun{}
	if err := kubernetes.Get(ctx, client.ObjectKeyFromObject(run), stored); err != nil {
		t.Fatal(err)
	}
	if stored.Status.NativeGuestBinding != nil || stored.Status.Phase != nvtv1alpha1.AgentRunPhaseCompleted {
		t.Fatalf("terminal status did not complete after acknowledged withdrawal: %#v", stored.Status)
	}
}

func TestNativeEgressReadinessWaitsForInfrastructureConfinement(t *testing.T) {
	run := readyNativeEgressRun("pending", "44444444-4444-4444-4444-444444444444", "guest-pending")
	run.Status.Conditions = nil
	scheme := testScheme(t)
	kubernetes := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(run).WithObjects(run).Build()
	boundary := &recordingPublicationBoundary{}
	reconciler := &AgentRunReconciler{Client: kubernetes, Scheme: scheme, nativeEgressTargets: boundary}
	current := &nvtv1alpha1.AgentRun{}
	if err := kubernetes.Get(context.Background(), client.ObjectKeyFromObject(run), current); err != nil {
		t.Fatal(err)
	}
	result, err := reconciler.reconcileNativeEgress(context.Background(), current, executiondriver.Status{
		Phase: executiondriver.PhaseRunning, Ready: true, ObservedGeneration: 1,
		EgressConfinement: &executiondriver.EgressConfinementStatus{Boundary: executiondriver.EgressConfinementBoundaryInfrastructure, Ready: false},
	})
	if err != nil || result.RequeueAfter == 0 || boundary.calls != 0 {
		t.Fatalf("result=%#v calls=%d err=%v", result, boundary.calls, err)
	}
	updated := &nvtv1alpha1.AgentRun{}
	if err := kubernetes.Get(context.Background(), client.ObjectKeyFromObject(run), updated); err != nil {
		t.Fatal(err)
	}
	if condition := meta.FindStatusCondition(updated.Status.Conditions, ConditionNativeEgressReady); condition == nil || condition.Status != metav1.ConditionFalse {
		t.Fatalf("unexpected native egress condition: %#v", condition)
	}
}

func TestNativeEgressConfinementLossWithdrawsPublishedBinding(t *testing.T) {
	run := readyNativeEgressRun("lost", "66666666-6666-6666-6666-666666666666", "guest-lost")
	scheme := testScheme(t)
	kubernetes := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(run).WithObjects(run).Build()
	boundary := &recordingPublicationBoundary{check: func(target *nativeegress.PublishedTarget, exclude string) error {
		if target != nil || exclude != string(run.UID) {
			t.Fatal("confinement loss did not withdraw the exact target")
		}
		current := &nvtv1alpha1.AgentRun{}
		if err := kubernetes.Get(context.Background(), client.ObjectKeyFromObject(run), current); err != nil {
			t.Fatal(err)
		}
		condition := meta.FindStatusCondition(current.Status.Conditions, ConditionNativeEgressReady)
		if condition == nil || condition.Status != metav1.ConditionFalse || condition.Reason != "NativeEgressWithdrawalPending" {
			t.Fatalf("confinement withdrawal was not durable before relay mutation: %#v", condition)
		}
		return nil
	}}
	reconciler := &AgentRunReconciler{Client: kubernetes, Scheme: scheme, nativeEgressTargets: boundary}
	current := &nvtv1alpha1.AgentRun{}
	if err := kubernetes.Get(context.Background(), client.ObjectKeyFromObject(run), current); err != nil {
		t.Fatal(err)
	}
	if _, err := reconciler.reconcileNativeEgress(context.Background(), current, executiondriver.Status{
		Phase: executiondriver.PhaseRunning, Ready: false, ObservedGeneration: 1,
		EgressConfinement: &executiondriver.EgressConfinementStatus{Boundary: executiondriver.EgressConfinementBoundaryInfrastructure, Ready: false},
	}); err != nil {
		t.Fatal(err)
	}
	if boundary.calls != 1 {
		t.Fatalf("withdraw calls=%d", boundary.calls)
	}
	updated := &nvtv1alpha1.AgentRun{}
	if err := kubernetes.Get(context.Background(), client.ObjectKeyFromObject(run), updated); err != nil {
		t.Fatal(err)
	}
	if meta.IsStatusConditionTrue(updated.Status.Conditions, ConditionNativeEgressReady) {
		t.Fatal("native egress remained ready after confinement loss")
	}
}

func TestNativeEgressPendingWithdrawalRetriesRelayUntilAcknowledged(t *testing.T) {
	ctx := context.Background()
	run := readyNativeEgressRun("retry-withdraw", "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "guest-retry-withdraw")
	scheme := testScheme(t)
	kubernetes := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(run).WithObjects(run).Build()
	boundary := &recordingPublicationBoundary{}
	boundary.check = func(*nativeegress.PublishedTarget, string) error {
		if boundary.calls == 1 {
			return errors.New("relay unavailable")
		}
		return nil
	}
	reconciler := &AgentRunReconciler{Client: kubernetes, Scheme: scheme, nativeEgressTargets: boundary}
	status := executiondriver.Status{
		Phase: executiondriver.PhaseRunning, Ready: false, ObservedGeneration: 1,
		EgressConfinement: &executiondriver.EgressConfinementStatus{Boundary: executiondriver.EgressConfinementBoundaryInfrastructure, Ready: false},
	}
	current := &nvtv1alpha1.AgentRun{}
	if err := kubernetes.Get(ctx, client.ObjectKeyFromObject(run), current); err != nil {
		t.Fatal(err)
	}
	if _, err := reconciler.reconcileNativeEgress(ctx, current, status); err == nil {
		t.Fatal("expected first withdrawal attempt to fail")
	}
	pending := &nvtv1alpha1.AgentRun{}
	if err := kubernetes.Get(ctx, client.ObjectKeyFromObject(run), pending); err != nil {
		t.Fatal(err)
	}
	condition := meta.FindStatusCondition(pending.Status.Conditions, ConditionNativeEgressReady)
	if condition == nil || condition.Status != metav1.ConditionFalse || condition.Reason != "NativeEgressWithdrawalPending" {
		t.Fatalf("failed withdrawal did not stay durably pending: %#v", condition)
	}
	if _, err := reconciler.reconcileNativeEgress(ctx, pending, status); err != nil {
		t.Fatal(err)
	}
	if boundary.calls != 2 {
		t.Fatalf("withdrawal calls=%d, want retry", boundary.calls)
	}
	withdrawn := &nvtv1alpha1.AgentRun{}
	if err := kubernetes.Get(ctx, client.ObjectKeyFromObject(run), withdrawn); err != nil {
		t.Fatal(err)
	}
	condition = meta.FindStatusCondition(withdrawn.Status.Conditions, ConditionNativeEgressReady)
	if condition == nil || condition.Status != metav1.ConditionFalse || condition.Reason != "NativeEgressWithdrawn" {
		t.Fatalf("retried withdrawal was not acknowledged: %#v", condition)
	}
}

func TestPodRunNeverUsesNativeEgressPublication(t *testing.T) {
	run := readyNativeEgressRun("pod", "55555555-5555-5555-5555-555555555555", "guest-pod")
	run.Spec.Execution = nil
	run.Status.NativeGuestBinding = nil
	boundary := &recordingPublicationBoundary{}
	reconciler := &AgentRunReconciler{nativeEgressTargets: boundary}
	if _, err := reconciler.reconcileNativeEgress(context.Background(), run, executiondriver.Status{}); err != nil {
		t.Fatal(err)
	}
	if boundary.calls != 0 {
		t.Fatal("Pod path touched native egress publication")
	}
}

func readyNativeEgressRun(name, uid, guest string) *nvtv1alpha1.AgentRun {
	run := &nvtv1alpha1.AgentRun{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "nvt", UID: types.UID(uid), Generation: 1},
		Spec: nvtv1alpha1.AgentRunSpec{
			Execution: &nvtv1alpha1.AgentRunExecution{Kind: nvtv1alpha1.AgentRunExecutionVM, Driver: "example-vm"},
			Egress:    nvtv1alpha1.AgentRunEgressMediated, EgressEnforcement: true, EgressTransport: nvtv1alpha1.AgentRunEgressTransportTransparent,
		},
		Status: nvtv1alpha1.AgentRunStatus{Phase: nvtv1alpha1.AgentRunPhaseRunning},
	}
	executionID, _ := externalExecutionID(run.UID)
	run.Status.NativeGuestBinding = &nvtv1alpha1.AgentRunNativeGuestBinding{
		AgentRunUID: uid, ExecutionID: executionID, DriverRegistration: "example-vm", DesiredGeneration: 1, GuestInstanceID: guest,
	}
	nativeEgressCondition(run, metav1.ConditionTrue, nativeEgressReadyReason, "ready")
	return run
}

func readyTargetObjects(run *nvtv1alpha1.AgentRun) (*corev1.Pod, *corev1.Service) {
	controller, block := true, true
	owner := metav1.OwnerReference{APIVersion: nvtv1alpha1.GroupVersion.String(), Kind: "AgentRun", Name: run.Name, UID: run.UID, Controller: &controller, BlockOwnerDeletion: &block}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: EgressdPodName(run.Name), Namespace: run.Namespace, OwnerReferences: []metav1.OwnerReference{owner}},
		Status:     corev1.PodStatus{Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}},
	}
	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: EgressdServiceName(run.Name), Namespace: run.Namespace, OwnerReferences: []metav1.OwnerReference{owner}},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{agentRunLabelKey: run.Name, roleLabelKey: roleLabelEgressd},
			Ports:    []corev1.ServicePort{{Name: "forward-proxy", Port: egressForwardProxyPort}},
		},
	}
	return pod, service
}
