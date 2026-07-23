package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/yaml"

	nvtv1alpha1 "github.com/mirkoSekulic/nvt-agent/operator/api/v1alpha1"
)

func TestAgentScheduleAPIDeepCopyAndScheme(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := nvtv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("add nvt scheme: %v", err)
	}

	schedule := testAgentSchedule()
	now := metav1.Now()
	schedule.Status.LastAcceptedAt = &now
	copyObject := schedule.DeepCopyObject()
	copied, ok := copyObject.(*nvtv1alpha1.AgentSchedule)
	if !ok {
		t.Fatalf("expected AgentSchedule deepcopy object, got %T", copyObject)
	}
	copied.Status.LastAcceptedAt.Time = copied.Status.LastAcceptedAt.Time.Add(1)
	if schedule.Status.LastAcceptedAt.Equal(copied.Status.LastAcceptedAt) {
		t.Fatal("expected status timestamp to be deep-copied")
	}
	workspaceSize := resource.MustParse("5Gi")
	schedule.Spec.Template = &nvtv1alpha1.AgentScheduleTemplate{}
	schedule.Spec.Template.Workspace = nvtv1alpha1.AgentRunWorkspace{Mode: nvtv1alpha1.AgentRunWorkspacePersistent, Size: &workspaceSize}
	schedule.Spec.Template.Resources = corev1.ResourceRequirements{
		Limits: corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("8Gi")},
	}
	tolerationSeconds := int64(90)
	schedule.Spec.Template.Tolerations = []corev1.Toleration{{
		Key: "purpose", Operator: corev1.TolerationOpEqual, Value: "nvt-agent",
		Effect: corev1.TaintEffectNoExecute, TolerationSeconds: &tolerationSeconds,
	}}
	copied = schedule.DeepCopyObject().(*nvtv1alpha1.AgentSchedule)
	copied.Spec.Template.Workspace.Size.Add(resource.MustParse("1Gi"))
	copied.Spec.Template.Resources.Limits[corev1.ResourceMemory] = resource.MustParse("1Gi")
	copied.Spec.Template.Tolerations[0].Key = "changed"
	*copied.Spec.Template.Tolerations[0].TolerationSeconds = 1
	if schedule.Spec.Template.Workspace.Size.Cmp(resource.MustParse("5Gi")) != 0 {
		t.Fatal("expected template workspace quantity to be deep-copied")
	}
	if schedule.Spec.Template.Resources.Limits.Memory().Cmp(resource.MustParse("8Gi")) != 0 {
		t.Fatal("expected template resources to be deep-copied")
	}
	if schedule.Spec.Template.Tolerations[0].Key != "purpose" || *schedule.Spec.Template.Tolerations[0].TolerationSeconds != tolerationSeconds {
		t.Fatal("expected template tolerations to be deep-copied")
	}
	raw, err := json.Marshal(schedule)
	if err != nil {
		t.Fatalf("marshal schedule: %v", err)
	}
	var roundTripped nvtv1alpha1.AgentSchedule
	if err := json.Unmarshal(raw, &roundTripped); err != nil {
		t.Fatalf("unmarshal schedule: %v", err)
	}
	if !reflect.DeepEqual(roundTripped.Spec.Template.Tolerations, schedule.Spec.Template.Tolerations) {
		t.Fatalf("tolerations changed across API round trip: %#v", roundTripped.Spec.Template.Tolerations)
	}
	if _, _, err := scheme.ObjectKinds(&nvtv1alpha1.AgentScheduleList{}); err != nil {
		t.Fatalf("AgentScheduleList not registered in scheme: %v", err)
	}
	kinds, _, err := scheme.ObjectKinds(&metav1.ListOptions{})
	if err != nil {
		t.Fatalf("ListOptions not registered in nvt scheme: %v", err)
	}
	if len(kinds) != 1 || kinds[0].GroupVersion() != nvtv1alpha1.GroupVersion {
		t.Fatalf("expected ListOptions registered for %s, got %#v", nvtv1alpha1.GroupVersion, kinds)
	}
}

func TestAgentScheduleCRDSchemaIncludesSpecAndStatus(t *testing.T) {
	data, err := os.ReadFile("../../config/crd/bases/nvt.dev_agentschedules.yaml")
	if err != nil {
		t.Fatalf("read AgentSchedule CRD: %v", err)
	}
	assertStrictCRDSchema(t, data)
	chartData, err := os.ReadFile("../../../charts/nvt/crds/nvt.dev_agentschedules.yaml")
	if err != nil || !bytes.Equal(data, chartData) {
		t.Fatalf("generated and Helm AgentSchedule CRDs differ: %v", err)
	}
	var crd map[string]any
	if err := yaml.Unmarshal(data, &crd); err != nil {
		t.Fatalf("parse AgentSchedule CRD: %v", err)
	}

	properties := crdPath(t, crd,
		"spec", "versions", 0, "schema", "openAPIV3Schema", "properties",
		"spec", "properties",
	).(map[string]any)
	if crdPath(t, properties, "maxParallelism", "type") != "integer" {
		t.Fatalf("expected spec.maxParallelism integer schema, got %#v", properties["maxParallelism"])
	}
	if crdPath(t, properties, "profiles", "items", "properties", "agentRuntimeConfig", "x-kubernetes-preserve-unknown-fields") != true {
		t.Fatalf("expected profile runtime config preservation schema, got %#v", properties["profiles"])
	}
	profileProperties := crdPath(t, properties, "profiles", "items", "properties").(map[string]any)
	legacy := crdPath(t, profileProperties, "egressForwardProxy").(map[string]any)
	if legacy["type"] != "boolean" || !strings.Contains(fmt.Sprint(legacy["description"]), "Deprecated:") {
		t.Fatalf("legacy profile egressForwardProxy must remain only as a deprecated tombstone: %#v", legacy)
	}
	validations := crdPath(t, properties, "profiles", "items", "x-kubernetes-validations").([]any)
	if !hasCRDValidation(validations, "!has(self.egressForwardProxy)", "use egressTransport") {
		t.Fatalf("missing profile rejection CEL for legacy egressForwardProxy: %#v", validations)
	}
	transport := crdPath(t, profileProperties, "egressTransport").(map[string]any)
	if !reflect.DeepEqual(transport["enum"], []any{"redirect", "forward-proxy", "transparent"}) {
		t.Fatalf("expected profile egressTransport to be the sole transport selector, got %#v", transport)
	}
	if crdPath(t, properties, "profileSelection", "properties", "onNoMatch", "type") != "string" {
		t.Fatalf("expected profileSelection.onNoMatch schema, got %#v", properties["profileSelection"])
	}
	if crdPath(t, properties, "allowedProducers", "items", "type") != "string" {
		t.Fatalf("expected allowedProducers string schema, got %#v", properties["allowedProducers"])
	}
	workspace := crdPath(t, properties, "template", "properties", "workspace").(map[string]any)
	if crdPath(t, workspace, "properties", "mode", "default") != "Ephemeral" ||
		crdPath(t, workspace, "properties", "size", "x-kubernetes-int-or-string") != true ||
		crdPath(t, workspace, "properties", "storageClassName", "type") != "string" {
		t.Fatalf("expected persistent template workspace schema, got %#v", workspace)
	}
	tolerations := crdPath(t, properties, "template", "properties", "tolerations").(map[string]any)
	if tolerations["type"] != "array" || crdPath(t, tolerations, "items", "properties", "effect", "type") != "string" {
		t.Fatalf("template tolerations schema incomplete: %#v", tolerations)
	}
	status := crdPath(t, crd,
		"spec", "versions", 0, "schema", "openAPIV3Schema", "properties",
		"status", "properties",
	).(map[string]any)
	if crdPath(t, status, "observedGeneration", "type") != "integer" {
		t.Fatalf("expected status.observedGeneration integer schema, got %#v", status["observedGeneration"])
	}
}

func TestAgentScheduleReconcileSetsObservedGenerationAndActiveRuns(t *testing.T) {
	ctx := context.Background()
	scheme := testScheme(t)
	schedule := testAgentSchedule()
	schedule.Generation = 7
	runs := []client.Object{
		scheduledRun("empty", schedule, "", ""),
		scheduledRun("pending", schedule, "", nvtv1alpha1.AgentRunPhasePending),
		scheduledRun("running", schedule, "", nvtv1alpha1.AgentRunPhaseRunning),
		scheduledRun("completed", schedule, "", nvtv1alpha1.AgentRunPhaseCompleted),
		scheduledRun("failed", schedule, "", nvtv1alpha1.AgentRunPhaseFailed),
		scheduledRun("deadline", schedule, "", nvtv1alpha1.AgentRunPhaseDeadlineExceeded),
	}
	objects := append([]client.Object{schedule}, runs...)
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&nvtv1alpha1.AgentSchedule{}, &nvtv1alpha1.AgentRun{}).
		WithObjects(objects...).
		Build()
	reconciler := &AgentScheduleReconciler{Client: k8sClient, Scheme: scheme}

	_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKeyForSchedule(schedule)})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	updated := getAgentSchedule(ctx, t, k8sClient, schedule)
	if updated.Status.ObservedGeneration != 7 {
		t.Fatalf("expected observedGeneration 7, got %d", updated.Status.ObservedGeneration)
	}
	if updated.Status.ActiveRuns != 3 {
		t.Fatalf("expected 3 active runs, got %d", updated.Status.ActiveRuns)
	}
}

func TestScheduleAdmissionCreatesAgentRunUnderCapacity(t *testing.T) {
	fixture := scheduleAdmissionFixture(t, testAgentSchedule())
	body := scheduleAdmissionBody(t, "work-1", "https://example.test/work/1", map[string]any{
		"metadata": map[string]any{
			"namespace":    "other",
			"generateName": "github-issue-",
			"labels": map[string]any{
				scheduleLabel: "user-value",
				"keep":        "label",
			},
			"annotations": map[string]any{
				workIDAnnotation:  "user-work",
				workURLAnnotation: "https://example.test/user",
				"keep":            "annotation",
			},
		},
	})

	response, k8sClient := serveScheduleAdmission(t, fixture, body)

	var decoded scheduleAdmissionResponse
	decodeAdmissionResponse(t, response, http.StatusCreated, &decoded)
	if !decoded.Scheduled || decoded.AgentRun == nil {
		t.Fatalf("expected scheduled response, got %#v", decoded)
	}
	if decoded.AgentRun.Namespace != fixture.schedule.Namespace || !strings.HasPrefix(decoded.AgentRun.Name, "github-issue-") {
		t.Fatalf("unexpected AgentRun response: %#v", decoded.AgentRun)
	}
	run := getScheduledAgentRun(context.Background(), t, k8sClient, decoded.AgentRun.Namespace, decoded.AgentRun.Name)
	if run.Namespace != fixture.schedule.Namespace {
		t.Fatalf("expected forced namespace %q, got %q", fixture.schedule.Namespace, run.Namespace)
	}
	assertOwnedByAgentSchedule(t, run.OwnerReferences, fixture.schedule)
	if run.Labels[scheduleLabel] != fixture.schedule.Name || run.Labels["keep"] != "label" {
		t.Fatalf("unexpected labels: %#v", run.Labels)
	}
	if run.Annotations[workIDAnnotation] != "work-1" ||
		run.Annotations[workURLAnnotation] != "https://example.test/work/1" ||
		run.Annotations["keep"] != "annotation" {
		t.Fatalf("unexpected annotations: %#v", run.Annotations)
	}
	if run.Annotations[accessKeyAnnotation] != run.Name ||
		run.Annotations[displayNameAnnotation] != "Work work-1" ||
		run.Annotations[sourceURLAnnotation] != "https://example.test/work/1" ||
		run.Annotations[accessPortAnnotation] != "4090" {
		t.Fatalf("unexpected gateway annotations: %#v", run.Annotations)
	}
}

func TestScheduleAdmissionPreservesExplicitGatewayAnnotations(t *testing.T) {
	fixture := scheduleAdmissionFixture(t, testAgentSchedule())
	body := scheduleAdmissionBody(t, "work-1", "https://example.test/work/1", map[string]any{
		"metadata": map[string]any{
			"annotations": map[string]any{
				displayNameAnnotation: "Custom display",
				accessPortAnnotation:  "4999",
			},
		},
	})

	response, k8sClient := serveScheduleAdmission(t, fixture, body)

	var decoded scheduleAdmissionResponse
	decodeAdmissionResponse(t, response, http.StatusCreated, &decoded)
	run := getScheduledAgentRun(context.Background(), t, k8sClient, decoded.AgentRun.Namespace, decoded.AgentRun.Name)
	if run.Annotations[displayNameAnnotation] != "Custom display" ||
		run.Annotations[accessPortAnnotation] != "4999" ||
		run.Annotations[accessKeyAnnotation] != run.Name {
		t.Fatalf("unexpected gateway annotations: %#v", run.Annotations)
	}
}

func TestScheduleAdmissionDefaultsGenerateName(t *testing.T) {
	fixture := scheduleAdmissionFixture(t, testAgentSchedule())
	body := scheduleAdmissionBody(t, "work-1", "", map[string]any{
		"metadata": map[string]any{"generateName": ""},
	})

	response, _ := serveScheduleAdmission(t, fixture, body)

	var decoded scheduleAdmissionResponse
	decodeAdmissionResponse(t, response, http.StatusCreated, &decoded)
	if decoded.AgentRun == nil || !strings.HasPrefix(decoded.AgentRun.Name, "default-") {
		t.Fatalf("expected default generated name, got %#v", decoded.AgentRun)
	}
}

func TestScheduleAdmissionMaxParallelismCreatesNoRun(t *testing.T) {
	schedule := testAgentSchedule()
	schedule.Spec.MaxParallelism = 1
	fixture := scheduleAdmissionFixture(t, schedule, scheduledRun("active", schedule, "existing", nvtv1alpha1.AgentRunPhaseRunning))

	response, k8sClient := serveScheduleAdmission(t, fixture, scheduleAdmissionBody(t, "new-work", "", nil))

	var decoded scheduleAdmissionResponse
	decodeAdmissionResponse(t, response, http.StatusTooManyRequests, &decoded)
	if decoded.Scheduled || decoded.Reason != "max-parallelism-reached" {
		t.Fatalf("unexpected response: %#v", decoded)
	}
	assertScheduledRunCount(t, k8sClient, schedule, 1)
}

func TestScheduleAdmissionDuplicateActiveWorkCreatesNoRun(t *testing.T) {
	schedule := testAgentSchedule()
	schedule.Spec.MaxParallelism = 2
	fixture := scheduleAdmissionFixture(t, schedule, scheduledRun("active", schedule, "same-work", nvtv1alpha1.AgentRunPhasePending))

	response, k8sClient := serveScheduleAdmission(t, fixture, scheduleAdmissionBody(t, "same-work", "", nil))

	var decoded scheduleAdmissionResponse
	decodeAdmissionResponse(t, response, http.StatusAccepted, &decoded)
	if decoded.Scheduled || decoded.Reason != "duplicate-work" {
		t.Fatalf("unexpected response: %#v", decoded)
	}
	assertScheduledRunCount(t, k8sClient, schedule, 1)
}

func TestScheduleAdmissionTerminalSameWorkCreatesNoRun(t *testing.T) {
	schedule := testAgentSchedule()
	schedule.Spec.MaxParallelism = 2
	fixture := scheduleAdmissionFixture(t, schedule, scheduledRun("done", schedule, "same-work", nvtv1alpha1.AgentRunPhaseCompleted))

	response, k8sClient := serveScheduleAdmission(t, fixture, scheduleAdmissionBody(t, "same-work", "", nil))

	var decoded scheduleAdmissionResponse
	decodeAdmissionResponse(t, response, http.StatusAccepted, &decoded)
	if decoded.Scheduled || decoded.Reason != "duplicate-work" {
		t.Fatalf("expected retained terminal same work to be duplicate, got %#v", decoded)
	}
	assertScheduledRunCount(t, k8sClient, schedule, 1)
}

func TestScheduleAdmissionTerminalDifferentWorkDoesNotConsumeCapacity(t *testing.T) {
	schedule := testAgentSchedule()
	schedule.Spec.MaxParallelism = 1
	fixture := scheduleAdmissionFixture(t, schedule, scheduledRun("done", schedule, "old-work", nvtv1alpha1.AgentRunPhaseCompleted))

	response, k8sClient := serveScheduleAdmission(t, fixture, scheduleAdmissionBody(t, "new-work", "", nil))

	var decoded scheduleAdmissionResponse
	decodeAdmissionResponse(t, response, http.StatusCreated, &decoded)
	if !decoded.Scheduled {
		t.Fatalf("expected new run when only terminal different work exists, got %#v", decoded)
	}
	assertScheduledRunCount(t, k8sClient, schedule, 2)
}

func TestScheduleAdmissionSuspendedCreatesNoRun(t *testing.T) {
	schedule := testAgentSchedule()
	schedule.Spec.Suspend = true
	fixture := scheduleAdmissionFixture(t, schedule)

	response, k8sClient := serveScheduleAdmission(t, fixture, scheduleAdmissionBody(t, "work-1", "", nil))

	var decoded scheduleAdmissionResponse
	decodeAdmissionResponse(t, response, http.StatusAccepted, &decoded)
	if decoded.Scheduled || decoded.Reason != "schedule-suspended" {
		t.Fatalf("unexpected response: %#v", decoded)
	}
	assertScheduledRunCount(t, k8sClient, schedule, 0)
}

func TestScheduleAdmissionMissingScheduleReturnsNotFound(t *testing.T) {
	fixture := scheduleAdmissionFixture(t, testAgentSchedule())
	fixture.objects = nil

	response, _ := serveScheduleAdmission(t, fixture, scheduleAdmissionBody(t, "work-1", "", nil))

	if response.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d body=%q", response.Code, response.Body.String())
	}
}

func TestScheduleAdmissionRejectsMalformedJSON(t *testing.T) {
	fixture := scheduleAdmissionFixture(t, testAgentSchedule())

	response, _ := serveScheduleAdmission(t, fixture, `{"work":`)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%q", response.Code, response.Body.String())
	}
}

func TestScheduleAdmissionRejectsMissingWorkID(t *testing.T) {
	fixture := scheduleAdmissionFixture(t, testAgentSchedule())

	response, _ := serveScheduleAdmission(t, fixture, scheduleAdmissionBody(t, "", "", nil))

	if response.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%q", response.Code, response.Body.String())
	}
}

func TestLegacyScheduleAdmissionRejectsInvalidPersistentWorkspaceBeforeCreate(t *testing.T) {
	for _, test := range []struct {
		name      string
		workspace map[string]any
		broker    map[string]any
		want      string
	}{
		{
			name:      "missing size",
			workspace: map[string]any{"mode": "Persistent"},
			want:      "spec.workspace.size must be a positive Kubernetes resource quantity",
		},
		{
			name:      "file bundle",
			workspace: map[string]any{"mode": "Persistent", "size": "5Gi"},
			broker: map[string]any{"grants": []any{map[string]any{
				"provider": "github-main", "repositories": []any{"example/*"}, "materialization": "file-bundle",
			}}},
			want: "persistent workspace is incompatible with broker grant github-main materialization file-bundle",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := scheduleAdmissionFixture(t, testAgentSchedule())
			spec := map[string]any{"workspace": test.workspace}
			if test.broker != nil {
				spec["broker"] = test.broker
			}
			response, k8sClient := serveScheduleAdmission(t, fixture, scheduleAdmissionBody(t, "invalid-workspace", "", map[string]any{"spec": spec}))
			var decoded scheduleAdmissionResponse
			decodeAdmissionResponse(t, response, http.StatusBadRequest, &decoded)
			if decoded.Scheduled || !strings.Contains(decoded.Reason, test.want) {
				t.Fatalf("response = %#v, want reason %q", decoded, test.want)
			}
			runs := &nvtv1alpha1.AgentRunList{}
			if err := k8sClient.List(context.Background(), runs, client.InNamespace(fixture.schedule.Namespace)); err != nil {
				t.Fatal(err)
			}
			if len(runs.Items) != 0 {
				t.Fatalf("invalid admission created AgentRuns: %#v", runs.Items)
			}
		})
	}
}

func TestLegacyScheduleAdmissionRejectsRemovedEgressForwardProxy(t *testing.T) {
	for _, value := range []bool{true, false} {
		t.Run(fmt.Sprintf("value-%t", value), func(t *testing.T) {
			fixture := scheduleAdmissionFixture(t, testAgentSchedule())
			response, k8sClient := serveScheduleAdmission(t, fixture, scheduleAdmissionBody(t,
				"legacy-egress-selector", "", map[string]any{"spec": map[string]any{"egressForwardProxy": value}}))
			var decoded scheduleAdmissionResponse
			decodeAdmissionResponse(t, response, http.StatusBadRequest, &decoded)
			if decoded.Scheduled || !strings.Contains(decoded.Reason, "egressForwardProxy is removed; use spec.egressTransport") {
				t.Fatalf("legacy value %t was not rejected explicitly: %#v", value, decoded)
			}
			assertScheduledRunCount(t, k8sClient, fixture.schedule, 0)
		})
	}
}

func TestScheduleAdmissionConcurrentRequestsCannotExceedMaxParallelism(t *testing.T) {
	schedule := testAgentSchedule()
	schedule.Spec.MaxParallelism = 1
	fixture := scheduleAdmissionFixture(t, schedule)
	requests := make([]string, 8)
	for i := range requests {
		requests[i] = scheduleAdmissionBody(t, "work-"+string(rune('a'+i)), "", nil)
	}

	responses, k8sClient := serveConcurrentScheduleAdmissions(t, fixture, requests)

	statusCounts := map[int]int{}
	for _, response := range responses {
		statusCounts[response.Code]++
	}
	if statusCounts[http.StatusCreated] != 1 {
		t.Fatalf("expected exactly one created response, got counts %#v", statusCounts)
	}
	if statusCounts[http.StatusTooManyRequests] != len(requests)-1 {
		t.Fatalf("expected remaining responses to be 429, got counts %#v", statusCounts)
	}
	assertScheduledRunCount(t, k8sClient, schedule, 1)
}

func TestScheduleAdmissionConcurrentDuplicateWorkCreatesOneRun(t *testing.T) {
	schedule := testAgentSchedule()
	schedule.Spec.MaxParallelism = 10
	fixture := scheduleAdmissionFixture(t, schedule)
	requests := make([]string, 8)
	for i := range requests {
		requests[i] = scheduleAdmissionBody(t, "same-work", "", nil)
	}

	responses, k8sClient := serveConcurrentScheduleAdmissions(t, fixture, requests)

	statusCounts := map[int]int{}
	reasonCounts := map[string]int{}
	for _, response := range responses {
		statusCounts[response.Code]++
		var decoded scheduleAdmissionResponse
		decodeAdmissionResponse(t, response, response.Code, &decoded)
		reasonCounts[decoded.Reason]++
	}
	if statusCounts[http.StatusCreated] != 1 {
		t.Fatalf("expected exactly one created response, got counts %#v", statusCounts)
	}
	if statusCounts[http.StatusAccepted] != len(requests)-1 || reasonCounts["duplicate-work"] != len(requests)-1 {
		t.Fatalf("expected remaining responses to be duplicate-work, status=%#v reasons=%#v", statusCounts, reasonCounts)
	}
	assertScheduledRunCount(t, k8sClient, schedule, 1)
}

type scheduleAdmissionTestFixture struct {
	schedule *nvtv1alpha1.AgentSchedule
	objects  []client.Object
}

func scheduleAdmissionFixture(
	t *testing.T,
	schedule *nvtv1alpha1.AgentSchedule,
	extraObjects ...client.Object,
) scheduleAdmissionTestFixture {
	t.Helper()

	objects := append([]client.Object{schedule}, extraObjects...)
	return scheduleAdmissionTestFixture{schedule: schedule, objects: objects}
}

func serveScheduleAdmission(
	t *testing.T,
	fixture scheduleAdmissionTestFixture,
	body string,
) (*httptest.ResponseRecorder, client.Client) {
	t.Helper()

	scheme := testScheme(t)
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&nvtv1alpha1.AgentSchedule{}, &nvtv1alpha1.AgentRun{}).
		WithObjects(fixture.objects...).
		Build()
	handler := &agentScheduleAdmissionHandler{
		client: k8sClient,
		scheme: scheme,
		now:    metav1.Now,
	}
	request := httptest.NewRequest(
		http.MethodPost,
		"/v1/schedules/"+fixture.schedule.Namespace+"/"+fixture.schedule.Name+"/admissions",
		bytes.NewBufferString(body),
	)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)
	return response, k8sClient
}

func serveConcurrentScheduleAdmissions(
	t *testing.T,
	fixture scheduleAdmissionTestFixture,
	bodies []string,
) ([]*httptest.ResponseRecorder, client.Client) {
	t.Helper()

	scheme := testScheme(t)
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&nvtv1alpha1.AgentSchedule{}, &nvtv1alpha1.AgentRun{}).
		WithObjects(fixture.objects...).
		Build()
	handler := &agentScheduleAdmissionHandler{
		client:         k8sClient,
		scheme:         scheme,
		now:            metav1.Now,
		admissionLocks: newScheduleAdmissionLocks(),
	}
	responses := make([]*httptest.ResponseRecorder, len(bodies))
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i, body := range bodies {
		wg.Add(1)
		go func(index int, requestBody string) {
			defer wg.Done()
			<-start
			request := httptest.NewRequest(
				http.MethodPost,
				"/v1/schedules/"+fixture.schedule.Namespace+"/"+fixture.schedule.Name+"/admissions",
				bytes.NewBufferString(requestBody),
			)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			responses[index] = response
		}(i, body)
	}
	close(start)
	wg.Wait()
	return responses, k8sClient
}

func scheduleAdmissionBody(t *testing.T, workID, workURL string, agentRunOverrides map[string]any) string {
	t.Helper()

	agentRun := map[string]any{
		"metadata": map[string]any{
			"generateName": "scheduled-",
		},
		"spec": map[string]any{
			"runtime": map[string]any{
				"type":     "codex",
				"autonomy": "trusted-local",
			},
			"image": "nvt-agent-runtime:test",
			"workspace": map[string]any{
				"mode": "Ephemeral",
			},
			"agent": map[string]any{
				"config": map[string]any{},
			},
		},
	}
	mergeMap(agentRun, agentRunOverrides)
	payload := map[string]any{
		"work": map[string]any{
			"id":    workID,
			"title": "Work " + workID,
			"url":   workURL,
		},
		"agentRun": agentRun,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func testAgentSchedule() *nvtv1alpha1.AgentSchedule {
	return &nvtv1alpha1.AgentSchedule{
		TypeMeta: metav1.TypeMeta{
			APIVersion: nvtv1alpha1.GroupVersion.String(),
			Kind:       "AgentSchedule",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "default",
			Namespace: "nvt",
			UID:       "agentschedule-uid",
		},
		Spec: nvtv1alpha1.AgentScheduleSpec{MaxParallelism: 5},
	}
}

func scheduledRun(name string, schedule *nvtv1alpha1.AgentSchedule, workID string, phase nvtv1alpha1.AgentRunPhase) *nvtv1alpha1.AgentRun {
	run := testAgentRun()
	run.Name = name
	run.Namespace = schedule.Namespace
	run.Labels = map[string]string{scheduleLabel: schedule.Name}
	run.Annotations = map[string]string{}
	if workID != "" {
		run.Annotations[workIDAnnotation] = workID
	}
	run.Status.Phase = phase
	return run
}

func getAgentSchedule(ctx context.Context, t *testing.T, k8sClient client.Client, schedule *nvtv1alpha1.AgentSchedule) nvtv1alpha1.AgentSchedule {
	t.Helper()

	var updated nvtv1alpha1.AgentSchedule
	if err := k8sClient.Get(ctx, clientKeyForSchedule(schedule), &updated); err != nil {
		t.Fatalf("get AgentSchedule: %v", err)
	}
	return updated
}

func clientKeyForSchedule(schedule *nvtv1alpha1.AgentSchedule) types.NamespacedName {
	return types.NamespacedName{Name: schedule.Name, Namespace: schedule.Namespace}
}

func getScheduledAgentRun(ctx context.Context, t *testing.T, k8sClient client.Client, namespace, name string) nvtv1alpha1.AgentRun {
	t.Helper()

	var run nvtv1alpha1.AgentRun
	if err := k8sClient.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, &run); err != nil {
		t.Fatalf("get scheduled AgentRun: %v", err)
	}
	return run
}

func assertScheduledRunCount(t *testing.T, k8sClient client.Client, schedule *nvtv1alpha1.AgentSchedule, want int) {
	t.Helper()

	runs, err := ListScheduledRuns(context.Background(), k8sClient, schedule)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs.Items) != want {
		t.Fatalf("expected %d scheduled AgentRuns, got %d: %#v", want, len(runs.Items), runs.Items)
	}
}

func assertOwnedByAgentSchedule(t *testing.T, ownerReferences []metav1.OwnerReference, schedule *nvtv1alpha1.AgentSchedule) {
	t.Helper()

	for _, owner := range ownerReferences {
		if owner.APIVersion == nvtv1alpha1.GroupVersion.String() &&
			owner.Kind == "AgentSchedule" &&
			owner.Name == schedule.Name &&
			owner.UID == schedule.UID {
			return
		}
	}
	t.Fatalf("expected owner reference for AgentSchedule %s, got %#v", schedule.Name, ownerReferences)
}

func decodeAdmissionResponse(t *testing.T, response *httptest.ResponseRecorder, wantStatus int, target *scheduleAdmissionResponse) {
	t.Helper()

	if response.Code != wantStatus {
		t.Fatalf("expected status %d, got %d body=%q", wantStatus, response.Code, response.Body.String())
	}
	if err := json.NewDecoder(response.Body).Decode(target); err != nil {
		t.Fatalf("decode response: %v body=%q", err, response.Body.String())
	}
}

func mergeMap(target, overrides map[string]any) {
	for key, value := range overrides {
		valueMap, valueIsMap := value.(map[string]any)
		targetMap, targetIsMap := target[key].(map[string]any)
		if valueIsMap && targetIsMap {
			mergeMap(targetMap, valueMap)
			continue
		}
		target[key] = value
	}
}
