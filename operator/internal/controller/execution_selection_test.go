package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/yaml"

	nvtv1alpha1 "github.com/mirkoSekulic/nvt-agent/operator/api/v1alpha1"
)

func requestFor(agentRun *nvtv1alpha1.AgentRun) ctrl.Request {
	return ctrl.Request{NamespacedName: client.ObjectKeyFromObject(agentRun)}
}

func TestProfileExecutionSelectionSnapshotsClassConfiguration(t *testing.T) {
	schedule := testProfiledAgentSchedule()
	schedule.Spec.ExecutionClasses = []nvtv1alpha1.AgentScheduleExecutionClass{{
		Name: "vm-standard", Kind: nvtv1alpha1.AgentRunExecutionVM, Driver: "example-vm",
		Configuration: rawJSON(`{"cpu":4,"network":{"isolation":"required"}}`),
	}}
	schedule.Spec.Profiles[0].Execution = &nvtv1alpha1.AgentScheduleExecutionSelection{
		Kind: nvtv1alpha1.AgentRunExecutionVM, Driver: "example-vm", ClassRef: "vm-standard",
	}

	copy := schedule.DeepCopyObject().(*nvtv1alpha1.AgentSchedule)
	copy.Spec.ExecutionClasses[0].Configuration.Raw[7] = '8'
	copy.Spec.Profiles[0].Execution.Driver = "changed"
	if bytes.Equal(copy.Spec.ExecutionClasses[0].Configuration.Raw, schedule.Spec.ExecutionClasses[0].Configuration.Raw) ||
		schedule.Spec.Profiles[0].Execution.Driver != "example-vm" {
		t.Fatal("execution class/profile selection was not deep-copied")
	}

	fixture := newProfileAdmissionFixture(t, schedule)
	response := fixture.serve(t, profiledAdmissionBody(t, "external-execution", nil, nil), "Bearer projected-token")
	var decoded scheduleAdmissionResponse
	decodeAdmissionResponse(t, response, 201, &decoded)
	run := fixture.run(t, decoded.AgentRun.Name)
	if run.Spec.Execution == nil || run.Spec.Execution.Kind != nvtv1alpha1.AgentRunExecutionVM ||
		run.Spec.Execution.Driver != "example-vm" || run.Spec.Execution.ClassRef != "vm-standard" ||
		!bytes.Equal(run.Spec.Execution.Configuration.Raw, schedule.Spec.ExecutionClasses[0].Configuration.Raw) {
		t.Fatalf("execution selection was not snapshotted exactly: %#v", run.Spec.Execution)
	}

	schedule.Spec.ExecutionClasses[0].Configuration.Raw[7] = '9'
	if bytes.Equal(run.Spec.Execution.Configuration.Raw, schedule.Spec.ExecutionClasses[0].Configuration.Raw) {
		t.Fatal("resolved AgentRun execution configuration aliases the schedule class")
	}
	runCopy := run.DeepCopyObject().(*nvtv1alpha1.AgentRun)
	runCopy.Spec.Execution.Configuration.Raw[7] = '7'
	if bytes.Equal(runCopy.Spec.Execution.Configuration.Raw, run.Spec.Execution.Configuration.Raw) {
		t.Fatal("AgentRun execution configuration was not deep-copied")
	}
	raw, err := json.Marshal(&run)
	if err != nil {
		t.Fatal(err)
	}
	var roundTripped nvtv1alpha1.AgentRun
	if err := json.Unmarshal(raw, &roundTripped); err != nil || !reflect.DeepEqual(roundTripped.Spec.Execution, run.Spec.Execution) {
		t.Fatalf("execution snapshot did not round-trip: err=%v got=%#v", err, roundTripped.Spec.Execution)
	}
	storedSchedule := &nvtv1alpha1.AgentSchedule{}
	if err := fixture.client.Get(context.Background(), client.ObjectKeyFromObject(schedule), storedSchedule); err != nil {
		t.Fatal(err)
	}
	storedSchedule.Spec.ExecutionClasses[0].Configuration = rawJSON(`{"cpu":32}`)
	if err := fixture.client.Update(context.Background(), storedSchedule); err != nil {
		t.Fatal(err)
	}
	unchanged := fixture.run(t, run.Name)
	if !bytes.Equal(unchanged.Spec.Execution.Configuration.Raw, run.Spec.Execution.Configuration.Raw) {
		t.Fatalf("existing AgentRun execution snapshot changed after schedule mutation: %s", unchanged.Spec.Execution.Configuration.Raw)
	}
}

func TestProfileExecutionOmissionAndExplicitKubernetesSnapshot(t *testing.T) {
	omitted := testProfiledAgentSchedule()
	omittedFixture := newProfileAdmissionFixture(t, omitted)
	omittedResponse := omittedFixture.serve(t, profiledAdmissionBody(t, "omitted-execution", nil, nil), "Bearer projected-token")
	var omittedDecoded scheduleAdmissionResponse
	decodeAdmissionResponse(t, omittedResponse, 201, &omittedDecoded)
	if run := omittedFixture.run(t, omittedDecoded.AgentRun.Name); run.Spec.Execution != nil {
		t.Fatalf("omitted profile execution changed the stored compatibility shape: %#v", run.Spec.Execution)
	}

	explicit := testProfiledAgentSchedule()
	explicit.Spec.Profiles[0].Execution = &nvtv1alpha1.AgentScheduleExecutionSelection{
		Kind: nvtv1alpha1.AgentRunExecutionPod, Driver: builtInKubernetesDriver,
	}
	explicitFixture := newProfileAdmissionFixture(t, explicit)
	explicitResponse := explicitFixture.serve(t, profiledAdmissionBody(t, "explicit-execution", nil, nil), "Bearer projected-token")
	var explicitDecoded scheduleAdmissionResponse
	decodeAdmissionResponse(t, explicitResponse, 201, &explicitDecoded)
	run := explicitFixture.run(t, explicitDecoded.AgentRun.Name)
	if run.Spec.Execution == nil || run.Spec.Execution.Kind != nvtv1alpha1.AgentRunExecutionPod ||
		run.Spec.Execution.Driver != builtInKubernetesDriver || run.Spec.Execution.ClassRef != "" || len(run.Spec.Execution.Configuration.Raw) != 0 {
		t.Fatalf("explicit Kubernetes selection was not snapshotted exactly: %#v", run.Spec.Execution)
	}
}

func TestOmittedAndExplicitKubernetesExecutionPreservePodRendering(t *testing.T) {
	kataClass := "kata-vm-isolation"
	variants := map[string]*nvtv1alpha1.AgentRun{
		"direct":   testAgentRun(),
		"mediated": multiGrantMediatedAgentRun(),
		"kata": func() *nvtv1alpha1.AgentRun {
			run := testAgentRun()
			run.Spec.RuntimeClassName = &kataClass
			return run
		}(),
	}
	for name, omitted := range variants {
		t.Run(name, func(t *testing.T) {
			explicit := omitted.DeepCopyObject().(*nvtv1alpha1.AgentRun)
			explicit.Spec.Execution = &nvtv1alpha1.AgentRunExecution{
				Kind: nvtv1alpha1.AgentRunExecutionPod, Driver: builtInKubernetesDriver,
			}
			omittedPod, err := DesiredAgentPod(omitted, testScheme(t))
			if err != nil {
				t.Fatalf("render omitted selection: %v", err)
			}
			explicitPod, err := DesiredAgentPod(explicit, testScheme(t))
			if err != nil {
				t.Fatalf("render explicit selection: %v", err)
			}
			if !reflect.DeepEqual(explicitPod, omittedPod) {
				t.Fatalf("explicit Kubernetes selection changed Pod rendering\nomitted=%#v\nexplicit=%#v", omittedPod, explicitPod)
			}
		})
	}
}

func TestExplicitKubernetesExecutionUsesBuiltInAdapter(t *testing.T) {
	ctx := context.Background()
	run := testAgentRun()
	run.Spec.Execution = &nvtv1alpha1.AgentRunExecution{Kind: nvtv1alpha1.AgentRunExecutionPod, Driver: builtInKubernetesDriver}
	scheme := testScheme(t)
	k8sClient := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&nvtv1alpha1.AgentRun{}).
		WithObjects(run, testBrokerAgentsConfigMap(run.Namespace)).Build()
	reconciler := &AgentRunReconciler{Client: k8sClient, Scheme: scheme}
	if _, err := reconciler.Reconcile(ctx, requestFor(run)); err != nil {
		t.Fatalf("reconcile explicit Kubernetes execution: %v", err)
	}
	getAgentPod(ctx, t, k8sClient, run)
}

func TestExplicitKubernetesDeletionUsesBuiltInAdapter(t *testing.T) {
	ctx := context.Background()
	now := metav1.Now()
	run := testAgentRun()
	run.Finalizers = []string{agentRunFinalizer}
	run.DeletionTimestamp = &now
	run.Spec.Execution = &nvtv1alpha1.AgentRunExecution{Kind: nvtv1alpha1.AgentRunExecutionPod, Driver: builtInKubernetesDriver}
	scheme := testScheme(t)
	k8sClient := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&nvtv1alpha1.AgentRun{}).
		WithObjects(run, testBrokerAgentsConfigMap(run.Namespace)).Build()
	reconciler := &AgentRunReconciler{Client: k8sClient, Scheme: scheme}
	if _, err := reconciler.Reconcile(ctx, requestFor(run)); err != nil {
		t.Fatalf("reconcile explicit Kubernetes deletion: %v", err)
	}
	var updated nvtv1alpha1.AgentRun
	if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(run), &updated); err == nil {
		if len(updated.Finalizers) != 0 {
			t.Fatalf("built-in adapter did not complete legacy finalization: %#v", updated.Finalizers)
		}
	} else if !apierrors.IsNotFound(err) {
		t.Fatalf("get finalized AgentRun: %v", err)
	}
}

func TestUnavailableAndInvalidExecutionFailClosedWithoutPod(t *testing.T) {
	tests := []struct {
		name      string
		execution *nvtv1alpha1.AgentRunExecution
		reason    string
	}{
		{
			name: "unavailable external driver",
			execution: &nvtv1alpha1.AgentRunExecution{
				Kind: nvtv1alpha1.AgentRunExecutionVM, Driver: "example-vm", ClassRef: "vm-standard",
				Configuration: rawJSON(`{"cpu":4}`),
			},
			reason: executionDriverUnavailableReason,
		},
		{
			name: "kind driver mismatch",
			execution: &nvtv1alpha1.AgentRunExecution{
				Kind: nvtv1alpha1.AgentRunExecutionVM, Driver: builtInKubernetesDriver,
			},
			reason: executionSelectionInvalidReason,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			run := testAgentRun()
			run.Spec.Execution = test.execution
			scheme := testScheme(t)
			k8sClient := fake.NewClientBuilder().WithScheme(scheme).
				WithStatusSubresource(&nvtv1alpha1.AgentRun{}).
				WithObjects(run, testBrokerAgentsConfigMap(run.Namespace)).Build()
			reconciler := &AgentRunReconciler{Client: k8sClient, Scheme: scheme}
			if _, err := reconciler.Reconcile(ctx, requestFor(run)); err != nil {
				t.Fatalf("reconcile: %v", err)
			}
			var updated nvtv1alpha1.AgentRun
			if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(run), &updated); err != nil {
				t.Fatal(err)
			}
			condition := meta.FindStatusCondition(updated.Status.Conditions, ConditionExecutionBackendAvailable)
			if updated.Status.Reason != test.reason || condition == nil || condition.Status != metav1.ConditionFalse || condition.Reason != test.reason {
				t.Fatalf("unexpected portable execution failure status: %#v", updated.Status)
			}
			var pods corev1.PodList
			if err := k8sClient.List(ctx, &pods, client.InNamespace(run.Namespace)); err != nil || len(pods.Items) != 0 {
				t.Fatalf("failed selection created a Pod: err=%v pods=%#v", err, pods.Items)
			}
			if len(updated.Finalizers) != 0 {
				t.Fatalf("failed selection unexpectedly acquired Kubernetes finalizer: %#v", updated.Finalizers)
			}
		})
	}
}

func TestUnknownDriverDeletionNeverFallsBackToKubernetes(t *testing.T) {
	ctx := context.Background()
	now := metav1.Now()
	run := testAgentRun()
	run.Finalizers = []string{agentRunFinalizer}
	run.DeletionTimestamp = &now
	run.Spec.Execution = &nvtv1alpha1.AgentRunExecution{
		Kind: nvtv1alpha1.AgentRunExecutionVM, Driver: "example-vm", ClassRef: "vm-standard",
		Configuration: rawJSON(`{}`),
	}
	scheme := testScheme(t)
	pod, err := DesiredAgentPod(run, scheme)
	if err != nil {
		t.Fatal(err)
	}
	k8sClient := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&nvtv1alpha1.AgentRun{}).
		WithObjects(run, pod, testBrokerAgentsConfigMap(run.Namespace)).Build()
	reconciler := &AgentRunReconciler{Client: k8sClient, Scheme: scheme}
	if _, err := reconciler.Reconcile(ctx, requestFor(run)); err != nil {
		t.Fatalf("reconcile deleting external selection: %v", err)
	}
	var persisted corev1.Pod
	if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(pod), &persisted); err != nil {
		t.Fatalf("Kubernetes Pod was deleted by backend fallback: %v", err)
	}
	var updated nvtv1alpha1.AgentRun
	if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(run), &updated); err != nil {
		t.Fatal(err)
	}
	if len(updated.Finalizers) != 1 || updated.Finalizers[0] != agentRunFinalizer {
		t.Fatalf("external deletion silently used Kubernetes finalizer path: %#v", updated.Finalizers)
	}
}

func TestExecutionProfileClassValidationFailsClosed(t *testing.T) {
	validClass := nvtv1alpha1.AgentScheduleExecutionClass{
		Name: "vm-standard", Kind: nvtv1alpha1.AgentRunExecutionVM, Driver: "example-vm", Configuration: rawJSON(`{}`),
	}
	tests := []struct {
		name   string
		mutate func(*nvtv1alpha1.AgentSchedule)
	}{
		{
			name: "missing class",
			mutate: func(schedule *nvtv1alpha1.AgentSchedule) {
				schedule.Spec.Profiles[0].Execution = &nvtv1alpha1.AgentScheduleExecutionSelection{Kind: nvtv1alpha1.AgentRunExecutionVM, Driver: "example-vm", ClassRef: "missing"}
			},
		},
		{
			name: "driver mismatch",
			mutate: func(schedule *nvtv1alpha1.AgentSchedule) {
				schedule.Spec.ExecutionClasses = []nvtv1alpha1.AgentScheduleExecutionClass{validClass}
				schedule.Spec.Profiles[0].Execution = &nvtv1alpha1.AgentScheduleExecutionSelection{Kind: nvtv1alpha1.AgentRunExecutionVM, Driver: "other-vm", ClassRef: validClass.Name}
			},
		},
		{
			name: "kind mismatch",
			mutate: func(schedule *nvtv1alpha1.AgentSchedule) {
				schedule.Spec.ExecutionClasses = []nvtv1alpha1.AgentScheduleExecutionClass{validClass}
				schedule.Spec.Profiles[0].Execution = &nvtv1alpha1.AgentScheduleExecutionSelection{Kind: nvtv1alpha1.AgentRunExecutionPod, Driver: validClass.Driver, ClassRef: validClass.Name}
			},
		},
		{
			name: "duplicate class",
			mutate: func(schedule *nvtv1alpha1.AgentSchedule) {
				schedule.Spec.ExecutionClasses = []nvtv1alpha1.AgentScheduleExecutionClass{validClass, validClass}
			},
		},
		{
			name: "class for built-in driver",
			mutate: func(schedule *nvtv1alpha1.AgentSchedule) {
				schedule.Spec.ExecutionClasses = []nvtv1alpha1.AgentScheduleExecutionClass{{
					Name: "pod-standard", Kind: nvtv1alpha1.AgentRunExecutionPod, Driver: builtInKubernetesDriver,
					Configuration: rawJSON(`{}`),
				}}
			},
		},
		{
			name: "oversized configuration",
			mutate: func(schedule *nvtv1alpha1.AgentSchedule) {
				oversized := `{"value":"` + strings.Repeat("x", maxExecutionClassConfigurationBytes) + `"}`
				schedule.Spec.ExecutionClasses = []nvtv1alpha1.AgentScheduleExecutionClass{{
					Name: "vm-standard", Kind: nvtv1alpha1.AgentRunExecutionVM, Driver: "example-vm",
					Configuration: apiextensionsv1.JSON{Raw: []byte(oversized)},
				}}
			},
		},
		{
			name: "ambiguous configuration",
			mutate: func(schedule *nvtv1alpha1.AgentSchedule) {
				schedule.Spec.ExecutionClasses = []nvtv1alpha1.AgentScheduleExecutionClass{{
					Name: "vm-standard", Kind: nvtv1alpha1.AgentRunExecutionVM, Driver: "example-vm",
					Configuration: rawJSON(`{"network":{"mode":"a","mode":"b"}}`),
				}}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			schedule := testProfiledAgentSchedule()
			test.mutate(schedule)
			fixture := newProfileAdmissionFixture(t, schedule)
			response := fixture.serve(t, profiledAdmissionBody(t, "invalid-execution", nil, nil), "Bearer projected-token")
			var decoded scheduleAdmissionResponse
			decodeAdmissionResponse(t, response, 400, &decoded)
			if decoded.Reason != "invalid-execution-profile-configuration" {
				t.Fatalf("unsanitized or unstable rejection: %#v", decoded)
			}
			var runs nvtv1alpha1.AgentRunList
			if err := fixture.client.List(context.Background(), &runs, client.InNamespace(schedule.Namespace)); err != nil || len(runs.Items) != 0 {
				t.Fatalf("invalid class configuration created AgentRuns: err=%v runs=%#v", err, runs.Items)
			}
		})
	}
}

func TestProfiledProducerCannotSupplyExecutionSelection(t *testing.T) {
	schedule := testProfiledAgentSchedule()
	fixture := newProfileAdmissionFixture(t, schedule)
	body := profiledAdmissionPayload("producer-execution", nil, nil)
	body["execution"] = map[string]any{"kind": "vm", "driver": "example-vm", "classRef": "vm-standard"}
	response := fixture.serve(t, mustJSON(t, body), "Bearer projected-token")
	if response.Code != 400 || !strings.Contains(response.Body.String(), "accepts only work and input") ||
		strings.Contains(response.Body.String(), "example-vm") {
		t.Fatalf("producer execution selection was not rejected: status=%d body=%q", response.Code, response.Body.String())
	}
	var runs nvtv1alpha1.AgentRunList
	if err := fixture.client.List(context.Background(), &runs, client.InNamespace(schedule.Namespace)); err != nil || len(runs.Items) != 0 {
		t.Fatalf("producer execution selection created AgentRuns: err=%v runs=%#v", err, runs.Items)
	}
}

func TestExecutionSelectionCRDSchemas(t *testing.T) {
	agentRunData, err := os.ReadFile("../../config/crd/bases/nvt.dev_agentruns.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var agentRunCRD map[string]any
	if err := yaml.Unmarshal(agentRunData, &agentRunCRD); err != nil {
		t.Fatal(err)
	}
	execution := crdPath(t, agentRunCRD,
		"spec", "versions", 0, "schema", "openAPIV3Schema", "properties", "spec", "properties", "execution",
	).(map[string]any)
	if crdPath(t, execution, "properties", "kind", "enum", 0) != "pod" ||
		crdPath(t, execution, "properties", "kind", "enum", 1) != "vm" ||
		crdPath(t, execution, "properties", "configuration", "x-kubernetes-preserve-unknown-fields") != true {
		t.Fatalf("AgentRun execution schema is incomplete: %#v", execution)
	}
	validations := crdPath(t, agentRunCRD,
		"spec", "versions", 0, "schema", "openAPIV3Schema", "properties", "spec", "x-kubernetes-validations",
	).([]any)
	immutable := false
	for _, raw := range validations {
		if strings.Contains(raw.(map[string]any)["rule"].(string), "oldSelf.execution") {
			immutable = true
		}
	}
	if !immutable {
		t.Fatalf("AgentRun execution immutability validation missing: %#v", validations)
	}

	scheduleData, err := os.ReadFile("../../config/crd/bases/nvt.dev_agentschedules.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var scheduleCRD map[string]any
	if err := yaml.Unmarshal(scheduleData, &scheduleCRD); err != nil {
		t.Fatal(err)
	}
	classes := crdPath(t, scheduleCRD,
		"spec", "versions", 0, "schema", "openAPIV3Schema", "properties", "spec", "properties", "executionClasses",
	).(map[string]any)
	if classes["x-kubernetes-list-type"] != "map" ||
		crdPath(t, classes, "items", "properties", "configuration", "x-kubernetes-preserve-unknown-fields") != true {
		t.Fatalf("AgentSchedule execution class schema is incomplete: %#v", classes)
	}
	profileExecution := crdPath(t, scheduleCRD,
		"spec", "versions", 0, "schema", "openAPIV3Schema", "properties", "spec", "properties",
		"profiles", "items", "properties", "execution", "properties",
	).(map[string]any)
	if crdPath(t, profileExecution, "driver", "type") != "string" || crdPath(t, profileExecution, "classRef", "type") != "string" {
		t.Fatalf("AgentSchedule profile execution schema is incomplete: %#v", profileExecution)
	}
}
