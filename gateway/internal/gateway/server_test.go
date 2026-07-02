package gateway

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	nvtv1alpha1 "github.com/mirkoSekulic/nvt-agent/operator/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	ctrlfake "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestParseHost(t *testing.T) {
	tests := []struct {
		name       string
		host       string
		baseDomain string
		wantKind   routeKind
		wantKey    string
	}{
		{name: "base", host: "agents.localhost", baseDomain: "agents.localhost", wantKind: routeDashboard},
		{name: "base with port", host: "agents.localhost:4090", baseDomain: "agents.localhost", wantKind: routeDashboard},
		{name: "key", host: "run-1.agents.localhost", baseDomain: "agents.localhost", wantKind: routeAgentRun, wantKey: "run-1"},
		{name: "key with port", host: "run-1.agents.localhost:4090", baseDomain: "agents.localhost", wantKind: routeAgentRun, wantKey: "run-1"},
		{name: "nested prefix ignored", host: "x.run-1.agents.localhost", baseDomain: "agents.localhost", wantKind: routeNotFound},
		{name: "other host", host: "example.test", baseDomain: "agents.localhost", wantKind: routeNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseHost(tt.host, tt.baseDomain)
			if got.kind != tt.wantKind || got.accessKey != tt.wantKey {
				t.Fatalf("ParseHost() = %#v, want kind=%v key=%q", got, tt.wantKind, tt.wantKey)
			}
		})
	}
}

func TestResolveTarget(t *testing.T) {
	client := fakeClient(t,
		&nvtv1alpha1.AgentRun{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "nvt",
				Name:      "run-1",
				Annotations: map[string]string{
					AccessKeyAnnotation:  "access-1",
					AccessPortAnnotation: "4999",
				},
			},
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "nvt",
				Name:      "run-1-agent",
				Labels:    map[string]string{AgentRunPodLabel: "run-1"},
			},
			Status: readyPodStatus("10.0.0.9"),
		},
	)
	server := NewServer(Config{BaseDomain: "agents.localhost", ListenAddr: ":8080", DefaultTargetPort: 4090}, client, "nvt")
	target, err := server.resolveTarget(t.Context(), "access-1")
	if err != nil {
		t.Fatal(err)
	}
	if target.PodIP != "10.0.0.9" || target.Port != 4999 || target.AgentRun.Name != "run-1" {
		t.Fatalf("target = %#v", target)
	}
}

func TestResolveTargetNoRunningPod(t *testing.T) {
	client := fakeClient(t,
		&nvtv1alpha1.AgentRun{
			ObjectMeta: metav1.ObjectMeta{
				Namespace:   "nvt",
				Name:        "run-1",
				Annotations: map[string]string{AccessKeyAnnotation: "access-1"},
			},
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "nvt",
				Name:      "run-1-agent",
				Labels:    map[string]string{AgentRunPodLabel: "run-1"},
			},
			Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "10.0.0.9"},
		},
	)
	server := NewServer(Config{BaseDomain: "agents.localhost", ListenAddr: ":8080", DefaultTargetPort: 4090}, client, "nvt")
	_, err := server.resolveTarget(t.Context(), "access-1")
	if err != errNoRunningPod {
		t.Fatalf("err = %v, want errNoRunningPod", err)
	}
}

func TestDashboardListsAgentRuns(t *testing.T) {
	created := metav1.NewTime(time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC))
	client := fakeClient(t,
		&nvtv1alpha1.AgentRun{
			ObjectMeta: metav1.ObjectMeta{
				Namespace:         "nvt",
				Name:              "run-1",
				CreationTimestamp: created,
				Annotations: map[string]string{
					AccessKeyAnnotation:   "access-1",
					DisplayNameAnnotation: "Issue #7 - PR create",
					RequestedByAnnotation: "alice",
					SourceURLAnnotation:   "https://github.test/acme/widget/issues/7#issuecomment-1",
				},
			},
			Status: nvtv1alpha1.AgentRunStatus{Phase: nvtv1alpha1.AgentRunPhaseRunning},
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "nvt",
				Name:      "run-1-agent",
				Labels:    map[string]string{AgentRunPodLabel: "run-1"},
			},
			Status: readyPodStatus("10.0.0.9"),
		},
	)
	server := NewServer(Config{BaseDomain: "agents.localhost", ListenAddr: ":8080", DefaultTargetPort: 4090}, client, "nvt")
	req := httptest.NewRequest(http.MethodGet, "http://agents.localhost:4090/", nil)
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, req)
	body := recorder.Body.String()
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", recorder.Code, body)
	}
	for _, want := range []string{"Issue #7 - PR create", "Running", "alice", "Open Session", "http://access-1.agents.localhost:4090/"} {
		if !strings.Contains(body, want) {
			t.Fatalf("dashboard missing %q in:\n%s", want, body)
		}
	}
}

func TestHealthzDoesNotRequireKubernetes(t *testing.T) {
	server := NewServer(Config{BaseDomain: "agents.localhost", ListenAddr: ":8080", DefaultTargetPort: 4090}, nil, "nvt")
	req := httptest.NewRequest(http.MethodGet, "http://not-the-base-host/healthz", nil)
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	if recorder.Body.String() != "ok\n" {
		t.Fatalf("body = %q", recorder.Body.String())
	}
}

func fakeClient(t *testing.T, objects ...runtime.Object) ctrlclient.Client {
	t.Helper()
	s := runtime.NewScheme()
	if err := scheme.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := nvtv1alpha1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	return ctrlfake.NewClientBuilder().WithScheme(s).WithRuntimeObjects(objects...).Build()
}

func readyPodStatus(podIP string) corev1.PodStatus {
	return corev1.PodStatus{
		Phase: corev1.PodRunning,
		PodIP: podIP,
		Conditions: []corev1.PodCondition{
			{Type: corev1.PodReady, Status: corev1.ConditionTrue},
		},
	}
}
