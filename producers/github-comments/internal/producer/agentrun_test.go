package producer

import (
	"context"
	"testing"

	nvtv1alpha1 "github.com/mirkoSekulic/nvt-agent/operator/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"
	ctrlfake "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestSubmitBlocksExistingIdempotencyKeyRegardlessOfPhase(t *testing.T) {
	s := runtime.NewScheme()
	if err := scheme.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := nvtv1alpha1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	key := IdempotencyKey("acme", "widget", 7)
	existing := &nvtv1alpha1.AgentRun{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "nvt",
			Name:      "existing",
			Annotations: map[string]string{
				IdempotencyAnnotation: key,
			},
		},
		Status: nvtv1alpha1.AgentRunStatus{Phase: nvtv1alpha1.AgentRunPhaseCompleted},
	}
	client := ctrlfake.NewClientBuilder().WithScheme(s).WithObjects(existing).Build()
	submitter := NewAgentRunSubmitter(client, Config{
		AgentRun: AgentRunConfig{
			Namespace:       "nvt",
			RuntimeImage:    "runtime:latest",
			RuntimeType:     "codex",
			RuntimeAutonomy: "trusted-local",
			WorkspaceMode:   "Ephemeral",
		},
	})
	created, gotKey, err := submitter.Submit(context.Background(), Repository{Owner: "acme", Name: "widget"}, GitHubIssue{
		Number: 7,
		Title:  "broken",
	}, nil, GitHubIssueComment{Body: "/nvtagent pr create"}, Command{Prefix: "/nvtagent"})
	if err != nil {
		t.Fatal(err)
	}
	if created {
		t.Fatal("expected duplicate to block creation")
	}
	if gotKey != key {
		t.Fatalf("got key %q want %q", gotKey, key)
	}
}
