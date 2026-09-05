package producer

import (
	"context"
	"testing"

	nvtv1alpha1 "github.com/mirkoSekulic/nvt-agent/operator/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrlfake "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestEpicRunLookupUsesExactWorkRepositoryAndSchedule(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := nvtv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	newRun := func(name, key, repo, schedule string) *nvtv1alpha1.AgentRun {
		return &nvtv1alpha1.AgentRun{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "nvt", Labels: map[string]string{"nvt.dev/schedule": schedule}, Annotations: map[string]string{"nvt.dev/work-id": key, "nvt.dev/work-repository": repo}}}
	}
	client := ctrlfake.NewClientBuilder().WithScheme(scheme).WithObjects(newRun("match", "key", "o/r", "default"), newRun("other-key", "other", "o/r", "default"), newRun("other-repo", "key", "other/r", "default"), newRun("other-schedule", "key", "o/r", "other")).Build()
	s := NewAgentRunSubmitter(client, Config{Submission: SubmissionConfig{ScheduleNamespace: "nvt", ScheduleName: "default"}})
	found, err := s.FindEpicRun(context.Background(), Repository{Owner: "o", Name: "r"}, "key")
	if err != nil || found == nil || found.Name != "match" {
		t.Fatal(found, err)
	}
	if err := client.Create(context.Background(), newRun("duplicate", "key", "o/r", "default")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.FindEpicRun(context.Background(), Repository{Owner: "o", Name: "r"}, "key"); err == nil {
		t.Fatal("ambiguous run recovery")
	}
}
