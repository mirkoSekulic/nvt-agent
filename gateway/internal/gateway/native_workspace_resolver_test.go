package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	nvtv1alpha1 "github.com/mirkoSekulic/nvt-agent/operator/api/v1alpha1"
	"github.com/mirkoSekulic/nvt-agent/operator/executiondriver"
	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment"
	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment/workspacetunnel"
)

type resolverControl struct {
	ready bool
	seen  []guestenrollment.Binding
}

func (*resolverControl) RelayAgentd(context.Context, guestenrollment.Binding, json.RawMessage) (json.RawMessage, error) {
	return nil, ErrNativeSessionUnavailable
}

func (control *resolverControl) Ready(binding guestenrollment.Binding) bool {
	control.seen = append(control.seen, binding)
	return control.ready
}

type resolverWorkspace struct {
	opener workspacetunnel.StreamOpener
	ready  bool
	seen   []guestenrollment.Binding
}

func (workspace *resolverWorkspace) Lookup(binding guestenrollment.Binding) (workspacetunnel.StreamOpener, bool) {
	workspace.seen = append(workspace.seen, binding)
	return workspace.opener, workspace.ready
}

type resolverOpener struct {
	binding  guestenrollment.Binding
	sequence uint64
}

func (*resolverOpener) OpenStream(context.Context) (net.Conn, error) {
	return nil, errors.New("unused")
}
func (opener *resolverOpener) Binding() guestenrollment.Binding { return opener.binding }
func (opener *resolverOpener) Sequence() uint64                 { return opener.sequence }
func (*resolverOpener) Close() error                            { return nil }

func TestNativeWorkspaceResolverExactBinding(t *testing.T) {
	run, binding := nativeWorkspaceResolverFixture(t)
	control := &resolverControl{ready: true}
	opener := &resolverOpener{binding: binding, sequence: 7}
	workspace := &resolverWorkspace{ready: true, opener: opener}

	resolved, err := NewNativeWorkspaceResolver(control, workspace).Resolve(run)
	if err != nil || resolved != opener {
		t.Fatalf("resolve exact native workspace: opener=%v error=%v", resolved, err)
	}
	if len(control.seen) != 1 || control.seen[0] != binding || len(workspace.seen) != 1 || workspace.seen[0] != binding {
		t.Fatal("resolver did not use the exact complete status binding")
	}
}

func TestNativeWorkspaceResolverRejectsEveryBindingMismatch(t *testing.T) {
	mutations := map[string]func(*nvtv1alpha1.AgentRunNativeGuestBinding){
		"agent run UID":       func(value *nvtv1alpha1.AgentRunNativeGuestBinding) { value.AgentRunUID = "different-uid" },
		"execution ID":        func(value *nvtv1alpha1.AgentRunNativeGuestBinding) { value.ExecutionID = "different-execution" },
		"driver registration": func(value *nvtv1alpha1.AgentRunNativeGuestBinding) { value.DriverRegistration = "different-driver" },
		"desired generation":  func(value *nvtv1alpha1.AgentRunNativeGuestBinding) { value.DesiredGeneration++ },
		"guest instance":      func(value *nvtv1alpha1.AgentRunNativeGuestBinding) { value.GuestInstanceID = "" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			run, binding := nativeWorkspaceResolverFixture(t)
			mutate(run.Status.NativeGuestBinding)
			control := &resolverControl{ready: true}
			workspace := &resolverWorkspace{ready: true, opener: &resolverOpener{binding: binding, sequence: 1}}
			_, err := NewNativeWorkspaceResolver(control, workspace).Resolve(run)
			if !errors.Is(err, ErrNativeWorkspaceRouteNotFound) {
				t.Fatalf("mismatch error=%v, want not found", err)
			}
			if len(control.seen) != 0 || len(workspace.seen) != 0 {
				t.Fatal("registry was queried for a mismatched binding")
			}
		})
	}
}

func TestNativeWorkspaceResolverFailsClosed(t *testing.T) {
	run, binding := nativeWorkspaceResolverFixture(t)
	cases := []struct {
		name      string
		mutate    func(*nvtv1alpha1.AgentRun)
		control   NativeSessionRelay
		workspace NativeWorkspaceStreams
		want      error
	}{
		{name: "absent status", mutate: func(run *nvtv1alpha1.AgentRun) { run.Status.NativeGuestBinding = nil }, control: &resolverControl{ready: true}, workspace: &resolverWorkspace{}, want: ErrNativeWorkspaceRouteNotFound},
		{name: "pending run", mutate: func(run *nvtv1alpha1.AgentRun) { run.Status.Phase = nvtv1alpha1.AgentRunPhasePending }, control: &resolverControl{ready: true}, workspace: &resolverWorkspace{}, want: ErrNativeWorkspaceRouteNotFound},
		{name: "terminal run", mutate: func(run *nvtv1alpha1.AgentRun) { run.Status.Phase = nvtv1alpha1.AgentRunPhaseCompleted }, control: &resolverControl{ready: true}, workspace: &resolverWorkspace{}, want: ErrNativeWorkspaceRouteNotFound},
		{name: "external pod", mutate: func(run *nvtv1alpha1.AgentRun) {
			run.Spec.Execution.Kind = nvtv1alpha1.AgentRunExecutionPod
			run.Status.PodName = "must-not-fallback"
		}, control: &resolverControl{ready: true}, workspace: &resolverWorkspace{}, want: ErrNativeWorkspaceRouteNotFound},
		{name: "different guest instance", mutate: func(run *nvtv1alpha1.AgentRun) {
			run.Status.NativeGuestBinding.GuestInstanceID = "different-guest"
		}, control: &resolverControl{}, workspace: &resolverWorkspace{ready: true, opener: &resolverOpener{binding: binding, sequence: 1}}, want: ErrNativeWorkspaceRouteUnavailable},
		{name: "control unavailable", control: &resolverControl{}, workspace: &resolverWorkspace{ready: true, opener: &resolverOpener{binding: binding, sequence: 1}}, want: ErrNativeWorkspaceRouteUnavailable},
		{name: "workspace unavailable", control: &resolverControl{ready: true}, workspace: &resolverWorkspace{}, want: ErrNativeWorkspaceRouteUnavailable},
		{name: "control only configured", control: &resolverControl{ready: true}, want: ErrNativeWorkspaceRouteUnavailable},
		{name: "workspace only configured", workspace: &resolverWorkspace{ready: true, opener: &resolverOpener{binding: binding, sequence: 1}}, want: ErrNativeWorkspaceRouteUnavailable},
		{name: "invalid opener sequence", control: &resolverControl{ready: true}, workspace: &resolverWorkspace{ready: true, opener: &resolverOpener{binding: binding}}, want: ErrNativeWorkspaceRouteUnavailable},
		{name: "opener binding mismatch", control: &resolverControl{ready: true}, workspace: &resolverWorkspace{ready: true, opener: &resolverOpener{binding: guestenrollment.Binding{}, sequence: 1}}, want: ErrNativeWorkspaceRouteUnavailable},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			candidate := *run
			candidate.Status = *run.Status.DeepCopy()
			candidate.Spec = run.Spec
			execution := *run.Spec.Execution
			candidate.Spec.Execution = &execution
			if testCase.mutate != nil {
				testCase.mutate(&candidate)
			}
			_, err := NewNativeWorkspaceResolver(testCase.control, testCase.workspace).Resolve(&candidate)
			if !errors.Is(err, testCase.want) {
				t.Fatalf("Resolve error=%v, want %v", err, testCase.want)
			}
		})
	}
}

func TestNativeWorkspaceResolverFormattingContainsNoBindingOrCredential(t *testing.T) {
	const canary = "nvt.guest-session-credential/v1.secret-canary"
	resolver := NewNativeWorkspaceResolver(nil, nil)
	run, _ := nativeWorkspaceResolverFixture(t)
	run.Status.NativeGuestBinding.GuestInstanceID = canary
	_, resolveError := resolver.Resolve(run)
	for _, value := range []string{fmt.Sprintf("%v", resolver), fmt.Sprintf("%#v", resolver), resolveError.Error(), ErrNativeWorkspaceRouteNotFound.Error(), ErrNativeWorkspaceRouteUnavailable.Error()} {
		if strings.Contains(value, canary) || strings.Contains(value, "guest-instance") {
			t.Fatalf("resolver formatting exposed routing or credential data: %q", value)
		}
	}
}

func nativeWorkspaceResolverFixture(t *testing.T) (*nvtv1alpha1.AgentRun, guestenrollment.Binding) {
	t.Helper()
	uid := types.UID("11111111-2222-3333-4444-555555555555")
	executionID, err := executiondriver.AgentRunExecutionID(string(uid))
	if err != nil {
		t.Fatal(err)
	}
	binding := guestenrollment.Binding{
		AgentRunUID: string(uid), ExecutionID: executionID, DriverRegistration: "vm-driver",
		DesiredGeneration: 3, GuestInstanceID: "guest-instance",
	}
	run := &nvtv1alpha1.AgentRun{
		ObjectMeta: metav1.ObjectMeta{Name: "external", Namespace: "default", UID: uid, Generation: 3},
		Spec:       nvtv1alpha1.AgentRunSpec{Execution: &nvtv1alpha1.AgentRunExecution{Kind: nvtv1alpha1.AgentRunExecutionVM, Driver: "vm-driver"}},
		Status: nvtv1alpha1.AgentRunStatus{
			Phase: nvtv1alpha1.AgentRunPhaseRunning,
			NativeGuestBinding: &nvtv1alpha1.AgentRunNativeGuestBinding{
				AgentRunUID: binding.AgentRunUID, ExecutionID: binding.ExecutionID, DriverRegistration: binding.DriverRegistration,
				DesiredGeneration: binding.DesiredGeneration, GuestInstanceID: binding.GuestInstanceID,
			},
		},
	}
	return run, binding
}
