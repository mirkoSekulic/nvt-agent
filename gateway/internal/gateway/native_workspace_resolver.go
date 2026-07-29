package gateway

import (
	"errors"

	nvtv1alpha1 "github.com/mirkoSekulic/nvt-agent/operator/api/v1alpha1"
	"github.com/mirkoSekulic/nvt-agent/operator/executiondriver"
	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment"
	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment/workspacetunnel"
)

var (
	ErrNativeWorkspaceRouteNotFound    = errors.New("native workspace route not found")
	ErrNativeWorkspaceRouteUnavailable = errors.New("native workspace route unavailable")
)

// NativeWorkspaceResolver is the implementation-neutral exact-routing seam
// consumed only after browser authentication and AgentRun authorization. It
// does not scan registries or provide a Pod fallback.
type NativeWorkspaceResolver interface {
	Resolve(*nvtv1alpha1.AgentRun) (workspacetunnel.StreamOpener, error)
}

type nativeWorkspaceResolver struct {
	control   NativeSessionRelay
	workspace NativeWorkspaceStreams
}

func NewNativeWorkspaceResolver(control NativeSessionRelay, workspace NativeWorkspaceStreams) NativeWorkspaceResolver {
	return &nativeWorkspaceResolver{control: control, workspace: workspace}
}

func (resolver *nativeWorkspaceResolver) Resolve(agentRun *nvtv1alpha1.AgentRun) (workspacetunnel.StreamOpener, error) {
	if resolver == nil || agentRun == nil || agentRun.Spec.Execution == nil ||
		!agentRun.DeletionTimestamp.IsZero() ||
		agentRun.Spec.Execution.Kind != nvtv1alpha1.AgentRunExecutionVM ||
		agentRun.Spec.Execution.Driver == "" || agentRun.Spec.Execution.Driver == "kubernetes" ||
		agentRun.Status.Phase != nvtv1alpha1.AgentRunPhaseRunning {
		return nil, ErrNativeWorkspaceRouteNotFound
	}
	binding, err := routingBindingFromStatus(agentRun.Status.NativeGuestBinding)
	if err != nil {
		return nil, ErrNativeWorkspaceRouteNotFound
	}
	executionID, err := executiondriver.AgentRunExecutionID(string(agentRun.UID))
	if err != nil {
		return nil, ErrNativeWorkspaceRouteNotFound
	}
	generation := agentRun.Generation
	if generation < 1 {
		generation = 1
	}
	if binding.AgentRunUID != string(agentRun.UID) || binding.ExecutionID != executionID ||
		binding.DriverRegistration != agentRun.Spec.Execution.Driver || binding.DesiredGeneration != generation {
		return nil, ErrNativeWorkspaceRouteNotFound
	}
	if resolver.control == nil || resolver.workspace == nil || !resolver.control.Ready(binding) {
		return nil, ErrNativeWorkspaceRouteUnavailable
	}
	opener, ok := resolver.workspace.Lookup(binding)
	if !ok || opener == nil || opener.Sequence() == 0 || opener.Binding() != binding {
		return nil, ErrNativeWorkspaceRouteUnavailable
	}
	return opener, nil
}

func routingBindingFromStatus(status *nvtv1alpha1.AgentRunNativeGuestBinding) (guestenrollment.Binding, error) {
	if status == nil {
		return guestenrollment.Binding{}, ErrNativeWorkspaceRouteNotFound
	}
	binding := guestenrollment.Binding{
		AgentRunUID:        status.AgentRunUID,
		ExecutionID:        status.ExecutionID,
		DriverRegistration: status.DriverRegistration,
		DesiredGeneration:  status.DesiredGeneration,
		GuestInstanceID:    status.GuestInstanceID,
	}
	if guestenrollment.ValidateBinding(binding) != nil {
		return guestenrollment.Binding{}, ErrNativeWorkspaceRouteNotFound
	}
	return binding, nil
}

func (*nativeWorkspaceResolver) String() string   { return "[native workspace resolver]" }
func (*nativeWorkspaceResolver) GoString() string { return "[native workspace resolver]" }
