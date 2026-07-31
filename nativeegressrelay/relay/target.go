package relay

import (
	"context"
	"errors"

	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment"
	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment/nativeegress"
)

var ErrTargetUnavailable = errors.New("native egress target unavailable")

// TargetResolver resolves exactly one complete binding. It deliberately has
// no enumeration, partial-scope, endpoint, or guest-destination API.
type TargetResolver interface {
	ResolveNativeEgressTarget(context.Context, guestenrollment.Binding) (nativeegress.EgressTarget, error)
}

// DenyAllTargetResolver is the safe production default when no trusted
// exact-binding egressd descriptor snapshot is configured.
type DenyAllTargetResolver struct{}

func (DenyAllTargetResolver) ResolveNativeEgressTarget(context.Context, guestenrollment.Binding) (nativeegress.EgressTarget, error) {
	return nil, ErrTargetUnavailable
}

func (DenyAllTargetResolver) String() string   { return "[deny-all native egress target resolver]" }
func (DenyAllTargetResolver) GoString() string { return "[deny-all native egress target resolver]" }

type sessionAdmission struct {
	authenticator nativeegress.Authenticator
	resolver      TargetResolver
	target        nativeegress.EgressTarget
}

func (admission *sessionAdmission) AuthenticateNativeEgress(ctx context.Context, credential string, binding guestenrollment.Binding) (nativeegress.Authentication, error) {
	authentication, err := admission.authenticator.AuthenticateNativeEgress(ctx, credential, binding)
	credential = ""
	if err != nil {
		return nativeegress.Authentication{}, err
	}
	target, err := admission.resolver.ResolveNativeEgressTarget(ctx, binding)
	targetBinding, targetValid := bindingOfTarget(target)
	if err != nil || !targetValid || targetBinding != binding {
		return nativeegress.Authentication{}, nativeegress.ErrAuthenticationTemporary
	}
	admission.target = target
	return authentication, nil
}

func bindingOfTarget(target nativeegress.EgressTarget) (binding guestenrollment.Binding, valid bool) {
	if target == nil {
		return guestenrollment.Binding{}, false
	}
	defer func() {
		if recover() != nil {
			binding = guestenrollment.Binding{}
			valid = false
		}
	}()
	binding = target.Binding()
	return binding, guestenrollment.ValidateBinding(binding) == nil
}

type guardedTargetAdmission interface {
	acquireAdmission() (targetAdmissionLease, bool)
}

// targetAdmissionLease is internal to the relay. It keeps one target epoch
// alive across the small admission operation without exposing implementation
// details through the provider-neutral native-egress contract.
type targetAdmissionLease interface {
	Context() context.Context
	Active() bool
	Release()
}

type unguardedTargetAdmission struct{}

func (unguardedTargetAdmission) Context() context.Context { return context.Background() }
func (unguardedTargetAdmission) Active() bool             { return true }
func (unguardedTargetAdmission) Release()                 {}

type lifecycleTarget interface {
	Done() <-chan struct{}
}

func acquireTargetAdmission(target nativeegress.EgressTarget) (targetAdmissionLease, bool) {
	guarded, ok := target.(guardedTargetAdmission)
	if !ok {
		return unguardedTargetAdmission{}, true
	}
	return guarded.acquireAdmission()
}

func watchTargetLifecycle(session *nativeegress.Session, target nativeegress.EgressTarget) {
	lifecycle, ok := target.(lifecycleTarget)
	if !ok {
		return
	}
	go func() {
		select {
		case <-lifecycle.Done():
			_ = session.Close()
		case <-session.Done():
		}
	}()
}

func (*sessionAdmission) String() string   { return "[native egress session admission]" }
func (*sessionAdmission) GoString() string { return "[native egress session admission]" }
