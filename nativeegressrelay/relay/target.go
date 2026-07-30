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

// DenyAllTargetResolver is the safe production default until an
// operator-owned in-process adapter is implemented.
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

func (*sessionAdmission) String() string   { return "[native egress session admission]" }
func (*sessionAdmission) GoString() string { return "[native egress session admission]" }
