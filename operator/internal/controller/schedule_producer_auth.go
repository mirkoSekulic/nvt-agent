package controller

import (
	"context"
	"errors"

	authenticationv1 "k8s.io/api/authentication/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const scheduleProducerAudience = "nvt-operator"

var errScheduleProducerAuthentication = errors.New("schedule producer authentication failed")

// ScheduleProducerAuthenticator authenticates the caller independently of its request body.
type ScheduleProducerAuthenticator interface {
	Authenticate(context.Context, string) (string, error)
}

type tokenReviewCreator interface {
	Create(context.Context, *authenticationv1.TokenReview) error
}

type controllerRuntimeTokenReviewCreator struct {
	client client.Client
}

func (c controllerRuntimeTokenReviewCreator) Create(ctx context.Context, review *authenticationv1.TokenReview) error {
	return c.client.Create(ctx, review)
}

// KubernetesTokenReviewProducerAuthenticator validates projected ServiceAccount tokens.
type KubernetesTokenReviewProducerAuthenticator struct {
	reviews tokenReviewCreator
}

// NewKubernetesTokenReviewProducerAuthenticator constructs the production authenticator.
func NewKubernetesTokenReviewProducerAuthenticator(k8sClient client.Client) *KubernetesTokenReviewProducerAuthenticator {
	return &KubernetesTokenReviewProducerAuthenticator{
		reviews: controllerRuntimeTokenReviewCreator{client: k8sClient},
	}
}

func (a *KubernetesTokenReviewProducerAuthenticator) Authenticate(ctx context.Context, token string) (string, error) {
	if token == "" || a == nil || a.reviews == nil {
		return "", errScheduleProducerAuthentication
	}
	review := &authenticationv1.TokenReview{
		Spec: authenticationv1.TokenReviewSpec{
			Token:     token,
			Audiences: []string{scheduleProducerAudience},
		},
	}
	if err := a.reviews.Create(ctx, review); err != nil {
		return "", errScheduleProducerAuthentication
	}
	if !review.Status.Authenticated || review.Status.Error != "" || review.Status.User.Username == "" ||
		!containsString(review.Status.Audiences, scheduleProducerAudience) {
		return "", errScheduleProducerAuthentication
	}
	return review.Status.User.Username, nil
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
