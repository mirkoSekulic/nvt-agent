package gateway

import (
	"context"

	"github.com/mirkoSekulic/nvt-agent/protocol/eligibility"
)

const maxClaimSourceResponseSize = 64 * 1024

type ClaimEnrichmentConfig eligibility.EnrichmentConfig
type OAuthClaimSource = eligibility.ClaimSource
type ClaimResponseLimits = eligibility.ResponseLimits

func (c ClaimEnrichmentConfig) validate() error {
	return eligibility.EnrichmentConfig(c).Validate("auth.claimEnrichment")
}

func (a *Authenticator) enrichClaims(ctx context.Context, accessToken string, claims map[string]any) (map[string]any, error) {
	return eligibility.Enrich(ctx, eligibility.EnrichmentConfig(a.config.Auth.ClaimEnrichment), accessToken, claims, eligibility.EnrichOptions{
		Client: a.httpClient, UserAgent: "nvt-agent-gateway", TimeoutOverride: a.claimSourceTimeout,
	})
}

func ParseClaimEnrichmentConfig(raw string) (ClaimEnrichmentConfig, error) {
	config, err := eligibility.ParseEnrichmentConfig(raw, "gateway claim enrichment")
	return ClaimEnrichmentConfig(config), err
}
