package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const (
	maxClaimSources            = 8
	maxClaimSourceHosts        = 32
	maxClaimSourceResponseSize = 64 * 1024
	maxEnrichedClaimStringSize = 1024
	maxEnrichedClaimArraySize  = 64
	defaultClaimSourceTimeout  = 5 * time.Second
)

var (
	claimNamePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	claimPathPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_-]*(?:\[\])?(?:\.[A-Za-z_][A-Za-z0-9_-]*(?:\[\])?)*$`)
	dnsHostPattern   = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$`)
)

type ClaimEnrichmentConfig struct {
	AllowedHosts []string           `json:"allowedHosts"`
	Sources      []OAuthClaimSource `json:"sources"`
}

type OAuthClaimSource struct {
	Endpoint    string `json:"endpoint"`
	OutputClaim string `json:"outputClaim"`
	ValuePath   string `json:"valuePath"`
}

func (c ClaimEnrichmentConfig) validate() error {
	if len(c.Sources) > maxClaimSources {
		return fmt.Errorf("auth.claimEnrichment.sources must contain at most %d entries", maxClaimSources)
	}
	if len(c.AllowedHosts) > maxClaimSourceHosts {
		return fmt.Errorf("auth.claimEnrichment.allowedHosts must contain at most %d entries", maxClaimSourceHosts)
	}
	allowed := make(map[string]struct{}, len(c.AllowedHosts))
	for index, host := range c.AllowedHosts {
		if !validClaimSourceHost(host) {
			return fmt.Errorf("auth.claimEnrichment.allowedHosts[%d] must be a normalized lowercase DNS hostname or IPv4 address without a port", index)
		}
		if _, exists := allowed[host]; exists {
			return fmt.Errorf("auth.claimEnrichment.allowedHosts[%d] is duplicated", index)
		}
		allowed[host] = struct{}{}
	}
	seenClaims := map[string]struct{}{}
	for index, source := range c.Sources {
		parsed, err := url.Parse(source.Endpoint)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
			return fmt.Errorf("auth.claimEnrichment.sources[%d].endpoint must be an absolute HTTPS URL without credentials, query, or fragment", index)
		}
		host := strings.ToLower(parsed.Hostname())
		if _, ok := allowed[host]; !ok {
			return fmt.Errorf("auth.claimEnrichment.sources[%d].endpoint host is not allowed", index)
		}
		if !claimNamePattern.MatchString(source.OutputClaim) || isSensitiveEnrichmentPath(source.OutputClaim) {
			return fmt.Errorf("auth.claimEnrichment.sources[%d].outputClaim must be a safe non-sensitive top-level claim name", index)
		}
		if _, exists := seenClaims[source.OutputClaim]; exists {
			return fmt.Errorf("auth.claimEnrichment.sources[%d].outputClaim is duplicated", index)
		}
		seenClaims[source.OutputClaim] = struct{}{}
		if !claimPathPattern.MatchString(source.ValuePath) || isSensitiveEnrichmentPath(source.ValuePath) {
			return fmt.Errorf("auth.claimEnrichment.sources[%d].valuePath must be a safe non-sensitive JSON path", index)
		}
	}
	if len(c.Sources) > 0 && len(allowed) == 0 {
		return fmt.Errorf("auth.claimEnrichment.allowedHosts is required when sources are configured")
	}
	return nil
}

func validClaimSourceHost(host string) bool {
	if host == "" || host != strings.TrimSpace(host) || host != strings.ToLower(host) || strings.ContainsAny(host, "/@?#:") {
		return false
	}
	if net.ParseIP(host) != nil {
		return true
	}
	if !dnsHostPattern.MatchString(host) || strings.Contains(host, "..") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
	}
	return true
}

func isSensitiveEnrichmentPath(path string) bool {
	if isSensitiveClaimPath(path) {
		return true
	}
	compact := strings.NewReplacer(".", "", "[", "", "]", "", "-", "", "_", "").Replace(strings.ToLower(path))
	for _, sensitive := range []string{"token", "secret", "password", "credential", "authorization"} {
		if strings.Contains(compact, sensitive) {
			return true
		}
	}
	for _, part := range strings.FieldsFunc(strings.ToLower(path), func(r rune) bool {
		return r == '.' || r == '[' || r == ']' || r == '-' || r == '_'
	}) {
		switch part {
		case "token", "secret", "password", "authorization", "credential", "credentials":
			return true
		}
	}
	return false
}

func (a *Authenticator) enrichClaims(ctx context.Context, accessToken string, claims map[string]any) (map[string]any, error) {
	enriched := make(map[string]any, len(claims)+len(a.config.Auth.ClaimEnrichment.Sources))
	for key, value := range claims {
		enriched[key] = value
	}
	if len(a.config.Auth.ClaimEnrichment.Sources) == 0 {
		return enriched, nil
	}
	if accessToken == "" {
		return nil, errors.New("OAuth access token is unavailable for configured claim enrichment")
	}
	timeout := a.claimSourceTimeout
	if timeout <= 0 {
		timeout = defaultClaimSourceTimeout
	}
	for _, source := range a.config.Auth.ClaimEnrichment.Sources {
		if _, exists := enriched[source.OutputClaim]; exists {
			return nil, errors.New("configured claim enrichment output collides with an authenticated claim")
		}
		requestContext, cancel := context.WithTimeout(ctx, timeout)
		value, err := a.fetchEnrichedClaim(requestContext, accessToken, source)
		cancel()
		if err != nil {
			return nil, err
		}
		enriched[source.OutputClaim] = value
	}
	return enriched, nil
}

func (a *Authenticator) fetchEnrichedClaim(ctx context.Context, accessToken string, source OAuthClaimSource) (any, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, source.Endpoint, nil)
	if err != nil {
		return nil, errors.New("build OAuth claim source request")
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+accessToken)
	request.Header.Set("User-Agent", "nvt-agent-gateway")
	response, err := a.httpClient.Do(request)
	if err != nil {
		return nil, errors.New("request OAuth claim source")
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return nil, errors.New("OAuth claim source rejected request")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxClaimSourceResponseSize+1))
	if err != nil || len(body) > maxClaimSourceResponseSize {
		return nil, errors.New("read OAuth claim source response")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var document map[string]any
	if err := decoder.Decode(&document); err != nil || document == nil {
		return nil, errors.New("decode OAuth claim source response")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("decode OAuth claim source response")
	}
	selected := selectClaimValues(document, source.ValuePath)
	if len(selected) != 1 {
		return nil, errors.New("OAuth claim source value is missing or ambiguous")
	}
	value, ok := normalizeEnrichedClaim(selected[0])
	if !ok {
		return nil, errors.New("OAuth claim source value has an unsupported shape")
	}
	return value, nil
}

func normalizeEnrichedClaim(value any) (any, bool) {
	switch typed := value.(type) {
	case string:
		return typed, typed != "" && len(typed) <= maxEnrichedClaimStringSize
	case bool:
		return typed, true
	case json.Number:
		return typed.String(), len(typed.String()) <= maxEnrichedClaimStringSize
	case []any:
		if len(typed) == 0 || len(typed) > maxEnrichedClaimArraySize {
			return nil, false
		}
		output := make([]any, 0, len(typed))
		for _, item := range typed {
			normalized, ok := normalizeEnrichedClaim(item)
			if !ok {
				return nil, false
			}
			if _, nested := normalized.([]any); nested {
				return nil, false
			}
			output = append(output, normalized)
		}
		return output, true
	default:
		return nil, false
	}
}

// ParseClaimEnrichmentConfig parses the provider-neutral OAuth claim sources.
func ParseClaimEnrichmentConfig(raw string) (ClaimEnrichmentConfig, error) {
	if strings.TrimSpace(raw) == "" {
		return ClaimEnrichmentConfig{}, nil
	}
	var config ClaimEnrichmentConfig
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return ClaimEnrichmentConfig{}, fmt.Errorf("parse gateway claim enrichment: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ClaimEnrichmentConfig{}, fmt.Errorf("parse gateway claim enrichment: trailing JSON value")
	}
	return config, nil
}
