package egress

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Material is one injectable-header response from the broker. It may contain
// credentials, so Material must never be logged or serialized.
type Material struct {
	Headers       map[string]string
	AppendHeaders map[string]string
	Strip         []string
	ExpiresAt     time.Time // zero when the broker reported no expiry
}

// BrokerClient calls brokerd's injection endpoint under the egress-role
// identity.
type BrokerClient struct {
	URL    string
	Token  string
	Client *http.Client
}

type injectionRequest struct {
	Capability string `json:"capability"`
	Host       string `json:"host"`
	Method     string `json:"method"`
	Path       string `json:"path"`
}

type injectionResponse struct {
	OK                  bool              `json:"ok"`
	Error               string            `json:"error"`
	Headers             map[string]string `json:"headers"`
	AppendHeaders       map[string]string `json:"append_headers"`
	ExpiresAt           string            `json:"expires_at"`
	StripRequestHeaders []string          `json:"strip_request_headers"`
}

// FetchHeaders requests injectable headers for one (capability, host,
// method, path). Any failure is returned as an error; callers must fail
// closed rather than reuse stale material.
func (b *BrokerClient) FetchHeaders(ctx context.Context, capability, host, method, path string) (*Material, error) {
	body, err := json.Marshal(injectionRequest{
		Capability: capability,
		Host:       host,
		Method:     method,
		Path:       path,
	})
	if err != nil {
		return nil, fmt.Errorf("encode injection request: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, b.URL+"/v1/injection/headers", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build injection request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+b.Token)
	response, err := b.Client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("broker unreachable: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	var decoded injectionResponse
	if err := json.NewDecoder(response.Body).Decode(&decoded); err != nil {
		return nil, fmt.Errorf("decode injection response: %w", err)
	}
	if response.StatusCode != http.StatusOK || !decoded.OK {
		// decoded.Error is a machine reason (e.g. provider-not-granted),
		// never a header value; safe to wrap.
		return nil, fmt.Errorf("broker denied injection: %s", decoded.Error)
	}
	if overlappingHeaderNames(decoded.Headers, decoded.AppendHeaders, decoded.StripRequestHeaders) {
		return nil, fmt.Errorf("broker returned overlapping replacement, append, or strip headers")
	}
	material := &Material{
		Headers:       decoded.Headers,
		AppendHeaders: decoded.AppendHeaders,
		Strip:         decoded.StripRequestHeaders,
	}
	if decoded.ExpiresAt != "" {
		expires, parseErr := time.Parse(time.RFC3339, decoded.ExpiresAt)
		if parseErr != nil {
			return nil, fmt.Errorf("broker returned invalid expires_at")
		}
		material.ExpiresAt = expires
	}
	return material, nil
}

func overlappingHeaderNames(headers, appendHeaders map[string]string, strip []string) bool {
	restricted := make(map[string]struct{}, len(headers)+len(strip))
	for name := range headers {
		restricted[http.CanonicalHeaderKey(name)] = struct{}{}
	}
	for _, name := range strip {
		restricted[http.CanonicalHeaderKey(name)] = struct{}{}
	}
	for name := range appendHeaders {
		if _, exists := restricted[http.CanonicalHeaderKey(name)]; exists {
			return true
		}
	}
	return false
}

// ReportRequests posts a batch of per-request audit entries to the broker.
// It carries no credential material — only sanitized report fields — so its
// failures are non-fatal to the request path (the Reporter drops on error).
func (b *BrokerClient) ReportRequests(ctx context.Context, entries []map[string]any) error {
	body, err := json.Marshal(map[string]any{"entries": entries})
	if err != nil {
		return fmt.Errorf("encode report request: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, b.URL+"/v1/injection/report", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build report request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+b.Token)
	response, err := b.Client.Do(request)
	if err != nil {
		return fmt.Errorf("broker unreachable: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("broker rejected report: status %d", response.StatusCode)
	}
	return nil
}
