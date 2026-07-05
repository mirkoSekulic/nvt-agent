package egress

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Material is one injectable-header response from the broker. Header values
// are credentials: Material must never be logged or serialized.
type Material struct {
	Headers   map[string]string
	Strip     []string
	ExpiresAt time.Time // zero when the broker reported no expiry
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
	material := &Material{Headers: decoded.Headers, Strip: decoded.StripRequestHeaders}
	if decoded.ExpiresAt != "" {
		expires, parseErr := time.Parse(time.RFC3339, decoded.ExpiresAt)
		if parseErr != nil {
			return nil, fmt.Errorf("broker returned invalid expires_at")
		}
		material.ExpiresAt = expires
	}
	return material, nil
}
