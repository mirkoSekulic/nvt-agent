package egress

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"
)

const publicCatalogPath = "/_nvt/catalog"
const maxPublicCatalogBytes = 1024 * 1024

// Public catalogs are provider-neutral, zero-credential output. This local
// control endpoint is not HTTP forwarding and never accepts an upstream URL.
func (p *ForwardProxy) servePublicCatalog(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet || r.URL.IsAbs() || r.URL.RawQuery != "" || r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
		http.Error(w, "invalid catalog request", http.StatusBadRequest)
		return
	}
	capability := capabilityHintFromConnect(r)
	configured := false
	for _, route := range p.Config.InjectRoutes {
		if capability != "" && route.Capability == capability {
			configured = true
		}
	}
	if !configured || p.Broker == nil {
		http.Error(w, "catalog capability not allowed", http.StatusForbidden)
		return
	}
	// Share the existing bounded concurrency/queue budget with CONNECT traffic.
	release, _ := p.acquireTunnel(r.Context())
	if release == nil {
		http.Error(w, "catalog capacity unavailable", http.StatusServiceUnavailable)
		return
	}
	defer release()
	ctx, cancel := context.WithTimeout(r.Context(), 40*time.Second)
	defer cancel()
	data, err := p.Broker.publicCatalog(ctx, capability)
	if err != nil {
		// Never reflect broker error bodies, headers, tokens, or diagnostics.
		http.Error(w, "public catalog unavailable", http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(data)
}

func (b *BrokerClient) publicCatalog(ctx context.Context, capability string) ([]byte, error) {
	body, _ := json.Marshal(map[string]string{"provider": capability})
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, b.URL+"/v1/injection/catalog", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+b.Token)
	request.Header.Set("Content-Type", "application/json")
	client := *b.Client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, errors.New("catalog denied")
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxPublicCatalogBytes+1))
	if err != nil || len(data) > maxPublicCatalogBytes {
		return nil, errors.New("catalog exceeds limit")
	}
	var result struct {
		OK    bool `json:"ok"`
		Files []struct {
			Path    string `json:"path"`
			Content string `json:"content"`
			Mode    string `json:"mode,omitempty"`
		} `json:"files"`
		ExpiresAt *string `json:"expires_at"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&result) != nil || !result.OK || result.Files == nil || len(result.Files) > 1024 || decoder.Decode(new(any)) != io.EOF {
		return nil, errors.New("invalid public catalog")
	}
	for _, file := range result.Files {
		if len(file.Path) == 0 || len(file.Path) > 4096 || len(file.Mode) > 16 {
			return nil, errors.New("invalid public catalog file")
		}
	}
	if result.ExpiresAt != nil {
		if _, err := time.Parse(time.RFC3339Nano, *result.ExpiresAt); err != nil {
			return nil, errors.New("invalid catalog expiry")
		}
	}
	// Re-encode only the public file schema, never a raw broker response.
	encoded, err := json.Marshal(result)
	if err != nil || len(encoded) > maxPublicCatalogBytes {
		return nil, errors.New("catalog exceeds limit")
	}
	return encoded, nil
}
