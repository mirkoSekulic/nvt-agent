package egress

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// expiryMargin is how long before broker-reported expiry cached material is
// considered stale.
const expiryMargin = 30 * time.Second

// defaultTTL bounds cache reuse when the broker reports no expiry.
const defaultTTL = 60 * time.Second

// hopByHopHeaders are never forwarded in either direction (RFC 9110 §7.6.1).
var hopByHopHeaders = map[string]bool{
	"Connection":          true,
	"Keep-Alive":          true,
	"Proxy-Authenticate":  true,
	"Proxy-Authorization": true,
	"Proxy-Connection":    true,
	"Te":                  true,
	"Trailer":             true,
	"Transfer-Encoding":   true,
	"Upgrade":             true,
}

// maxCacheEntries bounds the material cache under pathological request-path
// cardinality; hitting it resets the cache, which only costs refetches.
const maxCacheEntries = 256

type cacheEntry struct {
	material  *Material
	fetchedAt time.Time
}

// Proxy serves one route: it injects broker-fetched headers into incoming
// requests and forwards them to the pinned upstream.
type Proxy struct {
	Route     Route
	Broker    *BrokerClient
	Transport http.RoundTripper
	Now       func() time.Time

	mu    sync.Mutex
	cache map[string]*cacheEntry
}

func (p *Proxy) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

// material returns valid injectable material for one (method, path),
// refetching when the cache is stale. The cache is keyed by method and path
// because that is the scope the broker authorized: reusing material across
// paths would bypass provider method/path policy. It fails closed: fetch
// errors and already-expired material are errors, never masked by stale or
// unauthorized reuse.
func (p *Proxy) material(ctx context.Context, method, path string) (*Material, error) {
	key := method + " " + path
	p.mu.Lock()
	defer p.mu.Unlock()
	if entry, ok := p.cache[key]; ok {
		if p.entryValidLocked(entry) {
			return entry.material, nil
		}
		delete(p.cache, key)
	}
	material, err := p.Broker.FetchHeaders(ctx, p.Route.Capability, p.Route.Upstream, method, path)
	if err != nil {
		return nil, err
	}
	if !material.ExpiresAt.IsZero() && !p.now().Before(material.ExpiresAt.Add(-expiryMargin)) {
		return nil, fmt.Errorf("broker returned expired injection material")
	}
	if p.cache == nil {
		p.cache = map[string]*cacheEntry{}
	}
	if len(p.cache) >= maxCacheEntries {
		p.cache = map[string]*cacheEntry{}
	}
	p.cache[key] = &cacheEntry{material: material, fetchedAt: p.now()}
	return material, nil
}

func (p *Proxy) entryValidLocked(entry *cacheEntry) bool {
	now := p.now()
	if !entry.material.ExpiresAt.IsZero() {
		return now.Before(entry.material.ExpiresAt.Add(-expiryMargin))
	}
	return now.Before(entry.fetchedAt.Add(defaultTTL))
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	material, err := p.material(r.Context(), r.Method, r.URL.Path)
	if err != nil {
		// err carries broker reasons only, never header values.
		log.Printf("egressd %s: injection material unavailable: %v", p.Route.Capability, err)
		writeError(w, http.StatusBadGateway, "egress-injection-unavailable")
		return
	}
	outbound, err := p.buildOutbound(r, material)
	if err != nil {
		writeError(w, http.StatusBadGateway, "egress-request-invalid")
		return
	}
	response, err := p.Transport.RoundTrip(outbound)
	if err != nil {
		log.Printf("egressd %s: upstream unreachable", p.Route.Capability)
		writeError(w, http.StatusBadGateway, "egress-upstream-unreachable")
		return
	}
	defer func() { _ = response.Body.Close() }()
	copyResponse(w, response)
}

func (p *Proxy) buildOutbound(r *http.Request, material *Material) (*http.Request, error) {
	scheme := "https"
	if p.Route.AllowInsecureUpstream {
		scheme = "http"
	}
	outbound, err := http.NewRequestWithContext(r.Context(), r.Method, scheme+"://"+p.Route.Upstream+r.URL.RequestURI(), r.Body)
	if err != nil {
		return nil, err
	}
	outbound.ContentLength = r.ContentLength
	strip := map[string]bool{}
	for _, name := range material.Strip {
		strip[http.CanonicalHeaderKey(name)] = true
	}
	for name, values := range r.Header {
		canonical := http.CanonicalHeaderKey(name)
		if hopByHopHeaders[canonical] || strip[canonical] || canonical == "Host" {
			continue
		}
		if containsPlaceholder(values) {
			continue
		}
		outbound.Header[canonical] = values
	}
	for name, value := range material.Headers {
		outbound.Header.Set(name, value)
	}
	outbound.Host = p.Route.Upstream
	return outbound, nil
}

func containsPlaceholder(values []string) bool {
	for _, value := range values {
		if strings.Contains(value, Placeholder) {
			return true
		}
	}
	return false
}

func copyResponse(w http.ResponseWriter, response *http.Response) {
	header := w.Header()
	for name, values := range response.Header {
		if hopByHopHeaders[http.CanonicalHeaderKey(name)] {
			continue
		}
		header[name] = values
	}
	w.WriteHeader(response.StatusCode)
	flusher, _ := w.(http.Flusher)
	writer := io.Writer(w)
	if flusher != nil {
		writer = flushWriter{w: w, flusher: flusher}
	}
	_, _ = io.Copy(writer, response.Body)
}

// flushWriter flushes after every write so streaming responses (SSE) reach
// the agent without buffering delays.
type flushWriter struct {
	w       io.Writer
	flusher http.Flusher
}

func (fw flushWriter) Write(p []byte) (int, error) {
	n, err := fw.w.Write(p)
	fw.flusher.Flush()
	return n, err
}

func writeError(w http.ResponseWriter, status int, reason string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(`{"ok":false,"error":"` + reason + `"}`))
}
