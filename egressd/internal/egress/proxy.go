package egress

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// expiryMargin is how long before broker-reported expiry cached material is
// considered stale.
const expiryMargin = 30 * time.Second

// maxCacheTTL bounds cache reuse regardless of credential expiry. This is
// the load-bearing half of the revocation bound: broker-side grant checks
// run per *fetch*, so a revoked grant keeps working until the cache expires.
// Credential validity (e.g. a ~1h GitHub installation token) must not set
// that window; refetching is cheap because the broker caches minted tokens
// with its own buffer.
const maxCacheTTL = 60 * time.Second

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
	Reporter  *Reporter
	Now       func() time.Time
	// UpgradeIdleTimeout bounds upgraded HTTP/WebSocket relays. Zero disables
	// the relay-specific deadline, which keeps redirect routes compatible; the
	// forward-proxy MITM path sets this from its tunnel idle timeout.
	UpgradeIdleTimeout time.Duration

	mu    sync.Mutex
	cache map[string]*cacheEntry

	// requestCount is the per-process request tally for max_requests. It is
	// incremented atomically; see quotaExceeded for the TOCTOU-free check.
	requestCount atomic.Int64
}

// quotaExceeded increments the request tally and reports whether this request
// is over the route's max_requests. Add-then-compare is TOCTOU-free: exactly
// the first MaxRequests callers observe a count within the limit; the
// (N+1)th and beyond fail closed. 0 means unlimited.
func (p *Proxy) quotaExceeded() bool {
	if p.Route.MaxRequests <= 0 {
		return false
	}
	return p.requestCount.Add(1) > int64(p.Route.MaxRequests)
}

// report enqueues one sanitized audit entry for this route. Nil-safe and
// non-blocking; PathClass keeps raw paths out of the report.
func (p *Proxy) report(method, path string, status int) {
	p.Reporter.Enqueue(ReportEntry{
		Capability: p.Route.Capability,
		Host:       injectionHost(p.Route.Upstream),
		Method:     method,
		PathClass:  PathClass(path),
		Status:     status,
	})
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
	material, err := p.Broker.FetchHeaders(ctx, p.Route.Capability, injectionHost(p.Route.Upstream), method, path)
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
	if !now.Before(entry.fetchedAt.Add(maxCacheTTL)) {
		return false
	}
	if !entry.material.ExpiresAt.IsZero() {
		return now.Before(entry.material.ExpiresAt.Add(-expiryMargin))
	}
	return true
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	material, err := p.material(r.Context(), r.Method, r.URL.Path)
	if err != nil {
		// err carries broker reasons only, never header values.
		log.Printf("egressd %s: injection material unavailable: %v", p.Route.Capability, err)
		p.report(r.Method, r.URL.Path, http.StatusBadGateway)
		writeError(w, http.StatusBadGateway, "egress-injection-unavailable")
		return
	}
	outbound, err := p.buildOutbound(r, material)
	if err != nil {
		p.report(r.Method, r.URL.Path, http.StatusBadGateway)
		writeError(w, http.StatusBadGateway, "egress-request-invalid")
		return
	}
	// Quota is checked only after the request is authorized and ready for the
	// upstream, so exactly MaxRequests authorized attempts reach upstream. A
	// broker outage, a revoked grant, or a projection-lag failure fails above
	// without ever consuming quota.
	if p.quotaExceeded() {
		log.Printf("egressd %s: request quota exceeded", p.Route.Capability)
		p.report(r.Method, r.URL.Path, http.StatusTooManyRequests)
		writeError(w, http.StatusTooManyRequests, "egress-quota-exceeded")
		return
	}
	if isUpgradeRequest(r) {
		p.serveUpgrade(w, r, outbound)
		return
	}
	response, err := p.Transport.RoundTrip(outbound)
	if err != nil {
		log.Printf("egressd %s: upstream unreachable", p.Route.Capability)
		p.report(r.Method, r.URL.Path, http.StatusBadGateway)
		writeError(w, http.StatusBadGateway, "egress-upstream-unreachable")
		return
	}
	defer func() { _ = response.Body.Close() }()
	p.report(r.Method, r.URL.Path, response.StatusCode)
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
	if isUpgradeRequest(r) {
		copyUpgradeHeaders(outbound.Header, r.Header)
	}
	outbound.Host = p.Route.Upstream
	return outbound, nil
}

func (p *Proxy) serveUpgrade(w http.ResponseWriter, r *http.Request, outbound *http.Request) {
	response, err := p.Transport.RoundTrip(outbound)
	if err != nil {
		log.Printf("egressd %s: upstream upgrade unreachable", p.Route.Capability)
		p.report(r.Method, r.URL.Path, http.StatusBadGateway)
		writeError(w, http.StatusBadGateway, "egress-upstream-unreachable")
		return
	}
	if response.StatusCode != http.StatusSwitchingProtocols {
		defer func() { _ = response.Body.Close() }()
		p.report(r.Method, r.URL.Path, response.StatusCode)
		copyResponse(w, response)
		return
	}
	upstream, ok := response.Body.(readWriteCloser)
	if !ok {
		_ = response.Body.Close()
		log.Printf("egressd %s: upstream upgrade body is not bidirectional", p.Route.Capability)
		p.report(r.Method, r.URL.Path, http.StatusBadGateway)
		writeError(w, http.StatusBadGateway, "egress-upgrade-unavailable")
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		_ = response.Body.Close()
		p.report(r.Method, r.URL.Path, http.StatusBadGateway)
		writeError(w, http.StatusBadGateway, "egress-upgrade-unavailable")
		return
	}
	client, buffered, err := hijacker.Hijack()
	if err != nil {
		_ = response.Body.Close()
		p.report(r.Method, r.URL.Path, http.StatusBadGateway)
		return
	}
	defer func() { _ = client.Close() }()
	defer func() { _ = upstream.Close() }()

	p.report(r.Method, r.URL.Path, response.StatusCode)
	if err := writeUpgradeResponse(client, response); err != nil {
		return
	}
	relayUpgrade(client, buffered, upstream, p.UpgradeIdleTimeout)
}

// injectionHost is the host presented to the broker for authorization: the
// pinned upstream's hostname with any port stripped. Provider injection-hosts
// are bare hostnames (protocol/injection.md); only the dial target keeps the
// port. Without this, an upstream pinned as "github.com:443" would never
// match a provider's "github.com" and every request would fail closed.
func injectionHost(upstream string) string {
	host, _, err := net.SplitHostPort(upstream)
	if err != nil {
		return upstream
	}
	return host
}

func containsPlaceholder(values []string) bool {
	for _, value := range values {
		if strings.Contains(value, Placeholder) {
			return true
		}
	}
	return false
}

func isUpgradeRequest(r *http.Request) bool {
	return headerHasToken(r.Header, "Connection", "upgrade") && r.Header.Get("Upgrade") != ""
}

func copyUpgradeHeaders(dst, src http.Header) {
	dst.Set("Connection", "Upgrade")
	if upgrade := src.Get("Upgrade"); upgrade != "" {
		dst.Set("Upgrade", upgrade)
	}
}

func headerHasToken(header http.Header, name, token string) bool {
	for _, value := range header.Values(name) {
		for _, part := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(part), token) {
				return true
			}
		}
	}
	return false
}

type readWriteCloser interface {
	io.Reader
	io.Writer
	io.Closer
}

func writeUpgradeResponse(w io.Writer, response *http.Response) error {
	reason := response.Status
	if reason == "" {
		reason = fmt.Sprintf("%03d %s", response.StatusCode, http.StatusText(response.StatusCode))
	}
	if _, err := fmt.Fprintf(w, "HTTP/%d.%d %s\r\n", response.ProtoMajor, response.ProtoMinor, reason); err != nil {
		return err
	}
	for name, values := range response.Header {
		for _, value := range values {
			if _, err := fmt.Fprintf(w, "%s: %s\r\n", name, value); err != nil {
				return err
			}
		}
	}
	_, err := io.WriteString(w, "\r\n")
	return err
}

func relayUpgrade(client net.Conn, buffered *bufio.ReadWriter, upstream readWriteCloser, idleTimeout time.Duration) {
	setUpgradeDeadline(idleTimeout, client, upstream)
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(upstream, upgradeActivityReader{
			reader:      buffered,
			idleTimeout: idleTimeout,
			values:      []any{client, upstream},
		})
		_ = closeWriteAny(upstream)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(client, upgradeActivityReader{
			reader:      upstream,
			idleTimeout: idleTimeout,
			values:      []any{client, upstream},
		})
		_ = closeWriteAny(client)
		done <- struct{}{}
	}()
	<-done
	<-done
}

type upgradeActivityReader struct {
	reader      io.Reader
	idleTimeout time.Duration
	values      []any
}

func (r upgradeActivityReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	if n > 0 {
		setUpgradeDeadline(r.idleTimeout, r.values...)
	}
	return n, err
}

func setUpgradeDeadline(idleTimeout time.Duration, values ...any) {
	if idleTimeout <= 0 {
		return
	}
	deadline := time.Now().Add(idleTimeout)
	for _, value := range values {
		if deadliner, ok := value.(interface{ SetDeadline(time.Time) error }); ok {
			_ = deadliner.SetDeadline(deadline)
		}
	}
}

func closeWriteAny(value any) error {
	type closeWriter interface {
		CloseWrite() error
	}
	if writer, ok := value.(closeWriter); ok {
		return writer.CloseWrite()
	}
	if closer, ok := value.(io.Closer); ok {
		return closer.Close()
	}
	return nil
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
