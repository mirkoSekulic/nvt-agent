// Command echo is a hermetic upstream fixture for the kind egress smokes. It
// reflects the incoming request — method, path, and headers — as JSON so a
// smoke can assert what egressd actually forwarded (injected auth header,
// stripped placeholder, path). It is deliberately trivial and stdlib-only so
// it builds into a tiny static image loaded straight into the kind cluster,
// replacing the external httpbin.org dependency.
package main

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
)

type reflection struct {
	Method        string              `json:"method"`
	Path          string              `json:"path"`
	Query         string              `json:"query"`
	Headers       map[string][]string `json:"headers"`
	Authenticated bool                `json:"authenticated"`
}

func handler(w http.ResponseWriter, r *http.Request) {
	// Reflect headers with canonical names. The smoke greps this for the
	// injected credential value and asserts the placeholder never appears.
	headers := make(map[string][]string, len(r.Header))
	authenticated := false
	for name, values := range r.Header {
		headers[name] = values
		lower := strings.ToLower(name)
		// A credential-bearing header proves egressd injected material. Both
		// the Bearer path (authorization) and key-header providers (x-api-key)
		// count, so the fixture stays provider-agnostic.
		if lower == "authorization" || lower == "x-api-key" {
			for _, v := range values {
				if strings.TrimSpace(v) != "" {
					authenticated = true
				}
			}
		}
	}
	body := reflection{
		Method:        r.Method,
		Path:          r.URL.Path,
		Query:         r.URL.RawQuery,
		Headers:       headers,
		Authenticated: authenticated,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(body)
}

func main() {
	addr := os.Getenv("ECHO_LISTEN")
	if addr == "" {
		addr = ":8080"
	}
	mux := http.NewServeMux()
	// A dedicated readiness path so a Pod probe never depends on reflecting a
	// real request.
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/", handler)
	server := &http.Server{Addr: addr, Handler: mux}
	if err := server.ListenAndServe(); err != nil {
		os.Stderr.WriteString(err.Error() + "\n")
		os.Exit(1)
	}
}
