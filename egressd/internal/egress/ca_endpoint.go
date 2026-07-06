package egress

import (
	"net/http"
)

// CAEndpointHandler serves the CA certificate for the operator to fetch in
// own-Pod mode, plus the readiness probe. It is deliberately plain HTTP: the
// certificate is public material and *is* the trust anchor being
// bootstrapped — TLS on this endpoint would be circular. Only the trusted
// operator fetches it (once, at reconcile time); the agent receives the CA
// through the operator-published ConfigMap, never over the network.
//
// The handler serves exactly two paths and nothing else. Key material has no
// code path here: the handler only ever reads CertPEM (public bytes).
func CAEndpointHandler(ca *CA) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/"+CACertFileName, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/x-pem-file")
		_, _ = w.Write(ca.CertPEM())
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	return mux
}
