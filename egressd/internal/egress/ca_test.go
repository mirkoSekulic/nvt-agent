package egress

// Phase 4 CA and TLS-termination proofs (docs/phase4-git-mediation-plan.md
// §2, §4): the boot-generated CA publishes only its certificate, mints leafs
// only for local redirect names, and the first TLS-terminated route pins the
// upstream identity requirement — outbound URL, Host, and SNI all forced to
// the pinned upstream, never derived from the client request.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func caCertPool(t *testing.T, ca *CA) *x509.CertPool {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca.CertPEM()) {
		t.Fatal("CA PEM did not parse")
	}
	return pool
}

func mintedLocalLeaf(t *testing.T, ca *CA) *x509.Certificate {
	t.Helper()
	leaf, err := ca.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

// TestCALeafIsLocalOnly pins leaf SAN minimalism: local redirect names only,
// never an upstream name, short TTL, verifiable against the CA.
func TestCALeafIsLocalOnly(t *testing.T) {
	ca, err := NewCA()
	if err != nil {
		t.Fatal(err)
	}
	leaf := mintedLocalLeaf(t, ca)
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != localLeafName {
		t.Fatalf("leaf DNS SANs = %v, want only %q", leaf.DNSNames, localLeafName)
	}
	ips := map[string]bool{}
	for _, ip := range leaf.IPAddresses {
		ips[ip.String()] = true
	}
	if len(ips) != 2 || !ips["127.0.0.1"] || !ips["::1"] {
		t.Fatalf("leaf IP SANs = %v, want loopback only", leaf.IPAddresses)
	}
	if ttl := time.Until(leaf.NotAfter); ttl > leafValidity+time.Minute {
		t.Fatalf("leaf TTL %s exceeds the hours-scale bound", ttl)
	}
	for _, name := range []string{"localhost"} {
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: caCertPool(t, ca), DNSName: name}); err != nil {
			t.Fatalf("leaf does not verify for %s against the CA: %v", name, err)
		}
	}
}

// TestCARefusesUpstreamLeaf pins the Phase 4/Phase 6 boundary: a ClientHello
// naming a real upstream is refused, not answered with a minted certificate.
func TestCARefusesUpstreamLeaf(t *testing.T) {
	ca, err := NewCA()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"github.com", "chatgpt.com", "api.github.com"} {
		if _, err := ca.GetCertificate(&tls.ClientHelloInfo{ServerName: name}); err == nil {
			t.Fatalf("CA minted a leaf for upstream name %q", name)
		}
	}
}

// TestCACertCarriesNameConstraints pins the defense-in-depth property: even
// a leaked CA key could not sign for arbitrary hosts.
func TestCACertCarriesNameConstraints(t *testing.T) {
	ca, err := NewCA()
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(ca.CertPEM())
	if block == nil {
		t.Fatal("no PEM block in CA certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !cert.PermittedDNSDomainsCritical {
		t.Fatal("CA name constraints are not critical")
	}
	if len(cert.PermittedDNSDomains) != 1 || cert.PermittedDNSDomains[0] != localLeafName {
		t.Fatalf("CA permitted DNS domains = %v", cert.PermittedDNSDomains)
	}
	if len(cert.PermittedIPRanges) != 2 {
		t.Fatalf("CA permitted IP ranges = %v", cert.PermittedIPRanges)
	}
	if !cert.MaxPathLenZero {
		t.Fatal("CA must not permit intermediate CAs")
	}
}

// TestCAPublishesOnlyCertificate pins CA key custody: the publish directory
// receives ca.crt and nothing else, and no private key material.
func TestCAPublishesOnlyCertificate(t *testing.T) {
	ca, err := NewCA()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := ca.PublishCert(dir); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != CACertFileName {
		names := make([]string, 0, len(entries))
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		t.Fatalf("publish dir contents = %v, want only %s", names, CACertFileName)
	}
	content, err := os.ReadFile(filepath.Join(dir, CACertFileName))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), "BEGIN CERTIFICATE") {
		t.Fatal("published file is not a certificate")
	}
	if strings.Contains(string(content), "PRIVATE KEY") {
		t.Fatal("published file contains private key material")
	}
}

// TestConfigListenTLSCA pins the config shape: listen_tls: ca requires the
// ca block, excludes static cert/key files, and rejects unknown modes.
func TestConfigListenTLSCA(t *testing.T) {
	base := func() *Config {
		return &Config{
			BrokerURL: "https://broker:7347",
			Routes:    []Route{{Listen: "127.0.0.1:8473", Capability: "git-app", Upstream: "github.com:443", ListenTLS: RouteListenTLSCA}},
			CA:        &CAConfig{PublishDir: "/nvt-egress-ca"},
		}
	}
	if err := base().Validate(); err != nil {
		t.Fatalf("valid listen_tls: ca config rejected: %v", err)
	}
	if !base().Routes[0].TLSEnabled() {
		t.Fatal("listen_tls: ca route must report TLSEnabled")
	}

	noCA := base()
	noCA.CA = nil
	if err := noCA.Validate(); err == nil {
		t.Fatal("listen_tls: ca without ca block must be rejected")
	}
	emptyDir := base()
	emptyDir.CA.PublishDir = ""
	if err := emptyDir.Validate(); err == nil {
		t.Fatal("ca block without publish_dir must be rejected")
	}
	withFiles := base()
	withFiles.Routes[0].ListenTLSCert = "/tls/cert.pem"
	withFiles.Routes[0].ListenTLSKey = "/tls/key.pem"
	if err := withFiles.Validate(); err == nil {
		t.Fatal("listen_tls: ca combined with static cert/key must be rejected")
	}
	unknown := base()
	unknown.Routes[0].ListenTLS = "self-signed"
	if err := unknown.Validate(); err == nil {
		t.Fatal("unknown listen_tls mode must be rejected")
	}
}

// gitBrokerMaterial is the injectable material shape a github-app git grant
// produces: Basic x-access-token credentials with authorization stripped.
func gitBrokerServer(t *testing.T, injected string) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/injection/headers" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":                    true,
			"headers":               map[string]string{"authorization": injected},
			"strip_request_headers": []string{"authorization"},
			"expires_at":            time.Now().UTC().Add(time.Hour).Format(time.RFC3339),
		})
	}))
	t.Cleanup(server.Close)
	return server
}

type tlsUpstream struct {
	listener net.Listener
	pool     *x509.CertPool

	mu             sync.Mutex
	serverNames    []string
	hosts          []string
	authorizations [][]string
}

// newTLSUpstream serves HTTPS for the given DNS name on a loopback listener,
// recording the SNI of every handshake and the Host/Authorization of every
// request.
func newTLSUpstream(t *testing.T, name string) *tlsUpstream {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{name},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(parsed)
	certificate := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: parsed}

	upstream := &tlsUpstream{pool: pool}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsConfig := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{certificate},
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			upstream.mu.Lock()
			upstream.serverNames = append(upstream.serverNames, hello.ServerName)
			upstream.mu.Unlock()
			return nil, nil
		},
	}
	upstream.listener = tls.NewListener(listener, tlsConfig)
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstream.mu.Lock()
		upstream.hosts = append(upstream.hosts, r.Host)
		upstream.authorizations = append(upstream.authorizations, r.Header.Values("Authorization"))
		upstream.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	})}
	go func() { _ = server.Serve(upstream.listener) }()
	t.Cleanup(func() { _ = server.Close() })
	return upstream
}

// TestGitRouteTLSEndToEnd is the first real TLS e2e for the git route: a
// client trusting only the published CA reaches the HTTPS listener, an
// agent-supplied Basic credential is stripped, the upstream sees exactly one
// broker-injected Basic header, and the outbound Host and SNI are the pinned
// upstream — never the client-facing 127.0.0.1 identity.
func TestGitRouteTLSEndToEnd(t *testing.T) {
	injected := "Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:fixture-installation-token"))
	broker := gitBrokerServer(t, injected)
	upstream := newTLSUpstream(t, "git.upstream.test")

	proxy := &Proxy{
		Route: Route{
			Listen:     "unused",
			Capability: "git-app",
			Upstream:   "git.upstream.test:443",
			ListenTLS:  RouteListenTLSCA,
		},
		Broker: &BrokerClient{URL: broker.URL, Token: "egress-role-token", Client: broker.Client()},
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: upstream.pool, MinVersion: tls.VersionTLS12},
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				if address != "git.upstream.test:443" {
					return nil, fmt.Errorf("unexpected outbound dial %q", address)
				}
				return net.Dial("tcp", upstream.listener.Addr().String())
			},
		},
	}

	ca, err := NewCA()
	if err != nil {
		t.Fatal(err)
	}
	publishDir := t.TempDir()
	if err := ca.PublishCert(publishDir); err != nil {
		t.Fatal(err)
	}
	published, err := os.ReadFile(filepath.Join(publishDir, CACertFileName))
	if err != nil {
		t.Fatal(err)
	}
	clientPool := x509.NewCertPool()
	if !clientPool.AppendCertsFromPEM(published) {
		t.Fatal("published CA certificate did not parse")
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: proxy}
	go func() { _ = server.Serve(tls.NewListener(listener, ca.ServerTLSConfig())) }()
	t.Cleanup(func() { _ = server.Close() })

	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: clientPool, MinVersion: tls.VersionTLS12},
	}}
	url := "https://" + listener.Addr().String() + "/my-user/my-repo.git/info/refs?service=git-upload-pack"
	request, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	// A git client that was fed garbage credentials volunteers them as Basic
	// auth; the strip guarantee must remove them.
	request.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("agent:garbage")))
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 through the TLS route, got %d", response.StatusCode)
	}

	upstream.mu.Lock()
	defer upstream.mu.Unlock()
	if len(upstream.authorizations) != 1 {
		t.Fatalf("upstream request count = %d", len(upstream.authorizations))
	}
	if got := upstream.authorizations[0]; len(got) != 1 || got[0] != injected {
		t.Fatalf("upstream authorization = %v, want exactly the injected Basic header", got)
	}
	if got := upstream.hosts[0]; got != "git.upstream.test:443" {
		t.Fatalf("upstream Host = %q, want the pinned upstream, never the client-facing host", got)
	}
	for _, name := range upstream.serverNames {
		if name != "git.upstream.test" {
			t.Fatalf("outbound SNI = %q, want the pinned upstream name", name)
		}
	}
	if len(upstream.serverNames) == 0 {
		t.Fatal("upstream recorded no TLS handshakes")
	}
}
