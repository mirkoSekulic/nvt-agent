package egress

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// CACertFileName is the only file the CA ever publishes. The private key
// stays in egressd process memory: it is subject to the same zero-secrets
// invariant as every other credential (protocol/injection.md).
const CACertFileName = "ca.crt"

const (
	caValidity       = 30 * 24 * time.Hour
	leafValidity     = 6 * time.Hour
	leafRemintMargin = time.Hour
)

// localLeafName is the only DNS name leafs are ever minted for. Together
// with the loopback IP SANs it defines the local redirect-name boundary.
const localLeafName = "localhost"

// CA is the per-agent certificate authority generated at egressd boot. It
// signs short-lived leaf certificates for the local redirect listeners and
// nothing else; name constraints on the CA certificate enforce that even a
// leaked key could not sign for arbitrary hosts (defense in depth — the
// primary invariant is that the key never leaves this process).
type CA struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte
	// leafDNSNames are the extra DNS names leafs may carry beyond localhost:
	// per-run egressd Service names in own-Pod mode. They are synthetic
	// redirect names, never upstream names — the config layer refuses any
	// overlap with route upstream hosts.
	leafDNSNames []string

	// upstreamLeafNames are the real upstream hostnames this CA may mint a
	// per-SNI leaf for, to TLS-terminate the forward proxy. It is bounded by
	// exactly the configured, allowlisted injectable hosts. Each name is minted as its own
	// leaf carrying only that DNS SAN (never a loopback IP SAN).
	upstreamLeafNames []string

	// Now is a test seam; nil means time.Now.
	Now func() time.Time
	// Logger receives one sanitized event when a leaf is minted or reminted.
	// Nil disables event logging (primarily useful in tests and library use).
	Logger *log.Logger

	mu         sync.Mutex
	leaf       *tls.Certificate
	leafExpiry time.Time
	// upstreamLeaves caches one leaf per allowlisted upstream SNI.
	upstreamLeaves map[string]*cachedLeaf
}

type cachedLeaf struct {
	cert   *tls.Certificate
	expiry time.Time
}

// NewCA generates the CA keypair and self-signed certificate in memory.
// leafDNSNames extends the local redirect boundary with synthetic Service
// names for own-Pod mode; name constraints cover exactly localhost plus
// these names.
func NewCA(leafDNSNames ...string) (*CA, error) {
	return NewCAWithUpstreams(leafDNSNames, nil)
}

// NewCAWithUpstreams additionally allows minting a per-SNI leaf for each name
// in upstreamLeafNames — the real upstream hosts the forward proxy terminates.
// Name constraints cover exactly localhost, the local Service
// names, and these allowlisted upstream hosts, and nothing else.
func NewCAWithUpstreams(leafDNSNames, upstreamLeafNames []string) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate CA key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	names := append([]string(nil), leafDNSNames...)
	upstreams := append([]string(nil), upstreamLeafNames...)
	// X.509 validity is wall-clock based. Keep certificate timestamps free of
	// Go's monotonic reading so suspend/resume cannot skew later comparisons.
	now := time.Now().UTC().Truncate(time.Second)
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "nvt-egressd per-agent CA"},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(caValidity),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign,

		// Name constraints: even a leaked key can only ever vouch for local
		// redirect names plus the allowlisted upstream hosts and their
		// subdomains (RFC 5280 dNSName constraints are suffix matches — Go
		// cannot express exact-only). The in-process GetCertificate gate is
		// exact-match, so egressd itself never mints a subdomain leaf.
		PermittedDNSDomainsCritical: true,
		PermittedDNSDomains:         permittedDomains(names, upstreams),
		PermittedIPRanges: []*net.IPNet{
			{IP: net.IPv4(127, 0, 0, 0).To4(), Mask: net.CIDRMask(8, 32)},
			{IP: net.IPv6loopback, Mask: net.CIDRMask(128, 128)},
		},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create CA certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse CA certificate: %w", err)
	}
	return &CA{
		cert:              cert,
		key:               key,
		certPEM:           pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		leafDNSNames:      names,
		upstreamLeafNames: upstreams,
		upstreamLeaves:    map[string]*cachedLeaf{},
	}, nil
}

// permittedDomains is the exact DNS name-constraint set: localhost, the local
// Service names, and the allowlisted upstream hosts.
func permittedDomains(leafDNSNames, upstreamLeafNames []string) []string {
	domains := append([]string{localLeafName}, leafDNSNames...)
	return append(domains, upstreamLeafNames...)
}

// LoadCA loads a durable CA keypair from PEM files. Own-Pod enforcement uses
// this so egressd restarts keep the same trust anchor already mounted by the
// agent.
func LoadCA(certFile, keyFile string, leafDNSNames ...string) (*CA, error) {
	return LoadCAWithUpstreams(certFile, keyFile, leafDNSNames, nil)
}

// LoadCAWithUpstreams loads a durable CA and additionally allows the
// allowlisted upstream hosts as per-SNI leaf names. A durable cert
// minted before the upstream widening will not carry the upstream name
// constraints, so leaf signing for those names fails verification at handshake
// time — the durable Secret must be regenerated when the allowlist changes.
func LoadCAWithUpstreams(certFile, keyFile string, leafDNSNames, upstreamLeafNames []string) (*CA, error) {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("read CA certificate: %w", err)
	}
	block, rest := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("CA certificate file contains no certificate")
	}
	if len(bytesTrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("CA certificate file contains trailing data")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA certificate: %w", err)
	}
	if !cert.IsCA {
		return nil, fmt.Errorf("CA certificate is not a CA")
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("read CA key: %w", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("CA key file contains no PEM block")
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA key: %w", err)
	}
	if !key.PublicKey.Equal(cert.PublicKey) {
		return nil, fmt.Errorf("CA key does not match certificate")
	}
	ca := &CA{
		cert:              cert,
		key:               key,
		certPEM:           pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes}),
		leafDNSNames:      append([]string(nil), leafDNSNames...),
		upstreamLeafNames: append([]string(nil), upstreamLeafNames...),
		upstreamLeaves:    map[string]*cachedLeaf{},
	}
	// Verify the durable cert actually carries critical DNS name constraints
	// covering exactly the configured names. Without this a BYO/unconstrained
	// durable CA would load silently, collapsing the two-gate model (a leaked
	// key could then sign any host), and a stale constrained cert would fail
	// only as a confusing runtime handshake error instead of loudly at boot.
	if err := ca.verifyDurableConstraints(); err != nil {
		return nil, err
	}
	return ca, nil
}

func (ca *CA) verifyDurableConstraints() error {
	if !ca.cert.PermittedDNSDomainsCritical {
		return fmt.Errorf("durable CA certificate must carry critical DNS name constraints")
	}
	if len(ca.cert.ExcludedDNSDomains) != 0 || len(ca.cert.ExcludedIPRanges) != 0 {
		return fmt.Errorf("durable CA certificate must not carry excluded-name constraints")
	}
	want := map[string]bool{}
	for _, name := range permittedDomains(ca.leafDNSNames, ca.upstreamLeafNames) {
		want[name] = true
	}
	got := map[string]bool{}
	for _, name := range ca.cert.PermittedDNSDomains {
		got[name] = true
	}
	if len(got) != len(want) {
		return fmt.Errorf("durable CA permitted DNS domains %v do not match configured names %v", ca.cert.PermittedDNSDomains, permittedDomains(ca.leafDNSNames, ca.upstreamLeafNames))
	}
	for name := range want {
		if !got[name] {
			return fmt.Errorf("durable CA permitted DNS domains are missing configured name %q", name)
		}
	}
	// The CA must not permit non-loopback IP leaves; loopback is the only
	// permitted range (local redirect listeners).
	for _, permitted := range ca.cert.PermittedIPRanges {
		if !permitted.IP.IsLoopback() {
			return fmt.Errorf("durable CA permits a non-loopback IP range %s", permitted.String())
		}
	}
	return nil
}

func bytesTrimSpace(data []byte) []byte {
	for len(data) > 0 {
		switch data[0] {
		case ' ', '\n', '\r', '\t':
			data = data[1:]
		default:
			goto trimRight
		}
	}
trimRight:
	for len(data) > 0 {
		switch data[len(data)-1] {
		case ' ', '\n', '\r', '\t':
			data = data[:len(data)-1]
		default:
			return data
		}
	}
	return data
}

// CertPEM returns the CA certificate (public material only).
func (ca *CA) CertPEM() []byte {
	return append([]byte(nil), ca.certPEM...)
}

// WriteKeyPair writes the durable CA certificate and private key. This is for
// local/host state and operator-owned Secret creation only; egressd never
// publishes the private key into the agent-visible CA directory.
func (ca *CA) WriteKeyPair(certFile, keyFile string) error {
	if err := os.MkdirAll(filepath.Dir(certFile), 0o700); err != nil {
		return fmt.Errorf("create CA certificate dir: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(keyFile), 0o700); err != nil {
		return fmt.Errorf("create CA key dir: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(ca.key)
	if err != nil {
		return fmt.Errorf("marshal CA key: %w", err)
	}
	if err := writeFileAtomic(certFile, ca.certPEM, 0o644); err != nil {
		return fmt.Errorf("write CA certificate: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := writeFileAtomic(keyFile, keyPEM, 0o600); err != nil {
		return fmt.Errorf("write CA key: %w", err)
	}
	return nil
}

// PublishCert atomically writes ca.crt (and only ca.crt) into dir, the
// shared volume the agent container mounts read-only. The private key is
// never written anywhere.
func (ca *CA) PublishCert(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create CA publish dir: %w", err)
	}
	target := filepath.Join(dir, CACertFileName)
	if err := writeFileAtomic(target, ca.certPEM, 0o644); err != nil {
		return fmt.Errorf("write CA certificate: %w", err)
	}
	return nil
}

func writeFileAtomic(target string, content []byte, mode os.FileMode) error {
	temporary := target + ".tmp"
	if err := os.WriteFile(temporary, content, mode); err != nil {
		return err
	}
	if err := os.Chmod(temporary, mode); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	if err := os.Rename(temporary, target); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	return nil
}

// ServerTLSConfig returns the tls.Config for a listen_tls: ca route.
func (ca *CA) ServerTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: ca.GetCertificate,
	}
}

// GetCertificate mints (and caches) a leaf certificate on demand. A local name
// (localhost or a configured synthetic Service name) gets the shared local
// leaf; an allowlisted upstream name gets its own per-SNI leaf carrying only
// that DNS SAN for forward-proxy TLS termination. Any other ServerName — and any
// IP-literal upstream SNI — is refused outright.
func (ca *CA) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	name := hello.ServerName
	if name == "" || ca.isLocalLeafName(name) {
		return ca.localLeaf()
	}
	if ca.isUpstreamLeafName(name) {
		return ca.upstreamLeaf(name)
	}
	return nil, fmt.Errorf("refusing to mint leaf for non-allowlisted name %q", name)
}

func (ca *CA) allowedLeafName(name string) bool {
	return ca.isLocalLeafName(name) || ca.isUpstreamLeafName(name)
}

func (ca *CA) isLocalLeafName(name string) bool {
	if name == localLeafName {
		return true
	}
	for _, allowed := range ca.leafDNSNames {
		if name == allowed {
			return true
		}
	}
	return false
}

func (ca *CA) isUpstreamLeafName(name string) bool {
	for _, allowed := range ca.upstreamLeafNames {
		if name == allowed {
			return true
		}
	}
	return false
}

func (ca *CA) now() time.Time {
	if ca.Now != nil {
		return ca.Now().UTC()
	}
	return time.Now().UTC()
}

func (ca *CA) localLeaf() (*tls.Certificate, error) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	now := ca.now()
	if ca.leaf != nil && now.Before(ca.leafExpiry.Add(-leafRemintMargin)) {
		return ca.leaf, nil
	}
	old := ca.leaf
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate leaf key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	expiry := now.Add(leafValidity)
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "nvt-egressd local redirect"},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     expiry,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     append([]string{localLeafName}, ca.leafDNSNames...),
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return nil, fmt.Errorf("sign leaf certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse leaf certificate: %w", err)
	}
	ca.leaf = &tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
		Leaf:        leaf,
	}
	// Use the parsed X.509 timestamp as the cache deadline. Besides matching
	// the certificate's second precision exactly, parsed timestamps carry no
	// monotonic reading, so wall time advanced by host/VM suspend is honored.
	ca.leafExpiry = leaf.NotAfter
	ca.logLeafEvent(localLeafName, old, ca.leaf)
	return ca.leaf, nil
}

// upstreamLeaf mints (and caches per SNI) a leaf for an allowlisted upstream
// host. The leaf carries only that DNS SAN and no IP SANs; an IP-literal SNI is
// refused so the MITM boundary is exactly the configured DNS hosts.
func (ca *CA) upstreamLeaf(name string) (*tls.Certificate, error) {
	if net.ParseIP(name) != nil {
		return nil, fmt.Errorf("refusing to mint upstream leaf for IP literal %q", name)
	}
	ca.mu.Lock()
	defer ca.mu.Unlock()
	now := ca.now()
	if entry, ok := ca.upstreamLeaves[name]; ok && now.Before(entry.expiry.Add(-leafRemintMargin)) {
		return entry.cert, nil
	}
	var old *tls.Certificate
	if entry, ok := ca.upstreamLeaves[name]; ok {
		old = entry.cert
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate leaf key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	expiry := now.Add(leafValidity)
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     expiry,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{name},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return nil, fmt.Errorf("sign upstream leaf certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse upstream leaf certificate: %w", err)
	}
	cert := &tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
		Leaf:        leaf,
	}
	ca.upstreamLeaves[name] = &cachedLeaf{cert: cert, expiry: leaf.NotAfter}
	ca.logLeafEvent(name, old, cert)
	return cert, nil
}

func (ca *CA) logLeafEvent(host string, old, current *tls.Certificate) {
	if ca.Logger == nil || current == nil || current.Leaf == nil {
		return
	}
	if old == nil || old.Leaf == nil {
		ca.Logger.Printf("event=tls_leaf_mint host=%q new_serial=%s new_expiry=%s",
			host, current.Leaf.SerialNumber, current.Leaf.NotAfter.UTC().Format(time.RFC3339))
		return
	}
	ca.Logger.Printf("event=tls_leaf_remint host=%q old_serial=%s old_expiry=%s new_serial=%s new_expiry=%s",
		host, old.Leaf.SerialNumber, old.Leaf.NotAfter.UTC().Format(time.RFC3339),
		current.Leaf.SerialNumber, current.Leaf.NotAfter.UTC().Format(time.RFC3339))
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("generate certificate serial: %w", err)
	}
	return serial, nil
}
