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
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// CACertFileName is the only file the CA ever publishes. The private key
// stays in egressd process memory: it is subject to the same zero-secrets
// invariant as every other credential (docs/phase4-git-mediation-plan.md §2).
const CACertFileName = "ca.crt"

const (
	caValidity       = 30 * 24 * time.Hour
	leafValidity     = 6 * time.Hour
	leafRemintMargin = time.Hour
)

// localLeafName is the only DNS name leafs are ever minted for. Together
// with the loopback IP SANs it defines the "local redirect names" boundary:
// minting an upstream-name SAN (github.com, ...) is exactly the line Phase 6
// crosses deliberately and Phase 4 must not.
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

	// Now is a test seam; nil means time.Now.
	Now func() time.Time

	mu         sync.Mutex
	leaf       *tls.Certificate
	leafExpiry time.Time
}

// NewCA generates the CA keypair and self-signed certificate in memory.
// leafDNSNames extends the local redirect boundary with synthetic Service
// names for own-Pod mode; name constraints cover exactly localhost plus
// these names.
func NewCA(leafDNSNames ...string) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate CA key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	names := append([]string(nil), leafDNSNames...)
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "nvt-egressd per-agent CA"},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(caValidity),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign,

		// Name constraints: this CA can only ever vouch for local redirect
		// names, even if the key leaked.
		PermittedDNSDomainsCritical: true,
		PermittedDNSDomains:         append([]string{localLeafName}, names...),
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
		cert:         cert,
		key:          key,
		certPEM:      pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		leafDNSNames: names,
	}, nil
}

// LoadCA loads a durable CA keypair from PEM files. Own-Pod enforcement uses
// this so egressd restarts keep the same trust anchor already mounted by the
// agent.
func LoadCA(certFile, keyFile string, leafDNSNames ...string) (*CA, error) {
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
		cert:         cert,
		key:          key,
		certPEM:      pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes}),
		leafDNSNames: append([]string(nil), leafDNSNames...),
	}
	for _, name := range append([]string{localLeafName}, ca.leafDNSNames...) {
		if !ca.allowedLeafName(name) {
			return nil, fmt.Errorf("CA refused configured leaf name %q", name)
		}
	}
	return ca, nil
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

// PublishCert atomically writes ca.crt (and only ca.crt) into dir, the
// shared volume the agent container mounts read-only. The private key is
// never written anywhere.
func (ca *CA) PublishCert(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create CA publish dir: %w", err)
	}
	target := filepath.Join(dir, CACertFileName)
	temporary := target + ".tmp"
	if err := os.WriteFile(temporary, ca.certPEM, 0o644); err != nil {
		return fmt.Errorf("write CA certificate: %w", err)
	}
	if err := os.Rename(temporary, target); err != nil {
		return fmt.Errorf("publish CA certificate: %w", err)
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

// GetCertificate mints (and caches) the local leaf certificate on demand.
// Leafs carry only local redirect SANs (localhost plus the configured
// synthetic Service names); a ClientHello naming anything else — in
// particular a real upstream name — is refused outright.
func (ca *CA) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if hello.ServerName != "" && !ca.allowedLeafName(hello.ServerName) {
		return nil, fmt.Errorf("refusing to mint leaf for non-local name %q", hello.ServerName)
	}
	return ca.localLeaf()
}

func (ca *CA) allowedLeafName(name string) bool {
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

func (ca *CA) now() time.Time {
	if ca.Now != nil {
		return ca.Now()
	}
	return time.Now()
}

func (ca *CA) localLeaf() (*tls.Certificate, error) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	now := ca.now()
	if ca.leaf != nil && now.Before(ca.leafExpiry.Add(-leafRemintMargin)) {
		return ca.leaf, nil
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
	ca.leafExpiry = expiry
	return ca.leaf, nil
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("generate certificate serial: %w", err)
	}
	return serial, nil
}
