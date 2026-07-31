package config

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestDecodeStrictConfiguration(t *testing.T) {
	valid := validConfiguration(t)
	encoded, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(encoded); err != nil {
		t.Fatalf("valid configuration rejected: %v", err)
	}
	for name, mutate := range map[string]func(*Configuration){
		"mutable guest image":    func(value *Configuration) { value.GuestImage.Digest = "latest" },
		"plain registry":         func(value *Configuration) { value.HostBundle.Repository = "http://registry.example/nvt/host" },
		"registry port":          func(value *Configuration) { value.HostBundle.Repository = "https://registry.example:444/nvt/host" },
		"invalid CA":             func(value *Configuration) { value.EnrollmentCAPEM = "not a certificate" },
		"invalid session CA":     func(value *Configuration) { value.NativeSessionCAPEM = "not a certificate" },
		"plain session endpoint": func(value *Configuration) { value.NativeSessionEndpoint = "tcp://gateway.example:7443" },
		"excess CPU":             func(value *Configuration) { value.CPUs = 9 },
		"undersized memory":      func(value *Configuration) { value.MemoryMiB = 255 },
		"unknown accelerator":    func(value *Configuration) { value.Acceleration = "magic" },
		"unbounded timeout":      func(value *Configuration) { value.BootTimeoutSec = MaxBootTimeoutSeconds + 1 },
	} {
		t.Run(name, func(t *testing.T) {
			value := valid
			mutate(&value)
			content, _ := json.Marshal(value)
			if _, err := Decode(content); err == nil {
				t.Fatal("invalid configuration was accepted")
			}
		})
	}
	unknown := append(encoded[:len(encoded)-1], []byte(`,"provider_secret":"canary"}`)...)
	if _, err := Decode(unknown); err == nil {
		t.Fatal("unknown provider configuration was accepted")
	}
	duplicate := []byte(strings.Replace(string(encoded), `"cpus":1`, `"cpus":1,"cpus":2`, 1))
	if _, err := Decode(duplicate); err == nil {
		t.Fatal("duplicate configuration key was accepted")
	}
}

func TestValidateArtifactAcceptsExplicitHTTPSPort(t *testing.T) {
	if err := ValidateArtifact(Artifact{
		Repository: "https://registry.example:443/nvt/host-bundle",
		Digest:     "sha256:" + strings.Repeat("b", 64),
	}); err != nil {
		t.Fatalf("explicit HTTPS port rejected: %v", err)
	}
}

func TestNativeEgressProbeIsStrictBoundedAndNonSecret(t *testing.T) {
	valid := validConfiguration(t)
	valid.NativeEgressProbe = &NativeEgressProbe{Host: "echo.example", Port: 443, Capability: "github-main"}
	encoded, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(encoded)
	if err != nil || decoded.NativeEgressProbe == nil || *decoded.NativeEgressProbe != *valid.NativeEgressProbe {
		t.Fatalf("valid native egress proof rejected: %#v, %v", decoded.NativeEgressProbe, err)
	}
	for name, mutate := range map[string]func(*NativeEgressProbe){
		"missing host":       func(value *NativeEgressProbe) { value.Host = "" },
		"noncanonical host":  func(value *NativeEgressProbe) { value.Host = "Echo.example" },
		"IP fixture host":    func(value *NativeEgressProbe) { value.Host = "8.8.8.8" },
		"missing port":       func(value *NativeEgressProbe) { value.Port = 0 },
		"missing capability": func(value *NativeEgressProbe) { value.Capability = "" },
		"secret-shaped hint": func(value *NativeEgressProbe) { value.Capability = "nvt_eg1_secret" },
	} {
		t.Run(name, func(t *testing.T) {
			copy := *valid.NativeEgressProbe
			mutate(&copy)
			if ValidateNativeEgressProbe(copy) == nil {
				t.Fatal("invalid QEMU proof input was accepted")
			}
		})
	}
}

func validConfiguration(t *testing.T) Configuration {
	t.Helper()
	return Configuration{
		ContractVersion:       Version,
		GuestImage:            GuestImage{Digest: "sha256:" + strings.Repeat("a", 64)},
		HostBundle:            Artifact{Repository: "https://registry.example/nvt/host-bundle", Digest: "sha256:" + strings.Repeat("b", 64)},
		EnrollmentCAPEM:       testCAPEM(t),
		NativeSessionEndpoint: "tls://gateway.example:7443",
		NativeSessionCAPEM:    testCAPEM(t),
		CPUs:                  1,
		MemoryMiB:             512,
		Acceleration:          "tcg",
		BootTimeoutSec:        30,
	}
}

func testCAPEM(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-ca"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}, &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-ca"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}
