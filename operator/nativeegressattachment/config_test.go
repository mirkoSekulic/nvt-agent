package nativeegressattachment

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mirkoSekulic/nvt-agent/operator/executiondriver"
)

func writeTestCA(t *testing.T, directory string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "attachment CA"},
		NotBefore: time.Unix(1, 0), NotAfter: time.Unix(4_102_444_800, 0),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "relay-ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadConfiguredIsStrictOperatorOwnedAndOptional(t *testing.T) {
	t.Setenv(EnvironmentConfigFile, "")
	if plan, err := LoadConfigured(); err != nil || plan != nil {
		t.Fatalf("omitted plan=%#v err=%v", plan, err)
	}
	directory := t.TempDir()
	document := configDocument{
		Version: 1, Generation: 2,
		RelayHost: "nvt-native-egress-relay.nvt.svc", RelayPort: 7445,
		RelayServerName: "nvt-native-egress-relay.nvt.svc", CAFile: writeTestCA(t, directory),
		RequiredDestinations: []executiondriver.NativeEgressRequiredDestination{
			{Purpose: executiondriver.NativeEgressDestinationControl, Host: "nvt-gateway.nvt.svc", Port: 7444},
			{Purpose: executiondriver.NativeEgressDestinationBootstrap, Host: "nvt-broker.nvt.svc", Port: 7443},
		},
		Redirect: executiondriver.NativeEgressRedirectIntent{
			Mode: executiondriver.NativeEgressRedirectModeCaptureTCP, LoopbackAddress: "127.0.0.1",
			TransparentTCPPort: 15001, ExplicitCONNECTPort: 15002,
		},
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "attachment.json")
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(EnvironmentConfigFile, path)
	plan, err := LoadConfigured()
	if err != nil || plan == nil || executiondriver.ValidateNativeEgressAttachment(*plan) != nil {
		t.Fatalf("plan=%#v err=%v", plan, err)
	}
	if plan.RequiredDestinations[0].Purpose != executiondriver.NativeEgressDestinationBootstrap {
		t.Fatal("installation destinations were not canonicalized")
	}
	formatted := plan.String()
	if strings.Contains(formatted, plan.Relay.Host) || strings.Contains(formatted, plan.Digest) {
		t.Fatalf("unsafe formatting %q", formatted)
	}

	for name, content := range map[string][]byte{
		"unknown":   append(encoded[:len(encoded)-1], []byte(`,"unknown":true}`)...),
		"trailing":  append(encoded, []byte(` {}`)...),
		"duplicate": append([]byte(`{"version":1,"version":1,`), encoded[1:]...),
		"oversized": []byte(strings.Repeat("x", maxConfigBytes+1)),
	} {
		t.Run(name, func(t *testing.T) {
			bad := filepath.Join(directory, name+".json")
			if err := os.WriteFile(bad, content, 0o600); err != nil {
				t.Fatal(err)
			}
			t.Setenv(EnvironmentConfigFile, bad)
			if plan, err := LoadConfigured(); err == nil || plan != nil {
				t.Fatalf("invalid config plan=%#v err=%v", plan, err)
			}
		})
	}
}
