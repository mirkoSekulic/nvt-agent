package relay

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigurationIsStrictCanonicalProcessOwnedAndRedacted(t *testing.T) {
	directory := t.TempDir()
	config := Configuration{
		Version: ConfigurationVersion, ListenAddress: "127.0.0.1:7445",
		TLSCertificateFile: filepath.Join(directory, "relay.crt"), TLSKeyFile: filepath.Join(directory, "relay.key"),
		BrokerURL: "https://broker.example:8443", BrokerServerName: "broker.example", BrokerCAFile: filepath.Join(directory, "broker-ca.crt"),
		AuthenticationTimeoutSeconds: 5, RevalidationIntervalSeconds: 30,
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	configPath := writeTestFile(t, directory, "config.json", encoded, 0o600)
	loaded, err := LoadConfiguration(configPath)
	if err != nil || loaded != config {
		t.Fatalf("valid configuration failed: %#v %v", loaded, err)
	}
	for _, formatted := range []string{fmt.Sprint(config), fmt.Sprintf("%+v", config), fmt.Sprintf("%#v", config)} {
		if strings.Contains(formatted, config.BrokerURL) || strings.Contains(formatted, config.TLSKeyFile) {
			t.Fatalf("configuration formatting exposed internals: %q", formatted)
		}
	}

	invalidValues := []Configuration{
		func() Configuration { value := config; value.ListenAddress = "relay.example:7445"; return value }(),
		func() Configuration { value := config; value.ListenAddress = "127.0.0.1:07445"; return value }(),
		func() Configuration { value := config; value.BrokerURL = "http://broker.example:8443"; return value }(),
		func() Configuration { value := config; value.BrokerURL = "https://broker.example:08443"; return value }(),
		func() Configuration { value := config; value.BrokerURL += "/v1"; return value }(),
		func() Configuration { value := config; value.BrokerServerName = "other.example"; return value }(),
		func() Configuration { value := config; value.BrokerServerName = "Broker.example"; return value }(),
		func() Configuration { value := config; value.TLSKeyFile = value.TLSCertificateFile; return value }(),
		func() Configuration { value := config; value.AuthenticationTimeoutSeconds = 6; return value }(),
		func() Configuration { value := config; value.RevalidationIntervalSeconds = 31; return value }(),
	}
	for index, invalid := range invalidValues {
		if invalid.validate() == nil {
			t.Fatalf("invalid configuration %d was accepted", index)
		}
	}

	unknown := append([]byte(nil), encoded[:len(encoded)-1]...)
	unknown = append(unknown, []byte(`,"credential":"forbidden"}`)...)
	for name, value := range map[string][]byte{
		"duplicate": []byte(`{"version":1,"version":1}`),
		"unknown":   unknown,
		"trailing":  append(append([]byte(nil), encoded...), []byte(` {}`)...),
		"oversized": append(make([]byte, MaxConfigurationBytes), 'x'),
	} {
		t.Run(name, func(t *testing.T) {
			path := writeTestFile(t, directory, name+".json", value, 0o600)
			if _, err := LoadConfiguration(path); err == nil {
				t.Fatal("malformed configuration was accepted")
			}
		})
	}

	if err := os.Chmod(configPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfiguration(configPath); err == nil {
		t.Fatal("group/world-readable configuration was accepted")
	}
	if err := os.Chmod(configPath, 0o600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(directory, "config-link.json")
	if err := os.Symlink(configPath, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfiguration(symlink); err == nil {
		t.Fatal("configuration symlink was accepted")
	}
}

func TestServerRejectsUnsafeServingAndTrustFiles(t *testing.T) {
	directory := t.TempDir()
	pki := newTestPKI(t, "localhost")
	certificatePath := writeTestFile(t, directory, "relay.crt", pki.certificatePEM, 0o644)
	keyPath := writeTestFile(t, directory, "relay.key", pki.keyPEM, 0o600)
	caPath := writeTestFile(t, directory, "broker-ca.crt", pki.caPEM, 0o644)
	config := Configuration{
		Version: ConfigurationVersion, ListenAddress: "127.0.0.1:7445",
		TLSCertificateFile: certificatePath, TLSKeyFile: keyPath, BrokerURL: "https://localhost:8443",
		BrokerServerName: "localhost", BrokerCAFile: caPath, AuthenticationTimeoutSeconds: 5, RevalidationIntervalSeconds: 30,
	}
	if _, err := NewServer(config, nil); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(keyPath, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := NewServer(config, nil); err == nil {
		t.Fatal("readable private key was accepted")
	}
	if err := os.Chmod(keyPath, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(caPath, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := NewServer(config, nil); err == nil {
		t.Fatal("writable CA trust was accepted")
	}
}
