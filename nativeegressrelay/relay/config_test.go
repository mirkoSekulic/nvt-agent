package relay

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestConfigurationIsStrictCanonicalProcessOwnedAndRedacted(t *testing.T) {
	directory := t.TempDir()
	config := Configuration{
		Version: ConfigurationVersion, ListenAddress: "127.0.0.1:7445",
		TLSCertificateFile: filepath.Join(directory, "relay.crt"), TLSKeyFile: filepath.Join(directory, "relay.key"),
		ControlListenAddress: "127.0.0.1:7446", ControlTLSCertificateFile: filepath.Join(directory, "control.crt"),
		ControlTLSKeyFile: filepath.Join(directory, "control.key"), ControlCredentialFile: filepath.Join(directory, "control-token"),
		ControlTimeoutSeconds: 5,
		BrokerURL:             "https://broker.example:8443", BrokerServerName: "broker.example", BrokerCAFile: filepath.Join(directory, "broker-ca.crt"),
		AuthenticationTimeoutSeconds: 5, RevalidationIntervalSeconds: 30,
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	configPath := writeTestFile(t, directory, "config.json", encoded, 0o600)
	loaded, err := LoadConfiguration(configPath)
	if err != nil || !reflect.DeepEqual(loaded, config) {
		t.Fatalf("valid configuration failed: %#v %v", loaded, err)
	}
	for _, formatted := range []string{fmt.Sprint(config), fmt.Sprintf("%+v", config), fmt.Sprintf("%#v", config)} {
		if strings.Contains(formatted, config.BrokerURL) || strings.Contains(formatted, config.TLSKeyFile) ||
			strings.Contains(formatted, config.ControlCredentialFile) {
			t.Fatalf("configuration formatting exposed internals: %q", formatted)
		}
	}

	invalidValues := []Configuration{
		func() Configuration { value := config; value.Version = 1; return value }(),
		func() Configuration { value := config; value.ListenAddress = "relay.example:7445"; return value }(),
		func() Configuration { value := config; value.ListenAddress = "127.0.0.1:07445"; return value }(),
		func() Configuration { value := config; value.ControlListenAddress = value.ListenAddress; return value }(),
		func() Configuration { value := config; value.ControlListenAddress = "127.0.0.1:07446"; return value }(),
		func() Configuration { value := config; value.BrokerURL = "http://broker.example:8443"; return value }(),
		func() Configuration { value := config; value.BrokerURL = "https://broker.example:08443"; return value }(),
		func() Configuration { value := config; value.BrokerURL += "/v1"; return value }(),
		func() Configuration { value := config; value.BrokerServerName = "other.example"; return value }(),
		func() Configuration { value := config; value.BrokerServerName = "Broker.example"; return value }(),
		func() Configuration { value := config; value.TLSKeyFile = value.TLSCertificateFile; return value }(),
		func() Configuration {
			value := config
			value.ControlCredentialFile = value.ControlTLSKeyFile
			return value
		}(),
		func() Configuration { value := config; value.AuthenticationTimeoutSeconds = 6; return value }(),
		func() Configuration { value := config; value.RevalidationIntervalSeconds = 31; return value }(),
		func() Configuration { value := config; value.ControlTimeoutSeconds = 11; return value }(),
	}
	for index, invalid := range invalidValues {
		if invalid.validate() == nil {
			t.Fatalf("invalid configuration %d was accepted", index)
		}
	}

	unknown := append([]byte(nil), encoded[:len(encoded)-1]...)
	unknown = append(unknown, []byte(`,"credential":"forbidden"}`)...)
	legacyTargets := append([]byte(nil), encoded[:len(encoded)-1]...)
	legacyTargets = append(legacyTargets, []byte(`,"egressd_targets":[]}`)...)
	for name, value := range map[string][]byte{
		"duplicate":              []byte(`{"version":1,"version":1}`),
		"unknown":                unknown,
		"legacy target snapshot": legacyTargets,
		"trailing":               append(append([]byte(nil), encoded...), []byte(` {}`)...),
		"oversized":              append(make([]byte, MaxConfigurationBytes), 'x'),
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
		ControlListenAddress:      "127.0.0.1:7446",
		ControlTLSCertificateFile: writeTestFile(t, directory, "control.crt", pki.certificatePEM, 0o644),
		ControlTLSKeyFile:         writeTestFile(t, directory, "control.key", pki.keyPEM, 0o600),
		ControlCredentialFile:     writeTestFile(t, directory, "control-token", []byte(mustControlCredential(t)), 0o600),
		ControlTimeoutSeconds:     5,
		BrokerServerName:          "localhost", BrokerCAFile: caPath, AuthenticationTimeoutSeconds: 5, RevalidationIntervalSeconds: 30,
	}
	if _, err := NewServer(config, nil); err != nil {
		t.Fatal(err)
	}
	defaultServer, err := NewServer(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := defaultServer.resolver.(DenyAllTargetResolver); !ok {
		t.Fatal("unpublished relay did not preserve deny-all default")
	}
	if len(defaultServer.tlsConfig.NextProtos) != 0 {
		t.Fatal("guest data listener unexpectedly advertised an HTTP ALPN")
	}
	configuredRegistry, err := NewEgressdTargetRegistry([]EgressdTargetDescriptor{{Binding: testBinding("configured-server"), ConnectURL: "http://egressd.example:8470"}})
	if err != nil {
		t.Fatal(err)
	}
	configuredServer, err := NewServer(config, configuredRegistry)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := configuredServer.resolver.(*EgressdTargetRegistry); !ok {
		t.Fatal("explicit egressd target snapshot did not configure adapter")
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

func TestControlServerRejectsUnsafePurposeCredentialAndServingIdentity(t *testing.T) {
	fixture := newBrokerFixture(t, http.NotFoundHandler())
	registry, err := NewEgressdTargetRegistry([]EgressdTargetDescriptor{})
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := NewTargetPublisher(registry)
	if err != nil {
		t.Fatal(err)
	}
	control, err := NewControlServer(fixture.config, publisher)
	if err != nil {
		t.Fatal(err)
	}
	if len(control.tlsConfig.NextProtos) != 1 || control.tlsConfig.NextProtos[0] != "http/1.1" {
		t.Fatal("control listener did not pin HTTP/1.1 ALPN")
	}
	if err := os.Chmod(fixture.config.ControlCredentialFile, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := NewControlServer(fixture.config, publisher); err == nil {
		t.Fatal("group-readable control credential was accepted")
	}
	if err := os.Chmod(fixture.config.ControlCredentialFile, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixture.config.ControlCredentialFile, []byte("ordinary-bearer"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewControlServer(fixture.config, publisher); err == nil {
		t.Fatal("non-purpose control credential was accepted")
	}
}
