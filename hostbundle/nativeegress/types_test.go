package nativeegress

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigurationIsStrictRootOwnedAndNonSecret(t *testing.T) {
	directory := t.TempDir()
	configurationPath := filepath.Join(directory, "native-egress.json")
	configuration := `{"version":1,"runtime_directory":"/run/nvt-agent-egress","identity_socket_path":"/run/nvt-agent-identity/session-credential.sock","relay_endpoint":"tls://egress-relay.example:7445","ca_pem_path":"/etc/nvt-agent/ca.pem"}`
	if err := os.WriteFile(configurationPath, []byte(configuration+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	value, err := LoadConfiguration(configurationPath)
	if err != nil || value.Version != ConfigurationVersion || value.RelayEndpoint != "tls://egress-relay.example:7445" {
		t.Fatalf("configuration=%#v error=%v", value, err)
	}
	for _, canary := range []string{"nvt.runtime-identity/v1", "nvt_ri_", "nvt_eg1_", "audience", "binding", "provider"} {
		if strings.Contains(configuration, canary) || strings.Contains(value.String(), canary) {
			t.Fatalf("configuration surface contained sensitive/authority field %q", canary)
		}
	}

	for name, contents := range map[string]string{
		"unknown":           strings.TrimSuffix(configuration, "}") + `,"credential":"nvt_eg1_canary"}`,
		"duplicate":         strings.Replace(configuration, `"version":1`, `"version":1,"version":1`, 1),
		"trailing":          configuration + "\n{}",
		"non TLS":           strings.Replace(configuration, "tls://", "http://", 1),
		"IP relay":          strings.Replace(configuration, "egress-relay.example", "127.0.0.1", 1),
		"capture unknown":   strings.TrimSuffix(configuration, "}") + `,"capture":{"listen_address":"127.0.0.1:15001","credential":"nvt_eg1_canary"}}`,
		"capture duplicate": strings.TrimSuffix(configuration, "}") + `,"capture":{"listen_address":"127.0.0.1:15001","listen_address":"127.0.0.1:15001"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(directory, strings.ReplaceAll(name, " ", "-")+".json")
			if err := os.WriteFile(path, []byte(contents+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadConfiguration(path); err == nil {
				t.Fatal("invalid configuration was accepted")
			}
		})
	}

	captureConfiguration := strings.TrimSuffix(configuration, "}") + `,"capture":{"listen_address":"127.0.0.1:15001","capability_hint":"provider-main"}}`
	capturePath := filepath.Join(directory, "capture.json")
	if err := os.WriteFile(capturePath, []byte(captureConfiguration+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	captureValue, err := LoadConfiguration(capturePath)
	if err != nil || captureValue.Capture == nil || captureValue.Capture.ListenAddress != "127.0.0.1:15001" ||
		captureValue.Capture.CapabilityHint != "provider-main" {
		t.Fatalf("capture configuration=%#v error=%v", captureValue, err)
	}

	if err := os.Chmod(configurationPath, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfiguration(configurationPath); err == nil {
		t.Fatal("group/world-writable configuration was accepted")
	}
}
