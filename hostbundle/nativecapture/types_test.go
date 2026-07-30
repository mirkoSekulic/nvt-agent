package nativecapture

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigurationIsStrictCanonicalAndHasNoGlobalCapability(t *testing.T) {
	directory := t.TempDir()
	valid := `{"version":1,"runtime_directory":"/run/nvt-agent-capture","transparent_listen_address":"127.0.0.1:15001","explicit_listen_address":"127.0.0.1:15002","flow_socket_path":"/run/nvt-agent-egress/flow.sock","readiness_socket_path":"/run/nvt-agent-capture/ready.sock"}`
	path := filepath.Join(directory, "capture.json")
	if err := os.WriteFile(path, []byte(valid+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	value, err := LoadConfiguration(path)
	if err != nil || value.ExplicitListenAddress != "127.0.0.1:15002" {
		t.Fatalf("configuration=%#v error=%v", value, err)
	}
	for name, content := range map[string]string{
		"global capability": strings.TrimSuffix(valid, "}") + `,"capability_hint":"github-main"}`,
		"authority":         strings.TrimSuffix(valid, "}") + `,"binding":{"guest_instance_id":"canary"}}`,
		"duplicate":         strings.Replace(valid, `"version":1`, `"version":1,"version":1`, 1),
		"leading port":      strings.Replace(valid, "127.0.0.1:15002", "127.0.0.1:015002", 1),
		"non loopback":      strings.Replace(valid, "127.0.0.1:15002", "0.0.0.0:15002", 1),
		"same listeners":    strings.Replace(valid, "127.0.0.1:15002", "127.0.0.1:15001", 1),
		"socket alias":      strings.Replace(valid, "/run/nvt-agent-capture/ready.sock", "/run/nvt-agent-egress/flow.sock", 1),
	} {
		t.Run(name, func(t *testing.T) {
			candidate := filepath.Join(directory, strings.ReplaceAll(name, " ", "-")+".json")
			if err := os.WriteFile(candidate, []byte(content+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadConfiguration(candidate); err == nil {
				t.Fatal("invalid configuration was accepted")
			}
		})
	}
}
