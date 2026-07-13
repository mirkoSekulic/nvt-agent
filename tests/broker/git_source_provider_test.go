package broker_test

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestGitSourcedProviderPluginKeepsInstancesIndependent(t *testing.T) {
	bin := buildExecutableProvider(t)
	cache := t.TempDir()
	url, revision := seedBrokerGitSource(t, cache, bin)
	state := t.TempDir()
	script := fmt.Sprintf(`
import os
from broker.core.config import BrokerConfigError, provider_plugin_entries
from broker.core.providers import load_providers

os.environ["FIXTURE_CREDENTIAL"]=%q
os.environ["NVT_GIT_SOURCE_CACHE"]=%q
source={"git":{"url":%q,"revision":%q,"subdir":"implementations/provider"}}
registration={"name":"git-fixture","source":source,"command":["provider"],"pass-env":["FIXTURE_CREDENTIAL"],"initialize-timeout-seconds":2,"request-timeout-seconds":1}
source_two={"git":{"url":%q,"revision":%q,"subdir":"implementations/provider-two"}}
registration_two={**registration,"name":"git-fixture-two","source":source_two}
config={"provider-plugins":[registration,registration_two],"providers":[
 {"name":"claude-mirko","plugin":"git-fixture","config":{"state-file":%q,"lineage":"mirko"}},
 {"name":"claude-john","plugin":"git-fixture","config":{"state-file":%q,"lineage":"john"}},
]}
implementations=provider_plugin_entries(config, {})
assert implementations["git-fixture"]["command"][0] != implementations["git-fixture-two"]["command"][0]
providers=load_providers(config)
mirko=providers["claude-mirko"]
john=providers["claude-john"]
assert mirko._process.pid != john._process.pid
assert os.path.exists(%q + ".pid") and os.path.exists(%q + ".pid")
assert '"lineage":"mirko"' in open(%q + ".config.json").read()
assert '"lineage":"john"' in open(%q + ".config.json").read()
assert mirko.normalize_target("owner/mirko").audit_target == "audit/owner/mirko"
assert john.normalize_target("owner/john").audit_target == "audit/owner/john"
assert os.path.isabs(mirko._plugin["command"][0])
for provider in providers.values(): provider.close()

bad_sources=[
 {"git":{"url":"ssh://github.com/example/plugins.git","revision":%q,"subdir":"implementations/provider"}},
 {"git":{"url":"https://user:secret@github.com/example/plugins.git","revision":%q,"subdir":"implementations/provider"}},
 {"git":{"url":"https://internal.example/plugins.git","revision":%q,"subdir":"implementations/provider"}},
 {"git":{"url":%q,"revision":"main","subdir":"implementations/provider"}},
 {"git":{"url":%q,"revision":%q,"subdir":"../provider"}},
]
for bad in bad_sources:
 entry={**registration,"source":bad}
 try: provider_plugin_entries({"provider-plugins":[entry]}, {})
 except BrokerConfigError: pass
 else: raise AssertionError("unsafe broker Git source accepted")
print("OK")
`, executableCanary, cache, url, revision, url, revision,
		filepath.Join(state, "mirko"), filepath.Join(state, "john"),
		filepath.Join(state, "mirko"), filepath.Join(state, "john"),
		filepath.Join(state, "mirko"), filepath.Join(state, "john"),
		revision, revision, revision, url, url, revision)
	out, err := runBrokerPython(t, script)
	if err != nil || !strings.Contains(out, "OK") {
		t.Fatalf("Git-sourced provider test failed: %v\n%s", err, out)
	}
}

func seedBrokerGitSource(t *testing.T, cache, binary string) (string, string) {
	t.Helper()
	work := t.TempDir()
	implementation := filepath.Join(work, "implementations", "provider")
	if err := os.MkdirAll(implementation, 0o755); err != nil {
		t.Fatal(err)
	}
	provider := filepath.Join(implementation, "provider")
	data, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(provider, data, 0o755); err != nil {
		t.Fatal(err)
	}
	second := filepath.Join(work, "implementations", "provider-two")
	if err := os.MkdirAll(second, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(second, "provider"), data, 0o755); err != nil {
		t.Fatal(err)
	}
	brokerGit(t, work, "init", "--quiet")
	brokerGit(t, work, "config", "user.name", "Test")
	brokerGit(t, work, "config", "user.email", "test@example.invalid")
	brokerGit(t, work, "add", ".")
	brokerGit(t, work, "commit", "--quiet", "-m", "provider fixture")
	revision := strings.TrimSpace(brokerGit(t, work, "rev-parse", "HEAD"))
	url := "https://github.com/example/broker-providers.git"
	sum := sha256.Sum256([]byte(url + "\x00" + revision))
	checkout := filepath.Join(cache, hex.EncodeToString(sum[:]))
	if out, err := exec.Command("cp", "-a", work, checkout).CombinedOutput(); err != nil {
		t.Fatalf("copy cached checkout: %v: %s", err, out)
	}
	marker := fmt.Sprintf("{\"revision\": %q, \"url\": %q}\n", revision, url)
	if err := os.WriteFile(filepath.Join(checkout, ".git", "nvt-source.json"), []byte(marker), 0o644); err != nil {
		t.Fatal(err)
	}
	return url, revision
}

func brokerGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v: %s", args, err, out)
	}
	return string(out)
}
