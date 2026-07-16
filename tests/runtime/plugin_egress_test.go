package runtime_test

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPluginEgressScopesLifecycleProcessesAndExportedTools(t *testing.T) {
	f := newFixture(t)
	f.writePluginEgressRuntime("github-main", "company/oauth")
	f.writeBin("plugin-egress-exec", "#!/usr/bin/env bash\nexec python3 "+shellQuote(filepath.Join(f.root, "runtime", "core", "plugin-egress-exec.py"))+" \"$@\"\n")

	firstOut := filepath.Join(f.home, "first-env")
	secondOut := filepath.Join(f.home, "second-env")
	tool := f.writeTool("egress-tool", `#!/usr/bin/env bash
set -euo pipefail
printf '%s\n%s\n%s\n%s\n%s\n%s\n' "${HTTPS_PROXY:-}" "${HTTP_PROXY:-}" "${ALL_PROXY:-}" "${NO_PROXY:-}" "${NVT_PLUGIN_EGRESS_PROVIDER:-}" "${NVT_EGRESS_BROKER_TOKEN:-}"
`)
	first := f.writeTool("first-plugin", "#!/usr/bin/env bash\nprintf '%s|%s|%s|%s\\n' \"${HTTPS_PROXY:-}\" \"${HTTP_PROXY:-}\" \"${ALL_PROXY:-}\" \"${NVT_PLUGIN_EGRESS_PROVIDER:-}\" > "+shellQuote(firstOut)+"\n")
	second := f.writeTool("second-plugin", "#!/usr/bin/env bash\nprintf '%s\\n' \"${HTTPS_PROXY:-}\" > "+shellQuote(secondOut)+"\n")
	config := f.writeAgentConfig(fmt.Sprintf(`
plugins:
  - name: first
    source: custom
    command: %s
    egress:
      provider: github-main
    exports:
      tools:
        - name: egress-http-tool
          command: %s
  - name: second
    source: custom
    command: %s
    egress:
      provider: company/oauth
`, quoteYAML(first), quoteYAML(tool), quoteYAML(second)))

	env := []string{
		"NVT_EGRESS_MODE=mediated",
		"NVT_EGRESS_FORWARD_PROXY_URL_GITHUB_MAIN=http://github-main@127.0.0.1:8470",
		"NVT_EGRESS_FORWARD_PROXY_URL_COMPANY_OAUTH=http://company%2Foauth@127.0.0.1:8470",
		"NVT_EGRESS_BROKER_TOKEN=agent-egress-secret-canary",
		"HTTP_PROXY=http://incompatible-mediated-listener:8470",
		"ALL_PROXY=http://incompatible-mediated-listener:8470",
	}
	f.runWithEnv(exportPluginToolsBin(f.root), true, env, config)
	f.runWithEnv(runPluginsBin(f.root), true, env, "after-agent", config)
	if got := strings.TrimSpace(mustReadFile(t, firstOut)); got != "http://github-main@127.0.0.1:8470|||github-main" {
		t.Fatalf("first plugin proxy = %q", got)
	}
	if got := strings.TrimSpace(mustReadFile(t, secondOut)); got != "http://company%2Foauth@127.0.0.1:8470" {
		t.Fatalf("second plugin proxy = %q", got)
	}
	output := f.runWithEnv("egress-http-tool", true, env)
	if !strings.Contains(output, "http://github-main@127.0.0.1:8470") ||
		!strings.Contains(output, "localhost,127.0.0.1,::1") ||
		!strings.Contains(output, "github-main") ||
		strings.Contains(output, "incompatible-mediated-listener") ||
		strings.Contains(output, "agent-egress-secret-canary") {
		t.Fatalf("unexpected exported tool environment:\n%s", output)
	}
}

func TestPluginEgressAbsentAndDirectModesAreUnchanged(t *testing.T) {
	f := newFixture(t)
	f.writeBin("plugin-egress-exec", "#!/usr/bin/env bash\nexec python3 "+shellQuote(filepath.Join(f.root, "runtime", "core", "plugin-egress-exec.py"))+" \"$@\"\n")
	out := filepath.Join(f.home, "env")
	command := f.writeTool("plain-plugin", "#!/usr/bin/env bash\nprintf '%s\\n' \"${HTTPS_PROXY:-}\" > "+shellQuote(out)+"\n")
	without := f.writeAgentConfig(fmt.Sprintf("plugins:\n  - name: plain\n    source: custom\n    command: %s\n", quoteYAML(command)))
	f.runWithEnv(runPluginsBin(f.root), true, []string{"NVT_EGRESS_MODE=mediated", "HTTPS_PROXY=http://ambient.example:8080"}, "after-agent", without)
	if got := strings.TrimSpace(mustReadFile(t, out)); got != "http://ambient.example:8080" {
		t.Fatalf("plugin without egress declaration changed: %q", got)
	}

	with := f.writeAgentConfig(fmt.Sprintf("plugins:\n  - name: direct\n    source: custom\n    command: %s\n    egress: {provider: github-main}\n    exports:\n      tools:\n        - name: direct-egress-tool\n          command: %s\n", quoteYAML(command), quoteYAML(command)))
	f.runWithEnv(runPluginsBin(f.root), true, []string{"NVT_EGRESS_MODE=direct", "HTTPS_PROXY=http://direct.example:8080"}, "after-agent", with)
	if got := strings.TrimSpace(mustReadFile(t, out)); got != "http://direct.example:8080" {
		t.Fatalf("direct plugin environment changed: %q", got)
	}
	f.runWithEnv(exportPluginToolsBin(f.root), true, []string{"NVT_EGRESS_MODE=direct", "HTTPS_PROXY=http://direct.example:8080"}, with)
	f.runWithEnv("direct-egress-tool", true, []string{"NVT_EGRESS_MODE=direct", "HTTPS_PROXY=http://direct.example:8080"})
	if got := strings.TrimSpace(mustReadFile(t, out)); got != "http://direct.example:8080" {
		t.Fatalf("direct exported tool environment changed: %q", got)
	}
}

func TestPluginEgressFailsBeforeLaunchForInvalidMediatedSelection(t *testing.T) {
	f := newFixture(t)
	marker := filepath.Join(f.home, "ran")
	command := f.writeTool("must-not-run", "#!/usr/bin/env bash\ntouch "+shellQuote(marker)+"\n")
	config := f.writeAgentConfig(fmt.Sprintf("plugins:\n  - name: invalid\n    source: custom\n    command: %s\n    egress: {provider: missing-provider}\n", quoteYAML(command)))
	f.writePluginEgressRuntime("github-main")
	output := f.runWithEnv(runPluginsBin(f.root), false, []string{"NVT_EGRESS_MODE=mediated"}, "after-agent", config)
	if !strings.Contains(output, "not an exact injection-eligible mediated grant") {
		t.Fatalf("unexpected selection failure:\n%s", output)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("invalid plugin ran: %v", err)
	}
}

func TestPluginEgressRejectsMissingScopedProxyAndUnknownFields(t *testing.T) {
	for _, tc := range []struct {
		name       string
		egressYAML string
		provider   string
		want       string
	}{
		{"missing-proxy", "{provider: unavailable-fixture}", "unavailable-fixture", "provider-scoped mediated proxy is unavailable"},
		{"unknown-field", "{provider: github-main, endpoint: http://example.invalid}", "github-main", "unsupported field: endpoint"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			marker := filepath.Join(f.home, "ran")
			command := f.writeTool("must-not-run", "#!/usr/bin/env bash\ntouch "+shellQuote(marker)+"\n")
			config := f.writeAgentConfig(fmt.Sprintf("plugins:\n  - name: invalid\n    source: custom\n    command: %s\n    egress: %s\n", quoteYAML(command), tc.egressYAML))
			f.writePluginEgressRuntime(tc.provider)
			output := f.runWithEnv(runPluginsBin(f.root), false, []string{"NVT_EGRESS_MODE=mediated", "NVT_EGRESS_FORWARD_PROXY_URL_UNAVAILABLE_FIXTURE="}, "after-agent", config)
			if !strings.Contains(output, tc.want) {
				t.Fatalf("unexpected validation failure:\n%s", output)
			}
			if _, err := os.Stat(marker); !os.IsNotExist(err) {
				t.Fatalf("invalid plugin ran: %v", err)
			}
		})
	}
}

func (f *fixture) writePluginEgressRuntime(providers ...string) {
	f.t.Helper()
	if err := os.MkdirAll(filepath.Join(f.home, ".nvt-agent"), 0o700); err != nil {
		f.t.Fatal(err)
	}
	grants := make([]string, 0, len(providers))
	env := ""
	for _, provider := range providers {
		grants = append(grants, fmt.Sprintf(`{"provider":%q,"materialization":"header-inject"}`, provider))
		suffix := strings.ToUpper(strings.NewReplacer("-", "_", ".", "_", "_", "_").Replace(provider))
		env += fmt.Sprintf("export NVT_EGRESS_FORWARD_PROXY_URL_%s=%q\n", suffix, "http://"+url.PathEscape(provider)+"@127.0.0.1:8470")
	}
	metadata := fmt.Sprintf(`{"mode":"mediated","transport":"forward-proxy","grants":[%s]}`, strings.Join(grants, ","))
	if err := os.WriteFile(filepath.Join(f.state, "egress.json"), []byte(metadata), 0o600); err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.home, ".nvt-agent", "env"), []byte(env), 0o600); err != nil {
		f.t.Fatal(err)
	}
}
