package runtime_test

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPluginEgressAggregatedGrantsScopeLifecycleProcessesAndExportedTools(t *testing.T) {
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

func TestPluginEgressAggregatedGrantsScopeDoctorAndHealthCommands(t *testing.T) {
	f := newFixture(t)
	f.writePluginEgressRuntime("github-main", "company/oauth")
	firstDoctor := filepath.Join(f.home, "first-doctor")
	firstHealth := filepath.Join(f.home, "first-health")
	secondDoctor := filepath.Join(f.home, "second-doctor")
	secondHealth := filepath.Join(f.home, "second-health")
	command := func(name, output string) string {
		return f.writeTool(name, "#!/usr/bin/env bash\nprintf '%s|%s|%s|%s|%s\\n' \"${HTTPS_PROXY:-}\" \"${HTTP_PROXY:-}\" \"${NVT_PLUGIN_EGRESS_PROVIDER:-}\" \"${NVT_EGRESS_BROKER_TOKEN:-}\" \"${NVT_PLUGIN_NAME:-}\" > "+shellQuote(output)+"\n")
	}
	config := f.writeAgentConfig(fmt.Sprintf(`
plugins:
  - name: first
    source: custom
    command: /bin/true
    egress: {provider: github-main}
    doctor: {command: %s}
    health: {readiness: true, command: %s}
  - name: second
    source: custom
    command: /bin/true
    egress: {provider: company/oauth}
    doctor: {command: %s}
    health: {readiness: true, command: %s}
`, quoteYAML(command("first-doctor-command", firstDoctor)), quoteYAML(command("first-health-command", firstHealth)), quoteYAML(command("second-doctor-command", secondDoctor)), quoteYAML(command("second-health-command", secondHealth))))
	for _, name := range []string{"first", "second"} {
		dir := filepath.Join(f.state, "plugins", name)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "state.json"), []byte(`{"ready":true,"status":"running"}`), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	env := []string{
		"NVT_AGENT_CONFIG_FILE=" + config,
		"NVT_EGRESS_MODE=mediated",
		"AGENT_SESSION=nvt-missing-session",
		"CODE_SERVER_PORT=1",
		"NVT_AGENTD_SOCKET=/nonexistent",
		"NVT_EGRESS_BROKER_TOKEN=doctor-health-secret-canary",
		"HTTP_PROXY=http://must-not-propagate:8470",
		"NVT_EGRESS_FORWARD_PROXY_URL_GITHUB_MAIN=http://github-main@127.0.0.1:8470",
		"NVT_EGRESS_FORWARD_PROXY_URL_COMPANY_OAUTH=http://company%2Foauth@127.0.0.1:8470",
	}
	for _, name := range []string{"first", "second"} {
		f.runWithEnv("python3", true, env, filepath.Join(f.root, "runtime", "core", "doctor.py"), "--plugin", name)
	}
	f.runWithEnv("python3", false, env, filepath.Join(f.root, "runtime", "core", "health.py"), "--json")

	want := map[string]string{
		firstDoctor:  "http://github-main@127.0.0.1:8470||github-main||first",
		firstHealth:  "http://github-main@127.0.0.1:8470||github-main||first",
		secondDoctor: "http://company%2Foauth@127.0.0.1:8470||company/oauth||second",
		secondHealth: "http://company%2Foauth@127.0.0.1:8470||company/oauth||second",
	}
	for path, expected := range want {
		if got := strings.TrimSpace(mustReadFile(t, path)); got != expected {
			t.Fatalf("scoped command %s = %q, want %q", filepath.Base(path), got, expected)
		}
	}
}

func TestPluginEgressDoctorAndHealthPreserveDirectAndNoEgress(t *testing.T) {
	f := newFixture(t)
	directOut := filepath.Join(f.home, "direct-doctor")
	directHealthOut := filepath.Join(f.home, "direct-health")
	plainDoctorOut := filepath.Join(f.home, "plain-doctor")
	plainOut := filepath.Join(f.home, "plain-health")
	directCommand := f.writeTool("direct-doctor-command", "#!/usr/bin/env bash\nprintf '%s|%s\\n' \"${HTTPS_PROXY:-}\" \"${NVT_PLUGIN_EGRESS_PROVIDER:-}\" > "+shellQuote(directOut)+"\n")
	directHealthCommand := f.writeTool("direct-health-command", "#!/usr/bin/env bash\nprintf '%s|%s\\n' \"${HTTPS_PROXY:-}\" \"${NVT_PLUGIN_EGRESS_PROVIDER:-}\" > "+shellQuote(directHealthOut)+"\n")
	plainDoctorCommand := f.writeTool("plain-doctor-command", "#!/usr/bin/env bash\nprintf '%s|%s\\n' \"${HTTPS_PROXY:-}\" \"${NVT_PLUGIN_EGRESS_PROVIDER:-}\" > "+shellQuote(plainDoctorOut)+"\n")
	plainCommand := f.writeTool("plain-health-command", "#!/usr/bin/env bash\nprintf '%s|%s\\n' \"${HTTPS_PROXY:-}\" \"${NVT_PLUGIN_EGRESS_PROVIDER:-}\" > "+shellQuote(plainOut)+"\n")
	config := f.writeAgentConfig(fmt.Sprintf(`
plugins:
  - name: direct
    source: custom
    egress: {provider: github-main}
    doctor: {command: %s}
    health: {readiness: true, command: %s}
  - name: plain
    source: custom
    doctor: {command: %s}
    health: {readiness: true, command: %s}
`, quoteYAML(directCommand), quoteYAML(directHealthCommand), quoteYAML(plainDoctorCommand), quoteYAML(plainCommand)))
	for _, name := range []string{"direct", "plain"} {
		dir := filepath.Join(f.state, "plugins", name)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "state.json"), []byte(`{"ready":true}`), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	env := []string{"NVT_AGENT_CONFIG_FILE=" + config, "NVT_EGRESS_MODE=direct", "HTTPS_PROXY=http://ambient-direct:8080", "AGENT_SESSION=nvt-missing-session", "CODE_SERVER_PORT=1", "NVT_AGENTD_SOCKET=/nonexistent"}
	f.runWithEnv("python3", true, env, filepath.Join(f.root, "runtime", "core", "doctor.py"), "--plugin", "direct")
	f.runWithEnv("python3", true, env, filepath.Join(f.root, "runtime", "core", "doctor.py"), "--plugin", "plain")
	f.runWithEnv("python3", false, env, filepath.Join(f.root, "runtime", "core", "health.py"), "--json")
	for _, path := range []string{directOut, directHealthOut, plainDoctorOut, plainOut} {
		if got := strings.TrimSpace(mustReadFile(t, path)); got != "http://ambient-direct:8080|" {
			t.Fatalf("direct/no-egress command changed: %s = %q", filepath.Base(path), got)
		}
	}
}

func TestPluginEgressDoctorAndHealthFailBeforeInvalidCommand(t *testing.T) {
	f := newFixture(t)
	f.writePluginEgressRuntime("github-main")
	doctorMarker := filepath.Join(f.home, "doctor-ran")
	healthMarker := filepath.Join(f.home, "health-ran")
	doctor := f.writeTool("invalid-doctor", "#!/usr/bin/env bash\ntouch "+shellQuote(doctorMarker)+"\n")
	health := f.writeTool("invalid-health", "#!/usr/bin/env bash\ntouch "+shellQuote(healthMarker)+"\n")
	config := f.writeAgentConfig(fmt.Sprintf(`
plugins:
  - name: invalid
    source: custom
    egress: {provider: missing-provider}
    doctor: {command: %s}
    health: {readiness: true, command: %s}
`, quoteYAML(doctor), quoteYAML(health)))
	dir := filepath.Join(f.state, "plugins", "invalid")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "state.json"), []byte(`{"ready":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	env := []string{"NVT_AGENT_CONFIG_FILE=" + config, "NVT_EGRESS_MODE=mediated", "NVT_EGRESS_BROKER_TOKEN=doctor-health-secret-canary", "AGENT_SESSION=nvt-missing-session", "CODE_SERVER_PORT=1", "NVT_AGENTD_SOCKET=/nonexistent"}
	doctorOutput := f.runWithEnv("python3", false, env, filepath.Join(f.root, "runtime", "core", "doctor.py"), "--plugin", "invalid")
	healthOutput := f.runWithEnv("python3", false, env, filepath.Join(f.root, "runtime", "core", "health.py"), "--json")
	for _, output := range []string{doctorOutput, healthOutput} {
		if !strings.Contains(output, "plugin egress configuration is invalid") || strings.Contains(output, "doctor-health-secret-canary") {
			t.Fatalf("unsafe or missing egress failure:\n%s", output)
		}
	}
	for _, marker := range []string{doctorMarker, healthMarker} {
		if _, err := os.Stat(marker); !os.IsNotExist(err) {
			t.Fatalf("invalid scoped command ran: %s (%v)", marker, err)
		}
	}
}

func TestPluginEgressFailsBeforeLaunchForInvalidMediatedSelection(t *testing.T) {
	f := newFixture(t)
	marker := filepath.Join(f.home, "ran")
	command := f.writeTool("must-not-run", "#!/usr/bin/env bash\ntouch "+shellQuote(marker)+"\n")
	config := f.writeAgentConfig(fmt.Sprintf("plugins:\n  - name: invalid\n    source: custom\n    command: %s\n    egress: {provider: missing-provider}\n", quoteYAML(command)))
	f.writePluginEgressRuntime("github-main")
	output := f.runWithEnv(runPluginsBin(f.root), false, []string{"NVT_EGRESS_MODE=mediated"}, "after-agent", config)
	if !strings.Contains(output, "not a granted mediated capability") {
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

func TestPluginEgressRejectsInvalidRepeatedGrantsAtEveryBoundary(t *testing.T) {
	for _, tc := range []struct {
		name   string
		grants string
		want   string
	}{
		{
			name:   "zero-matches",
			grants: `[{"provider":"other","materialization":"header-inject"}]`,
			want:   "not a granted mediated capability",
		},
		{
			name:   "conflicting-repeated",
			grants: `[{"provider":"selected","materialization":"header-inject"},{"provider":"selected","materialization":"placeholder-file"}]`,
			want:   "conflicting mediated materializations",
		},
		{
			name:   "ineligible-repeated",
			grants: `[{"provider":"selected","materialization":"header-inject"},{"provider":"selected","materialization":"file-bundle"}]`,
			want:   "ineligible mediated materialization",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			f.writePluginEgressRuntime("selected")
			metadata := fmt.Sprintf(`{"mode":"mediated","transport":"forward-proxy","grants":%s}`, tc.grants)
			if err := os.WriteFile(filepath.Join(f.state, "egress.json"), []byte(metadata), 0o600); err != nil {
				t.Fatal(err)
			}
			marker := filepath.Join(f.home, "command-ran")
			command := f.writeTool("must-not-run", "#!/usr/bin/env bash\ntouch "+shellQuote(marker)+"\n")
			config := f.writeAgentConfig(fmt.Sprintf(`
plugins:
  - name: invalid
    source: custom
    command: %s
    egress: {provider: selected}
    doctor: {command: %s}
    health: {readiness: true, command: %s}
    exports:
      tools:
        - name: invalid-egress-tool
          command: %s
`, quoteYAML(command), quoteYAML(command), quoteYAML(command), quoteYAML(command)))
			dir := filepath.Join(f.state, "plugins", "invalid")
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "state.json"), []byte(`{"ready":true}`), 0o600); err != nil {
				t.Fatal(err)
			}
			env := []string{
				"NVT_AGENT_CONFIG_FILE=" + config,
				"NVT_EGRESS_MODE=mediated",
				"NVT_EGRESS_BROKER_TOKEN=repeated-grant-secret-canary",
				"NVT_EGRESS_FORWARD_PROXY_URL_SELECTED=http://selected@127.0.0.1:8470",
				"AGENT_SESSION=nvt-missing-session",
				"CODE_SERVER_PORT=1",
				"NVT_AGENTD_SOCKET=/nonexistent",
			}
			outputs := []string{
				f.runWithEnv(exportPluginToolsBin(f.root), false, env, config),
				f.runWithEnv(runPluginsBin(f.root), false, env, "after-agent", config),
				f.runWithEnv("python3", false, env, filepath.Join(f.root, "runtime", "core", "doctor.py"), "--plugin", "invalid"),
				f.runWithEnv("python3", false, env, filepath.Join(f.root, "runtime", "core", "health.py"), "--json"),
			}
			for _, output := range outputs {
				if !strings.Contains(output, tc.want) || strings.Contains(output, "repeated-grant-secret-canary") {
					t.Fatalf("unsafe or missing %s failure:\n%s", tc.name, output)
				}
			}
			if _, err := os.Stat(marker); !os.IsNotExist(err) {
				t.Fatalf("invalid repeated grant command ran: %v", err)
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
		grants = append(grants, fmt.Sprintf(`{"provider":%q,"materialization":"header-inject","repositories":["example/one"]}`, provider))
		if provider == "github-main" {
			grants = append(grants, fmt.Sprintf(`{"provider":%q,"materialization":"header-inject","repositories":["example/two"]}`, provider))
		}
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
