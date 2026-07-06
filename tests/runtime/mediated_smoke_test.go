package runtime_test

// Phase 0 skeletons for the mediated-mode smoke tests
// (protocol/injection.md, docs/mediated-egress-plan.md).
//
// The plan defines two decoupled guarantees with one smoke test each:
//
//   (a) non-possession  - zero secret material in the agent container
//                         (ships with plan Phase 3, operator/compose wiring)
//   (b) egress-denied   - direct egress to upstream hosts is refused
//                         (ships with plan Phase 5, enforcement)
//
// plus the placeholder-inertness test from the placeholder convention.
// The tests are split so (a) lands and ratchets in CI independent of the
// harder enforcement work. All are skipped pending their phase; bodies pin
// the intended assertions. Both smoke tests are mode-aware by design: they
// run against mediated agents and must skip *visibly* for direct-mode runs.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	nonPossessionPending = "pending Phase 3 (docs/mediated-egress-plan.md): mediated operator/compose wiring not implemented"
	placeholderPending   = "pending Phase 3 (docs/mediated-egress-plan.md): protocol-level inertness is covered by egressd/internal/egress tests as of Phase 1; this container-level test lands with mediated wiring"
	egressDeniedPending  = "pending Phase 5 (docs/mediated-egress-plan.md): egress enforcement not implemented"
)

// mediatedPlaceholder is the documented zero-entropy constant from
// protocol/injection.md. It is the only credential-shaped string allowed to
// exist inside a mediated agent container.
const mediatedPlaceholder = "NVT-PLACEHOLDER-NOT-A-KEY"

// scanTreeForSecretMaterial walks root and fails the test if any known secret
// value appears in a regular file. Phase 3 points this at an export of the
// mediated agent container filesystem (state dir, home, git config, env
// snapshots) with the real fixture secrets as needles.
func scanTreeForSecretMaterial(t *testing.T, root string, secrets []string) {
	t.Helper()
	err := filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !info.Mode().IsRegular() || info.Size() > 8*1024*1024 {
			return nil
		}
		content, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		text := string(content)
		for _, secret := range secrets {
			if secret == "" || secret == mediatedPlaceholder {
				continue
			}
			if strings.Contains(text, secret) {
				t.Errorf("secret material found in %s", path)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func scanTextForSecretMaterial(t *testing.T, label string, text string, secrets []string) {
	t.Helper()
	for _, secret := range secrets {
		if secret == "" || secret == mediatedPlaceholder {
			continue
		}
		if strings.Contains(text, secret) {
			t.Fatalf("secret material found in %s", label)
		}
	}
}

// assertScrubbedGitState fails if the container's git configuration retains
// any credential path: helpers, extraHeader injection, URL rewrites, or
// stored credential files (protocol/injection.md, plan section 5). The one
// allowed rewrite is the managed Phase 4 insteadOf pointing at the local
// egressd redirect listener — anything else is retained pre-existing state.
func assertScrubbedGitState(t *testing.T, home string) {
	t.Helper()
	forbiddenConfig := []string{"credential.helper", "http.extraheader", "helper =", "extraheader ="}
	for _, name := range []string{".gitconfig", ".config/git/config"} {
		path := filepath.Join(home, name)
		content, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		text := strings.ToLower(string(content))
		for _, needle := range forbiddenConfig {
			if strings.Contains(text, needle) {
				t.Errorf("mediated git config %s retains %q", path, needle)
			}
		}
		section := ""
		for _, line := range strings.Split(text, "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "[") {
				section = trimmed
			}
			if strings.Contains(trimmed, "insteadof") &&
				!strings.HasPrefix(section, `[url "https://127.0.0.1`) &&
				!strings.HasPrefix(section, `[url "http://127.0.0.1`) {
				t.Errorf("mediated git config %s retains foreign insteadOf under %s: %s", path, section, trimmed)
			}
		}
	}
	for _, name := range []string{".git-credentials", ".config/git/credentials"} {
		if _, err := os.Stat(filepath.Join(home, name)); err == nil {
			t.Errorf("mediated container retains stored git credentials: %s", name)
		}
	}
}

// TestMediatedNonPossession is smoke test (a): boot an agent in mediated
// mode, then assert zero secret material anywhere the agent can read.
//
// Phase 3 wiring for this skeleton:
//  1. Start broker routing fixtures with known fixture secrets.
//  2. Boot/render the agent container in mediated mode (MEDIATED=1 / egress:
//     mediated) with header-inject grant metadata for all fixture providers.
//  3. Validate routing-plumbing metadata and generic redirect env; the
//     egressd fake-upstream proof lives in egressd/internal/egress tests.
//  4. Export the container-visible state: agent home, NVT state dir, env
//     (`/proc/1/environ` and shell env), process args (`ps axww`).
//  5. Assert none of the fixture secrets appear (scanTreeForSecretMaterial
//     over the export; direct checks over env and args).
//  6. Assert git state is scrubbed (assertScrubbedGitState).
//  7. Assert no auth bundles were materialized (no auth.json for mediated
//     providers).
//
// Mode-awareness: for a direct-mode agent this test must skip loudly, never
// pass silently — a misconfigured default that flips runs back to bundles
// must not turn the suite green.
func TestMediatedNonPossession(t *testing.T) {
	f := newFixture(t)
	secrets := []string{
		"fixture-agent-broker-token",
		"fixture-egress-broker-token",
		"fixture-access-token",
		"fixture-refresh-token",
		"fixture-provider-header",
		"fixture-derived-token",
		"fixture-git-stored-token",
	}
	f.writeBin("brokerctl", `#!/usr/bin/env bash
set -euo pipefail
if [ "$*" = "injection routing --capability api-main" ]; then
  printf '%s\n' '{"ok":true,"hosts":["api.example.test"],"placeholder":"NVT-PLACEHOLDER-NOT-A-KEY"}'
  exit 0
fi
echo "unexpected brokerctl args: $*" >&2
exit 1
`)
	mustWriteFile(t, filepath.Join(f.home, ".gitconfig"), `[credential]
	helper = store
[http]
	extraHeader = Authorization: Bearer fixture-derived-token
[url "https://fixture-git-stored-token@example.test/"]
	insteadOf = https://example.test/
`)
	mustWriteFile(t, filepath.Join(f.home, ".git-credentials"), "https://fixture-git-stored-token@example.test\n")
	mustWriteFile(t, filepath.Join(f.home, "agent-visible-env.txt"), strings.Join([]string{
		"HOME=" + f.home,
		"NVT_EGRESS_MODE=mediated",
		"NVT_EGRESS_PLACEHOLDER=" + mediatedPlaceholder,
	}, "\n")+"\n")
	mustWriteFile(t, filepath.Join(f.home, "agent-visible-argv.txt"), "bootstrap /nvt-agent/agent.yaml\n")
	config := f.writeAgentConfig(`
egress:
  mode: mediated
  placeholder: NVT-PLACEHOLDER-NOT-A-KEY
  grants:
    - provider: api-main
      materialization: header-inject
      base-url: http://127.0.0.1:8471
      redirect-env:
        STATIC_BEARER_BASE_URL: base-url
        STATIC_BEARER_TOKEN: placeholder
runtime:
  command: codex
tools:
  packages: []
  mise: []
  additional-paths: []
  shell: []
code-server:
  extensions: []
`)
	output := f.runWithEnv(bootstrapBin(f.root), true, []string{
		"HOME=" + f.home,
		"PATH=" + f.pathPrefix + string(os.PathListSeparator) + os.Getenv("PATH"),
		"NVT_EGRESS_MODE=mediated",
	}, config)
	if strings.Contains(output, "fixture-access-token") || strings.Contains(output, "fixture-refresh-token") || strings.Contains(output, "fixture-derived-token") {
		t.Fatalf("bootstrap output leaked fixture secret:\n%s", output)
	}
	scanTreeForSecretMaterial(t, f.home, secrets)
	scanTextForSecretMaterial(t, "bootstrap output", output, secrets)
	assertScrubbedGitState(t, f.home)
	egressMetadata := mustReadFile(t, filepath.Join(f.home, ".nvt-agent", "egress.json"))
	envFile := mustReadFile(t, filepath.Join(f.home, ".nvt-agent", "env"))
	if strings.Contains(envFile, "NVT_EGRESS_BROKER_TOKEN") {
		t.Fatalf("mediated agent env must not contain egress broker token key:\n%s", envFile)
	}
	if !strings.Contains(envFile, `export STATIC_BEARER_BASE_URL="http://127.0.0.1:8471"`) ||
		!strings.Contains(envFile, `export STATIC_BEARER_TOKEN="`+mediatedPlaceholder+`"`) {
		t.Fatalf("mediated redirect env missing base URL or placeholder:\n%s", envFile)
	}
	if !strings.Contains(egressMetadata, mediatedPlaceholder) || !strings.Contains(envFile, mediatedPlaceholder) {
		t.Fatalf("mediated placeholder missing from metadata/env:\n%s\n%s", egressMetadata, envFile)
	}
	if _, err := os.Stat(filepath.Join(f.home, ".codex", "auth.json")); err == nil {
		t.Fatalf("mediated bootstrap wrote Codex auth bundle")
	}
}

func TestMediatedRedirectEnvValidation(t *testing.T) {
	f := newFixture(t)
	f.writeBin("brokerctl", `#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' '{"ok":true,"hosts":["api.example.test"],"placeholder":"NVT-PLACEHOLDER-NOT-A-KEY"}'
`)
	config := f.writeAgentConfig(`
egress:
  mode: mediated
  grants:
    - provider: api-main
      materialization: header-inject
      base-url: http://127.0.0.1:8471
      redirect-env:
        STATIC_BEARER_SECRET: real-token
runtime:
  command: bash
tools:
  packages: []
  mise: []
  additional-paths: []
  shell: []
code-server:
  extensions: []
`)
	output := f.runWithEnv(bootstrapBin(f.root), false, []string{
		"HOME=" + f.home,
		"PATH=" + f.pathPrefix + string(os.PathListSeparator) + os.Getenv("PATH"),
		"NVT_EGRESS_MODE=mediated",
	}, config)
	if !strings.Contains(output, "must be base-url or placeholder") {
		t.Fatalf("expected redirect-env validation failure, got:\n%s", output)
	}
}

// TestMediatedGitWiring pins the Phase 4 bootstrap wiring for a git-typed
// grant (docs/phase4-git-mediation-plan.md §6): pre-existing git credential
// state is scrubbed, then the managed insteadOf rewrite and http.sslCAInfo
// are installed pointing at the local TLS redirect, GIT_TERMINAL_PROMPT is
// disabled, and no installation-token or CA-private-key material exists
// anywhere the agent can read.
func TestMediatedGitWiring(t *testing.T) {
	f := newFixture(t)
	secrets := []string{
		"fixture-installation-token",
		"fixture-ca-private-key",
	}
	f.writeBin("brokerctl", `#!/usr/bin/env bash
set -euo pipefail
if [ "$*" = "injection routing --capability git-app" ]; then
  printf '%s\n' '{"ok":true,"hosts":["github.com"],"placeholder":"NVT-PLACEHOLDER-NOT-A-KEY","git":true}'
  exit 0
fi
echo "unexpected brokerctl args: $*" >&2
exit 1
`)
	mustWriteFile(t, filepath.Join(f.home, ".gitconfig"), `[credential]
	helper = store
[url "https://fixture-git-stored-token@example.test/"]
	insteadOf = https://example.test/
`)
	mustWriteFile(t, filepath.Join(f.home, ".git-credentials"), "https://fixture-git-stored-token@example.test\n")
	f.writeBin("update-ca-certificates", "#!/usr/bin/env bash\nexit 0\n")
	caDir := t.TempDir()
	caFile := filepath.Join(caDir, "ca.crt")
	mustWriteFile(t, caFile, "-----BEGIN CERTIFICATE-----\nfixture-ca-cert\n-----END CERTIFICATE-----\n")
	config := f.writeAgentConfig(`
egress:
  mode: mediated
  placeholder: NVT-PLACEHOLDER-NOT-A-KEY
  grants:
    - provider: git-app
      materialization: header-inject
      base-url: https://127.0.0.1:8473
runtime:
  command: bash
tools:
  packages: []
  mise: []
  additional-paths: []
  shell: []
code-server:
  extensions: []
`)
	output := f.runWithEnv(bootstrapBin(f.root), true, []string{
		"HOME=" + f.home,
		"PATH=" + f.pathPrefix + string(os.PathListSeparator) + os.Getenv("PATH"),
		"NVT_EGRESS_MODE=mediated",
		"NVT_EGRESS_CA_FILE=" + caFile,
		"NVT_CA_TRUST_DIR=" + t.TempDir(),
	}, config)

	gitConfig := mustReadFile(t, filepath.Join(f.home, ".gitconfig"))
	if !strings.Contains(gitConfig, "sslCAInfo = "+caFile) {
		t.Fatalf("git config missing http.sslCAInfo:\n%s", gitConfig)
	}
	if !strings.Contains(gitConfig, `[url "https://127.0.0.1:8473/"]`) ||
		!strings.Contains(gitConfig, "insteadOf = https://github.com/") {
		t.Fatalf("git config missing managed insteadOf rewrite:\n%s", gitConfig)
	}
	if !strings.Contains(gitConfig, "insteadOf = git@github.com:") {
		t.Fatalf("git config missing SSH-shape convenience rewrite:\n%s", gitConfig)
	}
	if strings.Contains(gitConfig, "example.test") || strings.Contains(gitConfig, "helper") {
		t.Fatalf("pre-existing git credential state survived scrub:\n%s", gitConfig)
	}
	envFile := mustReadFile(t, filepath.Join(f.home, ".nvt-agent", "env"))
	if !strings.Contains(envFile, `export GIT_TERMINAL_PROMPT="0"`) {
		t.Fatalf("mediated git env missing GIT_TERMINAL_PROMPT:\n%s", envFile)
	}
	assertScrubbedGitState(t, f.home)
	scanTreeForSecretMaterial(t, f.home, secrets)
	scanTextForSecretMaterial(t, "bootstrap output", output, secrets)
}

// TestMediatedGitWiringFailsClosedWithoutCA pins the fail-closed CA wait: a
// git grant with an https redirect and no published ca.crt aborts bootstrap
// instead of continuing without a trust path.
func TestMediatedGitWiringFailsClosedWithoutCA(t *testing.T) {
	f := newFixture(t)
	f.writeBin("brokerctl", `#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' '{"ok":true,"hosts":["github.com"],"placeholder":"NVT-PLACEHOLDER-NOT-A-KEY","git":true}'
`)
	config := f.writeAgentConfig(`
egress:
  mode: mediated
  grants:
    - provider: git-app
      materialization: header-inject
      base-url: https://127.0.0.1:8473
runtime:
  command: bash
tools:
  packages: []
  mise: []
  additional-paths: []
  shell: []
code-server:
  extensions: []
`)
	output := f.runWithEnv(bootstrapBin(f.root), false, []string{
		"HOME=" + f.home,
		"PATH=" + f.pathPrefix + string(os.PathListSeparator) + os.Getenv("PATH"),
		"NVT_EGRESS_MODE=mediated",
		"NVT_EGRESS_CA_FILE=" + filepath.Join(t.TempDir(), "missing", "ca.crt"),
		"NVT_EGRESS_CA_WAIT_SECONDS=1",
	}, config)
	if !strings.Contains(output, "CA certificate") || !strings.Contains(output, "git grant git-app") {
		t.Fatalf("expected fail-closed CA wait error, got:\n%s", output)
	}
}

// TestMediatedHTTPSTrustStoreInstall pins the enforcement-mode agent trust
// path: with an https base-url, bootstrap waits for the egress CA, installs
// it into the container trust store, and persists the bundle env for
// generic CLIs — while git-free grants get no git wiring.
func TestMediatedHTTPSTrustStoreInstall(t *testing.T) {
	f := newFixture(t)
	f.writeBin("brokerctl", `#!/usr/bin/env bash
printf '%s\n' '{"ok":true,"hosts":["api.example.test"],"placeholder":"NVT-PLACEHOLDER-NOT-A-KEY"}'
`)
	updateLog := filepath.Join(f.home, "update-ca-certificates.log")
	f.writeBin("update-ca-certificates", "#!/usr/bin/env bash\necho called >> "+updateLog+"\nexit 0\n")
	caDir := t.TempDir()
	caFile := filepath.Join(caDir, "ca.crt")
	mustWriteFile(t, caFile, "-----BEGIN CERTIFICATE-----\nfixture-ca-cert\n-----END CERTIFICATE-----\n")
	trustDir := t.TempDir()
	config := f.writeAgentConfig(`
egress:
  mode: mediated
  grants:
    - provider: api-main
      materialization: header-inject
      base-url: https://run-egressd:8471
runtime:
  command: bash
tools:
  packages: []
  mise: []
  additional-paths: []
  shell: []
code-server:
  extensions: []
`)
	f.runWithEnv(bootstrapBin(f.root), true, []string{
		"HOME=" + f.home,
		"PATH=" + f.pathPrefix + string(os.PathListSeparator) + os.Getenv("PATH"),
		"NVT_EGRESS_MODE=mediated",
		"NVT_EGRESS_CA_FILE=" + caFile,
		"NVT_CA_TRUST_DIR=" + trustDir,
		"NVT_CA_BUNDLE_FILE=/etc/ssl/certs/ca-certificates.crt",
	}, config)
	installed := mustReadFile(t, filepath.Join(trustDir, "nvt-egress-ca.crt"))
	if !strings.Contains(installed, "BEGIN CERTIFICATE") {
		t.Fatalf("trust store file is not a certificate:\n%s", installed)
	}
	if _, err := os.Stat(updateLog); err != nil {
		t.Fatal("update-ca-certificates was not invoked")
	}
	envFile := mustReadFile(t, filepath.Join(f.home, ".nvt-agent", "env"))
	if !strings.Contains(envFile, `export SSL_CERT_FILE="/etc/ssl/certs/ca-certificates.crt"`) ||
		!strings.Contains(envFile, `export REQUESTS_CA_BUNDLE="/etc/ssl/certs/ca-certificates.crt"`) {
		t.Fatalf("bundle env not persisted:\n%s", envFile)
	}
}

// TestMediatedTrustStoreInstallFailsClosed pins the no-fallback rule: a
// failing trust-store install or a non-certificate CA file aborts bootstrap.
func TestMediatedTrustStoreInstallFailsClosed(t *testing.T) {
	config := `
egress:
  mode: mediated
  grants:
    - provider: api-main
      materialization: header-inject
      base-url: https://run-egressd:8471
runtime:
  command: bash
tools:
  packages: []
  mise: []
  additional-paths: []
  shell: []
code-server:
  extensions: []
`
	t.Run("update-ca-certificates fails", func(t *testing.T) {
		f := newFixture(t)
		f.writeBin("brokerctl", `#!/usr/bin/env bash
printf '%s\n' '{"ok":true,"hosts":["api.example.test"],"placeholder":"NVT-PLACEHOLDER-NOT-A-KEY"}'
`)
		f.writeBin("update-ca-certificates", "#!/usr/bin/env bash\nexit 1\n")
		caFile := filepath.Join(t.TempDir(), "ca.crt")
		mustWriteFile(t, caFile, "-----BEGIN CERTIFICATE-----\nfixture-ca-cert\n-----END CERTIFICATE-----\n")
		output := f.runWithEnv(bootstrapBin(f.root), false, []string{
			"HOME=" + f.home,
			"PATH=" + f.pathPrefix + string(os.PathListSeparator) + os.Getenv("PATH"),
			"NVT_EGRESS_MODE=mediated",
			"NVT_EGRESS_CA_FILE=" + caFile,
			"NVT_CA_TRUST_DIR=" + t.TempDir(),
		}, f.writeAgentConfig(config))
		if !strings.Contains(output, "refusing to continue without egress trust") {
			t.Fatalf("expected fail-closed trust install error, got:\n%s", output)
		}
	})
	t.Run("CA file is not a certificate", func(t *testing.T) {
		f := newFixture(t)
		f.writeBin("brokerctl", `#!/usr/bin/env bash
printf '%s\n' '{"ok":true,"hosts":["api.example.test"],"placeholder":"NVT-PLACEHOLDER-NOT-A-KEY"}'
`)
		f.writeBin("update-ca-certificates", "#!/usr/bin/env bash\nexit 0\n")
		caFile := filepath.Join(t.TempDir(), "ca.crt")
		mustWriteFile(t, caFile, "not a certificate\n")
		output := f.runWithEnv(bootstrapBin(f.root), false, []string{
			"HOME=" + f.home,
			"PATH=" + f.pathPrefix + string(os.PathListSeparator) + os.Getenv("PATH"),
			"NVT_EGRESS_MODE=mediated",
			"NVT_EGRESS_CA_FILE=" + caFile,
			"NVT_CA_TRUST_DIR=" + t.TempDir(),
		}, f.writeAgentConfig(config))
		if !strings.Contains(output, "is not a certificate") {
			t.Fatalf("expected invalid CA rejection, got:\n%s", output)
		}
	})
}

// TestMediatedBrokerRoutingNonObjectJSON pins clean failure when brokerctl
// emits valid JSON that is not an object: bootstrap must exit with its own
// error message, never a Python traceback.
func TestMediatedBrokerRoutingNonObjectJSON(t *testing.T) {
	f := newFixture(t)
	f.writeBin("brokerctl", `#!/usr/bin/env bash
printf '%s\n' '"error"'
exit 1
`)
	config := f.writeAgentConfig(`
egress:
  mode: mediated
  grants:
    - provider: api-main
      materialization: header-inject
      base-url: http://127.0.0.1:8471
runtime:
  command: bash
tools:
  packages: []
  mise: []
  additional-paths: []
  shell: []
code-server:
  extensions: []
`)
	output := f.runWithEnv(bootstrapBin(f.root), false, []string{
		"HOME=" + f.home,
		"PATH=" + f.pathPrefix + string(os.PathListSeparator) + os.Getenv("PATH"),
		"NVT_EGRESS_MODE=mediated",
		"NVT_BROKER_WAIT_SECONDS=1",
	}, config)
	if !strings.Contains(output, "bootstrap: broker routing failed for api-main") {
		t.Fatalf("expected clean broker routing failure, got:\n%s", output)
	}
	if strings.Contains(output, "Traceback") {
		t.Fatalf("bootstrap crashed with a traceback on non-object broker JSON:\n%s", output)
	}
}

// TestMediatedBrokerRoutingSharedRetryDeadline pins the shared retry window:
// retries for transient broker errors are bounded once per bootstrap pass,
// so a second grant must not get a fresh full window after the first grant
// already consumed it.
func TestMediatedBrokerRoutingSharedRetryDeadline(t *testing.T) {
	f := newFixture(t)
	f.writeBin("brokerctl", `#!/usr/bin/env bash
set -euo pipefail
capability="${!#}"
count_file="${HOME}/routing-calls-${capability}"
count=$(( $(cat "${count_file}" 2>/dev/null || echo 0) + 1 ))
printf '%s' "${count}" >"${count_file}"
if [ "${capability}" = "api-first" ] && [ "${count}" -gt 2 ]; then
  printf '%s\n' '{"ok":true,"hosts":["api.example.test"],"placeholder":"NVT-PLACEHOLDER-NOT-A-KEY"}'
  exit 0
fi
printf '%s\n' '{"ok":false,"error":"unauthorized"}'
exit 1
`)
	config := f.writeAgentConfig(`
egress:
  mode: mediated
  grants:
    - provider: api-first
      materialization: header-inject
      base-url: http://127.0.0.1:8471
    - provider: api-second
      materialization: header-inject
      base-url: http://127.0.0.1:8472
runtime:
  command: bash
tools:
  packages: []
  mise: []
  additional-paths: []
  shell: []
code-server:
  extensions: []
`)
	// The first grant burns most of the 5s window on two unauthorized
	// retries (2s sleep each) before succeeding; the second grant then hits
	// the already-consumed deadline after at most one retry.
	output := f.runWithEnv(bootstrapBin(f.root), false, []string{
		"HOME=" + f.home,
		"PATH=" + f.pathPrefix + string(os.PathListSeparator) + os.Getenv("PATH"),
		"NVT_EGRESS_MODE=mediated",
		"NVT_BROKER_WAIT_SECONDS=5",
	}, config)
	if !strings.Contains(output, "bootstrap: broker routing denied for api-second: unauthorized") {
		t.Fatalf("expected api-second to fail after the shared deadline, got:\n%s", output)
	}
	firstCalls := mustReadFile(t, filepath.Join(f.home, "routing-calls-api-first"))
	if firstCalls != "3" {
		t.Fatalf("expected api-first to succeed on its third attempt, got %s calls", firstCalls)
	}
	secondCalls := mustReadFile(t, filepath.Join(f.home, "routing-calls-api-second"))
	if secondCalls != "1" && secondCalls != "2" {
		t.Fatalf("api-second got a fresh retry window (%s calls); the deadline must be shared across grants", secondCalls)
	}
}

// TestMediatedPlaceholderInert pins the placeholder convention: the constant
// satisfies CLI syntax checks but grants nothing upstream.
//
// Phase 1 wiring for this skeleton:
//  1. Start a fake upstream that accepts only the real fixture credential.
//  2. Issue a direct request (bypassing egressd) presenting the placeholder
//     as a bearer token; assert the upstream rejects it.
//  3. Issue the same request through egressd; assert the upstream sees the
//     real credential and never sees the placeholder
//     (strip_request_headers behavior).
func TestMediatedPlaceholderInert(t *testing.T) {
	t.Skip("pending full container/upstream mediated smoke: egressd/internal/egress covers placeholder stripping; avoid tautological pass here")
}

func TestBootstrapRejectsEgressModeDisagreement(t *testing.T) {
	f := newFixture(t)
	config := f.writeAgentConfig(`
egress:
  mode: direct
runtime:
  command: codex
tools:
  packages: []
  mise: []
  additional-paths: []
  shell: []
code-server:
  extensions: []
`)
	output := f.runWithEnv(bootstrapBin(f.root), false, []string{
		"HOME=" + f.home,
		"NVT_EGRESS_MODE=mediated",
	}, config)
	if !strings.Contains(output, "disagrees with NVT_EGRESS_MODE") {
		t.Fatalf("expected mode disagreement failure, got:\n%s", output)
	}
}

// TestMediatedEgressDenied is smoke test (b): direct egress from the agent
// to upstream hosts is refused; egressd is the only way out.
//
// Phase 5 wiring for this skeleton:
//  1. Boot a mediated agent with enforcement enabled.
//  2. From the agent process: direct connections to the mediated upstream
//     hosts must fail (connection refused/blocked, not 401).
//  3. From a container spawned inside dind: the same connections must fail
//     (FORWARD-chain coverage, plan section 7).
//  4. The same requests through egressd succeed.
//
// Where enforcement is not a real control (today's compose privileged-dind
// model), this test documents the gap by skipping with an explicit reason,
// never by passing.
func TestMediatedEgressDenied(t *testing.T) {
	t.Skip(egressDeniedPending)
}
