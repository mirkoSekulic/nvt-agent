package runtime_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGitHostCredentialResolveDoctorAndGhAuthStatus(t *testing.T) {
	f := newFixture(t)
	f.writeBin("gh", "#!/usr/bin/env bash\necho gh stub\n")
	config := f.writePluginConfig("git-host-credentials.yaml", `
default-provider: fork-app
providers:
  - name: fork-app
    type: github-app
    app-id-env: TEST_GITHUB_APP_ID
    installation-id-env: TEST_GITHUB_INSTALLATION_ID
    private-key-base64-env: TEST_GITHUB_PRIVATE_KEY_BASE64
    match:
      - github.com/my-user/*
`)
	env := []string{
		"NVT_PLUGIN_CONFIG=" + config,
		"TEST_GITHUB_APP_ID=12345",
		"TEST_GITHUB_INSTALLATION_ID=67890",
		"TEST_GITHUB_PRIVATE_KEY_BASE64=ZmFrZS1wcml2YXRlLWtleQ==",
	}

	resolved := f.runWithEnv(gitHostCredentialBin(f.root), true, env, "resolve", "--target", "github.com/my-user/project")
	if strings.TrimSpace(resolved) != "fork-app" {
		t.Fatalf("unexpected provider resolution: %q", resolved)
	}

	providerType := f.runWithEnv(gitHostCredentialBin(f.root), true, env, "type", "--provider", "fork-app")
	if strings.TrimSpace(providerType) != "github-app" {
		t.Fatalf("unexpected provider type: %q", providerType)
	}

	f.runWithEnv(gitHostCredentialBin(f.root), true, env, "doctor", "--provider", "fork-app")

	status := f.runWithEnv(ghAuthBin(f.root), true, env, "auth", "status")
	if !strings.Contains(status, "gh-auth provider: fork-app") ||
		!strings.Contains(status, "installation id: 67890") {
		t.Fatalf("unexpected gh-auth auth status:\n%s", status)
	}
}

func TestGitHostCredentialResolvesGenericSshRemotes(t *testing.T) {
	f := newFixture(t)
	config := f.writePluginConfig("git-host-credentials.yaml", `
providers:
  - name: gitlab-token
    type: token-env
    token-env: GITLAB_TOKEN
    match:
      - gitlab.com/my-user/*
`)
	env := []string{"NVT_PLUGIN_CONFIG=" + config}

	resolved := f.runWithEnv(gitHostCredentialBin(f.root), true, env, "resolve", "--target", "git@gitlab.com:my-user/project.git")
	if strings.TrimSpace(resolved) != "gitlab-token" {
		t.Fatalf("unexpected provider resolution: %q", resolved)
	}
}

func TestGitHostCredentialBrokerProviderDelegatesToBrokerctl(t *testing.T) {
	f := newFixture(t)
	f.writeBin("brokerctl", `#!/usr/bin/env bash
set -euo pipefail
if [ "$1" = "token" ] &&
   [ "$2" = "--provider" ] && [ "$3" = "fork-app" ] &&
   [ "$4" = "--target" ] && [ "$5" = "github.com/my-user/project" ] &&
   [ "$6" = "--raw" ]; then
  echo broker-token
  exit 0
fi
echo "unexpected brokerctl args: $*" >&2
exit 1
`)
	config := f.writePluginConfig("git-host-credentials.yaml", `
providers:
  - name: fork-app-broker
    type: broker
    broker-provider: fork-app
    match:
      - github.com/my-user/*
`)
	env := []string{"NVT_PLUGIN_CONFIG=" + config}

	output := f.runWithEnv(gitHostCredentialBin(f.root), true, env, "token", "--target", "github.com/my-user/project")
	if strings.TrimSpace(output) != "broker-token" {
		t.Fatalf("unexpected broker token: %q", output)
	}
}

func TestGhAuthPassesRepoTargetToBrokerTokenProvider(t *testing.T) {
	f := newFixture(t)
	f.writeBin("brokerctl", `#!/usr/bin/env bash
set -euo pipefail
if [ "$1" = "token" ] &&
   [ "$2" = "--provider" ] && [ "$3" = "fork-app" ] &&
   [ "$4" = "--target" ] && [ "$5" = "github.com/my-user/project" ] &&
   [ "$6" = "--raw" ]; then
  echo broker-token
  exit 0
fi
echo "unexpected brokerctl args: $*" >&2
exit 1
`)
	f.writeBin("gh", `#!/usr/bin/env bash
set -euo pipefail
if [ "${GH_TOKEN:-}" != "broker-token" ]; then
  echo "unexpected GH_TOKEN" >&2
  exit 1
fi
printf '%s\n' "$*"
`)
	config := f.writePluginConfig("git-host-credentials.yaml", `
providers:
  - name: fork-app-broker
    type: broker
    broker-provider: fork-app
    match:
      - github.com/my-user/*
`)
	env := []string{"NVT_PLUGIN_CONFIG=" + config}

	output := f.runWithEnv(ghAuthBin(f.root), true, env, "pr", "view", "--repo", "my-user/project")
	if strings.TrimSpace(output) != "pr view --repo my-user/project" {
		t.Fatalf("unexpected gh args: %q", output)
	}
}

func TestGitHostCredentialBrokerProviderDelegatesIdentityToBrokerctl(t *testing.T) {
	f := newFixture(t)
	f.writeBin("brokerctl", `#!/usr/bin/env bash
set -euo pipefail
if [ "$1" = "identity" ] &&
   [ "$2" = "--provider" ] && [ "$3" = "fork-app" ] &&
   [ "$4" = "--target" ] && [ "$5" = "github.com/my-user/project" ]; then
  echo '{"ok":true,"name":"local-agent[bot]","email":"987654321+local-agent[bot]@users.noreply.github.com"}'
  exit 0
fi
echo "unexpected brokerctl args: $*" >&2
exit 1
`)
	config := f.writePluginConfig("git-host-credentials.yaml", `
providers:
  - name: fork-app-broker
    type: broker
    broker-provider: fork-app
    match:
      - github.com/my-user/*
`)
	env := []string{"NVT_PLUGIN_CONFIG=" + config}

	output := f.runWithEnv(gitHostCredentialBin(f.root), true, env, "identity", "--target", "github.com/my-user/project")
	if !strings.Contains(output, `"name":"local-agent[bot]"`) ||
		!strings.Contains(output, `"email":"987654321+local-agent[bot]@users.noreply.github.com"`) {
		t.Fatalf("unexpected broker identity: %q", output)
	}
}

func TestGitHostCredentialBrokerProviderDelegatesHeadersToBrokerctl(t *testing.T) {
	f := newFixture(t)
	f.writeBin("brokerctl", `#!/usr/bin/env bash
set -euo pipefail
if [ "$1" = "headers" ] &&
   [ "$2" = "--provider" ] && [ "$3" = "company-headers" ] &&
   [ "$4" = "--target" ] && [ "$5" = "github.com/my-user/project" ] &&
   [ "$6" = "--raw" ]; then
  echo "Authorization: Bearer broker-header"
  echo "X-Api-Key: broker-extra"
  exit 0
fi
echo "unexpected brokerctl args: $*" >&2
exit 1
`)
	config := f.writePluginConfig("git-host-credentials.yaml", `
providers:
  - name: company-headers
    type: broker
    broker-provider: company-headers
    credential-kind: headers
    match:
      - github.com/my-user/*
`)
	env := []string{"NVT_PLUGIN_CONFIG=" + config}

	kind := strings.TrimSpace(f.runWithEnv(gitHostCredentialBin(f.root), true, env, "credential-kind", "--provider", "company-headers"))
	if kind != "headers" {
		t.Fatalf("unexpected credential kind: %q", kind)
	}
	output := f.runWithEnv(gitHostCredentialBin(f.root), true, env, "headers", "--target", "github.com/my-user/project")
	if !strings.Contains(output, "Authorization: Bearer broker-header") ||
		!strings.Contains(output, "X-Api-Key: broker-extra") {
		t.Fatalf("unexpected broker headers:\n%s", output)
	}
}

func TestGitHostCredentialMediatedBrokerProviderRefusesTokenAndHeaders(t *testing.T) {
	f := newFixture(t)
	f.writeBin("brokerctl", "#!/usr/bin/env bash\necho should-not-run >&2\nexit 1\n")
	config := f.writePluginConfig("git-host-credentials.yaml", `
providers:
  - name: fork-app-mediated
    type: broker
    broker-provider: fork-app
    credential-kind: mediated
    match:
      - github.com/my-user/*
`)
	env := []string{"NVT_PLUGIN_CONFIG=" + config}

	kind := strings.TrimSpace(f.runWithEnv(gitHostCredentialBin(f.root), true, env, "credential-kind", "--provider", "fork-app-mediated"))
	if kind != "mediated" {
		t.Fatalf("unexpected credential kind: %q", kind)
	}

	tokenOutput := f.runWithEnv(gitHostCredentialBin(f.root), false, env, "token", "--provider", "fork-app-mediated", "--target", "github.com/my-user/project")
	if !strings.Contains(tokenOutput, "is mediated") || !strings.Contains(tokenOutput, "token credentials are not available") {
		t.Fatalf("unexpected token failure:\n%s", tokenOutput)
	}

	headersOutput := f.runWithEnv(gitHostCredentialBin(f.root), false, env, "headers", "--provider", "fork-app-mediated", "--target", "github.com/my-user/project")
	if !strings.Contains(headersOutput, "is mediated") || !strings.Contains(headersOutput, "injected by egressd") {
		t.Fatalf("unexpected headers failure:\n%s", headersOutput)
	}
}

func TestGitHostCredentialMediatedProxyReadsRuntimeEnvFile(t *testing.T) {
	f := newFixture(t)
	f.writePluginEgressRuntime("github-main-app")
	config := f.writePluginConfig("git-host-credentials.yaml", `
providers:
  - name: fork-app-mediated
    type: broker
    broker-provider: github-main-app
    credential-kind: mediated
    match:
      - github.com/my-user/*
`)
	output := f.runWithEnv(gitHostCredentialBin(f.root), true, []string{"NVT_PLUGIN_CONFIG=" + config, "NVT_EGRESS_MODE=mediated", "NVT_EGRESS_FORWARD_PROXY_URL_GITHUB_MAIN_APP=http://github-main-app@127.0.0.1:8470"}, "mediated-proxy", "--provider", "fork-app-mediated")
	if strings.TrimSpace(output) != "http://github-main-app@127.0.0.1:8470" {
		t.Fatalf("unexpected mediated proxy URL: %q", output)
	}
}

func TestGhAuthWrapsMediatedProviderWithPlaceholderAndProxy(t *testing.T) {
	f := newFixture(t)
	f.writePluginEgressRuntime("fork-app")
	f.writeBin("brokerctl", "#!/usr/bin/env bash\necho should-not-run >&2\nexit 1\n")
	f.writeBin("gh", `#!/usr/bin/env bash
set -euo pipefail
if [ "${GH_TOKEN:-}" != "NVT-PLACEHOLDER-NOT-A-KEY" ]; then
  echo "unexpected GH_TOKEN=${GH_TOKEN:-}" >&2
  exit 1
fi
if [ "${GITHUB_TOKEN+x}" = "x" ]; then
  echo "GITHUB_TOKEN must be unset" >&2
  exit 1
fi
if [ "${GH_ENTERPRISE_TOKEN+x}" = "x" ]; then
  echo "GH_ENTERPRISE_TOKEN must be unset" >&2
  exit 1
fi
if [ "${GITHUB_ENTERPRISE_TOKEN+x}" = "x" ]; then
  echo "GITHUB_ENTERPRISE_TOKEN must be unset" >&2
  exit 1
fi
if [ "${HTTPS_PROXY:-}" != "http://fork-app@127.0.0.1:8470" ]; then
  echo "unexpected HTTPS_PROXY=${HTTPS_PROXY:-}" >&2
  exit 1
fi
case ",${NO_PROXY:-}," in
  *,github.com,*|*,.github.com,*|*,api.github.com,*)
    echo "NO_PROXY still bypasses github: ${NO_PROXY:-}" >&2
    exit 1
    ;;
esac
printf '%s\n' "$*"
`)
	config := f.writePluginConfig("git-host-credentials.yaml", `
providers:
  - name: fork-app-mediated
    type: broker
    broker-provider: fork-app
    credential-kind: mediated
    match:
      - github.com/my-user/*
`)
	env := []string{
		"NVT_PLUGIN_CONFIG=" + config,
		"NVT_EGRESS_MODE=mediated",
		"NVT_EGRESS_FORWARD_PROXY_URL_FORK_APP=http://fork-app@127.0.0.1:8470",
		"NVT_EGRESS_PLACEHOLDER=NVT-PLACEHOLDER-NOT-A-KEY",
		"NO_PROXY=localhost,*,github.com,.github.com,api.github.com,example.test",
		"GITHUB_TOKEN=must-not-survive",
		"GH_ENTERPRISE_TOKEN=must-not-survive",
		"GITHUB_ENTERPRISE_TOKEN=must-not-survive",
	}

	output := f.runWithEnv(ghAuthBin(f.root), true, env, "pr", "view", "--repo", "my-user/project")
	if strings.TrimSpace(output) != "pr view --repo my-user/project" {
		t.Fatalf("unexpected gh output:\n%s", output)
	}
}

func TestGhAuthMediatedProviderReadsRuntimeEnvFile(t *testing.T) {
	f := newFixture(t)
	f.writePluginEgressRuntime("github-main-app")
	f.writeBin("gh", `#!/usr/bin/env bash
set -euo pipefail
if [ "${GH_TOKEN:-}" != "runtime-placeholder" ]; then
  echo "unexpected GH_TOKEN=${GH_TOKEN:-}" >&2
  exit 1
fi
if [ "${HTTPS_PROXY:-}" != "http://github-main-app@127.0.0.1:8470" ]; then
  echo "unexpected HTTPS_PROXY=${HTTPS_PROXY:-}" >&2
  exit 1
fi
printf '%s\n' "$*"
`)
	config := f.writePluginConfig("git-host-credentials.yaml", `
providers:
  - name: github-main
    type: broker
    broker-provider: github-main-app
    credential-kind: mediated
    match:
      - github.com/my-user/*
`)
	envDir := filepath.Join(f.home, ".nvt-agent")
	if err := os.MkdirAll(envDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(envDir, "env"), []byte(mustReadFile(t, filepath.Join(envDir, "env"))+`export NVT_EGRESS_PLACEHOLDER="runtime-placeholder"
`), 0o600); err != nil {
		t.Fatal(err)
	}

	output := f.runWithEnv(
		ghAuthBin(f.root),
		true,
		[]string{"NVT_PLUGIN_CONFIG=" + config, "NVT_EGRESS_MODE=mediated", "NVT_EGRESS_FORWARD_PROXY_URL_GITHUB_MAIN_APP=http://github-main-app@127.0.0.1:8470", "NVT_EGRESS_PLACEHOLDER=runtime-placeholder"},
		"--provider", "github-main", "api", "repos/my-user/project",
	)
	if strings.TrimSpace(output) != "api repos/my-user/project" {
		t.Fatalf("unexpected gh output:\n%s", output)
	}
}

func TestGhAuthMediatedProviderRequiresManagedProxyURL(t *testing.T) {
	f := newFixture(t)
	f.writeBin("gh", "#!/usr/bin/env bash\necho should-not-run >&2\nexit 1\n")
	config := f.writePluginConfig("git-host-credentials.yaml", `
providers:
  - name: fork-app-mediated
    type: broker
    broker-provider: fork-app
    credential-kind: mediated
    match:
      - github.com/my-user/*
`)
	env := []string{
		"NVT_PLUGIN_CONFIG=" + config,
		"NVT_EGRESS_MODE=mediated",
		"HTTPS_PROXY=http://ambient-proxy.invalid:8080",
		"https_proxy=http://ambient-proxy.invalid:8080",
	}

	output := f.runWithEnv(ghAuthBin(f.root), false, env, "pr", "view", "--repo", "my-user/project")
	if !strings.Contains(output, "mediated plugin egress metadata is unavailable") {
		t.Fatalf("unexpected missing proxy failure:\n%s", output)
	}
}

func TestGitCredentialsDelegatesToGitHostCredential(t *testing.T) {
	f := newFixture(t)
	f.writeBin("git-host-credential", `#!/usr/bin/env bash
set -euo pipefail
if [ "$1" = "token" ] && [ "$2" = "--provider" ] && [ "$3" = "fork-app" ] &&
   [ "$4" = "--target" ] && [ "$5" = "github.com/my-user/project" ]; then
  echo delegated-token
  exit 0
fi
if [ "$1" = "credential-kind" ] && [ "$2" = "--provider" ] && [ "$3" = "fork-app" ] &&
   [ "$4" = "--target" ] && [ "$5" = "github.com/my-user/project" ]; then
  echo token
  exit 0
fi
echo "unexpected git-host-credential args: $*" >&2
exit 1
`)

	configDir := filepath.Join(f.home, ".nvt-agent", "git-credentials")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "config.yaml"), []byte(`
credentials:
  - match: https://github.com/my-user/
    provider: fork-app
`), 0o600); err != nil {
		t.Fatal(err)
	}

	input := "protocol=https\nhost=github.com\npath=my-user/project.git\n\n"
	output := f.runWithInput(gitCredentialNvtBin(f.root), input, true, "get")
	if !strings.Contains(output, "username=x-access-token") ||
		!strings.Contains(output, "password=delegated-token") {
		t.Fatalf("unexpected credential output:\n%s", output)
	}
}

func TestGitCredentialsConfiguresMediatedProviderWithPlaceholderAndProxy(t *testing.T) {
	f := newFixture(t)
	logPath := filepath.Join(f.home, "git.log")
	f.writeBin("git", `#!/usr/bin/env bash
set -euo pipefail
printf "%s\n" "$*" >> "$GIT_LOG"
`)
	f.writeBin("git-host-credential", `#!/usr/bin/env bash
set -euo pipefail
case "$1:$3" in
  credential-kind:fork-app-mediated)
    echo mediated
    ;;
  mediated-proxy:fork-app-mediated)
    echo http://fork-app:x@127.0.0.1:8470
    ;;
  doctor:fork-app-mediated)
    exit 0
    ;;
  *)
    echo "unexpected git-host-credential args: $*" >&2
    exit 1
    ;;
esac
`)
	config := f.writePluginConfig("git-credentials.yaml", `
credentials:
  - match: https://github.com/my-user/project
    provider: fork-app-mediated
`)
	env := []string{"NVT_PLUGIN_CONFIG=" + config, "GIT_LOG=" + logPath}

	output := f.runWithEnv(gitCredentialsRunBin(f.root), true, env)
	if !strings.Contains(output, "mediated credential rule") ||
		!strings.Contains(output, "fork-app-mediated") {
		t.Fatalf("expected mediated rule summary, got:\n%s", output)
	}
	logData, err := os.ReadFile(logPath)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	log := string(logData)
	if !strings.Contains(log, "config --global http.https://github.com/my-user/project.proxy http://fork-app:x@127.0.0.1:8470") {
		t.Fatalf("mediated git credentials must configure provider-scoped proxy:\n%s", log)
	}
	if !strings.Contains(log, "config --global http.https://github.com/my-user/project.proxyAuthMethod basic") {
		t.Fatalf("mediated git credentials must force basic proxy auth for capability hinting:\n%s", log)
	}
	if !strings.Contains(log, "config --global credential.helper nvt") {
		t.Fatalf("mediated git credentials must configure helper:\n%s", log)
	}
	if strings.Contains(log, "extraHeader") {
		t.Fatalf("mediated git credentials must not configure headers:\n%s", log)
	}
	configData, err := os.ReadFile(filepath.Join(f.home, ".nvt-agent", "git-credentials", "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(configData), "fork-app-mediated") {
		t.Fatalf("mediated provider must be present in placeholder helper config:\n%s", configData)
	}

	input := "protocol=https\nhost=github.com\npath=my-user/project.git\n\n"
	helperOutput := f.runWithInput(gitCredentialNvtBin(f.root), input, true, "get")
	if !strings.Contains(helperOutput, "username=x-access-token") ||
		!strings.Contains(helperOutput, "password=NVT-PLACEHOLDER-NOT-A-KEY") {
		t.Fatalf("unexpected mediated helper output:\n%s", helperOutput)
	}
}

func TestGitCredentialsConfiguresBrokerHeaders(t *testing.T) {
	f := newFixture(t)
	logPath := filepath.Join(f.home, "git.log")
	f.writeBin("git", `#!/usr/bin/env bash
set -euo pipefail
printf "%s\n" "$*" >> "$GIT_LOG"
`)
	f.writeBin("git-host-credential", `#!/usr/bin/env bash
set -euo pipefail
case "$1:$3" in
  credential-kind:company-headers)
    echo headers
    ;;
  headers:company-headers)
    if [ "$4" = "--target" ] && [ "$5" = "github.com/my-user/project" ]; then
      echo "Authorization: Bearer broker-header"
      exit 0
    fi
    echo "unexpected target args: $*" >&2
    exit 1
    ;;
  *)
    echo "unexpected git-host-credential args: $*" >&2
    exit 1
    ;;
esac
`)
	config := f.writePluginConfig("git-credentials.yaml", `
credentials:
  - match: https://github.com/my-user/project
    provider: company-headers
    identity:
      mode: explicit
      name: Header Bot
      email: header@example.com
`)
	env := []string{"NVT_PLUGIN_CONFIG=" + config, "GIT_LOG=" + logPath}

	f.runWithEnv(gitCredentialsRunBin(f.root), true, env)
	logData, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(logData), "config --global --add http.https://github.com/my-user/project.extraHeader Authorization: Bearer broker-header") {
		t.Fatalf("expected broker header config, got:\n%s", logData)
	}
}

func TestGitCredentialsConfigureRepoExplicitIdentity(t *testing.T) {
	f := newFixture(t)
	repo := f.initRepo("project")
	f.runCommand("git", true, "-C", repo, "remote", "add", "origin", "https://github.com/my-user/project.git")
	config := f.writePluginConfig("git-credentials.yaml", `
credentials:
  - match: https://github.com/my-user/
    provider: fork-app
    identity:
      mode: explicit
      name: Explicit Bot
      email: explicit@example.com
`)
	env := []string{"NVT_PLUGIN_CONFIG=" + config}

	f.runWithEnv(gitCredentialsRunBin(f.root), true, env, "configure-repo", repo)

	name := strings.TrimSpace(f.runCommand("git", true, "-C", repo, "config", "--local", "--get", "user.name"))
	email := strings.TrimSpace(f.runCommand("git", true, "-C", repo, "config", "--local", "--get", "user.email"))
	if name != "Explicit Bot" || email != "explicit@example.com" {
		t.Fatalf("unexpected identity name=%q email=%q", name, email)
	}
}

func TestGitCredentialsConfigureRepoProviderIdentity(t *testing.T) {
	f := newFixture(t)
	repo := f.initRepo("project")
	f.runCommand("git", true, "-C", repo, "remote", "add", "origin", "https://github.com/my-user/project.git")
	f.writeBin("git-host-credential", `#!/usr/bin/env bash
set -euo pipefail
if [ "$1" = "identity" ] && [ "$2" = "--provider" ] && [ "$3" = "fork-app" ] &&
   [ "$4" = "--target" ] && [ "$5" = "github.com/my-user/project" ]; then
  echo '{"name":"local-agent[bot]","email":"987654321+local-agent[bot]@users.noreply.github.com"}'
  exit 0
fi
echo "unexpected git-host-credential args: $*" >&2
exit 1
`)
	config := f.writePluginConfig("git-credentials.yaml", `
credentials:
  - match: https://github.com/my-user/
    provider: fork-app
    identity:
      mode: provider
`)
	env := []string{"NVT_PLUGIN_CONFIG=" + config}

	f.runWithEnv(gitCredentialsRunBin(f.root), true, env, "configure-repo", repo)

	name := strings.TrimSpace(f.runCommand("git", true, "-C", repo, "config", "--local", "--get", "user.name"))
	email := strings.TrimSpace(f.runCommand("git", true, "-C", repo, "config", "--local", "--get", "user.email"))
	if name != "local-agent[bot]" || email != "987654321+local-agent[bot]@users.noreply.github.com" {
		t.Fatalf("unexpected identity name=%q email=%q", name, email)
	}
}

func TestGitCredentialsProviderIdentityFailsForUnsupportedProvider(t *testing.T) {
	f := newFixture(t)
	f.writeBin("git-host-credential", `#!/usr/bin/env bash
set -euo pipefail
case "$1:$3" in
  type:personal-token)
    echo token-env
    ;;
  doctor:personal-token)
    exit 0
    ;;
  *)
    echo "unexpected git-host-credential args: $*" >&2
    exit 1
    ;;
esac
`)
	config := f.writePluginConfig("git-credentials.yaml", `
credentials:
  - match: https://github.com/my-user/
    provider: personal-token
    identity:
      mode: provider
`)
	env := []string{"NVT_PLUGIN_CONFIG=" + config}

	output := f.runWithEnv(gitCredentialsRunBin(f.root), false, env)
	if !strings.Contains(output, "does not support commit identity") ||
		!strings.Contains(output, "identity.mode=explicit") {
		t.Fatalf("unexpected failure:\n%s", output)
	}
}

func TestGitCredentialsNoMatchingIdentityLeavesRepoLocalUnset(t *testing.T) {
	f := newFixture(t)
	repo := f.initRepo("project")
	f.runCommand("git", true, "-C", repo, "remote", "add", "origin", "https://github.com/other/project.git")
	config := f.writePluginConfig("git-credentials.yaml", `
credentials:
  - match: https://github.com/my-user/
    provider: fork-app
    identity:
      mode: explicit
      name: Explicit Bot
      email: explicit@example.com
`)
	env := []string{"NVT_PLUGIN_CONFIG=" + config}

	f.runWithEnv(gitCredentialsRunBin(f.root), true, env, "configure-repo", repo)
	f.runCommand("git", false, "-C", repo, "config", "--local", "--get", "user.name")
	f.runCommand("git", false, "-C", repo, "config", "--local", "--get", "user.email")
}

func TestGitCredentialsMatchRequiresBoundary(t *testing.T) {
	f := newFixture(t)
	repo := f.initRepo("nvt-agent-2")
	f.runCommand("git", true, "-C", repo, "remote", "add", "origin", "https://github.com/mirkoSekulic/nvt-agent-2.git")
	config := f.writePluginConfig("git-credentials.yaml", `
credentials:
  - match: https://github.com/mirkoSekulic/nvt-agent
    provider: fork-app
    identity:
      mode: explicit
      name: NVT Bot
      email: nvt@example.com
`)
	env := []string{"NVT_PLUGIN_CONFIG=" + config}

	f.runWithEnv(gitCredentialsRunBin(f.root), true, env, "configure-repo", repo)
	f.runCommand("git", false, "-C", repo, "config", "--local", "--get", "user.name")
}

func TestGitCredentialHelperMatchRequiresBoundary(t *testing.T) {
	f := newFixture(t)
	f.writeBin("git-host-credential", "#!/usr/bin/env bash\necho should-not-run >&2\nexit 1\n")
	configDir := filepath.Join(f.home, ".nvt-agent", "git-credentials")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "config.yaml"), []byte(`
credentials:
  - match: https://github.com/mirkoSekulic/nvt-agent
    provider: fork-app
`), 0o600); err != nil {
		t.Fatal(err)
	}

	input := "protocol=https\nhost=github.com\npath=mirkoSekulic/nvt-agent-2.git\n\n"
	output := f.runWithInput(gitCredentialNvtBin(f.root), input, true, "get")
	if strings.TrimSpace(output) != "" {
		t.Fatalf("expected no helper output for sibling repo, got:\n%s", output)
	}
}

func TestCheckoutReposInvokesGitCredentialsConfigureRepoBestEffort(t *testing.T) {
	f := newFixture(t)
	source := filepath.Join(f.home, "source")
	f.runCommand("git", true, "init", source)
	f.runCommand("git", true, "-C", source, "config", "user.name", "Source")
	f.runCommand("git", true, "-C", source, "config", "user.email", "source@example.com")
	if err := os.WriteFile(filepath.Join(source, "README.md"), []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	f.runCommand("git", true, "-C", source, "add", "README.md")
	f.runCommand("git", true, "-C", source, "commit", "-m", "initial")

	logPath := filepath.Join(f.home, "identity.log")
	f.writeBin("git-credentials", `#!/usr/bin/env bash
set -euo pipefail
printf "%s\n" "$*" >> "$IDENTITY_LOG"
exit 7
`)
	config := f.writePluginConfig("checkout-repos.yaml", fmt.Sprintf(`
repos:
  - url: %s
    path: cloned
`, quoteYAML(source)))
	env := []string{"NVT_PLUGIN_CONFIG=" + config, "IDENTITY_LOG=" + logPath}

	f.runWithEnv("python3 "+shellQuote(filepath.Join(f.root, "runtime", "plugins", "checkout-repos", "run.py")), true, env)

	logData, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(logData), "configure-repo "+filepath.Join(f.workspace, "cloned")) {
		t.Fatalf("expected checkout to invoke configure-repo, got:\n%s", logData)
	}
}

func TestGitCredentialsClearsRemovedManagedHeaders(t *testing.T) {
	f := newFixture(t)
	logPath := filepath.Join(f.home, "git.log")
	f.writeBin("git", `#!/usr/bin/env bash
set -euo pipefail
printf "%s\n" "$*" >> "$GIT_LOG"
`)
	f.writeBin("git-host-credential", `#!/usr/bin/env bash
set -euo pipefail
case "$1:$3" in
  credential-kind:company-headers)
    echo headers
    ;;
  headers:company-headers)
    echo "$COMPANY_GIT_AUTH_HEADER"
    ;;
  *)
    echo "unexpected git-host-credential args: $*" >&2
    exit 1
    ;;
esac
`)

	firstConfig := f.writePluginConfig("git-credentials-first.yaml", `
credentials:
  - match: https://git.company.com/team/
    provider: company-headers
`)
	env := []string{
		"NVT_PLUGIN_CONFIG=" + firstConfig,
		"GIT_LOG=" + logPath,
		"COMPANY_GIT_AUTH_HEADER=Authorization: Bearer old-token",
	}
	f.runWithEnv(gitCredentialsRunBin(f.root), true, env)

	secondConfig := f.writePluginConfig("git-credentials-second.yaml", "credentials: []\n")
	env[0] = "NVT_PLUGIN_CONFIG=" + secondConfig
	f.runWithEnv(gitCredentialsRunBin(f.root), true, env)

	logData, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	log := string(logData)
	if !strings.Contains(log, "config --global --add http.https://git.company.com/team/.extraHeader Authorization: Bearer old-token") {
		t.Fatalf("expected header add command, got:\n%s", log)
	}
	if !strings.Contains(log, "config --global --unset-all http.https://git.company.com/team/.extraHeader") {
		t.Fatalf("expected stale header unset command, got:\n%s", log)
	}
}

func TestGitCredentialsClearsRemovedMediatedProxy(t *testing.T) {
	f := newFixture(t)
	logPath := filepath.Join(f.home, "git.log")
	f.writeBin("git", `#!/usr/bin/env bash
set -euo pipefail
printf "%s\n" "$*" >> "$GIT_LOG"
`)
	f.writeBin("git-host-credential", `#!/usr/bin/env bash
set -euo pipefail
case "$1:$3" in
  credential-kind:fork-app-mediated)
    echo mediated
    ;;
  mediated-proxy:fork-app-mediated)
    echo http://fork-app:x@127.0.0.1:8470
    ;;
  *)
    echo "unexpected git-host-credential args: $*" >&2
    exit 1
    ;;
esac
`)

	firstConfig := f.writePluginConfig("git-credentials-first.yaml", `
credentials:
  - match: https://github.com/my-user/project
    provider: fork-app-mediated
`)
	env := []string{
		"NVT_PLUGIN_CONFIG=" + firstConfig,
		"GIT_LOG=" + logPath,
	}
	f.runWithEnv(gitCredentialsRunBin(f.root), true, env)

	secondConfig := f.writePluginConfig("git-credentials-second.yaml", "credentials: []\n")
	env[0] = "NVT_PLUGIN_CONFIG=" + secondConfig
	f.runWithEnv(gitCredentialsRunBin(f.root), true, env)

	logData, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	log := string(logData)
	if !strings.Contains(log, "config --global http.https://github.com/my-user/project.proxy http://fork-app:x@127.0.0.1:8470") ||
		!strings.Contains(log, "config --global http.https://github.com/my-user/project.git.proxy http://fork-app:x@127.0.0.1:8470") {
		t.Fatalf("expected mediated proxy config commands, got:\n%s", log)
	}
	if !strings.Contains(log, "config --global --unset-all http.https://github.com/my-user/project.proxy") ||
		!strings.Contains(log, "config --global --unset-all http.https://github.com/my-user/project.proxyAuthMethod") ||
		!strings.Contains(log, "config --global --unset-all http.https://github.com/my-user/project.git.proxy") ||
		!strings.Contains(log, "config --global --unset-all http.https://github.com/my-user/project.git.proxyAuthMethod") {
		t.Fatalf("expected stale mediated proxy unset commands, got:\n%s", log)
	}
}
