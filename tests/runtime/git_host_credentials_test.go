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

func TestGitCredentialsDelegatesToGitHostCredential(t *testing.T) {
	f := newFixture(t)
	f.writeBin("git-host-credential", `#!/usr/bin/env bash
set -euo pipefail
if [ "$1" = "token" ] && [ "$2" = "--provider" ] && [ "$3" = "fork-app" ] &&
   [ "$4" = "--target" ] && [ "$5" = "github.com/my-user/project" ]; then
  echo delegated-token
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
