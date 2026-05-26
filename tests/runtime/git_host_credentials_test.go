package runtime_test

import (
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

func TestGitCredentialsDelegatesToGitHostCredential(t *testing.T) {
	f := newFixture(t)
	f.writeBin("git-host-credential", `#!/usr/bin/env bash
set -euo pipefail
if [ "$1" = "token" ] && [ "$2" = "--provider" ] && [ "$3" = "fork-app" ]; then
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
    username: x-access-token
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
  type:company-headers)
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
