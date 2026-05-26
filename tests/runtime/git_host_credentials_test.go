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
