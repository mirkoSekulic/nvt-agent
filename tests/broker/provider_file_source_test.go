package broker_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuiltInProvidersReadPrivateFileSources(t *testing.T) {
	directory := t.TempDir()
	tokenPath := filepath.Join(directory, "token")
	keyPath := filepath.Join(directory, "key.pem")
	if err := os.WriteFile(tokenPath, []byte("file-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte("file-private-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	script := `
import sys
from broker.plugins.github_app.provider import GithubAppProvider
from broker.plugins.static_token.provider import StaticTokenProvider

token = StaticTokenProvider({"name":"file-token","config":{"token-file":sys.argv[1]}})
assert token.token == "file-token"
github = GithubAppProvider({"name":"file-app","config":{"app-id":1,"installation-id":2,"private-key-file":sys.argv[2]}})
assert github._private_key() == "file-private-key\n"
print("ok")
`
	command := exec.Command("python3", "-c", script, tokenPath, keyPath)
	command.Env = append(os.Environ(), "PYTHONPATH="+repoRoot(t)+string(os.PathListSeparator)+os.Getenv("PYTHONPATH"))
	output, err := command.CombinedOutput()
	if err != nil || strings.TrimSpace(string(output)) != "ok" {
		t.Fatalf("private provider file sources failed: %v %s", err, output)
	}
}
