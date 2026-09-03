package runtime_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPreparedKubeconfigUpdatePreservesOnlyStillGrantedCurrentContext(t *testing.T) {
	f := newFixture(t)
	target := filepath.Join(f.home, ".kube", "config")
	mustWriteFile(t, target, "apiVersion: v1\nkind: Config\ncurrent-context: selected\ncontexts:\n- name: selected\n  context: {}\n")
	config := f.writeAgentConfig(`
runtime:
  command: echo
preseed:
  files:
    - path: $HOME/.kube/config
      mode: "0600"
      overwrite: true
      preserve-yaml-selection:
        field: current-context
        collection: contexts
        item-field: name
      content: |
        apiVersion: v1
        kind: Config
        current-context: default
        contexts:
          - name: default
            context: {}
          - name: selected
            context: {}
`)
	f.runWithEnv(bootstrapBin(f.root), true, nil, config)
	updated := mustReadFile(t, target)
	if !strings.Contains(updated, "current-context: selected") {
		t.Fatalf("selected context was not preserved: %s", updated)
	}

	mustWriteFile(t, target, "apiVersion: v1\nkind: Config\ncurrent-context: revoked\ncontexts:\n- name: revoked\n  context: {}\n")
	f.runWithEnv(bootstrapBin(f.root), true, nil, config)
	updated = mustReadFile(t, target)
	if strings.Contains(updated, "current-context: revoked") || !strings.Contains(updated, "current-context: default") {
		t.Fatalf("revoked context survived replacement: %s", updated)
	}
	if info, err := os.Stat(target); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("kubeconfig mode = %v, %v", info, err)
	}
}
