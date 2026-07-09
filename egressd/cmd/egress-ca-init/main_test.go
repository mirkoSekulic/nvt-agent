package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/mirkoSekulic/nvt-agent/egressd/internal/egress"
)

func TestRunGeneratesDurableCAWithConfiguredNames(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "ca.crt")
	keyFile := filepath.Join(dir, "ca.key")

	args := []string{
		"--cert-file", certFile,
		"--key-file", keyFile,
		"--leaf-dns-name", "run-egressd",
		"--upstream-leaf-name", "chatgpt.com",
		"--upstream-leaf-name", "auth.openai.com",
	}
	if err := run(args); err != nil {
		t.Fatalf("generate durable CA: %v", err)
	}
	if _, err := egress.LoadCAWithUpstreams(certFile, keyFile, []string{"run-egressd"}, []string{"chatgpt.com", "auth.openai.com"}); err != nil {
		t.Fatalf("generated CA does not load with configured names: %v", err)
	}
	if err := run(args); err != nil {
		t.Fatalf("reuse matching durable CA: %v", err)
	}
	err := run([]string{
		"--cert-file", certFile,
		"--key-file", keyFile,
		"--upstream-leaf-name", "api.anthropic.com",
	})
	if err == nil || !strings.Contains(err.Error(), "existing durable CA does not match configured names") {
		t.Fatalf("expected stale durable CA rejection, got %v", err)
	}
}
