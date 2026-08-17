package main

import (
	"os"
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

func TestRunRecoversInterruptedRotation(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "ca.crt")
	keyFile := filepath.Join(dir, "ca.key")
	args := []string{"--cert-file", certFile, "--key-file", keyFile, "--leaf-dns-name", "run-egressd"}
	if err := run(args); err != nil {
		t.Fatal(err)
	}
	oldCert, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile+".rotation", []byte("rotation-in-progress\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certFile, []byte("partial"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := run(args); err != nil {
		t.Fatalf("recover rotation: %v", err)
	}
	newCert, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(newCert) == string(oldCert) {
		t.Fatal("interrupted rotation did not replace generation")
	}
	if _, err := os.Stat(keyFile + ".rotation"); !os.IsNotExist(err) {
		t.Fatalf("rotation marker remains: %v", err)
	}
	if _, err := egress.LoadCA(certFile, keyFile, "run-egressd"); err != nil {
		t.Fatalf("recovered keypair does not load: %v", err)
	}
}
