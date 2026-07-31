package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGuestObservabilityRejectsPlantedProviderSecretPrefix(t *testing.T) {
	root := t.TempDir()
	processRoot := t.TempDir()
	runtimeRoot := filepath.Join(root, "run-nvt-agent")
	if err := os.Mkdir(runtimeRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "ordinary.txt"), []byte("provider configuration is absent"), 0o600); err != nil {
		t.Fatal(err)
	}
	process := filepath.Join(processRoot, "1234")
	if err := os.Mkdir(process, 0o700); err != nil {
		t.Fatal(err)
	}
	if !observabilityRootsAreClean([]string{root, runtimeRoot}, processRoot) {
		t.Fatal("clean guest-visible root was rejected")
	}
	if err := os.WriteFile(filepath.Join(runtimeRoot, "leaked-token"), []byte("nvt_provider_secret_canary_planted-value"), 0o600); err != nil {
		t.Fatal(err)
	}
	if observabilityRootsAreClean([]string{root, runtimeRoot}, processRoot) {
		t.Fatal("planted provider secret prefix was not detected")
	}
	if err := os.Remove(filepath.Join(runtimeRoot, "leaked-token")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(process, "environ"), []byte("SAFE=1\x00nvt_provider_secret_canary_process"), 0o600); err != nil {
		t.Fatal(err)
	}
	if observabilityRootsAreClean([]string{root, runtimeRoot}, processRoot) {
		t.Fatal("provider secret in process environment was not detected")
	}
}
