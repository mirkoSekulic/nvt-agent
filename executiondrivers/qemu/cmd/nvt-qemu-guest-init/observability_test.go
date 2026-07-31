package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGuestObservabilityRejectsPlantedProviderSecretPrefix(t *testing.T) {
	root := t.TempDir()
	processRoot := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "ordinary.txt"), []byte("provider configuration is absent"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !observabilityRootsAreClean([]string{root}, processRoot) {
		t.Fatal("clean guest-visible root was rejected")
	}
	if err := os.WriteFile(filepath.Join(root, "leaked-token"), []byte("nvt_provider_secret_canary_planted-value"), 0o600); err != nil {
		t.Fatal(err)
	}
	if observabilityRootsAreClean([]string{root}, processRoot) {
		t.Fatal("planted provider secret prefix was not detected")
	}
}
