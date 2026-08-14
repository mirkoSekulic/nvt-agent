package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBrokerTokenFileIsStrictAndEnvironmentCompatible(t *testing.T) {
	path := filepath.Join(t.TempDir(), "broker-token")
	if err := os.WriteFile(path, []byte("file-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NVT_BROKER_TOKEN", "")
	t.Setenv("NVT_BROKER_TOKEN_FILE", path)
	token, err := brokerToken()
	if err != nil || token != "file-token" {
		t.Fatalf("file token = %q %v", token, err)
	}
	t.Setenv("NVT_BROKER_TOKEN", "inline-token")
	if _, err := brokerToken(); err == nil || strings.Contains(err.Error(), "file-token") || strings.Contains(err.Error(), "inline-token") {
		t.Fatalf("ambiguous token sources = %v", err)
	}
	t.Setenv("NVT_BROKER_TOKEN", "")
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := brokerToken(); err == nil || strings.Contains(err.Error(), "file-token") {
		t.Fatalf("broad token file = %v", err)
	}
}

func TestBrokerTokenInlineDefaultRemainsCompatible(t *testing.T) {
	t.Setenv("NVT_BROKER_TOKEN_FILE", "")
	t.Setenv("NVT_BROKER_TOKEN", "existing-inline-token")
	value, err := brokerToken()
	if err != nil || value != "existing-inline-token" {
		t.Fatalf("inline token = %q %v", value, err)
	}
}
