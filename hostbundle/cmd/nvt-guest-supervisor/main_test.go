package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestOptionalEgressReadinessPathIsDistinctAndGatesSessionStartup(t *testing.T) {
	config := configuration{
		SocketPath: "/run/nvt-agent/agentd.sock", SessionReadinessPath: "/run/nvt-agent-session/session-ready",
		EgressReadinessPath: "/run/nvt-agent-egress/egress-ready",
	}
	if !validEgressReadinessPath(config) {
		t.Fatal("valid root-owned egress readiness path was rejected")
	}
	for _, value := range []string{"relative", config.SocketPath, config.SessionReadinessPath} {
		config.EgressReadinessPath = value
		if validEgressReadinessPath(config) {
			t.Fatalf("invalid egress readiness path %q was accepted", value)
		}
	}

	marker := filepath.Join(t.TempDir(), "egress-ready")
	done := make(chan struct{})
	result := make(chan error, 1)
	go func() { result <- waitForEgressReadiness(marker, time.Now().Add(time.Second), done) }()
	select {
	case err := <-result:
		t.Fatalf("readiness returned before marker publication: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if err := os.WriteFile(marker, []byte("ready\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("egress readiness marker did not release startup gate")
	}
}
