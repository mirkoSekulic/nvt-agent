package runtime_test

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInitialPromptSendsPromptThroughAgentdctl(t *testing.T) {
	f := newFixture(t)
	capturePath := filepath.Join(f.home, "agentdctl-capture")
	writeInitialPromptAgentdctl(t, f, capturePath, true)
	config := f.writePluginConfig("initial-prompt.yaml", "text: |\n  hello agent\n  do work\n")

	f.runWithEnv(initialPromptRunBin(f.root), true, []string{"NVT_PLUGIN_CONFIG=" + config})

	capture := readTextFile(t, capturePath)
	if !strings.Contains(capture, "ARGS:prompt --source plugin:initial-prompt --no-external\n") {
		t.Fatalf("agentdctl prompt args not captured correctly:\n%s", capture)
	}
	if !strings.Contains(capture, "STDIN:hello agent\ndo work\n") {
		t.Fatalf("prompt text not delivered on stdin:\n%s", capture)
	}
	assertInitialPromptHash(t, f, "hello agent\ndo work\n")
}

func TestInitialPromptSkipsSamePromptHash(t *testing.T) {
	f := newFixture(t)
	capturePath := filepath.Join(f.home, "agentdctl-capture")
	writeInitialPromptAgentdctl(t, f, capturePath, true)
	config := f.writePluginConfig("initial-prompt.yaml", "text: repeat\n")

	f.runWithEnv(initialPromptRunBin(f.root), true, []string{"NVT_PLUGIN_CONFIG=" + config})
	f.runWithEnv(initialPromptRunBin(f.root), true, []string{"NVT_PLUGIN_CONFIG=" + config})

	capture := readTextFile(t, capturePath)
	if got := strings.Count(capture, "ARGS:prompt --source plugin:initial-prompt --no-external\n"); got != 1 {
		t.Fatalf("expected one delivery, got %d:\n%s", got, capture)
	}
}

func TestInitialPromptChangedHashDeliversAgain(t *testing.T) {
	f := newFixture(t)
	capturePath := filepath.Join(f.home, "agentdctl-capture")
	writeInitialPromptAgentdctl(t, f, capturePath, true)
	config := f.writePluginConfig("initial-prompt.yaml", "text: first\n")

	f.runWithEnv(initialPromptRunBin(f.root), true, []string{"NVT_PLUGIN_CONFIG=" + config})
	config = f.writePluginConfig("initial-prompt.yaml", "text: second\n")
	f.runWithEnv(initialPromptRunBin(f.root), true, []string{"NVT_PLUGIN_CONFIG=" + config})

	capture := readTextFile(t, capturePath)
	if got := strings.Count(capture, "ARGS:prompt --source plugin:initial-prompt --no-external\n"); got != 2 {
		t.Fatalf("expected two deliveries, got %d:\n%s", got, capture)
	}
	assertInitialPromptHash(t, f, "second")
}

func TestInitialPromptEmptyTextExitsWithoutDelivery(t *testing.T) {
	f := newFixture(t)
	capturePath := filepath.Join(f.home, "agentdctl-capture")
	writeInitialPromptAgentdctl(t, f, capturePath, false)
	config := f.writePluginConfig("initial-prompt.yaml", "text: \"\"\n")

	f.runWithEnv(initialPromptRunBin(f.root), true, []string{"NVT_PLUGIN_CONFIG=" + config})

	if _, err := os.Stat(capturePath); !os.IsNotExist(err) {
		t.Fatalf("expected no agentdctl delivery, stat err=%v", err)
	}
	if _, err := os.Stat(initialPromptHashPath(f)); !os.IsNotExist(err) {
		t.Fatalf("expected no hash file for empty text, stat err=%v", err)
	}
}

func TestInitialPromptWritesHashOnlyAfterSuccessfulDelivery(t *testing.T) {
	f := newFixture(t)
	capturePath := filepath.Join(f.home, "agentdctl-capture")
	writeInitialPromptAgentdctl(t, f, capturePath, false)
	config := f.writePluginConfig("initial-prompt.yaml", "text: will-fail\n")

	output := f.runWithEnv(initialPromptRunBin(f.root), false, initialPromptTestEnv(config))
	if !strings.Contains(output, "agentdctl prompt failed after 3 attempts; last exit 7") {
		t.Fatalf("expected agentdctl failure in output, got:\n%s", output)
	}
	capture := readTextFile(t, capturePath)
	if got := strings.Count(capture, "ARGS:prompt --source plugin:initial-prompt --no-external\n"); got != 3 {
		t.Fatalf("expected three delivery attempts, got %d:\n%s", got, capture)
	}
	if _, err := os.Stat(initialPromptHashPath(f)); !os.IsNotExist(err) {
		t.Fatalf("expected no hash file after failed delivery, stat err=%v", err)
	}
}

func TestInitialPromptRetriesAgentdctlUntilDeliverySucceeds(t *testing.T) {
	f := newFixture(t)
	capturePath := filepath.Join(f.home, "agentdctl-capture")
	writeFlakyInitialPromptAgentdctl(t, f, capturePath, 2)
	config := f.writePluginConfig("initial-prompt.yaml", "text: eventually-ready\n")

	f.runWithEnv(initialPromptRunBin(f.root), true, initialPromptTestEnv(config))

	capture := readTextFile(t, capturePath)
	if got := strings.Count(capture, "ARGS:prompt --source plugin:initial-prompt --no-external\n"); got != 3 {
		t.Fatalf("expected three delivery attempts, got %d:\n%s", got, capture)
	}
	if got := strings.Count(capture, "STDIN:eventually-ready"); got != 3 {
		t.Fatalf("expected prompt on stdin for every attempt, got %d:\n%s", got, capture)
	}
	assertInitialPromptHash(t, f, "eventually-ready")
}

func writeInitialPromptAgentdctl(t *testing.T, f *fixture, capturePath string, succeed bool) {
	t.Helper()
	exitCode := 7
	if succeed {
		exitCode = 0
	}
	f.writeBin("agentdctl", fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
{
  printf 'ARGS:%s\n' "$*"
  printf 'STDIN:'
  cat
  printf '\n'
} >> %s
exit %d
`, "%s", shellQuote(capturePath), exitCode))
}

func writeFlakyInitialPromptAgentdctl(t *testing.T, f *fixture, capturePath string, failuresBeforeSuccess int) {
	t.Helper()
	attemptsPath := filepath.Join(f.home, "agentdctl-attempts")
	f.writeBin("agentdctl", fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
attempts=0
if [ -f %s ]; then
  attempts="$(cat %s)"
fi
attempts=$((attempts + 1))
printf '%%s\n' "$attempts" > %s
{
  printf 'ARGS:%%s\n' "$*"
  printf 'STDIN:'
  cat
  printf '\n'
} >> %s
if [ "$attempts" -le %d ]; then
  exit 7
fi
exit 0
`, shellQuote(attemptsPath), shellQuote(attemptsPath), shellQuote(attemptsPath), shellQuote(capturePath), failuresBeforeSuccess))
}

func initialPromptTestEnv(config string) []string {
	return []string{
		"NVT_PLUGIN_CONFIG=" + config,
		"NVT_INITIAL_PROMPT_RETRY_ATTEMPTS=3",
		"NVT_INITIAL_PROMPT_RETRY_DELAY_SECONDS=0",
	}
}

func initialPromptHashPath(f *fixture) string {
	return filepath.Join(f.state, "initial-prompt", "last.sha256")
}

func assertInitialPromptHash(t *testing.T, f *fixture, text string) {
	t.Helper()
	wantBytes := sha256.Sum256([]byte(text))
	want := hex.EncodeToString(wantBytes[:])
	got := strings.TrimSpace(readTextFile(t, initialPromptHashPath(f)))
	if got != want {
		t.Fatalf("expected hash %s, got %s", want, got)
	}
}

func readTextFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
