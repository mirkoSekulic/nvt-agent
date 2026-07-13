package runtime_test

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestGitSourcedRuntimePluginsAndSourceSecurity(t *testing.T) {
	f := newFixture(t)
	url, revision, checkout := seedGitSourceCache(t, f.state)
	config := f.writeAgentConfig(fmt.Sprintf(`
plugins:
  - name: git-one
    source:
      git:
        url: %q
        revision: %s
        subdir: plugins/one
    when: before-agent
  - name: git-two
    source:
      git:
        url: %q
        revision: %s
        subdir: plugins/two
    when: before-agent
`, url, revision, url, revision))
	f.runExport(config, true)
	if got := f.runCommand(filepath.Join(f.home, ".local", "bin", "git-one-tool"), true); !strings.Contains(got, "one-tool") {
		t.Fatalf("wrong Git-sourced tool output: %s", got)
	}
	f.runRunPlugins(config, "before-agent", true)
	doctor := f.runWithEnv("python3", true, []string{"NVT_AGENT_CONFIG_FILE=" + config, "PYTHONPATH=" + f.root}, filepath.Join(f.root, "runtime", "core", "doctor.py"), "--plugin", "git-one")
	if !strings.Contains(doctor, "doctor-one") {
		t.Fatalf("Git-sourced doctor command did not run: %s", doctor)
	}
	for _, name := range []string{"one-ran", "two-ran"} {
		if _, err := os.Stat(filepath.Join(f.workspace, name)); err != nil {
			t.Fatalf("Git-sourced lifecycle did not run: %s: %v", name, err)
		}

	}

	script := fmt.Sprintf(`
import os, pathlib, shutil, threading
from shared import git_source

url=%q
revision=%q
cache=pathlib.Path(%q)
valid={"git":{"url":url,"revision":revision,"subdir":"plugins/one"}}
bad=[
 {"git":{"url":"ssh://github.com/example/plugins.git","revision":revision}},
 {"git":{"url":"git://github.com/example/plugins.git","revision":revision}},
 {"git":{"url":"file:///tmp/plugins","revision":revision}},
 {"git":{"url":"/tmp/plugins","revision":revision}},
 {"git":{"url":"https://user:secret@github.com/example/plugins.git","revision":revision}},
 {"git":{"url":"https://gitlab.com/example/plugins.git","revision":revision}},
 {"git":{"url":url,"revision":"main"}},
 {"git":{"url":url,"revision":revision,"subdir":"../escape"}},
]
for item in bad:
 try: git_source.parse_source(item)
 except git_source.GitSourceError as error:
  assert "secret" not in str(error)
 else: raise AssertionError(item)

results=[]
def worker(subdir):
 results.append(git_source.acquire({"git":{"url":url,"revision":revision,"subdir":subdir}}, cache))
threads=[threading.Thread(target=worker,args=("plugins/one",)), threading.Thread(target=worker,args=("plugins/two",))]
[thread.start() for thread in threads]
[thread.join() for thread in threads]
assert len(results)==2 and results[0] != results[1]
assert git_source.parse_source({"git":{"url":"https://gitlab.com/example/plugins.git","revision":revision}}, {"NVT_GIT_SOURCE_ALLOWED_HOSTS":"gitlab.com"})[0].startswith("https://gitlab.com/")

concurrent=cache.parent/"concurrent"
concurrent.mkdir()
original_populate=git_source._populate
populate_calls=[]
def populate(destination, canonical, selected_revision, cache_root, environment=None):
 import time
 populate_calls.append(destination)
 time.sleep(.05)
 shutil.copytree(pathlib.Path(%q), destination)
git_source._populate=populate
try:
 concurrent_results=[]
 threads=[threading.Thread(target=lambda: concurrent_results.append(git_source.acquire(valid, concurrent))) for _ in range(2)]
 [thread.start() for thread in threads]
 [thread.join() for thread in threads]
 assert len(concurrent_results)==2 and len(populate_calls)==1
finally: git_source._populate=original_populate

mismatch=cache.parent/"mismatch"
shutil.copytree(pathlib.Path(%q), mismatch)
(mismatch/".git"/"nvt-source.json").write_text('{"url":%%r,"revision":%%r}' %% (url, "0"*40))
assert not git_source._valid_checkout(mismatch, url, "0"*40)
tampered=cache.parent/"tampered"
shutil.copytree(pathlib.Path(%q), tampered)
(tampered/"plugins"/"one"/"tool.sh").write_text("#!/bin/sh\necho tampered\n")
assert not git_source._valid_checkout(tampered, url, revision)

outside=cache.parent/"outside"
outside.mkdir()
escape=pathlib.Path(%q)/"plugins"/"escape"
escape.symlink_to(outside, target_is_directory=True)
try: git_source._select_subdir(pathlib.Path(%q), pathlib.PurePosixPath("plugins/escape"))
except git_source.GitSourceError: pass
else: raise AssertionError("symlink escape accepted")

failed=cache.parent/"failed"
failed.mkdir()
original=git_source._git
def reject(*args, **kwargs): raise git_source.GitSourceError("failed")
git_source._git=reject
try:
 try: git_source._populate(failed/"final", url, revision, failed)
 except git_source.GitSourceError: pass
 else: raise AssertionError("failed fetch succeeded")
 assert not list(failed.glob(".*.tmp-*"))
finally: git_source._git=original
print("OK")
`, url, revision, filepath.Join(f.state, "git-sources"), checkout, checkout, checkout, checkout, checkout)
	out := f.runWithEnv("python3", true, []string{"PYTHONPATH=" + f.root}, "-c", script)
	if !strings.Contains(out, "OK") {
		t.Fatalf("Git source security checks failed: %s", out)
	}
}

func seedGitSourceCache(t *testing.T, state string) (string, string, string) {
	t.Helper()
	work := t.TempDir()
	for _, name := range []string{"one", "two"} {
		dir := filepath.Join(work, "plugins", name)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		run := fmt.Sprintf("#!/usr/bin/env bash\nset -euo pipefail\ntouch \"$NVT_WORKSPACE/%s-ran\"\n", name)
		tool := fmt.Sprintf("#!/usr/bin/env bash\necho %s-tool\n", name)
		doctor := fmt.Sprintf("#!/usr/bin/env bash\necho doctor-%s\n", name)
		if err := os.WriteFile(filepath.Join(dir, "run.sh"), []byte(run), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "tool.sh"), []byte(tool), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "doctor.sh"), []byte(doctor), 0o755); err != nil {
			t.Fatal(err)
		}
		manifest := fmt.Sprintf("command: run.sh\ndoctor:\n  command: doctor.sh\nexports:\n  tools:\n    - name: git-%s-tool\n      command: tool.sh\n", name)
		if err := os.WriteFile(filepath.Join(dir, "plugin.yaml"), []byte(manifest), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	runGit(t, work, "init", "--quiet")
	runGit(t, work, "config", "user.name", "Test")
	runGit(t, work, "config", "user.email", "test@example.invalid")
	runGit(t, work, "add", ".")
	runGit(t, work, "commit", "--quiet", "-m", "fixture")
	revision := strings.TrimSpace(runGit(t, work, "rev-parse", "HEAD"))
	url := "https://github.com/example/runtime-plugins.git"
	sum := sha256.Sum256([]byte(url + "\x00" + revision))
	checkout := filepath.Join(state, "git-sources", hex.EncodeToString(sum[:]))
	if err := os.MkdirAll(filepath.Dir(checkout), 0o755); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("cp", "-a", work, checkout).CombinedOutput(); err != nil {
		t.Fatalf("copy cached checkout: %v: %s", err, out)
	}
	marker := fmt.Sprintf("{\"revision\": %q, \"url\": %q}\n", revision, url)
	if err := os.WriteFile(filepath.Join(checkout, ".git", "nvt-source.json"), []byte(marker), 0o644); err != nil {
		t.Fatal(err)
	}
	return url, revision, checkout
}

func runGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v: %s", args, err, out)
	}
	return string(out)
}
