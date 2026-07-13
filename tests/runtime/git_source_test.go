package runtime_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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
	testGitSourceHealthCommands(t, f, url, revision)
	for _, name := range []string{"one-ran", "two-ran"} {
		if _, err := os.Stat(filepath.Join(f.workspace, name)); err != nil {
			t.Fatalf("Git-sourced lifecycle did not run: %s: %v", name, err)
		}

	}

	script := fmt.Sprintf(`
import hashlib, os, pathlib, shutil, subprocess, threading
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
 shutil.copytree(pathlib.Path(%q), destination, symlinks=True)
git_source._populate=populate
try:
 concurrent_results=[]
 threads=[threading.Thread(target=lambda: concurrent_results.append(git_source.acquire(valid, concurrent))) for _ in range(2)]
 [thread.start() for thread in threads]
 [thread.join() for thread in threads]
 assert len(concurrent_results)==2 and len(populate_calls)==1, (len(concurrent_results), len(populate_calls), concurrent_results)
finally: git_source._populate=original_populate

mismatch=cache.parent/"mismatch"
shutil.copytree(pathlib.Path(%q), mismatch, symlinks=True)
(mismatch/".git"/"nvt-source.json").write_text('{"url":%%r,"revision":%%r}' %% (url, "0"*40))
assert not git_source._valid_checkout(mismatch, url, "0"*40)
tampered=cache.parent/"tampered"
shutil.copytree(pathlib.Path(%q), tampered, symlinks=True)
(tampered/"plugins"/"one"/"tool.sh").write_text("#!/bin/sh\necho tampered\n")
assert not git_source._valid_checkout(tampered, url, revision)

def reacquire_after_ignored_file(label, tamper):
 root=cache.parent/label
 root.mkdir()
 key=hashlib.sha256((url+"\0"+revision).encode()).hexdigest()
 destination=root/key
 shutil.copytree(pathlib.Path(%q), destination, symlinks=True)
 tamper(destination)
 calls=[]
 original=git_source._populate
 def restore(selected, canonical, selected_revision, cache_root, environment=None):
  calls.append(selected)
  shutil.copytree(pathlib.Path(%q), selected, symlinks=True)
 git_source._populate=restore
 try:
  selected=git_source.acquire(valid, root)
  assert len(calls)==1
  return selected
 finally: git_source._populate=original

def add_repo_ignored(destination):
 path=destination/"plugins"/"one"/"ignored-module.sh"
 path.write_text("#!/bin/sh\necho untrusted\n")
 path.chmod(0o755)
assert not (reacquire_after_ignored_file("repo-ignored", add_repo_ignored)/"ignored-module.sh").exists()

def add_locally_ignored(destination):
 path=destination/"plugins"/"one"/"locally-hidden.sh"
 path.write_text("#!/bin/sh\necho untrusted\n")
 path.chmod(0o755)
 with (destination/".git"/"info"/"exclude").open("a") as file:
  file.write("plugins/one/locally-hidden.sh\n")
assert not (reacquire_after_ignored_file("info-exclude", add_locally_ignored)/"locally-hidden.sh").exists()

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

# Exercise the complete successful population pipeline through _git using a
# controlled subprocess runner. This keeps the test hermetic while asserting
# the exact security options, environment, immutable fetch, detached checkout,
# remote removal, marker, and atomic publication.
successful=cache.parent/"successful-populate"
successful.mkdir()
destination=successful/"published"
commands=[]
fixed=[
 "-c", "credential.helper=", "-c", "core.hooksPath=/dev/null",
 "-c", "http.followRedirects=false", "-c", "submodule.recurse=false",
 "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false",
 "-c", "filter.lfs.smudge=", "-c", "filter.lfs.required=false",
]
original_run=git_source.subprocess.run
def fake_run(command, **kwargs):
 assert command[0]=="git" and command[1:17]==fixed
 argv=command[17:]
 commands.append(argv)
 assert not destination.exists()
 assert kwargs["env"]==git_source._git_environment()
 assert "SHOULD_NOT_PASS" not in kwargs["env"]
 assert kwargs["stdin"] is subprocess.DEVNULL and "shell" not in kwargs
 assert kwargs["stdout"] is subprocess.PIPE and kwargs["stderr"] is subprocess.PIPE
 assert kwargs["check"] is True and kwargs["text"] is True and kwargs["timeout"]==120
 cwd=pathlib.Path(kwargs["cwd"])
 if argv==["init", "--quiet"]:
  (cwd/".git"/"info").mkdir(parents=True)
 elif argv[:3]==["remote", "add", "origin"]:
  assert argv==["remote", "add", "origin", url]
  (cwd/".git"/"config").write_text("origin="+url+"\n")
 elif argv[0]=="fetch":
  assert argv==["fetch", "--quiet", "--no-tags", "--depth=1", "origin", revision]
 elif argv==["rev-parse", "FETCH_HEAD^{commit}"]:
  return subprocess.CompletedProcess(command, 0, revision+"\n", "")
 elif argv[:3]==["checkout", "--quiet", "--detach"]:
  assert argv[3]==revision
  selected=cwd/"plugins"/"one"
  selected.mkdir(parents=True)
  executable=selected/"run.sh"
  executable.write_text("#!/bin/sh\nexit 0\n")
  executable.chmod(0o755)
 elif argv==["remote", "remove", "origin"]:
  config=cwd/".git"/"config"
  assert config.read_text()=="origin="+url+"\n"
  config.unlink()
 else: raise AssertionError(argv)
 return subprocess.CompletedProcess(command, 0, "", "")
git_source.subprocess.run=fake_run
try:
 git_source._populate(destination, url, revision, successful, {"SHOULD_NOT_PASS":"canary"})
finally: git_source.subprocess.run=original_run
assert commands==[
 ["init", "--quiet"],
 ["remote", "add", "origin", url],
 ["fetch", "--quiet", "--no-tags", "--depth=1", "origin", revision],
 ["rev-parse", "FETCH_HEAD^{commit}"],
 ["checkout", "--quiet", "--detach", revision],
 ["remote", "remove", "origin"],
]
assert destination.is_dir() and not list(successful.glob(".published.tmp-*"))
assert not (destination/".git"/"config").exists()
marker_data=__import__("json").loads((destination/".git"/"nvt-source.json").read_text())
assert marker_data=={"url":url,"revision":revision}
print("OK")
`, url, revision, filepath.Join(f.state, "git-sources"), checkout, checkout, checkout, checkout, checkout, checkout, checkout)
	out := f.runWithEnv("python3", true, []string{"PYTHONPATH=" + f.root}, "-c", script)
	if !strings.Contains(out, "OK") {
		t.Fatalf("Git source security checks failed: %s", out)
	}
}

func seedGitSourceCache(t *testing.T, state string) (string, string, string) {
	t.Helper()
	work := t.TempDir()
	outsideHealth := filepath.Join(t.TempDir(), "outside-health.sh")
	if err := os.WriteFile(outsideHealth, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"one", "two"} {
		dir := filepath.Join(work, "plugins", name)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		run := fmt.Sprintf("#!/usr/bin/env bash\nset -euo pipefail\ntouch \"$NVT_WORKSPACE/%s-ran\"\n", name)
		tool := fmt.Sprintf("#!/usr/bin/env bash\necho %s-tool\n", name)
		doctor := fmt.Sprintf("#!/usr/bin/env bash\necho doctor-%s\n", name)
		health := "#!/usr/bin/env bash\nexit 0\n"
		if err := os.WriteFile(filepath.Join(dir, "run.sh"), []byte(run), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "tool.sh"), []byte(tool), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "doctor.sh"), []byte(doctor), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "health.sh"), []byte(health), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outsideHealth, filepath.Join(dir, "escape-health")); err != nil {
			t.Fatal(err)
		}
		manifest := fmt.Sprintf("command: run.sh\ndoctor:\n  command: doctor.sh\nexports:\n  tools:\n    - name: git-%s-tool\n      command: tool.sh\n", name)
		if err := os.WriteFile(filepath.Join(dir, "plugin.yaml"), []byte(manifest), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(work, ".gitignore"), []byte("ignored-module.sh\n"), 0o644); err != nil {
		t.Fatal(err)
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

func testGitSourceHealthCommands(t *testing.T, f *fixture, url, revision string) {
	t.Helper()
	writeState := func(name string) {
		dir := filepath.Join(f.state, "plugins", name)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "state.json"), []byte(`{"ready":true,"status":"running"}`), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	runHealth := func(plugin map[string]any, wantOK bool) string {
		payload, err := json.Marshal(plugin)
		if err != nil {
			t.Fatal(err)
		}
		script := fmt.Sprintf(`
import importlib.util, json
spec = importlib.util.spec_from_file_location("nvt_health", %q)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
plugin = json.loads(%q)
print(json.dumps(module.readiness_plugin_result(plugin), sort_keys=True))
`, filepath.Join(f.root, "runtime", "core", "health.py"), string(payload))
		return f.runWithEnv("python3", wantOK, []string{
			"PYTHONPATH=" + f.root,
			"NVT_STATE_DIR=" + f.state,
			"NVT_WORKSPACE=" + f.workspace,
		}, "-c", script)
	}

	writeState("git-health")
	source := map[string]any{"git": map[string]any{
		"url": url, "revision": revision, "subdir": "plugins/one",
	}}
	plugin := func(command string) map[string]any {
		return map[string]any{
			"name": "git-health", "source": source,
			"health": map[string]any{"readiness": true, "command": command},
		}
	}
	if output := runHealth(plugin("health.sh"), true); !strings.Contains(output, `"ready": true`) {
		t.Fatalf("Git-relative health command did not pass: %s", output)
	}
	for _, command := range []string{"../health.sh", "/bin/true", "escape-health"} {
		runHealth(plugin(command), false)
	}
	shellMarker := filepath.Join(t.TempDir(), "shell-interpreted")
	runHealth(plugin("health.sh; touch "+shellMarker), false)
	if _, err := os.Stat(shellMarker); !os.IsNotExist(err) {
		t.Fatalf("Git-sourced health command was interpreted by a shell: %v", err)
	}

	writeState("local-health")
	local := map[string]any{
		"name": "local-health", "source": "custom",
		"health": map[string]any{"readiness": true, "command": "true && true"},
	}
	if output := runHealth(local, true); !strings.Contains(output, `"ready": true`) {
		t.Fatalf("existing local health shell behavior changed: %s", output)
	}
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
