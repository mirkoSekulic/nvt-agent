package runtime_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGithubWatchRegisterPersistsDynamicRegistration(t *testing.T) {
	f := newFixture(t)
	config := f.writePluginConfig("github-watcher.yaml", `
default-provider: fork-app
`)
	env := []string{"NVT_PLUGIN_CONFIG=" + config}

	f.runWithEnv(
		githubWatchBin(f.root),
		true,
		env,
		"register",
		"--repo", "my-user/my-repo",
		"--number", "123",
		"--label", "frontend",
		"--label", "urgent",
	)

	registryPath := filepath.Join(f.state, "plugins", "github-watcher", "registry.json")
	var registry map[string][]map[string]any
	decodeJSONFile(t, registryPath, &registry)
	if len(registry["prs"]) != 1 {
		t.Fatalf("expected one registration, got %#v", registry)
	}
	pr := registry["prs"][0]
	if pr["repo"] != "my-user/my-repo" || pr["provider"] != "fork-app" || pr["number"].(float64) != 123 {
		t.Fatalf("unexpected registration: %#v", pr)
	}
	labels, _ := pr["labels"].([]any)
	if len(labels) != 2 || labels[0] != "frontend" || labels[1] != "urgent" {
		t.Fatalf("unexpected labels: %#v", pr["labels"])
	}
	for _, field := range []string{"comments", "reviews"} {
		config, ok := pr[field].(map[string]any)
		if !ok {
			t.Fatalf("registration missing %s config: %#v", field, pr)
		}
		associations, _ := config["author-associations"].([]any)
		if !containsAnyString(associations, "CONTRIBUTOR") {
			t.Fatalf("expected CONTRIBUTOR in %s author associations, got %#v", field, associations)
		}
	}

	output := f.runWithEnv(githubWatchBin(f.root), true, env, "list")
	if !strings.Contains(output, "my-user/my-repo#123") || !strings.Contains(output, "labels=frontend,urgent") {
		t.Fatalf("unexpected list output:\n%s", output)
	}
}

func containsAnyString(values []any, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func TestGithubWatcherDefaultAssociationsAcceptContributor(t *testing.T) {
	f := newFixture(t)
	script := fmt.Sprintf(`
import importlib.util
import pathlib
import sys

root = pathlib.Path(%s)
module_path = root / "runtime" / "plugins" / "github-watcher" / "github_watcher_lib.py"
sys.path.insert(0, str(module_path.parent))
spec = importlib.util.spec_from_file_location("github_watcher_lib", module_path)
lib = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lib)

watch = lib.normalize_watch(
    {"repo": "my-user/my-repo", "number": 123},
    {"default-provider": "fork-app"},
    "test",
)
for field in ("comments", "reviews"):
    associations = watch[field]["author-associations"]
    if "CONTRIBUTOR" not in associations:
        raise SystemExit(f"CONTRIBUTOR missing from {field}: {associations}")
    if not lib.should_accept_author({"author_association": "CONTRIBUTOR"}, associations):
        raise SystemExit(f"CONTRIBUTOR was not accepted for {field}: {associations}")
    if lib.should_accept_author({"author_association": "FIRST_TIME_CONTRIBUTOR"}, associations):
        raise SystemExit(f"FIRST_TIME_CONTRIBUTOR should not be accepted for {field}: {associations}")
`, quoteYAML(f.root))

	f.runCommand("python3", true, "-c", script)
}

func TestGithubWatchRegisterPersistsCloseDefaultsAndFlags(t *testing.T) {
	f := newFixture(t)
	config := f.writePluginConfig("github-watcher.yaml", "default-provider: fork-app\n")
	env := []string{"NVT_PLUGIN_CONFIG=" + config}

	f.runWithEnv(
		githubWatchBin(f.root),
		true,
		env,
		"register",
		"--repo", "my-user/my-repo",
		"--number", "123",
	)

	registryPath := filepath.Join(f.state, "plugins", "github-watcher", "registry.json")
	var registry map[string][]map[string]any
	decodeJSONFile(t, registryPath, &registry)
	closed, ok := registry["prs"][0]["closed"].(map[string]any)
	if !ok {
		t.Fatalf("registration missing closed config: %#v", registry["prs"][0])
	}
	if closed["enabled"] != true || closed["remove"] != true || closed["publish"] != true || closed["prompt"] != false {
		t.Fatalf("unexpected close defaults: %#v", closed)
	}

	f.runWithEnv(
		githubWatchBin(f.root),
		true,
		env,
		"register",
		"--repo", "my-user/my-repo",
		"--number", "456",
		"--no-remove-on-close",
		"--prompt-on-close",
		"--no-publish-on-close",
	)

	decodeJSONFile(t, registryPath, &registry)
	var flagged map[string]any
	for _, pr := range registry["prs"] {
		if pr["number"].(float64) == 456 {
			flagged = pr
		}
	}
	if flagged == nil {
		t.Fatalf("flagged registration missing: %#v", registry)
	}
	closed = flagged["closed"].(map[string]any)
	if closed["enabled"] != true || closed["remove"] != false || closed["publish"] != false || closed["prompt"] != true {
		t.Fatalf("unexpected close flags: %#v", closed)
	}
}

func TestGithubWatchRegisterInheritsBrokerConfig(t *testing.T) {
	f := newFixture(t)
	config := f.writePluginConfig("github-watcher.yaml", `
default-provider: fork-app
broker:
  enabled: true
  provider: broker-fork-app
`)
	env := []string{"NVT_PLUGIN_CONFIG=" + config}

	f.runWithEnv(
		githubWatchBin(f.root),
		true,
		env,
		"register",
		"--repo", "my-user/my-repo",
		"--number", "123",
	)

	registryPath := filepath.Join(f.state, "plugins", "github-watcher", "registry.json")
	var registry map[string][]map[string]any
	decodeJSONFile(t, registryPath, &registry)
	broker, ok := registry["prs"][0]["broker"].(map[string]any)
	if !ok {
		t.Fatalf("registration missing broker config: %#v", registry["prs"][0])
	}
	if broker["enabled"] != true || broker["provider"] != "broker-fork-app" {
		t.Fatalf("registration did not inherit broker config: %#v", broker)
	}
}

func TestGithubWatchRegisterReplacesExistingRegistration(t *testing.T) {
	f := newFixture(t)
	config := f.writePluginConfig("github-watcher.yaml", "default-provider: fork-app\n")
	env := []string{"NVT_PLUGIN_CONFIG=" + config}

	f.runWithEnv(githubWatchBin(f.root), true, env, "register", "--repo", "my-user/my-repo", "--number", "123", "--label", "first")
	f.runWithEnv(githubWatchBin(f.root), true, env, "register", "--repo", "my-user/my-repo", "--number", "123", "--label", "second")

	data, err := os.ReadFile(filepath.Join(f.state, "plugins", "github-watcher", "registry.json"))
	if err != nil {
		t.Fatal(err)
	}
	var registry struct {
		PRs []map[string]any `json:"prs"`
	}
	if err := json.Unmarshal(data, &registry); err != nil {
		t.Fatal(err)
	}
	if len(registry.PRs) != 1 {
		t.Fatalf("expected replacement, got %s", data)
	}
	labels := registry.PRs[0]["labels"].([]any)
	if len(labels) != 1 || labels[0] != "second" {
		t.Fatalf("expected second label after replacement, got %s", data)
	}
}

func TestGithubWatcherDynamicMergedPRPublishesAndRemovesRegistration(t *testing.T) {
	f := newFixture(t)
	config := f.writePluginConfig("github-watcher.yaml", "default-provider: fork-app\n")
	writeGithubWatcherRegistry(t, f, `[{"repo":"my-user/my-repo","number":123,"provider":"fork-app","closed":{"enabled":true,"remove":true,"publish":true,"prompt":false}}]`)

	output := runGithubWatcherCloseScript(t, f, config, map[string]string{
		"state":       "closed",
		"merged":      "true",
		"source":      "dynamic",
		"seen":        "{}",
		"run_once":    "true",
		"expectEvent": "plugin.github.pr.merged",
	})
	if !strings.Contains(output, `"published": [["plugin.github.pr.merged"`) {
		t.Fatalf("merged event was not published:\n%s", output)
	}
	var registry map[string][]map[string]any
	decodeJSONFile(t, filepath.Join(f.state, "plugins", "github-watcher", "registry.json"), &registry)
	if len(registry["prs"]) != 0 {
		t.Fatalf("dynamic registration was not removed: %#v", registry)
	}
}

func TestGithubWatcherDynamicClosedUnmergedPRPublishesAndRemovesRegistration(t *testing.T) {
	f := newFixture(t)
	config := f.writePluginConfig("github-watcher.yaml", "default-provider: fork-app\n")
	writeGithubWatcherRegistry(t, f, `[{"repo":"my-user/my-repo","number":123,"provider":"fork-app","closed":{"enabled":true,"remove":true,"publish":true,"prompt":false}}]`)

	output := runGithubWatcherCloseScript(t, f, config, map[string]string{
		"state":       "closed",
		"merged":      "false",
		"source":      "dynamic",
		"seen":        "{}",
		"run_once":    "true",
		"expectEvent": "plugin.github.pr.closed",
	})
	if !strings.Contains(output, `"published": [["plugin.github.pr.closed"`) {
		t.Fatalf("closed event was not published:\n%s", output)
	}
	if !strings.Contains(output, `"merged_at": ""`) {
		t.Fatalf("closed event did not normalize null merged_at:\n%s", output)
	}
	var registry map[string][]map[string]any
	decodeJSONFile(t, filepath.Join(f.state, "plugins", "github-watcher", "registry.json"), &registry)
	if len(registry["prs"]) != 0 {
		t.Fatalf("dynamic registration was not removed: %#v", registry)
	}
}

func TestGithubWatcherClosedDynamicPRRemovesWhenCommentFetchFails(t *testing.T) {
	f := newFixture(t)
	config := f.writePluginConfig("github-watcher.yaml", "default-provider: fork-app\n")
	writeGithubWatcherRegistry(t, f, `[{"repo":"my-user/my-repo","number":123,"provider":"fork-app","closed":{"enabled":true,"remove":true,"publish":true,"prompt":false}}]`)

	output := runGithubWatcherCloseScript(t, f, config, map[string]string{
		"state":         "closed",
		"merged":        "true",
		"source":        "dynamic",
		"seen":          "{}",
		"run_once":      "true",
		"fail_comments": "true",
		"expectEvent":   "plugin.github.pr.merged",
	})
	if !strings.Contains(output, `"published": [["plugin.github.pr.merged"`) {
		t.Fatalf("merged event was not published:\n%s", output)
	}
	var registry map[string][]map[string]any
	decodeJSONFile(t, filepath.Join(f.state, "plugins", "github-watcher", "registry.json"), &registry)
	if len(registry["prs"]) != 0 {
		t.Fatalf("dynamic registration was not removed after closed PR despite comment fetch failure: %#v", registry)
	}
}

func TestGithubWatcherNoRemoveOnCloseKeepsDynamicRegistration(t *testing.T) {
	f := newFixture(t)
	config := f.writePluginConfig("github-watcher.yaml", "default-provider: fork-app\n")
	writeGithubWatcherRegistry(t, f, `[{"repo":"my-user/my-repo","number":123,"provider":"fork-app","closed":{"enabled":true,"remove":false,"publish":true,"prompt":false}}]`)

	runGithubWatcherCloseScript(t, f, config, map[string]string{
		"state":       "closed",
		"merged":      "true",
		"source":      "dynamic",
		"seen":        "{}",
		"run_once":    "true",
		"expectEvent": "plugin.github.pr.merged",
	})
	var registry map[string][]map[string]any
	decodeJSONFile(t, filepath.Join(f.state, "plugins", "github-watcher", "registry.json"), &registry)
	if len(registry["prs"]) != 1 {
		t.Fatalf("dynamic registration should have been kept: %#v", registry)
	}
}

func TestGithubWatcherStaticClosedWatchPublishesButIsNotRemoved(t *testing.T) {
	f := newFixture(t)
	config := f.writePluginConfig("github-watcher.yaml", `
default-provider: fork-app
prs:
  - repo: my-user/my-repo
    number: 123
    provider: fork-app
`)

	output := runGithubWatcherCloseScript(t, f, config, map[string]string{
		"state":       "closed",
		"merged":      "false",
		"source":      "static",
		"seen":        "{}",
		"run_once":    "true",
		"expectEvent": "plugin.github.pr.closed",
	})
	if !strings.Contains(output, `"published": [["plugin.github.pr.closed"`) {
		t.Fatalf("static closed event was not published:\n%s", output)
	}
	if _, err := os.Stat(filepath.Join(f.state, "plugins", "github-watcher", "registry.json")); err == nil {
		t.Fatalf("static close should not create or mutate dynamic registry")
	} else if !os.IsNotExist(err) {
		t.Fatal(err)
	}
}

func TestGithubWatcherAlreadySeenTerminalStateDoesNotRepublish(t *testing.T) {
	f := newFixture(t)
	config := f.writePluginConfig("github-watcher.yaml", "default-provider: fork-app\n")
	writeGithubWatcherRegistry(t, f, `[{"repo":"my-user/my-repo","number":123,"provider":"fork-app","closed":{"enabled":true,"remove":false,"publish":true,"prompt":false}}]`)

	output := runGithubWatcherCloseScript(t, f, config, map[string]string{
		"state":       "closed",
		"merged":      "true",
		"source":      "dynamic",
		"seen":        `{"my-user/my-repo#123:closed":"merged"}`,
		"run_once":    "true",
		"expectEvent": "",
	})
	if !strings.Contains(output, `"published": []`) {
		t.Fatalf("already-seen terminal state republished:\n%s", output)
	}
}

func TestGithubWatcherBaselinesExistingCommentsAndReviews(t *testing.T) {
	f := newFixture(t)
	script := fmt.Sprintf(`
import importlib.util
import json
import pathlib
import sys

root = pathlib.Path(%s)
module_path = root / "runtime" / "plugins" / "github-watcher" / "run.py"
sys.path.insert(0, str(module_path.parent))
spec = importlib.util.spec_from_file_location("github_watcher_run", module_path)
watcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(watcher)

published = []
prompted = []

def fake_fetch_comments(_watch):
    return [
        {
            "id": 1,
            "updated_at": "2026-05-26T10:00:00Z",
            "created_at": "2026-05-26T10:00:00Z",
            "author_association": "COLLABORATOR",
            "user": {"login": "reviewer"},
            "body": "existing comment",
            "html_url": "https://github.com/my-user/my-repo/pull/123#issuecomment-1",
        }
    ]

def fake_fetch_reviews(_watch):
    return [
        {
            "id": 2,
            "submitted_at": "2026-05-26T10:05:00Z",
            "author_association": "COLLABORATOR",
            "user": {"login": "reviewer"},
            "state": "CHANGES_REQUESTED",
            "body": "existing review",
            "html_url": "https://github.com/my-user/my-repo/pull/123#pullrequestreview-2",
        }
    ]

watcher.fetch_comments = fake_fetch_comments
watcher.fetch_reviews = fake_fetch_reviews
watcher.fetch_pull = lambda _watch: {"head": {"sha": "abc"}}
watcher.fetch_check_runs = lambda _watch, _sha: []
watcher.publish_event = lambda event, payload: published.append((event, payload))
watcher.prompt_agent = lambda message: prompted.append(message)

watch = {
    "repo": "my-user/my-repo",
    "number": 123,
    "provider": "fork-app",
    "labels": [],
    "publish": {"enabled": True},
    "comments": {
        "enabled": True,
        "author-associations": ["COLLABORATOR"],
        "prompt": {"enabled": True, "template": None},
    },
    "reviews": {
        "enabled": True,
        "author-associations": ["COLLABORATOR"],
        "prompt": {"enabled": True, "template": None},
    },
    "checks": {
        "enabled": True,
        "publish-failed-transition": True,
        "publish-passed-transition": False,
        "prompt": {"failed": True, "passed": False, "template": None},
    },
}
seen = {}
watcher.process_watch(watch, seen)
if published or prompted:
    raise SystemExit(f"first poll should baseline only, published={published}, prompted={prompted}")
if seen.get("my-user/my-repo#123:comments", 0) <= 0:
    raise SystemExit(f"comment watermark was not seeded: {json.dumps(seen)}")
if seen.get("my-user/my-repo#123:reviews", 0) <= 0:
    raise SystemExit(f"review watermark was not seeded: {json.dumps(seen)}")

watcher.process_watch(watch, seen)
if published or prompted:
    raise SystemExit(f"second poll should not replay baseline, published={published}, prompted={prompted}")
`, quoteYAML(f.root))

	f.runCommand("python3", true, "-c", script)
}

func TestGithubWatcherDirectRequestsPassTargetToCredentialProvider(t *testing.T) {
	f := newFixture(t)
	logPath := filepath.Join(f.home, "git-host-credential.log")
	f.writeBin("git-host-credential", fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
printf '%%s\n' "$*" > %s
printf 'test-token\n'
`, quoteYAML(logPath)))
	script := fmt.Sprintf(`
import importlib.util
import io
import json
import pathlib
import sys

root = pathlib.Path(%s)
module_path = root / "runtime" / "plugins" / "github-watcher" / "github_watcher_lib.py"
sys.path.insert(0, str(module_path.parent))
spec = importlib.util.spec_from_file_location("github_watcher_lib", module_path)
lib = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lib)

class Response:
    def __enter__(self):
        return self
    def __exit__(self, *_args):
        return False
    def read(self):
        return b'{"ok": true}'

requests = []
def fake_urlopen(request, timeout=30):
    requests.append((request.full_url, request.headers.get("Authorization")))
    return Response()

lib.urlopen = fake_urlopen
payload = lib.github_request("/repos/my-user/my-repo/issues/123/comments", "fork-app")
if payload != {"ok": True}:
    raise SystemExit(f"unexpected payload: {payload}")
if requests != [("https://api.github.com/repos/my-user/my-repo/issues/123/comments", "Bearer test-token")]:
    raise SystemExit(f"unexpected request: {requests}")
`, quoteYAML(f.root))

	f.runWithEnv("python3", true, nil, "-c", script)
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	args := string(data)
	if !strings.Contains(args, "token --provider fork-app --target github.com/my-user/my-repo") {
		t.Fatalf("git-host-credential was not called with target:\n%s", args)
	}
}

func TestGithubWatcherMediatedClosedPRUsesGhAuthAndRemovesRegistration(t *testing.T) {
	f := newFixture(t)
	config := f.writePluginConfig("github-watcher.yaml", `
default-provider: github-main
broker:
  enabled: true
  provider: github-main-app
`)
	writeGithubWatcherRegistry(t, f, `[{"repo":"my-user/my-repo","number":123,"provider":"github-main","closed":{"enabled":true,"remove":true,"publish":true,"prompt":false}}]`)

	ghAuthLog := filepath.Join(f.home, "gh-auth.log")
	brokerctlCalled := filepath.Join(f.home, "brokerctl-called")
	agentdctlLog := filepath.Join(f.home, "agentdctl.log")
	f.writeBin("gh-auth", fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
printf '%%s\n' "$*" >> %s
printf '%%s\n' '{"state":"closed","merged":false,"head":{"sha":"abc"},"html_url":"https://github.com/my-user/my-repo/pull/123","closed_at":"2026-07-15T15:00:00Z","merged_at":null}'
`, quoteYAML(ghAuthLog)))
	f.writeBin("brokerctl", fmt.Sprintf(`#!/usr/bin/env bash
touch %s
exit 99
`, quoteYAML(brokerctlCalled)))
	f.writeBin("git-host-credential", "#!/usr/bin/env bash\nexit 98\n")
	f.writeBin("agentdctl", fmt.Sprintf(`#!/usr/bin/env bash
printf '%%s\n' "$*" >> %s
`, quoteYAML(agentdctlLog)))

	f.runWithEnv(
		githubWatcherRunBin(f.root),
		true,
		[]string{"NVT_PLUGIN_CONFIG=" + config, "NVT_EGRESS_MODE=mediated"},
		"once",
	)

	if _, err := os.Stat(brokerctlCalled); err == nil {
		t.Fatal("mediated watcher called brokerctl")
	} else if !os.IsNotExist(err) {
		t.Fatal(err)
	}
	args, err := os.ReadFile(ghAuthLog)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(args), "--provider github-main api --method GET repos/my-user/my-repo/pulls/123") {
		t.Fatalf("unexpected gh-auth args:\n%s", args)
	}
	events, err := os.ReadFile(agentdctlLog)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(events), "publish plugin.github.pr.closed") {
		t.Fatalf("close event was not published:\n%s", events)
	}
	var registry map[string][]map[string]any
	decodeJSONFile(t, filepath.Join(f.state, "plugins", "github-watcher", "registry.json"), &registry)
	if len(registry["prs"]) != 0 {
		t.Fatalf("closed mediated watch was not removed: %#v", registry)
	}
}

func TestGithubWatcherMediatedPaginationUsesExplicitPageRequests(t *testing.T) {
	f := newFixture(t)
	ghAuthLog := filepath.Join(f.home, "gh-auth.log")
	ghAuthState := filepath.Join(f.home, "gh-auth.state")
	f.writeBin("gh-auth", fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
printf '%%s\n' "$*" >> %s
if [[ ! -f %s ]]; then
  touch %s
  python3 -c 'import json; print(json.dumps([{"id": i} for i in range(100)]))'
else
  printf '%%s\n' '[{"id":100}]'
fi
`, quoteYAML(ghAuthLog), quoteYAML(ghAuthState), quoteYAML(ghAuthState)))
	script := fmt.Sprintf(`
import importlib.util
import pathlib
import sys

root = pathlib.Path(%s)
module_path = root / "runtime" / "plugins" / "github-watcher" / "github_watcher_lib.py"
sys.path.insert(0, str(module_path.parent))
spec = importlib.util.spec_from_file_location("github_watcher_lib", module_path)
lib = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lib)

payload = lib.github_request(
    "/repos/my-user/my-repo/issues/123/comments",
    "github-main",
    {"per_page": 100},
    {"enabled": True, "provider": "github-main-app"},
    paginate=True,
)
if len(payload) != 101 or payload[-1] != {"id": 100}:
    raise SystemExit(f"unexpected paginated payload: {payload}")
`, quoteYAML(f.root))

	f.runWithEnv("python3", true, []string{"NVT_EGRESS_MODE=mediated"}, "-c", script)
	args, err := os.ReadFile(ghAuthLog)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(args), "comments?per_page=100&page=1") ||
		!strings.Contains(string(args), "comments?per_page=100&page=2") ||
		strings.Contains(string(args), "--paginate") || strings.Contains(string(args), "--slurp") {
		t.Fatalf("unexpected paginated gh-auth args:\n%s", args)
	}
}

func TestGithubWatcherPaginatesCommentsAndReviews(t *testing.T) {
	f := newFixture(t)
	script := fmt.Sprintf(`
import importlib.util
import pathlib
import sys

root = pathlib.Path(%s)
module_path = root / "runtime" / "plugins" / "github-watcher" / "run.py"
sys.path.insert(0, str(module_path.parent))
spec = importlib.util.spec_from_file_location("github_watcher_run", module_path)
watcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(watcher)

calls = []

def fake_request(path, provider, query, broker=None, paginate=False):
    calls.append((path, query["page"]))
    if path.endswith("/comments"):
        return [{}] * 100 if query["page"] == 1 else [{"id": "last-comment"}]
    if path.endswith("/reviews"):
        return [{}] * 100 if query["page"] == 1 else [{"id": "last-review"}]
    raise SystemExit(f"unexpected path {path}")

watcher.github_request = fake_request
watch = {"repo": "my-user/my-repo", "number": 123, "provider": "fork-app"}

comments = watcher.fetch_comments(watch)
reviews = watcher.fetch_reviews(watch)
if len(comments) != 101 or comments[-1].get("id") != "last-comment":
    raise SystemExit(f"comments were not paginated: {len(comments)}")
if len(reviews) != 101 or reviews[-1].get("id") != "last-review":
    raise SystemExit(f"reviews were not paginated: {len(reviews)}")
if calls != [
    ("/repos/my-user/my-repo/issues/123/comments", 1),
    ("/repos/my-user/my-repo/issues/123/comments", 2),
    ("/repos/my-user/my-repo/pulls/123/reviews", 1),
    ("/repos/my-user/my-repo/pulls/123/reviews", 2),
]:
    raise SystemExit(f"unexpected pagination calls: {calls}")
`, quoteYAML(f.root))

	f.runCommand("python3", true, "-c", script)
}

func TestGithubWatcherCanFetchCommentsThroughBroker(t *testing.T) {
	f := newFixture(t)
	logPath := filepath.Join(f.home, "brokerctl.log")
	f.writeBin("brokerctl", fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
printf '%%s\n' "$*" > %s
printf '%%s\n' '{"ok":true,"status":200,"headers":{},"body":"[{\"id\":1,\"updated_at\":\"2026-05-26T10:00:00Z\"}]"}'
`, quoteYAML(logPath)))
	script := fmt.Sprintf(`
import importlib.util
import pathlib
import sys

root = pathlib.Path(%s)
module_path = root / "runtime" / "plugins" / "github-watcher" / "run.py"
sys.path.insert(0, str(module_path.parent))
spec = importlib.util.spec_from_file_location("github_watcher_run", module_path)
watcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(watcher)

watch = {
    "repo": "my-user/my-repo",
    "number": 123,
    "provider": "direct-provider",
    "broker": {"enabled": True, "provider": "broker-provider"},
}
comments = watcher.fetch_comments(watch)
if len(comments) != 1 or comments[0]["id"] != 1:
    raise SystemExit(f"unexpected comments: {comments}")
`, quoteYAML(f.root))

	f.runCommand("python3", true, "-c", script)
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	args := string(data)
	if !strings.Contains(args, "--provider broker-provider") ||
		!strings.Contains(args, "--paginate") ||
		!strings.Contains(args, "https://api.github.com/repos/my-user/my-repo/issues/123/comments") {
		t.Fatalf("unexpected brokerctl args:\n%s", args)
	}
}

func TestGithubWatcherBrokerHTTPFailureDoesNotTerminateOnce(t *testing.T) {
	f := newFixture(t)
	config := f.writePluginConfig("github-watcher.yaml", `
default-provider: direct-provider
broker:
  enabled: true
  provider: broker-provider
prs:
  - repo: my-user/failing
    number: 123
    comments:
      enabled: true
    reviews:
      enabled: false
    checks:
      enabled: false
    closed:
      enabled: false
`)
	f.writeBin("brokerctl", `#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' '{"ok":true,"status":404,"headers":{},"body":"{\"message\":\"Not Found\"}"}'
`)

	output := f.runWithEnv(githubWatcherRunBin(f.root), true, []string{"NVT_PLUGIN_CONFIG=" + config}, "once")
	if !strings.Contains(output, "github-watcher: my-user/failing#123 failed: GitHub API request failed through broker: status=404") {
		t.Fatalf("watch failure was not logged:\n%s", output)
	}
}

func TestGithubWatcherContinuesAfterFailedWatch(t *testing.T) {
	f := newFixture(t)
	config := f.writePluginConfig("github-watcher.yaml", `
default-provider: direct-provider
broker:
  enabled: true
  provider: broker-provider
prs:
  - repo: my-user/failing
    number: 123
    comments:
      enabled: true
    reviews:
      enabled: false
    checks:
      enabled: false
    closed:
      enabled: false
  - repo: my-user/passing
    number: 456
    comments:
      enabled: true
    reviews:
      enabled: false
    checks:
      enabled: false
    closed:
      enabled: false
`)
	f.writeBin("brokerctl", `#!/usr/bin/env bash
set -euo pipefail
case "$*" in
  *my-user/failing*)
    printf '%s\n' '{"ok":true,"status":404,"headers":{},"body":"{\"message\":\"Not Found\"}"}'
    ;;
  *my-user/passing*)
    printf '%s\n' '{"ok":true,"status":200,"headers":{},"body":"[{\"id\":1,\"updated_at\":\"2026-05-28T10:00:00Z\",\"created_at\":\"2026-05-28T10:00:00Z\",\"author_association\":\"COLLABORATOR\",\"user\":{\"login\":\"reviewer\"},\"body\":\"existing comment\"}]"}'
    ;;
  *)
    echo "unexpected brokerctl args: $*" >&2
    exit 1
    ;;
esac
`)

	output := f.runWithEnv(githubWatcherRunBin(f.root), true, []string{"NVT_PLUGIN_CONFIG=" + config}, "once")
	if !strings.Contains(output, "github-watcher: my-user/failing#123 failed: GitHub API request failed through broker: status=404") {
		t.Fatalf("failed watch was not logged:\n%s", output)
	}

	var seen map[string]any
	decodeJSONFile(t, filepath.Join(f.state, "plugins", "github-watcher", "seen.json"), &seen)
	if seen["my-user/passing#456:comments"] == nil {
		t.Fatalf("second watch did not update seen state: %#v", seen)
	}
}

func TestGithubWatcherMalformedBrokerJSONDoesNotTerminateOnce(t *testing.T) {
	f := newFixture(t)
	config := f.writePluginConfig("github-watcher.yaml", `
default-provider: direct-provider
broker:
  enabled: true
  provider: broker-provider
prs:
  - repo: my-user/failing
    number: 123
    comments:
      enabled: true
    reviews:
      enabled: false
    checks:
      enabled: false
    closed:
      enabled: false
`)
	f.writeBin("brokerctl", `#!/usr/bin/env bash
set -euo pipefail
printf 'not json\n'
`)

	output := f.runWithEnv(githubWatcherRunBin(f.root), true, []string{"NVT_PLUGIN_CONFIG=" + config}, "once")
	if !strings.Contains(output, "github-watcher: my-user/failing#123 failed: broker response was not valid JSON") {
		t.Fatalf("malformed broker response was not logged:\n%s", output)
	}
}

func writeGithubWatcherRegistry(t *testing.T, f *fixture, prsJSON string) {
	t.Helper()
	dir := filepath.Join(f.state, "plugins", "github-watcher")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "registry.json"), []byte(`{"prs":`+prsJSON+`}`), 0o644); err != nil {
		t.Fatal(err)
	}
}

func runGithubWatcherCloseScript(t *testing.T, f *fixture, config string, opts map[string]string) string {
	t.Helper()
	merged := "False"
	if opts["merged"] == "true" {
		merged = "True"
	}
	runOnce := "False"
	if opts["run_once"] == "true" {
		runOnce = "True"
	}
	failComments := "False"
	if opts["fail_comments"] == "true" {
		failComments = "True"
	}
	script := fmt.Sprintf(`
import importlib.util
import json
import os
import pathlib
import sys

root = pathlib.Path(%s)
module_path = root / "runtime" / "plugins" / "github-watcher" / "run.py"
sys.path.insert(0, str(module_path.parent))
spec = importlib.util.spec_from_file_location("github_watcher_run", module_path)
watcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(watcher)

published = []
prompted = []

def fake_fetch_comments(_watch):
    if %s:
        raise RuntimeError("comments failed")
    return []

watcher.fetch_comments = fake_fetch_comments
watcher.fetch_reviews = lambda _watch: []
watcher.fetch_check_runs = lambda _watch, _sha: []
watcher.fetch_pull = lambda _watch: {
    "state": %s,
    "merged": %s,
    "head": {"sha": "abc"},
    "html_url": "https://github.com/my-user/my-repo/pull/123",
    "closed_at": "2026-05-28T10:00:00Z",
    "merged_at": "2026-05-28T10:00:00Z" if %s else None,
}
watcher.publish_event = lambda event, payload: published.append((event, payload))
watcher.prompt_agent = lambda message: prompted.append(message)
seen = json.loads(%s)

if %s:
    watcher.write_json(watcher.seen_path(), seen)
    watcher.run_once(watcher.load_config())
    seen = watcher.read_json(watcher.seen_path(), {})
else:
    watch = {
        "repo": "my-user/my-repo",
        "number": 123,
        "provider": "fork-app",
        "labels": [],
        "publish": {"enabled": True},
        "comments": {"enabled": False, "author-associations": [], "prompt": {"enabled": False, "template": None}},
        "reviews": {"enabled": False, "author-associations": [], "prompt": {"enabled": False, "template": None}},
        "checks": {"enabled": False, "publish-failed-transition": True, "publish-passed-transition": False, "prompt": {"failed": False, "passed": False, "template": None}},
        "closed": {"enabled": True, "remove": True, "publish": True, "prompt": False, "template": None},
        "_source": %s,
    }
    watcher.process_watch(watch, seen)

expected = %s
if expected:
    if [event for event, _payload in published] != [expected]:
        raise SystemExit(f"unexpected events: {published}")
elif published:
    raise SystemExit(f"unexpected events: {published}")

print(json.dumps({"published": published, "prompted": prompted, "seen": seen}, sort_keys=True))
`, quoteYAML(f.root), failComments, quoteYAML(opts["state"]), merged, merged, quoteYAML(opts["seen"]), runOnce, quoteYAML(opts["source"]), quoteYAML(opts["expectEvent"]))

	return f.runWithEnv("python3", true, []string{"NVT_PLUGIN_CONFIG=" + config}, "-c", script)
}
