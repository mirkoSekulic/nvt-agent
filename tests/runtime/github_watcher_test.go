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

	output := f.runWithEnv(githubWatchBin(f.root), true, env, "list")
	if !strings.Contains(output, "my-user/my-repo#123") || !strings.Contains(output, "labels=frontend,urgent") {
		t.Fatalf("unexpected list output:\n%s", output)
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

def fake_request(path, provider, query):
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
