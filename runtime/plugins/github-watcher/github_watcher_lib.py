import json
import os
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

import yaml


DEFAULT_ASSOCIATIONS = ["OWNER", "MEMBER", "COLLABORATOR", "CONTRIBUTOR"]
FAILURE_CONCLUSIONS = {"failure", "timed_out", "cancelled", "action_required"}
PASSING_CONCLUSIONS = {"success", "skipped", "neutral"}
REQUEST_TIMEOUT_SECONDS = 120


def fail(message):
    raise SystemExit(f"github-watcher: {message}")


class WatchError(Exception):
    pass


def utc_now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_time(value):
    if not isinstance(value, str):
        return 0
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return 0


def state_dir():
    return Path(os.environ.get("NVT_STATE_DIR", str(Path.home() / ".nvt-agent")))


def plugin_state_dir():
    return state_dir() / "plugins" / os.environ.get("NVT_PLUGIN_NAME", "github-watcher")


def registry_path():
    return plugin_state_dir() / "registry.json"


def seen_path():
    return plugin_state_dir() / "seen.json"


def lock_path():
    return plugin_state_dir() / "registry.lock"


def load_yaml(path):
    if not path.is_file():
        return {}
    with path.open("r", encoding="utf-8") as file:
        data = yaml.safe_load(file) or {}
    if not isinstance(data, dict):
        fail(f"{path} must be a YAML object")
    return data


def load_config():
    path = Path(os.environ.get("NVT_PLUGIN_CONFIG", ""))
    if not path.is_file():
        fail("NVT_PLUGIN_CONFIG must point to a config file")
    return load_yaml(path)


def read_json(path, default):
    try:
        with path.open("r", encoding="utf-8") as file:
            return json.load(file)
    except FileNotFoundError:
        return default
    except json.JSONDecodeError as error:
        fail(f"{path} is not valid JSON: {error}")


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(f".{os.getpid()}.tmp")
    with temporary.open("w", encoding="utf-8") as file:
        json.dump(value, file, indent=2, sort_keys=True)
        file.write("\n")
    temporary.replace(path)


class FileLock:
    def __init__(self, path):
        self.path = path
        self.file = None

    def __enter__(self):
        import fcntl

        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.file = self.path.open("a+", encoding="utf-8")
        fcntl.flock(self.file.fileno(), fcntl.LOCK_EX)
        return self

    def __exit__(self, _type, _value, _traceback):
        import fcntl

        fcntl.flock(self.file.fileno(), fcntl.LOCK_UN)
        self.file.close()


def string_value(value, field, required=False, default=None):
    if value is None:
        if required:
            fail(f"{field} is required")
        return default
    if not isinstance(value, str):
        fail(f"{field} must be a string")
    if required and not value.strip():
        fail(f"{field} must not be empty")
    return value


def int_value(value, field, default=None):
    if value is None:
        return default
    if not isinstance(value, int):
        fail(f"{field} must be an integer")
    return value


def bool_value(value, field, default=False):
    if value is None:
        return default
    if not isinstance(value, bool):
        fail(f"{field} must be a boolean")
    return value


def object_value(value, field):
    if value is None:
        return {}
    if not isinstance(value, dict):
        fail(f"{field} must be a YAML object")
    return value


def list_value(value, field):
    if value is None:
        return []
    if not isinstance(value, list):
        fail(f"{field} must be a list")
    return value


def validate_repo(value, field="repo"):
    repo = string_value(value, field, required=True).strip().removesuffix(".git")
    if repo.startswith("https://github.com/"):
        repo = repo.removeprefix("https://github.com/")
    if repo.startswith("github.com/"):
        repo = repo.removeprefix("github.com/")
    parts = repo.strip("/").split("/")
    if len(parts) != 2 or not all(parts):
        fail(f"{field} must be owner/repo")
    return "/".join(parts)


def watch_key(watch):
    return f"{watch['repo']}#{watch['number']}"


def normalize_watch(raw, defaults, source):
    if not isinstance(raw, dict):
        fail(f"{source} watch must be a YAML object")
    repo = validate_repo(raw.get("repo"), f"{source}.repo")
    number = int_value(raw.get("number") or raw.get("pr"), f"{source}.number")
    if not number or number < 1:
        fail(f"{source}.number must be a positive integer")

    labels = list_value(raw.get("labels"), f"{source}.labels")
    for label in labels:
        if not isinstance(label, str):
            fail(f"{source}.labels entries must be strings")

    publish = object_value(raw.get("publish"), f"{source}.publish")
    comments = object_value(raw.get("comments"), f"{source}.comments")
    reviews = object_value(raw.get("reviews"), f"{source}.reviews")
    checks = object_value(raw.get("checks"), f"{source}.checks")
    closed = object_value(raw.get("closed"), f"{source}.closed")

    normalized = {
        "repo": repo,
        "number": number,
        "provider": string_value(raw.get("provider"), f"{source}.provider") or defaults.get("default-provider"),
        "labels": labels,
        "publish": {"enabled": bool_value(publish.get("enabled"), f"{source}.publish.enabled", True)},
        "comments": normalize_discussion_config(comments, f"{source}.comments", True),
        "reviews": normalize_discussion_config(reviews, f"{source}.reviews", True),
        "checks": normalize_checks_config(checks, f"{source}.checks"),
        "closed": normalize_closed_config(closed, defaults.get("closed"), f"{source}.closed"),
    }
    if raw.get("broker") is not None or defaults.get("broker") is not None:
        fail("broker request configuration is removed; use plugin.egress.provider")
    return normalized


def normalize_discussion_config(config, field, default_enabled):
    prompt = object_value(config.get("prompt"), f"{field}.prompt")
    associations = list_value(config.get("author-associations"), f"{field}.author-associations") or DEFAULT_ASSOCIATIONS
    for association in associations:
        if not isinstance(association, str):
            fail(f"{field}.author-associations entries must be strings")
    return {
        "enabled": bool_value(config.get("enabled"), f"{field}.enabled", default_enabled),
        "author-associations": associations,
        "prompt": {
            "enabled": bool_value(prompt.get("enabled"), f"{field}.prompt.enabled", False),
            "template": string_value(prompt.get("template"), f"{field}.prompt.template"),
        },
    }


def normalize_checks_config(config, field):
    prompt = object_value(config.get("prompt"), f"{field}.prompt")
    mode = string_value(config.get("mode"), f"{field}.mode") or "aggregate"
    if mode != "aggregate":
        fail(f"{field}.mode only supports aggregate in v1")
    return {
        "enabled": bool_value(config.get("enabled"), f"{field}.enabled", True),
        "mode": mode,
        "publish-failed-transition": bool_value(
            config.get("publish-failed-transition"),
            f"{field}.publish-failed-transition",
            True,
        ),
        "publish-passed-transition": bool_value(
            config.get("publish-passed-transition"),
            f"{field}.publish-passed-transition",
            False,
        ),
        "prompt": {
            "failed": bool_value(prompt.get("failed"), f"{field}.prompt.failed", False),
            "passed": bool_value(prompt.get("passed"), f"{field}.prompt.passed", False),
            "template": string_value(prompt.get("template"), f"{field}.prompt.template"),
        },
    }


def normalize_closed_config(config, default, field):
    merged = {
        "enabled": True,
        "remove": False,
        "publish": True,
        "prompt": False,
    }
    merged.update(object_value(default, "closed"))
    merged.update(config)
    return {
        "enabled": bool_value(merged.get("enabled"), f"{field}.enabled", True),
        "remove": bool_value(merged.get("remove"), f"{field}.remove", False),
        "publish": bool_value(merged.get("publish"), f"{field}.publish", True),
        "prompt": bool_value(merged.get("prompt"), f"{field}.prompt", False),
        "template": string_value(merged.get("template"), f"{field}.template"),
    }


def static_watches(config):
    defaults = {
        "default-provider": string_value(config.get("default-provider"), "default-provider"),
        "broker": config.get("broker"),
        "closed": {"enabled": True, "remove": False, "publish": True, "prompt": False},
    }
    watches = []
    for index, raw in enumerate(list_value(config.get("prs"), "prs")):
        watch = normalize_watch(raw, defaults, f"prs[{index}]")
        watch["_source"] = "static"
        watches.append(watch)
    return watches


def dynamic_watches(config):
    defaults = {
        "default-provider": string_value(config.get("default-provider"), "default-provider"),
        "broker": config.get("broker"),
        "closed": {"enabled": True, "remove": True, "publish": True, "prompt": False},
    }
    data = read_json(registry_path(), {"prs": []})
    watches = []
    for index, raw in enumerate(data.get("prs", [])):
        watch = normalize_watch(raw, defaults, f"registry.prs[{index}]")
        watch["_source"] = "dynamic"
        watches.append(watch)
    return watches


def all_watches(config):
    watches = {}
    for watch in static_watches(config):
        watches[watch_key(watch)] = watch
    for watch in dynamic_watches(config):
        watches[watch_key(watch)] = watch
    return list(watches.values())


def token_for_provider(provider, target):
    try:
        result = subprocess.run(
            ["git-host-credential", "token", "--provider", provider, "--target", target],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except FileNotFoundError as error:
        raise WatchError(f"git-host-credential not found: {error}") from error
    except subprocess.CalledProcessError as error:
        output = (error.stderr or error.stdout or "").strip()
        raise WatchError(f"git-host-credential failed: {output}") from error
    token = result.stdout.strip()
    if not token:
        raise WatchError(f"provider {provider} returned an empty token")
    return token


def _request_page(path, provider, query, timeout):
    target = github_target_from_path(path)
    query_string = f"?{urlencode(query)}" if query else ""
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "nvt-agent-github-watcher",
    }
    if provider:
        headers["Authorization"] = f"Bearer {token_for_provider(provider, target)}"
    request = Request(f"https://api.github.com{path}{query_string}", headers=headers)
    try:
        with urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except HTTPError as error:
        raise WatchError(f"GitHub API request failed: status={error.code}") from error
    except URLError as error:
        raise WatchError("GitHub API request failed: network error") from error
    except json.JSONDecodeError as error:
        raise WatchError("GitHub API response was not valid JSON") from error


def github_request(path, provider=None, query=None, paginate=False):
    if not paginate:
        return _request_page(path, provider, query, REQUEST_TIMEOUT_SECONDS)
    page_query = dict(query or {})
    try:
        page = int(page_query.get("page", 1))
        per_page = int(page_query.get("per_page", 30))
    except (TypeError, ValueError) as error:
        raise WatchError("GitHub pagination requires integer page values") from error
    if page < 1 or per_page < 1 or per_page > 100:
        raise WatchError("GitHub pagination values are out of range")

    deadline = time.monotonic() + REQUEST_TIMEOUT_SECONDS
    items = []
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise WatchError("GitHub API request timed out")
        page_query["page"] = page
        page_items = _request_page(path, provider, page_query, remaining)
        if not isinstance(page_items, list):
            raise WatchError("paginated GitHub response page was not a list")
        items.extend(page_items)
        if len(page_items) < per_page:
            return items
        page += 1
def github_target_from_path(path):
    parts = path.split("/")
    if len(parts) < 4 or parts[1] != "repos" or not parts[2] or not parts[3]:
        fail(f"cannot resolve GitHub target from path: {path}")
    return f"github.com/{parts[2]}/{parts[3]}"


def agentdctl(args, input_text=None):
    result = subprocess.run(
        ["agentdctl", *args],
        input=input_text,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        print(result.stderr.strip() or result.stdout.strip(), file=sys.stderr, flush=True)
    return result.returncode == 0


def publish_event(event, payload):
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as file:
        json.dump(payload, file, separators=(",", ":"))
        path = Path(file.name)
    try:
        return agentdctl(["publish", event, "--source", "plugin:github-watcher", "--payload", f"@{path}"])
    finally:
        path.unlink(missing_ok=True)


def prompt_agent(message):
    return agentdctl(["prompt", "--source", "plugin:github-watcher"], input_text=message)


def render_template(template, values):
    if not template:
        template = default_template(values)
    output = template
    for key, value in values.items():
        output = output.replace("{{ " + key + " }}", str(value))
        output = output.replace("{{" + key + "}}", str(value))
    return output


def default_template(values):
    event = values.get("event", "github")
    if event == "comment":
        return "New PR comment.\n\nRepo: {{ repo }}\nPR: #{{ number }}\nAuthor: {{ author }}\nLabels: {{ labels }}\n\n{{ body }}\n"
    if event == "review":
        return "PR review received.\n\nRepo: {{ repo }}\nPR: #{{ number }}\nReviewer: {{ author }}\nState: {{ state }}\nLabels: {{ labels }}\n\n{{ body }}\n"
    if event in {"merged", "closed"}:
        return "PR {{ event }}.\n\nRepo: {{ repo }}\nPR: #{{ number }}\nState: {{ state }}\nLabels: {{ labels }}\n\n{{ url }}\n"
    return "PR checks update.\n\nRepo: {{ repo }}\nPR: #{{ number }}\nStatus: {{ status }}\nLabels: {{ labels }}\n\n{{ summary }}\n"


def should_accept_author(item, associations):
    association = item.get("author_association")
    return association in set(associations)


def event_payload(watch, event_id, event, **fields):
    return {
        "id": event_id,
        "repo": watch["repo"],
        "number": watch["number"],
        "url": f"https://github.com/{watch['repo']}/pull/{watch['number']}",
        "labels": watch.get("labels", []),
        "event": event,
        **fields,
    }


def update_watermark(seen, key, timestamp):
    current = seen.get(key, 0)
    if timestamp > current:
        seen[key] = timestamp


def remove_dynamic_watch(repo, number):
    removed = False
    with FileLock(lock_path()):
        data = read_json(registry_path(), {"prs": []})
        prs = []
        for raw in data.get("prs", []):
            watch = normalize_watch(
                raw,
                {
                    "default-provider": raw.get("provider"),
                    "closed": {"enabled": True, "remove": True, "publish": True, "prompt": False},
                },
                "registry",
            )
            if watch["repo"] == repo and watch["number"] == number:
                removed = True
                continue
            prs.append(raw)
        if removed:
            write_json(registry_path(), {"prs": prs})
    return removed
