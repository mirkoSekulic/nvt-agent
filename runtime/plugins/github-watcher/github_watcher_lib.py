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


DEFAULT_ASSOCIATIONS = ["OWNER", "MEMBER", "COLLABORATOR"]
FAILURE_CONCLUSIONS = {"failure", "timed_out", "cancelled", "action_required"}
PASSING_CONCLUSIONS = {"success", "skipped", "neutral"}


def fail(message):
    raise SystemExit(f"github-watcher: {message}")


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

    normalized = {
        "repo": repo,
        "number": number,
        "provider": string_value(raw.get("provider"), f"{source}.provider") or defaults.get("default-provider"),
        "labels": labels,
        "publish": {"enabled": bool_value(publish.get("enabled"), f"{source}.publish.enabled", True)},
        "comments": normalize_discussion_config(comments, f"{source}.comments", True),
        "reviews": normalize_discussion_config(reviews, f"{source}.reviews", True),
        "checks": normalize_checks_config(checks, f"{source}.checks"),
        "broker": normalize_broker_config(raw.get("broker"), defaults.get("broker"), f"{source}.broker"),
    }
    if not normalized["provider"]:
        fail(f"{source}.provider is required unless default-provider is configured")
    return normalized


def normalize_broker_config(raw, default, field):
    config = object_value(default, "broker")
    override = object_value(raw, field)
    merged = {**config, **override}
    return {
        "enabled": bool_value(merged.get("enabled"), f"{field}.enabled", False),
        "provider": string_value(merged.get("provider"), f"{field}.provider"),
    }


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


def static_watches(config):
    defaults = {
        "default-provider": string_value(config.get("default-provider"), "default-provider"),
        "broker": object_value(config.get("broker"), "broker"),
    }
    return [normalize_watch(raw, defaults, f"prs[{index}]") for index, raw in enumerate(list_value(config.get("prs"), "prs"))]


def dynamic_watches(config):
    defaults = {
        "default-provider": string_value(config.get("default-provider"), "default-provider"),
        "broker": object_value(config.get("broker"), "broker"),
    }
    data = read_json(registry_path(), {"prs": []})
    return [normalize_watch(raw, defaults, f"registry.prs[{index}]") for index, raw in enumerate(data.get("prs", []))]


def all_watches(config):
    watches = {}
    for watch in static_watches(config):
        watches[watch_key(watch)] = watch
    for watch in dynamic_watches(config):
        watches[watch_key(watch)] = watch
    return list(watches.values())


def token_for_provider(provider):
    result = subprocess.run(
        ["git-host-credential", "token", "--provider", provider],
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    )
    token = result.stdout.strip()
    if not token:
        fail(f"provider {provider} returned an empty token")
    return token


def broker_request(path, provider, query=None, paginate=False, broker=None):
    broker = broker or {}
    broker_provider = broker.get("provider") or provider
    query_string = f"?{urlencode(query)}" if query else ""
    command = [
        "brokerctl",
        "http",
        "request",
        "--provider",
        broker_provider,
        "--method",
        "GET",
        "--url",
        f"https://api.github.com{path}{query_string}",
        "--header",
        "Accept:application/vnd.github+json",
    ]
    if paginate:
        command.append("--paginate")
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0:
        fail(f"broker request failed: {result.stderr.strip() or result.stdout.strip()}")
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        fail(f"broker response was not valid JSON: {error}")
    if not payload.get("ok"):
        fail(f"broker request failed: {payload.get('error') or payload}")
    status = payload.get("status")
    if not isinstance(status, int) or status < 200 or status >= 300:
        fail(f"GitHub API request failed through broker: status={status} body={payload.get('body', '')}")
    try:
        return json.loads(payload.get("body") or "null")
    except json.JSONDecodeError as error:
        fail(f"GitHub API broker response body was not valid JSON: {error}")


def github_request(path, provider, query=None, broker=None, paginate=False):
    if broker and broker.get("enabled"):
        return broker_request(path, provider, query, paginate, broker)
    query_string = f"?{urlencode(query)}" if query else ""
    request = Request(
        f"https://api.github.com{path}{query_string}",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token_for_provider(provider)}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "nvt-agent-github-watcher",
        },
    )
    try:
        with urlopen(request, timeout=30) as response:
            return json.loads(response.read().decode("utf-8"))
    except HTTPError as error:
        body = error.read().decode("utf-8", errors="replace")
        fail(f"GitHub API request failed: {error.code} {error.reason}: {body}")
    except URLError as error:
        fail(f"GitHub API request failed: {error.reason}")


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
