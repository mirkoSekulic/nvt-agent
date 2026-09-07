"""Managed public Pi files. No host Pi home, credential resolver, or package install."""

import json
import os
import re
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

PLACEHOLDER = "NVT-PLACEHOLDER-NOT-A-KEY"


def fail():
    raise SystemExit(
        "bootstrap: invalid managed Pi configuration or model egress binding"
    )


def replace_file(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    # Replacing rather than truncating also avoids following stale symlinks.
    fd, name = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
        os.replace(name, path)
    finally:
        Path(name).unlink(missing_ok=True)


def prepare(runtime, egress, state, workspace, proxy_url):
    if runtime.get("command") != "pi" or set(runtime) - {
        "command",
        "args",
        "resume",
        "proxy",
        "pi",
        "initial-prompt",
    }:
        fail()
    config = runtime.get("pi")
    if not isinstance(config, dict) or set(config) - {
        "provider",
        "baseUrl",
        "api",
        "models",
        "compat",
        "settings",
        "extensions",
    }:
        fail()
    provider = runtime.get("proxy", {}).get("provider")
    if (
        egress.get("mode") != "mediated"
        or egress.get("transport") not in {"forward-proxy", "transparent"}
        or not provider
    ):
        fail()
    try:
        url = urlsplit(config["baseUrl"])
        if (
            url.scheme != "https"
            or not url.hostname
            or url.username
            or url.password
            or url.query
            or url.fragment
            or url.port not in {None, 443}
            or any(c in config["baseUrl"] for c in "!$%\\ \r\n\t?")
        ):
            fail()
        grants = [g for g in egress.get("grants", []) if g.get("provider") == provider]
        # Bootstrap receives the routing/materialization contract; capabilities
        # are enforced and validated in the broker and backend grant contracts.
        if len(grants) != 1 or grants[0].get("materialization") != "header-inject":
            fail()
        if config["api"] not in {
            "openai-completions",
            "openai-responses",
        } or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._-]*", config["provider"]):
            fail()
        models = config["models"]
        if not isinstance(models, list) or not 1 <= len(models) <= 128:
            fail()
        for model in models:
            if set(model) - {
                "id",
                "name",
                "reasoning",
                "contextWindow",
                "maxTokens",
            } or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._/-]{0,255}", model["id"]):
                fail()
        args = runtime.get("args")
        resume = runtime.get("resume")
        if (
            not isinstance(args, list)
            or len(args) != 4
            or args[0] != "--model"
            or args[2] != "--thinking"
            or args[1] not in {config["provider"] + "/" + m["id"] for m in models}
            or args[3] not in {"off", "minimal", "low", "medium", "high", "xhigh"}
            or resume != {"command": "pi", "args": args}
        ):
            fail()
        compat = config.get("compat", {})
        if set(compat) - {
            "supportsStore",
            "supportsDeveloperRole",
            "supportsReasoningEffort",
            "supportsUsageInStreaming",
            "requiresToolResultName",
            "requiresAssistantAfterToolResult",
            "requiresThinkingAsText",
            "supportsStrictMode",
        } or any(type(v) is not bool for v in compat.values()):
            fail()
        settings = config.get("settings", {}).copy()
        if set(settings) - {
            "hideThinkingBlock",
            "collapseChangelog",
            "showHardwareCursor",
        } or any(type(v) is not bool for v in settings.values()):
            fail()
        extensions = config.get("extensions", [])
        if len(extensions) > 32:
            fail()
        names = set()
        for extension in extensions:
            if (
                set(extension) != {"name", "content"}
                or not re.fullmatch(r"[a-zA-Z0-9_-]+\.(ts|js|mjs)", extension["name"])
                or len(extension["name"]) > 128
                or extension["name"] in names
                or not isinstance(extension["content"], str)
                or not 0 < len(extension["content"].encode("utf-8")) <= 65536
            ):
                fail()
            names.add(extension["name"])
    except (KeyError, TypeError, ValueError, AttributeError):
        fail()
    root = Path(state) / "pi"
    agent_dir = root / "agent"
    # This directory is NVT-owned; all managed files are replaced on every boot.
    # Sessions are separate, so declarative config changes preserve conversation.
    settings.update(
        {
            "quietStartup": True,
            "packages": [],
            "extensions": [],
            "skills": [],
            "prompts": [],
            "themes": [],
            "enableSkillCommands": False,
        }
    )
    managed_provider = {
        "baseUrl": config["baseUrl"],
        "api": config["api"],
        "apiKey": PLACEHOLDER,
        "authHeader": True,
        "models": models,
        "compat": compat,
    }
    replace_file(
        agent_dir / "models.json",
        json.dumps({"providers": {config["provider"]: managed_provider}}),
    )
    replace_file(agent_dir / "auth.json", "{}\n")
    replace_file(agent_dir / "settings.json", json.dumps(settings))
    flags = [
        "--no-approve",
        "--no-extensions",
        "--no-skills",
        "--no-prompt-templates",
        "--no-themes",
        "--session",
        str(root / "session.jsonl"),
        "--append-system-prompt",
        str(Path(workspace) / "AGENTS.md"),
    ]
    for extension in extensions:
        path = agent_dir / "managed-extensions" / extension["name"]
        replace_file(path, extension["content"])
        flags.extend(["--extension", str(path)])
    # Only explicit extensions load. Removed assets are no longer retained.
    extension_dir = agent_dir / "managed-extensions"
    if extension_dir.exists():
        for path in extension_dir.iterdir():
            if path.is_file() and path.name not in names:
                path.unlink()
    runtime["args"] = [*flags, *runtime["args"]]
    runtime["resume"]["args"] = [*flags, *runtime["resume"]["args"]]
    runtime["env"] = {
        "PI_CODING_AGENT_DIR": str(agent_dir),
        "PI_SKIP_VERSION_CHECK": "1",
        "HTTPS_PROXY": proxy_url,
        "https_proxy": proxy_url,
        "NO_PROXY": "",
        "no_proxy": "",
    }
    return runtime
