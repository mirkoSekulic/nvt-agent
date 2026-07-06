#!/usr/bin/env python3
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import yaml


def run(command, **kwargs):
    print("+", " ".join(command), flush=True)
    subprocess.run(command, check=True, **kwargs)


def as_string_list(value, field):
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise SystemExit(f"tools.{field} must be a list of strings")
    return value


def optional_string(value, field):
    if value is None:
        return None
    if not isinstance(value, str):
        raise SystemExit(f"{field} must be a string")
    return value


def optional_bool(value, field, default=False):
    if value is None:
        return default
    if not isinstance(value, bool):
        raise SystemExit(f"{field} must be a boolean")
    return value


def optional_string_list(value, field):
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise SystemExit(f"{field} must be a list of strings")
    return value


PLACEHOLDER = "NVT-PLACEHOLDER-NOT-A-KEY"
ENV_NAME_RE = re.compile(r"^[A-Z_][A-Z0-9_]*$")
DEFAULT_EGRESS_CA_FILE = "/nvt-egress-ca/ca.crt"
DEFAULT_EGRESS_CA_WAIT_SECONDS = 60
DEFAULT_BROKER_WAIT_SECONDS = 180


def load_bootstrap_config(path):
    if not path.is_file():
        print(f"bootstrap: no agent config at {path}", flush=True)
        return {}, {}, {}, {}

    with path.open("r", encoding="utf-8") as file:
        data = yaml.safe_load(file) or {}

    if not isinstance(data, dict):
        raise SystemExit("agent config must be a YAML object")

    runtime = data.get("runtime", {})
    if not isinstance(runtime, dict):
        raise SystemExit("runtime must be a YAML object")

    tools = data.get("tools", data)
    if not isinstance(tools, dict):
        raise SystemExit("tools must be a YAML object")

    code_server = data.get("code-server", {})
    if code_server is None:
        code_server = {}
    if not isinstance(code_server, dict):
        raise SystemExit("code-server must be a YAML object")

    egress = data.get("egress", {})
    if egress is None:
        egress = {}
    if not isinstance(egress, dict):
        raise SystemExit("egress must be a YAML object")

    return runtime, tools, code_server, egress


def expand_path(value):
    home = os.environ.get("HOME", "")
    if value == "~":
        return home
    if value.startswith("~/"):
        return str(Path(home) / value[2:])
    return value.replace("${HOME}", home).replace("$HOME", home)


def prepend_path(path):
    current = os.environ.get("PATH", "")
    parts = [part for part in current.split(":") if part]
    if path in parts:
        return
    os.environ["PATH"] = ":".join([path, *parts])


def persist_env_var(name, value):
    env_path = Path.home() / ".nvt-agent" / "env"
    lines = []
    if env_path.is_file():
        lines = env_path.read_text(encoding="utf-8").splitlines()

    prefix = f"export {name}="
    replacement = f'export {name}="{value}"'
    replaced = False
    updated = []
    for line in lines:
        if line.startswith(prefix):
            if not replaced:
                updated.append(replacement)
                replaced = True
            continue
        updated.append(line)

    if not replaced:
        updated.append(replacement)

    env_path.parent.mkdir(parents=True, exist_ok=True)
    env_path.write_text("\n".join(updated) + "\n", encoding="utf-8")


def persist_agent_command(command, args):
    target = Path.home() / ".nvt-agent" / "agent-command.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps({"command": command, "args": args}, separators=(",", ":")) + "\n", encoding="utf-8")


def codex_home():
    return Path(os.environ.get("CODEX_HOME", str(Path.home() / ".codex")))


def has_root_toml_key(lines, key):
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("["):
            return False
        if re.match(rf"^{re.escape(key)}\s*=", stripped):
            return True
    return False


def insert_root_toml_key(lines, key, value):
    entry = f"{key} = {value}"
    for index, line in enumerate(lines):
        if line.strip().startswith("["):
            return [*lines[:index], entry, *lines[index:]]
    return [*lines, entry]


def ensure_codex_update_check_disabled(command):
    if Path(command).name != "codex":
        return

    key = "check_for_update_on_startup"
    target = codex_home() / "config.toml"
    lines = target.read_text(encoding="utf-8").splitlines() if target.exists() else []
    if has_root_toml_key(lines, key):
        print(f"bootstrap: codex startup update check already configured in {target}", flush=True)
        return

    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("\n".join(insert_root_toml_key(lines, key, "false")) + "\n", encoding="utf-8")
    print(f"bootstrap: disabled codex startup update check in {target}", flush=True)


def setup_tmux_config():
    target = Path.home() / ".tmux.conf"
    if target.exists():
        return
    target.write_text(
        "\n".join([
            "set -g mouse on",
            "set -g history-limit 100000",
            "setw -g mode-keys vi",
        ]) + "\n",
        encoding="utf-8",
    )


def mediated_mode(egress):
    config_mode = egress.get("mode")
    env_mode = os.environ.get("NVT_EGRESS_MODE")
    if config_mode and env_mode and config_mode != env_mode:
        raise SystemExit(f"egress.mode {config_mode} disagrees with NVT_EGRESS_MODE {env_mode}")
    mode = config_mode or env_mode or "direct"
    if mode not in {"direct", "mediated"}:
        raise SystemExit("egress.mode must be direct or mediated")
    return mode == "mediated"


def scrub_git_state():
    for scope in ("--system", "--global"):
        for key in ("credential.helper", "http.extraHeader"):
            subprocess.run(["git", "config", scope, "--unset-all", key], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
        result = subprocess.run(["git", "config", scope, "--get-regexp", r"^url\..*\.insteadOf$"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
        for line in result.stdout.splitlines():
            key = line.split(" ", 1)[0]
            if key:
                subprocess.run(["git", "config", scope, "--unset-all", key], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
    for path in (Path.home() / ".git-credentials", Path.home() / ".config" / "git" / "credentials"):
        path.unlink(missing_ok=True)


def broker_wait_deadline():
    # One shared window for the whole bootstrap pass: multiple grants must
    # not multiply the startup wait.
    try:
        wait_seconds = float(os.environ.get("NVT_BROKER_WAIT_SECONDS") or DEFAULT_BROKER_WAIT_SECONDS)
    except ValueError:
        raise SystemExit("bootstrap: NVT_BROKER_WAIT_SECONDS must be a number")
    return time.monotonic() + wait_seconds


def broker_routing(capability, deadline):
    # In k8s the operator registers this run's token in the broker agents
    # ConfigMap right before creating the Pod, but the broker only sees the
    # update after kubelet's ConfigMap sync (~1min worst case). Until then the
    # broker answers "unauthorized" (or is not up yet), so those two failures
    # are retried until the shared deadline; everything else fails immediately.
    while True:
        result = subprocess.run(
            ["brokerctl", "injection", "routing", "--capability", capability],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        payload = None
        try:
            parsed = json.loads(result.stdout)
        except json.JSONDecodeError:
            parsed = None
        if isinstance(parsed, dict):
            payload = parsed
        if result.returncode == 0 and payload is not None and payload.get("ok"):
            return payload
        error = (payload or {}).get("error")
        if error in {"unauthorized", "broker-unreachable"} and time.monotonic() < deadline:
            print(f"bootstrap: broker not ready for {capability} ({error}); retrying", flush=True)
            time.sleep(2)
            continue
        if payload is None:
            raise SystemExit(f"bootstrap: broker routing failed for {capability}: {result.stderr.strip() or result.stdout.strip()}")
        raise SystemExit(f"bootstrap: broker routing denied for {capability}: {payload.get('message') or payload.get('error') or payload}")


def apply_redirect_env(provider, grant, placeholder):
    redirect_env = grant.get("redirect-env") or {}
    if not isinstance(redirect_env, dict):
        raise SystemExit(f"egress mediated grant {provider} redirect-env must be an object")
    base_url = grant.get("base-url")
    for name, source in redirect_env.items():
        if not isinstance(name, str) or not ENV_NAME_RE.match(name):
            raise SystemExit(f"egress mediated grant {provider} redirect-env contains invalid env name {name!r}")
        if source == "base-url":
            persist_env_var(name, base_url)
        elif source == "placeholder":
            persist_env_var(name, placeholder)
        else:
            raise SystemExit(
                f"egress mediated grant {provider} redirect-env.{name} must be base-url or placeholder"
            )


def wait_for_egress_ca(provider):
    ca_file = Path(os.environ.get("NVT_EGRESS_CA_FILE") or DEFAULT_EGRESS_CA_FILE)
    try:
        wait_seconds = float(os.environ.get("NVT_EGRESS_CA_WAIT_SECONDS") or DEFAULT_EGRESS_CA_WAIT_SECONDS)
    except ValueError:
        raise SystemExit("NVT_EGRESS_CA_WAIT_SECONDS must be a number")
    deadline = time.monotonic() + wait_seconds
    while True:
        try:
            if ca_file.stat().st_size > 0:
                return ca_file
        except FileNotFoundError:
            pass
        if time.monotonic() >= deadline:
            # Fail closed: without the CA certificate the git redirect cannot
            # be trusted, and falling back to direct git would need
            # credentials the agent must never hold.
            raise SystemExit(f"bootstrap: egress CA certificate {ca_file} was not published for git grant {provider}")
        time.sleep(0.2)


def apply_git_redirect(provider, grant, hosts):
    base_url = grant["base-url"].rstrip("/")
    if base_url.startswith("https://"):
        ca_file = wait_for_egress_ca(provider)
        run(["git", "config", "--global", "http.sslCAInfo", str(ca_file)])
    for host in hosts:
        # Config, not env, so the rewrite survives any shell. scrub_git_state
        # removed pre-existing rewrites before this managed one is installed.
        run(["git", "config", "--global", f"url.{base_url}/.insteadOf", f"https://{host}/"])
        # git-SSH stays disallowed in mediated mode; rewriting the SSH remote
        # shape onto the mediated HTTPS route is a convenience, not a bypass.
        run(["git", "config", "--global", "--add", f"url.{base_url}/.insteadOf", f"git@{host}:"])
    persist_env_var("GIT_TERMINAL_PROMPT", "0")


def apply_mediated_egress(egress):
    scrub_git_state()
    placeholder = egress.get("placeholder") or PLACEHOLDER
    if placeholder != PLACEHOLDER:
        raise SystemExit("egress.placeholder must use the documented NVT placeholder")
    grants = egress.get("grants") or []
    if not isinstance(grants, list):
        raise SystemExit("egress.grants must be a list")
    deadline = broker_wait_deadline()
    for index, grant in enumerate(grants):
        if not isinstance(grant, dict):
            raise SystemExit(f"egress.grants[{index}] must be an object")
        provider = grant.get("provider")
        if not isinstance(provider, str) or not provider:
            raise SystemExit(f"egress.grants[{index}].provider must be a non-empty string")
        if grant.get("materialization") != "header-inject":
            raise SystemExit(f"egress mediated grant {provider} must be materialization header-inject")
        base_url = grant.get("base-url")
        if not isinstance(base_url, str) or not base_url:
            raise SystemExit(f"egress mediated grant {provider} must include base-url")
        routing = broker_routing(provider, deadline)
        hosts = routing.get("hosts") or []
        if not hosts:
            raise SystemExit(f"bootstrap: mediated grant {provider} is not redirectable")
        if routing.get("git"):
            apply_git_redirect(provider, grant, hosts)
        apply_redirect_env(provider, grant, placeholder)
    target = Path.home() / ".nvt-agent" / "egress.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps({"mode": "mediated", "placeholder": PLACEHOLDER, "grants": grants}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    persist_env_var("NVT_EGRESS_PLACEHOLDER", PLACEHOLDER)


def apply_additional_paths(paths):
    for path in reversed(paths):
        prepend_path(expand_path(path))
    persist_env_var("PATH", os.environ["PATH"])


def install_packages(packages):
    if not packages:
        return
    run(["apt-get", "update"])
    run(["apt-get", "install", "-y", "--no-install-recommends", *packages])


def configured_packages(tools):
    packages = tools.get("packages")
    apt_packages = tools.get("apt")

    if packages is not None and apt_packages is not None:
        raise SystemExit("use tools.packages instead of tools.apt, not both")
    if packages is not None:
        return as_string_list(packages, "packages")
    if apt_packages is not None:
        print("bootstrap: tools.apt is deprecated; use tools.packages", flush=True)
        return as_string_list(apt_packages, "apt")
    return []


def install_mise(packages):
    if not packages:
        return

    env = os.environ.copy()
    env["MISE_YES"] = "1"

    for package in packages:
        run(["mise", "use", "--global", package], env=env)


def run_shell(scripts):
    for index, script in enumerate(scripts, start=1):
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            prefix=f"nvt-bootstrap-{index}-",
            suffix=".sh",
            delete=False,
        ) as file:
            file.write("#!/usr/bin/env bash\n")
            file.write("set -e\n")
            file.write(script)
            file.write("\n")
            path = Path(file.name)

        try:
            run(["bash", str(path)])
        finally:
            path.unlink(missing_ok=True)


def workspace():
    return Path(os.environ.get("NVT_WORKSPACE", "/workspace"))


def resolve_workspace_path(path):
    value = expand_path(path)
    target = Path(value)
    if target.is_absolute():
        return target
    return workspace() / target


def install_code_server_extensions(extensions):
    for extension in extensions:
        run(["code-server", "--install-extension", extension])


def code_server_settings_target():
    return Path.home() / ".local" / "share" / "code-server" / "User" / "settings.json"


def copy_code_server_settings(settings_file):
    source = resolve_workspace_path(settings_file)
    if not source.is_file():
        return

    target = code_server_settings_target()
    if target.exists():
        print(f"bootstrap: code-server settings already exist, skipping {target}", flush=True)
        return

    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)
    print(f"bootstrap: copied code-server settings from {source}", flush=True)


def write_code_server_settings(values, overwrite):
    target = code_server_settings_target()
    if target.exists() and not overwrite:
        print(f"bootstrap: code-server settings already exist, skipping {target}", flush=True)
        return

    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(values, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"bootstrap: wrote code-server settings to {target}", flush=True)


def apply_code_server_settings(config):
    settings_file = optional_string(config.get("settings-file"), "code-server.settings-file")
    settings = config.get("settings")

    if settings is None:
        if settings_file:
            print(
                "bootstrap: code-server.settings-file is deprecated; use code-server.settings.values",
                flush=True,
            )
            copy_code_server_settings(settings_file)
        return

    if not isinstance(settings, dict):
        raise SystemExit("code-server.settings must be a YAML object")

    has_values = "values" in settings
    if settings_file and has_values:
        raise SystemExit("code-server.settings-file is deprecated; use code-server.settings.values, not both")

    if not has_values:
        if settings_file:
            print(
                "bootstrap: code-server.settings-file is deprecated; use code-server.settings.values",
                flush=True,
            )
            copy_code_server_settings(settings_file)
        return

    values = settings.get("values")
    if not isinstance(values, dict):
        raise SystemExit("code-server.settings.values must be a YAML object")

    overwrite = optional_bool(settings.get("overwrite"), "code-server.settings.overwrite", False)
    write_code_server_settings(values, overwrite)


def setup_code_server(config):
    install_code_server_extensions(as_string_list(config.get("extensions"), "code-server.extensions"))
    apply_code_server_settings(config)


def main():
    config_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("/nvt-agent/agent.yaml")
    runtime, tools, code_server, egress = load_bootstrap_config(config_path)

    setup_tmux_config()
    if mediated_mode(egress):
        apply_mediated_egress(egress)
    command = optional_string(runtime.get("command"), "runtime.command")
    if command:
        # Kept for older helper scripts and diagnostics; start-agent-session uses
        # agent-command.json so runtime.args are passed without shell parsing.
        persist_env_var("AGENT_COMMAND", command)
        args = optional_string_list(runtime.get("args"), "runtime.args")
        persist_agent_command(command, args)
        ensure_codex_update_check_disabled(command)
    setup_code_server(code_server)
    apply_additional_paths(as_string_list(tools.get("additional-paths"), "additional-paths"))
    install_packages(configured_packages(tools))
    install_mise(as_string_list(tools.get("mise"), "mise"))
    run_shell(as_string_list(tools.get("shell"), "shell"))


if __name__ == "__main__":
    main()
