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
        return {}, {}, {}, {}, {}

    with path.open("r", encoding="utf-8") as file:
        data = yaml.safe_load(file) or {}

    if not isinstance(data, dict):
        raise SystemExit("agent config must be a YAML object")

    runtime = data.get("runtime", {})
    if not isinstance(runtime, dict):
        raise SystemExit("runtime must be a YAML object")

    # runtime.user is a declarative surface (root|non-root); the container user
    # is actually selected by compose/k8s. Validate it and reject unknown modes.
    # bootstrap itself is $HOME-relative, so it follows whatever HOME the
    # selected user has.
    runtime_user = runtime.get("user", "root")
    if runtime_user not in ("root", "non-root"):
        raise SystemExit("runtime.user must be root or non-root")

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

    preseed = data.get("preseed", {})
    if preseed is None:
        preseed = {}
    if not isinstance(preseed, dict):
        raise SystemExit("preseed must be a YAML object")

    return runtime, tools, code_server, egress, preseed


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


DEFAULT_CA_TRUST_DIR = "/usr/local/share/ca-certificates"
DEFAULT_CA_BUNDLE_FILE = "/etc/ssl/certs/ca-certificates.crt"


def validate_certificate_file(ca_file):
    try:
        subprocess.run(
            ["openssl", "x509", "-in", str(ca_file), "-noout"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True,
        )
    except FileNotFoundError:
        raise SystemExit("bootstrap: openssl not found; refusing to continue without validating egress trust")
    except subprocess.CalledProcessError:
        raise SystemExit(f"bootstrap: egress CA file {ca_file} is not a valid certificate; refusing to continue without trust")


def install_egress_ca_trust(provider):
    # With enforcement every grant's base-url is https on the per-run
    # egressd Service, and generic CLIs use the system trust store — so the
    # egress CA (public certificate) is installed system-wide; git keeps its
    # explicit http.sslCAInfo. Fail closed, no fallback: a missing or invalid
    # ca.crt or a failing trust-store install aborts bootstrap — never
    # continue without trust, never downgrade to plain HTTP or direct mode.
    ca_file = wait_for_egress_ca(provider)
    content = ca_file.read_text(encoding="utf-8")
    validate_certificate_file(ca_file)
    trust_dir = Path(os.environ.get("NVT_CA_TRUST_DIR") or DEFAULT_CA_TRUST_DIR)
    trust_dir.mkdir(parents=True, exist_ok=True)
    (trust_dir / "nvt-egress-ca.crt").write_text(content, encoding="utf-8")
    try:
        run(["update-ca-certificates"])
    except FileNotFoundError:
        raise SystemExit("bootstrap: update-ca-certificates not found; refusing to continue without egress trust")
    except subprocess.CalledProcessError as error:
        raise SystemExit(f"bootstrap: update-ca-certificates failed with exit {error.returncode}; refusing to continue without egress trust")
    bundle = os.environ.get("NVT_CA_BUNDLE_FILE") or DEFAULT_CA_BUNDLE_FILE
    persist_env_var("SSL_CERT_FILE", bundle)
    persist_env_var("REQUESTS_CA_BUNDLE", bundle)


def apply_git_redirect(provider, grant, hosts):
    base_url = grant["base-url"].rstrip("/")
    if base_url.startswith("https://"):
        ca_file = wait_for_egress_ca(provider)
        validate_certificate_file(ca_file)
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
    https_provider = None
    enforced = bool(egress.get("enforcement"))
    for index, grant in enumerate(grants):
        if not isinstance(grant, dict):
            raise SystemExit(f"egress.grants[{index}] must be an object")
        provider = grant.get("provider")
        if not isinstance(provider, str) or not provider:
            raise SystemExit(f"egress.grants[{index}].provider must be a non-empty string")
        materialization = grant.get("materialization")
        if materialization == "placeholder-file":
            # Materialized separately by apply_placeholder_files; not an egress
            # route.
            continue
        if materialization != "header-inject":
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
        if base_url.startswith("https://") and https_provider is None:
            https_provider = provider
        apply_redirect_env(provider, grant, placeholder)
    forward_proxy = bool(egress.get("forward-proxy"))
    if enforced and (https_provider is not None or forward_proxy):
        # Forward-proxy mode has no https base-url to trigger the install, but
        # the MITM leaf must be trusted system-wide so proxy-env HTTPS clients
        # (curl, requests, node, ...) accept it.
        install_egress_ca_trust(https_provider or "forward-proxy")
    target = Path.home() / ".nvt-agent" / "egress.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    metadata = {"mode": "mediated", "placeholder": PLACEHOLDER, "grants": grants}
    if forward_proxy:
        metadata["forward_proxy"] = True
    target.write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    persist_env_var("NVT_EGRESS_PLACEHOLDER", PLACEHOLDER)


def broker_placeholder_files(provider, deadline):
    # Same bounded retry as broker_routing: the broker agents ConfigMap can lag
    # behind Pod start, so unauthorized/unreachable are retried; everything else
    # fails immediately.
    while True:
        result = subprocess.run(
            ["brokerctl", "placeholder-files", "--provider", provider],
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
            print(f"bootstrap: broker not ready for placeholder files {provider} ({error}); retrying", flush=True)
            time.sleep(2)
            continue
        if payload is None:
            raise SystemExit(f"bootstrap: placeholder-files failed for {provider}: {result.stderr.strip() or result.stdout.strip()}")
        raise SystemExit(f"bootstrap: placeholder-files denied for {provider}: {payload.get('message') or payload.get('error') or payload}")


def placeholder_file_target(home, rel):
    # Defense in depth: the broker already refuses absolute/traversal paths, but
    # the runtime re-validates before writing anywhere.
    if not isinstance(rel, str) or not rel or rel.startswith("/") or rel.startswith("\\"):
        raise SystemExit(f"bootstrap: placeholder file path {rel!r} must be a relative path")
    segments = rel.replace("\\", "/").split("/")
    if any(segment in ("", ".", "..") for segment in segments):
        raise SystemExit(f"bootstrap: placeholder file path {rel!r} must not contain traversal segments")
    return home.joinpath(*segments)


def write_placeholder_file(target, content, mode, home):
    target.parent.mkdir(parents=True, exist_ok=True)
    # Defense in depth: the relative path had no '..', but a symlinked parent
    # could still redirect the write outside HOME. Verify the resolved parent
    # stays under the resolved HOME before writing anything.
    resolved_home = Path(os.path.realpath(home))
    resolved_parent = Path(os.path.realpath(target.parent))
    if resolved_parent != resolved_home and resolved_home not in resolved_parent.parents:
        raise SystemExit(f"bootstrap: placeholder file target {target} resolves outside HOME")
    fd, temporary = tempfile.mkstemp(dir=str(target.parent), prefix=".nvt-placeholder-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
        os.chmod(temporary, mode)
        os.replace(temporary, str(target))
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def parse_file_mode(raw_mode, field):
    if raw_mode is None:
        raw_mode = "0600"
    if not isinstance(raw_mode, str) or len(raw_mode) != 4 or any(char not in "01234567" for char in raw_mode):
        raise SystemExit(f"{field} has an invalid mode {raw_mode!r}")
    return int(raw_mode, 8)


def preseed_file_target(home, path):
    if not isinstance(path, str) or not path:
        raise SystemExit(f"bootstrap: preseed file path {path!r} must be a non-empty string")
    expanded = expand_path(path)
    target = Path(expanded)
    if not target.is_absolute():
        target = home / expanded
    return target


def preseed_file_content(entry, index):
    has_content = "content" in entry
    has_json = "json" in entry
    if has_content == has_json:
        raise SystemExit(f"preseed.files[{index}] must set exactly one of content or json")
    if has_content:
        content = entry.get("content")
        if not isinstance(content, str):
            raise SystemExit(f"preseed.files[{index}].content must be a string")
        return content
    return json.dumps(entry.get("json"), indent=2, sort_keys=True) + "\n"


def apply_preseed_files(preseed):
    files = preseed.get("files") or []
    if not isinstance(files, list):
        raise SystemExit("preseed.files must be a list")
    home = Path.home()
    for index, entry in enumerate(files):
        if not isinstance(entry, dict):
            raise SystemExit(f"preseed.files[{index}] must be an object")
        target = preseed_file_target(home, entry.get("path"))
        content = preseed_file_content(entry, index)
        mode = parse_file_mode(entry.get("mode"), f"preseed.files[{index}]")
        overwrite = optional_bool(entry.get("overwrite"), f"preseed.files[{index}].overwrite", default=True)
        if target.exists() and not overwrite:
            print(f"bootstrap: preseed file {target} already exists", flush=True)
            continue
        write_placeholder_file(target, content, mode, home)
        print(f"bootstrap: wrote preseed file {target}", flush=True)


def apply_placeholder_files(egress):
    # Materialize provider-owned placeholder auth files (placeholders only; the
    # real secret stays broker-side). Runs regardless of egress mode. Never
    # reads a host auth file as the source of truth.
    if not isinstance(egress, dict):
        return
    grants = egress.get("grants") or []
    if not isinstance(grants, list):
        return
    deadline = None
    for index, grant in enumerate(grants):
        if not isinstance(grant, dict) or grant.get("materialization") != "placeholder-file":
            continue
        provider = grant.get("provider")
        if not isinstance(provider, str) or not provider:
            raise SystemExit(f"egress.grants[{index}].provider must be a non-empty string")
        if deadline is None:
            deadline = broker_wait_deadline()
        response = broker_placeholder_files(provider, deadline)
        files = response.get("files")
        if not isinstance(files, list) or not files:
            raise SystemExit(f"bootstrap: placeholder-files for {provider} returned no files")
        home = Path.home()
        for file_index, entry in enumerate(files):
            if not isinstance(entry, dict):
                raise SystemExit(f"bootstrap: placeholder-files[{file_index}] for {provider} must be an object")
            content = entry.get("content")
            if not isinstance(content, str):
                raise SystemExit(f"bootstrap: placeholder-files[{file_index}] for {provider} must include string content")
            mode = parse_file_mode(entry.get("mode"), f"bootstrap: placeholder-files[{file_index}] for {provider}")
            target = placeholder_file_target(home, entry.get("path"))
            write_placeholder_file(target, content, mode, home)


def apply_additional_paths(paths):
    for path in reversed(paths):
        prepend_path(expand_path(path))
    persist_env_var("PATH", os.environ["PATH"])


def install_packages(packages):
    if not packages:
        return
    # nvt-as-root is a no-op passthrough as root (unchanged) and uses the
    # agent's passwordless sudo in non-root mode, so apt works under both.
    run(["nvt-as-root", "apt-get", "update"])
    run(["nvt-as-root", "apt-get", "install", "-y", "--no-install-recommends", *packages])


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
    runtime, tools, code_server, egress, preseed = load_bootstrap_config(config_path)

    setup_tmux_config()
    apply_preseed_files(preseed)
    if mediated_mode(egress):
        apply_mediated_egress(egress)
    # Placeholder-file materialization is independent of egress mode: it writes
    # inert placeholder auth files whether or not mediated routing is applied.
    apply_placeholder_files(egress)
    command = optional_string(runtime.get("command"), "runtime.command")
    if command:
        # Kept for older helper scripts and diagnostics; start-agent-session uses
        # agent-command.json so runtime.args are passed without shell parsing.
        persist_env_var("AGENT_COMMAND", command)
        args = optional_string_list(runtime.get("args"), "runtime.args")
        persist_agent_command(command, args)
    setup_code_server(code_server)
    apply_additional_paths(as_string_list(tools.get("additional-paths"), "additional-paths"))
    install_packages(configured_packages(tools))
    install_mise(as_string_list(tools.get("mise"), "mise"))
    run_shell(as_string_list(tools.get("shell"), "shell"))


if __name__ == "__main__":
    main()
