#!/usr/bin/env python3
import os
import subprocess
import sys
import tempfile
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


def load_tools(path):
    if not path.is_file():
        print(f"nvt-install-tools: no tools config at {path}", flush=True)
        return {}

    with path.open("r", encoding="utf-8") as file:
        data = yaml.safe_load(file) or {}

    if not isinstance(data, dict):
        raise SystemExit("tools config must be a YAML object")

    tools = data.get("tools", data)
    if not isinstance(tools, dict):
        raise SystemExit("tools must be a YAML object")

    return tools


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


def apply_additional_paths(paths):
    for path in reversed(paths):
        prepend_path(expand_path(path))
    persist_env_var("PATH", os.environ["PATH"])


def install_apt(packages):
    if not packages:
        return
    run(["apt-get", "update"])
    run(["apt-get", "install", "-y", "--no-install-recommends", *packages])


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
            prefix=f"nvt-tools-{index}-",
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


def main():
    config_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("/workspace/.nvt-agent/tools.yaml")
    tools = load_tools(config_path)

    apply_additional_paths(as_string_list(tools.get("additional_paths"), "additional_paths"))
    install_apt(as_string_list(tools.get("apt"), "apt"))
    install_mise(as_string_list(tools.get("mise"), "mise"))
    run_shell(as_string_list(tools.get("shell"), "shell"))


if __name__ == "__main__":
    main()
