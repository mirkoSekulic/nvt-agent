"""Install a relocated Azure plugin and run the production startup exporter.

Only image installation/interpreter paths are relocated into an isolated HOME.
Manifest validation, generated wrappers and plugin-egress-exec are unchanged.
"""
import importlib.util
import json
import os
from pathlib import Path
import shlex
import shutil
import sys

import yaml

ROOT = Path(__file__).resolve().parents[2]


def prepare(home, python):
    source = ROOT / "runtime/plugins/azure-cli"
    plugins = home / "installed-plugins"
    installed = plugins / "azure-cli"
    installed.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source / "adapter.py", installed / "adapter.py")
    launcher = installed / "az"
    launcher.write_text((source / "az").read_text().replace(
        "/opt/nvt-azure/bin/python", shlex.quote(str(python))).replace(
        "/usr/local/lib/nvt-agent/plugins/azure-cli/adapter.py",
        shlex.quote(str(installed / "adapter.py"))))
    # Preserve the source executable bit so a missing packaging permission is
    # caught rather than silently repaired by this fixture.
    shutil.copymode(source / "az", launcher)
    (installed / "plugin.yaml").write_text((source / "plugin.yaml").read_text().replace(
        "/usr/local/lib/nvt-agent/plugins/", str(plugins) + "/"))

    config = yaml.safe_load(Path(os.environ["NVT_PLUGIN_CONFIG"]).read_text())
    selected = os.environ["NVT_PLUGIN_EGRESS_PROVIDER"]
    agent = home / "agent.yaml"
    agent.write_text(yaml.safe_dump({"plugins": [{"name": "azure-cli", "source": "builtin",
        "egress": {"provider": selected}, "config": config}]}))
    state = home / ".nvt-agent"
    state.mkdir(exist_ok=True)
    (state / "egress.json").write_text(json.dumps({"mode": "mediated", "transport": "forward-proxy",
        "grants": [{"provider": name, "materialization": "header-inject"} for name in config["providers"]]}))
    binary = home / ".local/bin"
    binary.mkdir(parents=True, exist_ok=True)
    # Callers expose only fixture directories on PATH. The launchers need
    # bash, but the runner's unrelated tools (notably /usr/bin/az) must stay out.
    helpers = home / "fixture-bin"
    helpers.mkdir(exist_ok=True)
    bash = shutil.which("bash", path=os.defpath)
    if bash is None:
        raise RuntimeError("fixture requires bash")
    if not (helpers / "bash").exists():
        (helpers / "bash").symlink_to(bash)
    egress = binary / "plugin-egress-exec"
    egress.write_text("#!/usr/bin/env bash\nexec " + shlex.quote(sys.executable) + " " +
                      shlex.quote(str(ROOT / "runtime/core/plugin-egress-exec.py")) + ' "$@"\n')
    egress.chmod(0o755)

    spec = importlib.util.spec_from_file_location("exporter", ROOT / "runtime/core/export-plugin-tools.py")
    exporter = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(exporter)
    exporter.BUILTIN_PLUGIN_DIR = plugins
    exporter.export_tools(agent)


if __name__ == "__main__":
    prepare(Path(os.environ["HOME"]), Path(sys.argv[1]))
