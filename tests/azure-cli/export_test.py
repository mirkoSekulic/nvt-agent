"""Always-on startup/export/launcher contract tests; no Azure installation needed."""
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest

FIXTURE = Path(__file__).with_name("export_fixture.py")


class ExportTests(unittest.TestCase):
    def test_builtin_export_launcher_arguments_context_and_exit_status(self):
        with tempfile.TemporaryDirectory(prefix="nvt-azure-export ") as tmp:
            home = Path(tmp)
            config = home / "public-config.json"
            config.write_text(json.dumps({"providers": {"azure-one": {"tenant": "fixture"}}}))
            # Stand in for the optional pinned Python executable, not the
            # production launcher/exporter. Capture exact argv and launch context.
            probe = home / "python-probe"
            probe.write_text("#!/bin/sh\nexec " + shlex.quote(sys.executable) + " -c " + shlex.quote(
                "import json,os,sys; print(json.dumps({'argv':sys.argv[1:],"
                "'provider':os.environ['NVT_PLUGIN_EGRESS_PROVIDER'],"
                "'proxy':os.environ['HTTPS_PROXY'], 'plugin':os.environ['NVT_PLUGIN_NAME'],"
                "'config':os.environ['NVT_PLUGIN_CONFIG']})); sys.exit(7)") + ' "$@"\n')
            probe.chmod(0o755)
            env = {"HOME": tmp, "PATH": os.pathsep.join([str(home / ".local/bin"), str(home / "fixture-bin")]),
                   "NVT_STATE_DIR": str(home / ".nvt-agent"), "NVT_WORKSPACE": tmp,
                   "NVT_EGRESS_MODE": "mediated", "NVT_PLUGIN_CONFIG": str(config),
                   "NVT_PLUGIN_EGRESS_PROVIDER": "azure-one",
                   "NVT_EGRESS_FORWARD_PROXY_URL_AZURE_ONE": "http://azure-one:x@127.0.0.1:12345"}
            for _ in range(2):  # A restart recreates the managed wrapper cleanly.
                exported = subprocess.run([sys.executable, str(FIXTURE), str(probe)], env=env,
                                          capture_output=True, text=True)
                self.assertEqual(exported.returncode, 0, exported.stderr)
                self.assertIn("exported 1 tool(s)", exported.stdout)
                wrapper = home / ".local/bin/az"
                self.assertTrue(os.access(wrapper, os.X_OK))
                args = ["monitor", "log-analytics", "query", "--analytics-query", "print Value='a b'", ""]
                result = subprocess.run([str(wrapper), *args], env=env, capture_output=True, text=True)
                self.assertEqual(result.returncode, 7, result.stderr)
                context = json.loads(result.stdout)
                self.assertEqual(context["argv"], [str(home / "installed-plugins/azure-cli/adapter.py"), *args])
                self.assertEqual(context["plugin"], "azure-cli")
                self.assertEqual(context["provider"], "azure-one")
                self.assertEqual(context["proxy"], env["NVT_EGRESS_FORWARD_PROXY_URL_AZURE_ONE"])
                self.assertEqual(context["config"], str(home / ".nvt-agent/plugins/azure-cli/config.yaml"))

            # Model an unrelated Azure CLI preinstalled on the CI runner.
            # Its directory is intentionally absent from the controlled PATH.
            runner_bin = home / "runner-bin"
            runner_bin.mkdir()
            runner_az = runner_bin / "az"
            runner_az.write_text("#!/bin/sh\nexit 99\n")
            runner_az.chmod(0o755)
            polluted = {**env, "PATH": env["PATH"] + os.pathsep + str(runner_bin)}
            rejected = subprocess.run([sys.executable, str(FIXTURE), str(probe)], env=polluted,
                                      capture_output=True, text=True)
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("would shadow existing command: " + str(runner_az), rejected.stderr)
            isolated = subprocess.run([sys.executable, str(FIXTURE), str(probe)], env=env,
                                      capture_output=True, text=True)
            self.assertEqual(isolated.returncode, 0, isolated.stderr)
            self.assertTrue(runner_az.is_file())  # Never remove/alter runner tools.


if __name__ == "__main__":
    unittest.main()
