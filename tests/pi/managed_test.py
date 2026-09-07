import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "pi_runtime", ROOT / "runtime/core/pi_runtime.py"
)
pi_runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pi_runtime)


class ManagedPiTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.state = Path(self.tmp.name)
        self.config = {
            "command": "pi",
            "args": ["--model", "custom/example-model", "--thinking", "off"],
            "resume": {
                "command": "pi",
                "args": ["--model", "custom/example-model", "--thinking", "off"],
            },
            "proxy": {"provider": "model-api"},
            "pi": {
                "provider": "custom",
                "baseUrl": "https://models.example.test/v1",
                "api": "openai-completions",
                "models": [{"id": "example-model"}],
            },
        }
        self.egress = {
            "mode": "mediated",
            "transport": "forward-proxy",
            "grants": [{"provider": "model-api", "materialization": "header-inject"}],
        }

    def prepare(self, state=None):
        return pi_runtime.prepare(
            copy.deepcopy(self.config),
            self.egress,
            state or self.state,
            "/workspace",
            "http://model-api@127.0.0.1:8443",
        )

    def test_managed_update_and_isolated_sessions(self):
        self.config["pi"]["extensions"] = [
            {"name": "compat.ts", "content": "export default function() {}"}
        ]
        first = self.prepare()
        path = self.state / "pi/agent"
        self.assertEqual(
            json.loads((path / "models.json").read_text())["providers"]["custom"][
                "apiKey"
            ],
            pi_runtime.PLACEHOLDER,
        )
        (path / "auth.json").write_text('{"stale":"fake-old-key"}')
        (self.state / "pi/session.jsonl").write_text("conversation")
        self.config["pi"]["extensions"] = []
        self.config["pi"]["settings"] = {"hideThinkingBlock": True}
        updated = self.prepare()
        self.assertEqual((self.state / "pi/session.jsonl").read_text(), "conversation")
        self.assertEqual(json.loads((path / "auth.json").read_text()), {})
        self.assertFalse((path / "managed-extensions/compat.ts").exists())
        self.assertTrue(
            json.loads((path / "settings.json").read_text())["hideThinkingBlock"]
        )
        self.assertEqual(updated["args"], updated["resume"]["args"])
        other = self.prepare(self.state / "other-workstation")
        self.assertNotEqual(updated["args"], other["args"])
        self.assertEqual(first["env"]["NO_PROXY"], "")
        self.assertIn("model-api@", first["env"]["HTTPS_PROXY"])
        self.assertIn("--no-approve", updated["args"])
        self.assertIn("/workspace/AGENTS.md", updated["args"])

    def test_rejects_credentials_and_resolvers_before_writes(self):
        for field, value in {
            "apiKey": "fake-secret",
            "headers": {"Authorization": "!touch /tmp/must-not-execute"},
            "oauth": {"type": "custom"},
        }.items():
            with self.subTest(field=field):
                self.config["pi"][field] = value
                with self.assertRaises(SystemExit) as error:
                    self.prepare()
                self.assertNotIn("fake-secret", str(error.exception))
                del self.config["pi"][field]
                self.assertFalse((self.state / "pi").exists())
        self.config["pi"]["models"][0]["apiKey"] = "$TOKEN"
        with self.assertRaises(SystemExit):
            self.prepare()
        self.assertFalse((self.state / "pi").exists())

    def test_missing_and_wrong_bindings(self):
        for egress in [
            {"mode": "direct"},
            {**self.egress, "transport": "redirect"},
            {**self.egress, "grants": []},
            {
                **self.egress,
                "grants": [{"provider": "model-api", "materialization": "file-bundle"}],
            },
        ]:
            self.egress = egress
            with self.assertRaises(SystemExit):
                self.prepare()
            self.assertFalse((self.state / "pi").exists())


if __name__ == "__main__":
    unittest.main()
