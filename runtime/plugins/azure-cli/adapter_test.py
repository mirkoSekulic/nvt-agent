import importlib.util
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("azure_adapter", Path(__file__).with_name("adapter.py"))
adapter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(adapter)


class AdapterTests(unittest.TestCase):
    def test_inert_tokens_and_fixed_audiences(self):
        for scope in adapter.SCOPES:
            self.assertEqual(adapter.InertCredential().acquire_token([scope])["access_token"], adapter.PLACEHOLDER)
        for scopes in [[], ["https://graph.microsoft.com/.default"], list(adapter.SCOPES)]:
            with self.assertRaises(ValueError):
                adapter.InertCredential().acquire_token(scopes)
        with self.assertRaises(ValueError):
            adapter.InertCredential().acquire_token([next(iter(adapter.SCOPES))], data={"ssh": True})

    def test_account_selection_survives_restart_but_revoked_selection_does_not(self):
        fake_profile = types.ModuleType("azure.cli.core._profile")
        fake_profile.ManagedIdentityAuth = type("ManagedIdentityAuth", (), {})
        metadata = {"tenant": "fixture-tenant", "subscriptions": [{"id": "one"}, {"id": "two"}]}
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {}, clear=False), patch.dict("sys.modules", {"azure.cli.core._profile": fake_profile}), patch.object(adapter.importlib.metadata, "version", return_value=adapter.CLI_VERSION):
            directory = Path(tmp)
            adapter.configure(metadata, directory)
            profile = directory / "azureProfile.json"
            prior = json.loads(profile.read_text())
            for sub in prior["subscriptions"]:
                sub["isDefault"] = sub["id"] == "two"
            profile.write_text(json.dumps(prior))
            adapter.configure(metadata, directory)
            self.assertTrue(json.loads(profile.read_text())["subscriptions"][1]["isDefault"])
            adapter.configure({**metadata, "subscriptions": [{"id": "one"}]}, directory)
            self.assertNotIn('"two"', profile.read_text())
            self.assertEqual(sorted(p.name for p in directory.iterdir()), ["azureProfile.json", "versionCheck.json"])

    def test_unknown_cli_version_fails(self):
        with patch.object(adapter.importlib.metadata, "version", return_value="unsupported"):
            with self.assertRaises(ValueError):
                adapter.configure({}, Path("unused"))


if __name__ == "__main__":
    unittest.main()
