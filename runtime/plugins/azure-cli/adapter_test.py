import importlib.util
import io
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
        one, two = "11111111-1111-1111-1111-111111111111", "33333333-3333-3333-3333-333333333333"
        metadata = {"tenant": "22222222-2222-2222-2222-222222222222", "subscriptions": [{"id": one}, {"id": two}]}
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {}, clear=False), patch.dict("sys.modules", {"azure.cli.core._profile": fake_profile}), patch.object(adapter.importlib.metadata, "version", return_value=adapter.CLI_VERSION):
            directory = Path(tmp)
            adapter.configure(metadata, directory)
            profile = directory / "azureProfile.json"
            prior = json.loads(profile.read_text())
            for sub in prior["subscriptions"]:
                sub["isDefault"] = sub["id"] == two
            profile.write_text(json.dumps(prior))
            adapter.configure(metadata, directory)
            self.assertTrue(json.loads(profile.read_text())["subscriptions"][1]["isDefault"])
            adapter.configure({**metadata, "subscriptions": [{"id": one}]}, directory)
            self.assertNotIn(two, profile.read_text())
            self.assertEqual(sorted(p.name for p in directory.iterdir()), ["azureProfile.json", "versionCheck.json"])

    def test_unknown_cli_version_fails(self):
        with patch.object(adapter.importlib.metadata, "version", return_value="unsupported"):
            with self.assertRaises(ValueError):
                adapter.configure({}, Path("unused"))

    def test_catalog_is_bounded_tenant_checked_and_never_uses_stale_metadata(self):
        tenant = "22222222-2222-2222-2222-222222222222"
        metadata = {"tenant": tenant, "subscriptions": [{"id": "11111111-1111-1111-1111-111111111111", "name": "Public"}]}
        catalog = {"ok": True, "routes": [], "files": [{"path": "azure-account-metadata.json", "content": json.dumps(metadata)}]}
        class Opener:
            def open(inner, request, timeout):
                self.assertEqual(request.full_url, "http://broker.test/v1/catalog")
                self.assertEqual(json.loads(request.data), {"provider": "azure-one"})
                return io.BytesIO(json.dumps(catalog).encode())
        with patch.dict(os.environ, {"NVT_BROKER_URL": "http://broker.test", "NVT_BROKER_TOKEN": "fixture-agent-role", "NVT_BROKER_CA_FILE": ""}), patch.object(adapter, "build_opener", return_value=Opener()):
            self.assertEqual(adapter.account_metadata("azure-one", {"tenant": tenant, "catalog": True}), metadata)
            with self.assertRaises(ValueError):
                adapter.account_metadata("azure-one", {"tenant": metadata["subscriptions"][0]["id"], "catalog": True})
            catalog["files"][0]["content"] = json.dumps({**metadata, "token": "must-not-be-metadata"})
            with self.assertRaises(ValueError):
                adapter.account_metadata("azure-one", {"tenant": tenant, "catalog": True})
            catalog["files"][0]["content"] = "x" * (adapter.METADATA_LIMIT+1)
            with self.assertRaises(ValueError):
                adapter.account_metadata("azure-one", {"tenant": tenant, "catalog": True})
        with patch.object(adapter, "build_opener", side_effect=OSError("fixture failure")), patch.dict(os.environ, {"NVT_BROKER_URL": "http://broker.test", "NVT_BROKER_TOKEN": "fixture", "NVT_BROKER_CA_FILE": ""}), self.assertRaises(OSError):
            adapter.account_metadata("azure-one", {"tenant": tenant, "catalog": True})
        with self.assertRaises(ValueError):
            adapter.NoRedirect().redirect_request(None)


if __name__ == "__main__":
    unittest.main()
