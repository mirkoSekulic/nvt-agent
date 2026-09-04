#!/usr/bin/env python3
"""Actual pinned CLI, isolated account state and HTTP fixture; no live Azure calls.

Run with the optional Azure Python environment. The HTTP transport is replaced
only in this fixture, below the real CLI command/SDK serialization/auth layers.
"""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("adapter", ROOT / "runtime/plugins/azure-cli/adapter.py")
adapter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(adapter)
SUB = "11111111-1111-1111-1111-111111111111"
TENANT = "22222222-2222-2222-2222-222222222222"
WORKSPACE = "33333333-3333-3333-3333-333333333333"


class Compatibility(unittest.TestCase):
    def test_trusted_source_pins_public_cloud_and_uses_real_cli_token_path(self):
        import copy
        import requests
        from azure.cli.core import get_default_cli
        from azure.cli.core.cloud import AZURE_PUBLIC_CLOUD
        token_spec = importlib.util.spec_from_file_location("token_source", ROOT / "broker/providers/azure/token_source.py")
        token_source = importlib.util.module_from_spec(token_spec)
        token_spec.loader.exec_module(token_source)
        with tempfile.TemporaryDirectory(prefix="nvt-azure-source-") as tmp, patch.dict(os.environ, {"HOME": tmp, "AZURE_CONFIG_DIR": tmp}):
            adapter.configure({"tenant": TENANT, "subscriptions": [{"id": SUB}]}, Path(tmp))
            cli = get_default_cli()
            cli.cloud = copy.deepcopy(AZURE_PUBLIC_CLOUD)
            cli.cloud.endpoints.active_directory = "https://unapproved.invalid"
            with patch("azure.cli.core.get_default_cli", return_value=cli), patch.object(requests.Session, "send", side_effect=AssertionError("no network or real credentials in fixture")):
                for audience in ["https://management.azure.com/", "https://api.loganalytics.io"]:
                    result = token_source.acquire(TENANT, audience)
                    self.assertEqual(result["accessToken"], adapter.PLACEHOLDER)
                    self.assertEqual(result["tenant"], TENANT)
                    self.assertEqual(cli.cloud.endpoints.active_directory, AZURE_PUBLIC_CLOUD.endpoints.active_directory)
                with self.assertRaises(ValueError):
                    token_source.acquire(TENANT, "https://graph.microsoft.com")

    def test_actual_cli_arm_and_log_query_without_credentials(self):
        import requests
        from azure.cli.core import get_default_cli
        requests_seen = []

        def send(session, request, **kwargs):
            self.assertEqual(request.headers.get("Authorization"), "Bearer " + adapter.PLACEHOLDER, request.url)
            requests_seen.append((request.method, request.url, request.body))
            response = requests.Response()
            response.status_code = 200
            response.request = request
            response.headers["Content-Type"] = "application/json"
            if request.url.startswith("https://management.azure.com/subscriptions/" + SUB + "/resourcegroups?"):
                data = {"value": [{"id": "/subscriptions/" + SUB + "/resourceGroups/fixture",
                                    "name": "fixture", "location": "westeurope"}]}
            elif request.url == "https://api.loganalytics.io/v1/workspaces/" + WORKSPACE + "/query":
                self.assertEqual(request.method, "POST")
                self.assertEqual(json.loads(request.body)["query"], "print Result=42")
                data = {"tables": [{"name": "PrimaryResult", "columns": [{"name": "Result", "type": "long"}], "rows": [[42]]}]}
            else:
                self.fail("unexpected network request: " + request.method + " " + request.url)
            response._content = json.dumps(data).encode()
            response.raw = io.BytesIO(response._content)
            return response

        with tempfile.TemporaryDirectory(prefix="nvt-azure-cli-fixture-") as tmp:
            directory = Path(tmp)
            with patch.dict(os.environ, {"HOME": tmp, "AZURE_CONFIG_DIR": tmp}, clear=False):
                adapter.configure({"tenant": TENANT, "subscriptions": [{"id": SUB}]}, directory)
                with patch.object(requests.Session, "send", send):
                    for args, expected in [
                        (["group", "list"], "fixture"),
                        (["monitor", "log-analytics", "query", "-w", WORKSPACE, "--analytics-query", "print Result=42"], "42"),
                        (["account", "get-access-token"], adapter.PLACEHOLDER),
                    ]:
                        output = io.StringIO()
                        with contextlib.redirect_stdout(output):
                            cli = get_default_cli()
                            cli.out_file = output
                            status = cli.invoke(args)
                        self.assertEqual(status, 0, output.getvalue())
                        self.assertIn(expected, output.getvalue())
            self.assertEqual(len(requests_seen), 2)
            self.assertFalse(list(directory.rglob("*token_cache*")))
            self.assertFalse(list(directory.rglob("*service_principal*")))
            self.assertFalse(list(directory.rglob("commands/*.log")))
        for method, url, _ in requests_seen:
            print("CLI fixture:", method, url)

    def test_initial_command_matrix_request_serialization(self):
        import requests
        from azure.cli.core import get_default_cli
        provider_spec = importlib.util.spec_from_file_location("provider_tests", ROOT / "broker/providers/azure/provider_test.py")
        fixture = importlib.util.module_from_spec(provider_spec)
        provider_spec.loader.exec_module(fixture)
        provider = fixture.p.AzureProvider(fixture.configuration(), fixture.FakeSource())
        grant = {"materialization": "header-inject", "resources": [fixture.ARM_SCOPE, fixture.QUERY_SCOPE], "authorization": fixture.observe([fixture.ARM_SCOPE, fixture.QUERY_SCOPE])}
        seen = []
        failures = []

        def send(session, request, **kwargs):
            from urllib.parse import urlsplit
            parsed = urlsplit(request.url)
            path = parsed.path + ("?" + parsed.query if parsed.query else "")
            decision = provider.injection_authorization({"host": parsed.hostname, "method": request.method, "path": path, "grant": grant})
            seen.append((request.method, path))
            if not decision["allowed"]:
                failures.append((request.method, path))
            self.assertEqual(request.headers.get("Authorization"), "Bearer " + adapter.PLACEHOLDER)
            response = requests.Response()
            response.request = request
            response.status_code = 200
            response.headers["Content-Type"] = "application/json"
            data = {"value": [], "name": "fixture", "id": fixture.VM, "location": "westeurope", "properties": {"provisioningState": "Succeeded"}}
            response._content = json.dumps(data).encode()
            response.raw = io.BytesIO(response._content)
            return response

        commands = [
            ["account", "list"], ["account", "show"], ["account", "set", "-s", SUB],
            ["group", "show", "-n", "fixture"],
            ["resource", "list", "--resource-type", "Microsoft.Compute/virtualMachines"],
            ["resource", "show", "--ids", fixture.VM, "--api-version", "2025-04-01"],
            ["vm", "list"], ["vm", "show", "-g", "fixture", "-n", "vm"],
            ["vm", "get-instance-view", "-g", "fixture", "-n", "vm"],
            ["network", "vnet", "list"], ["network", "vnet", "show", "-g", "fixture", "-n", "net"],
            ["network", "nic", "list"], ["network", "nic", "show", "-g", "fixture", "-n", "nic"],
            ["network", "nsg", "list"], ["network", "nsg", "show", "-g", "fixture", "-n", "nsg"],
            ["network", "public-ip", "list"], ["network", "public-ip", "show", "-g", "fixture", "-n", "public-ip"],
            ["aks", "list"], ["aks", "show", "-g", "fixture", "-n", "aks"],
            ["storage", "account", "list"], ["storage", "account", "show", "-g", "fixture", "-n", "storage"],
            ["deployment", "group", "list", "-g", "fixture"], ["deployment", "group", "show", "-g", "fixture", "-n", "deploy"],
            ["monitor", "metrics", "list", "--resource", fixture.VM, "--metric", "Percentage CPU"],
            ["monitor", "activity-log", "list", "--start-time", "2026-09-01T00:00:00Z", "--end-time", "2026-09-01T01:00:00Z"],
        ]
        with tempfile.TemporaryDirectory(prefix="nvt-azure-matrix-") as tmp:
            with patch.dict(os.environ, {"HOME": tmp, "AZURE_CONFIG_DIR": tmp}, clear=False):
                adapter.configure({"tenant": TENANT, "subscriptions": [{"id": SUB}]}, Path(tmp))
                with patch.object(requests.Session, "send", send):
                    for args in commands:
                        with self.subTest(command=" ".join(args)):
                            cli = get_default_cli()
                            output = io.StringIO()
                            cli.out_file = output
                            self.assertEqual(cli.invoke(args), 0)
        for method, path in seen:
            print("CLI matrix:", method, path)
        self.assertEqual(failures, [])


if __name__ == "__main__":
    unittest.main()
