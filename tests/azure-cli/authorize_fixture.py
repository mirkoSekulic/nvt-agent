#!/usr/bin/env python3
"""Test bridge between real egress HTTP and the production Azure classifier."""
import importlib.util
import json
from pathlib import Path
import sys
import time

root = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("azure_tests", root / "broker/providers/azure/provider_test.py")
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
params = json.load(sys.stdin)
capability = params.get("provider") if params.get("catalog") else params.get("capability")
if capability not in {"azure-one", "azure-two"}:
    print(json.dumps({"ok": False, "error": "capability-not-granted"}))
    sys.exit(0)
params["grant"] = {"materialization": "header-inject", "resources": [fixture.ARM_SCOPE, fixture.QUERY_SCOPE],
                   "authorization": fixture.observe([fixture.ARM_SCOPE, fixture.QUERY_SCOPE])}
provider = fixture.p.AzureProvider(fixture.configuration(), fixture.FakeSource())
if params.get("compact"):
    class DiscoverySource(fixture.FakeSource):
        def discover(self):
            return {"tenant": fixture.TENANT, "subscriptions": [{"id": fixture.SUB, "name": capability}]}
    config = fixture.configuration()
    config["config"].pop("subscriptions")
    config["config"]["allSubscriptions"] = True
    config["allow"] = {"queryIdentity": True, "authorization": {"preset": "observe"}}
    resources = ["provider-scope/"+fixture.TENANT, fixture.QUERY_SCOPE]
    params["grant"] = {"materialization": "header-inject", "resources": resources, "authorization": fixture.observe(resources)}
    provider = fixture.p.AzureProvider(config, DiscoverySource())
if params.get("catalog"):
    result = provider.catalog(params)
    print(json.dumps({"ok": True, "files": result["files"], "expires_at": result["expires_at"]}))
    sys.exit(0)
if provider.injection_authorization(params)["allowed"]:
    print(json.dumps({"ok": True, "headers": {"authorization": "Bearer fixture-trusted-" + capability},
                      "strip_request_headers": ["authorization", "x-ms-authorization-auxiliary"]}))
else:
    print(json.dumps({"ok": False, "error": "operation-not-allowed"}))
