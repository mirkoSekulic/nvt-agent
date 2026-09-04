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
capability = params.get("capability")
if capability not in {"azure-one", "azure-two"}:
    print(json.dumps({"ok": False, "error": "capability-not-granted"}))
    sys.exit(0)
params["grant"] = {"materialization": "header-inject", "resources": [fixture.ARM_SCOPE, fixture.QUERY_SCOPE],
                   "authorization": fixture.observe([fixture.ARM_SCOPE, fixture.QUERY_SCOPE])}
provider = fixture.p.AzureProvider(fixture.configuration(), fixture.FakeSource())
if provider.injection_authorization(params)["allowed"]:
    print(json.dumps({"ok": True, "headers": {"authorization": "Bearer fixture-trusted-" + capability},
                      "strip_request_headers": ["authorization", "x-ms-authorization-auxiliary"]}))
else:
    print(json.dumps({"ok": False, "error": "operation-not-allowed"}))
