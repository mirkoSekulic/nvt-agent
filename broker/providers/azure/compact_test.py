"""Compact scope/discovery contract: no Azure state or live requests."""
import copy
import importlib.util
import io
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from broker.providers.azure.provider_test import p, SUB, TENANT, WORKSPACE, ARM_SCOPE, QUERY_SCOPE, VM, FakeSource, observe, configuration

spec = importlib.util.spec_from_file_location("azure_discovery", Path(__file__).with_name("token_source.py"))
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)
MARKER = "provider-scope/" + TENANT


def compact(query=False):
    return {"config": {"tenant": TENANT, "allSubscriptions": True, "state-dir": "/fixture/one"},
            "allow": {"authorization": {"preset": "observe"}, **({"queryIdentity": True} if query else {})}}


class DiscoverySource(FakeSource):
    def __init__(self):
        super().__init__()
        self.discovery_calls = 0
        self.accounts = {"tenant": TENANT, "subscriptions": [{"id": SUB, "name": "One"}]}

    def discover(self):
        self.discovery_calls += 1
        if self.fail:
            raise RuntimeError("private-failure-canary")
        return copy.deepcopy(self.accounts)


class CompactTests(unittest.TestCase):
    def setUp(self):
        self.clock = patch.object(p.time, "monotonic", return_value=10)
        self.now = self.clock.start()
        self.addCleanup(self.clock.stop)
        self.source = DiscoverySource()
        self.provider = p.AzureProvider(compact(), self.source)
        self.grant = {"materialization": "header-inject", "resources": [MARKER], "authorization": observe([MARKER])}

    def decision(self, path=VM+"?api-version=2025-04-01", method="GET", host=p.ARM, grant=None):
        return self.provider.injection_authorization({"host": host, "method": method, "path": path, "grant": self.grant if grant is None else grant})["allowed"]

    def test_refresh_add_remove_failure_and_recovery(self):
        self.assertTrue(self.decision())
        self.source.accounts["subscriptions"] = [{"id": WORKSPACE, "name": "New"}]
        self.assertTrue(self.decision())
        self.assertEqual(self.source.discovery_calls, 1)
        self.now.return_value = 71
        self.assertFalse(self.decision())
        self.assertTrue(self.decision(VM.replace(SUB, WORKSPACE)+"?api-version=2025-04-01"))
        self.source.fail = True
        self.now.return_value = 132
        self.assertFalse(self.decision(VM.replace(SUB, WORKSPACE)+"?api-version=2025-04-01"))
        with self.assertRaises(p.Failure) as failure:
            self.provider.catalog({"grant": self.grant})
        self.assertEqual(failure.exception.reason, "azure-discovery-unavailable")
        self.assertEqual(self.provider.subscriptions, [])
        self.source.fail = False
        self.assertTrue(self.decision(VM.replace(SUB, WORKSPACE)+"?api-version=2025-04-01"))

    def test_independent_policy_scope_and_query_opt_in(self):
        self.assertTrue(self.decision())
        self.assertFalse(self.decision(method="DELETE"))
        self.assertFalse(self.decision(VM+"/runCommand?api-version=2025-04-01", "POST"))
        unrestricted = {"materialization": "header-inject", "resources": [MARKER]}
        self.assertFalse(self.decision(method="DELETE", grant=unrestricted))
        query_grant = {**unrestricted, "resources": [MARKER, QUERY_SCOPE]}
        query = "/v1/workspaces/"+WORKSPACE+"/query"
        self.assertFalse(self.decision(query, "POST", p.LOGS, query_grant))
        self.provider = p.AzureProvider(compact(query=True), self.source)
        self.assertFalse(self.decision(query, "POST", p.LOGS))
        self.assertTrue(self.decision(query, "POST", p.LOGS, query_grant))
        self.assertFalse(self.decision(grant={"materialization": "header-inject"}))
        narrow = {"materialization": "header-inject", "resources": ["arm:"+VM]}
        self.assertTrue(self.decision(grant=narrow))
        self.assertFalse(self.decision(VM+"-other?api-version=2025-04-01", grant=narrow))
        no_ceiling_policy = compact()
        no_ceiling_policy["allow"] = {}
        self.provider = p.AzureProvider(no_ceiling_policy, self.source)
        self.assertFalse(self.decision(method="DELETE"))  # agent observe still wins
        self.assertTrue(self.decision(method="DELETE", grant=unrestricted))
        explicit = configuration()
        explicit["allow"] = {"resources": ["arm:"+VM], "authorization": {"preset": "observe"}}
        self.provider = p.AzureProvider(explicit, self.source)
        self.assertTrue(self.decision())
        self.assertFalse(self.decision(VM+"-other?api-version=2025-04-01"))

    def test_catalog_is_public_filtered_bounded_and_identity_specific(self):
        self.source.accounts["subscriptions"].append({"id": WORKSPACE, "name": "Two"})
        grant = {"materialization": "header-inject", "resources": [ARM_SCOPE]}
        result = self.provider.catalog({"grant": grant})
        self.assertEqual(result["routes"], [])
        metadata = json.loads(result["files"][0]["content"])
        self.assertEqual(metadata, {"tenant": TENANT, "subscriptions": [{"id": SUB, "name": "One"}]})
        self.assertEqual(self.source.calls, [])  # no token result in catalog
        second = DiscoverySource()
        second.accounts["subscriptions"] = [{"id": WORKSPACE, "name": "Other identity"}]
        provider_two = p.AzureProvider(compact(), second)
        public = provider_two.catalog({"grant": self.grant})
        self.assertNotIn(SUB, json.dumps(public))
        for accounts in [{"tenant": SUB, "subscriptions": []}, {"tenant": TENANT, "subscriptions": [{"id": SUB, "name": "unsafe\nname"}]},
                         {"tenant": TENANT, "subscriptions": [{"id": SUB, "name": "One", "token": "canary"}]},
                         {"tenant": TENANT, "subscriptions": [{"id": SUB, "name": "One"}]*257}]:
            self.source.accounts = accounts
            self.now.return_value += 61
            with self.assertRaises(p.Failure):
                self.provider.catalog({"grant": self.grant})
        self.source.accounts = {"tenant": TENANT, "subscriptions": []}
        self.assertEqual(json.loads(self.provider.catalog({"grant": self.grant})["files"][0]["content"])["subscriptions"], [])

    def test_invalid_compact_and_conflicting_options(self):
        for field, key, value in [("config", "allSubscriptions", False), ("config", "allSubscriptions", 1),
                                  ("config", "subscriptions", [SUB]), ("allow", "resources", []),
                                  ("allow", "queryIdentity", False), ("allow", "queryIdentity", "true"),
                                  ("allow", "authorization", {"preset": "observe", "defaultAction": "allow"})]:
            config = compact()
            config[field][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(p.Failure):
                p.AzureProvider(config, self.source)
        for resources in [[MARKER, ARM_SCOPE], ["provider-scope/"+SUB], ["provider-scope/*"], []]:
            self.assertFalse(self.decision(grant={"materialization": "header-inject", "resources": resources}))


class DiscoveryHelperTests(unittest.TestCase):
    def test_fixed_tenant_bounded_pages_and_public_projection(self):
        pages = [{"value": [self.item(SUB), self.item(WORKSPACE, tenant=SUB)], "nextLink": "https://management.azure.com/subscriptions?api-version=2022-12-01&$skiptoken=page2"},
                 {"value": [self.item(TENANT, state="Disabled")]}]
        requests = []
        class Opener:
            def open(inner, request, timeout):
                requests.append(request)
                return io.BytesIO(json.dumps(pages.pop(0)).encode())
        token = {"tenant": TENANT, "tokenType": "Bearer", "accessToken": "fixture-only"}
        with patch.object(helper, "acquire", return_value=token) as acquire, patch.object(helper, "build_opener", return_value=Opener()):
            result = helper.discover(TENANT)
        acquire.assert_called_once_with(TENANT, p.AUDIENCES[p.ARM])
        self.assertEqual(result, {"tenant": TENANT, "subscriptions": [{"id": SUB, "name": "Public name"}]})
        self.assertEqual(len(requests), 2)
        self.assertNotIn("fixture-only", json.dumps(result))
        for url in ["https://evil.test/subscriptions?api-version=2022-12-01", "https://management.azure.com/tenants?api-version=2022-12-01",
                    "http://management.azure.com/subscriptions?api-version=2022-12-01", "https://management.azure.com/subscriptions?api-version=2022-12-01&extra=x"]:
            with self.assertRaises(ValueError):
                helper.discovery_url(url)
        with self.assertRaises(ValueError):
            helper.NoRedirect().redirect_request(None)

    @staticmethod
    def item(identifier, tenant=TENANT, state="Enabled"):
        return {"subscriptionId": identifier, "tenantId": tenant, "displayName": "Public name", "state": state, "untrustedExtra": "never forwarded"}

    def test_invalid_oversized_and_incomplete_inventory_fails_closed(self):
        for page in [{"value": [self.item(SUB)]*257}, {"value": [self.item(SUB)]*2},
                     {"value": [{**self.item(SUB), "state": "unknown"}]},
                     {"value": [], "padding": "x"*helper.LIMIT},
                     {"value": [{**self.item(SUB), "tenantId": "*"}]}, {"value": [self.item(SUB)], "nextLink": "https://evil.test/"},
                     {"value": [], "nextLink": "https://management.azure.com/subscriptions?api-version=2022-12-01&$skiptoken=again"}]:
            class Opener:
                def open(inner, request, timeout):
                    return io.BytesIO(json.dumps(page).encode())
            with patch.object(helper, "acquire", return_value={"tenant": TENANT, "tokenType": "Bearer", "accessToken": "fixture"}), patch.object(helper, "build_opener", return_value=Opener()), self.assertRaises(ValueError):
                helper.discover(TENANT)

    def test_exact_subscription_bound_and_restart_discovery(self):
        source = DiscoverySource()
        source.accounts["subscriptions"] = [{"id": f"{i:08x}-1111-1111-1111-111111111111", "name": "Public"} for i in range(256)]
        grant = {"materialization": "header-inject", "resources": [MARKER]}
        provider = p.AzureProvider(compact(), source)
        self.assertEqual(len(json.loads(provider.catalog({"grant": grant})["files"][0]["content"])["subscriptions"]), 256)
        self.assertEqual(source.discovery_calls, 1)
        restarted = p.AzureProvider(compact(), source)
        restarted.catalog({"grant": grant})
        self.assertEqual(source.discovery_calls, 2)
        source.accounts["subscriptions"].append({"id": WORKSPACE, "name": "Overflow"})
        with self.assertRaises(p.Failure):
            p.AzureProvider(compact(), source).catalog({"grant": grant})


if __name__ == "__main__":
    unittest.main()
