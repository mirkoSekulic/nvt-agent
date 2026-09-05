import copy
import importlib.util
from pathlib import Path
import time
import tempfile
import json
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("azure_provider", Path(__file__).with_name("provider.py"))
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)
SUB = "11111111-1111-1111-1111-111111111111"
TENANT = "22222222-2222-2222-2222-222222222222"
WORKSPACE = "33333333-3333-3333-3333-333333333333"
ARM_SCOPE = "arm:/subscriptions/" + SUB
QUERY_SCOPE = "query-identity/" + TENANT
VM = "/subscriptions/" + SUB + "/resourcegroups/fixture/providers/microsoft.compute/virtualmachines/vm"


def observe(resources):
    return {"defaultAction": "deny", "rules": [{"operation": "observe", "resource": "azure/" + r} for r in resources]}


def configuration():
    return {"provider_instance_name": "azure-one", "config": {"tenant": TENANT, "subscriptions": [SUB], "state-dir": "/private/one"},
            "allow": {"resources": [ARM_SCOPE, QUERY_SCOPE], "authorization": observe([ARM_SCOPE, QUERY_SCOPE])}}


class FakeSource:
    def __init__(self):
        self.calls = []
        self.fail = False

    def acquire(self, audience):
        self.calls.append(audience)
        if self.fail:
            raise p.Failure("azure-credentials-unavailable", 503)
        return "fixture-broker-only", int(time.time()) + 3600


class AzureTests(unittest.TestCase):
    def setUp(self):
        self.source = FakeSource()
        self.provider = p.AzureProvider(configuration(), self.source)
        self.grant = {"materialization": "header-inject", "resources": [ARM_SCOPE, QUERY_SCOPE], "authorization": observe([ARM_SCOPE, QUERY_SCOPE])}

    def request(self, path, method="GET", host=p.ARM, grant=None, **extra):
        return {"host": host, "method": method, "path": path, "grant": self.grant if grant is None else grant, **extra}

    def decision(self, path, method="GET", host=p.ARM, grant=None, **extra):
        return self.provider.injection_authorization(self.request(path, method, host, grant, **extra))["allowed"]

    def test_observation_matrix(self):
        for path in ["/subscriptions/" + SUB + "/resourcegroups?api-version=2024-11-01",
                     VM + "?api-version=2025-04-01", VM + "/instanceView?api-version=2025-04-01",
                     "/subscriptions/" + SUB + "/resources?api-version=2024-11-01&$filter=resourceType%20eq%20%27Microsoft.Compute/virtualMachines%27",
                     VM + "/providers/Microsoft.Insights/metrics?api-version=2018-01-01&metricnames=Percentage%20CPU"]:
            with self.subTest(path=path):
                self.assertTrue(self.decision(path))
        for kind, versions in p.TYPES.items():
            for suffix in ["", "/name"]:
                path = "/subscriptions/" + SUB + "/resourcegroups/fixture/providers/" + kind + suffix + "?api-version=" + sorted(versions)[0]
                self.assertTrue(self.decision(path), path)

    def test_mutations_exports_ambiguous_and_unknown_fail_before_credentials(self):
        for method, tail in [("DELETE", ""), ("PUT", ""), ("POST", "/start"), ("POST", "/runCommand"),
                             ("GET", "/listKeys"), ("POST", "/listKeys"), ("GET", "/secret"), ("GET", "/proxy")]:
            self.assertFalse(self.decision(VM + tail + "?api-version=2025-04-01", method))
        for path in [VM + "?api-version=unknown", VM + "?api-version=2025-04-01&api-version=2025-04-01",
                     VM + "?api-version=2025-04-01&$expand=secrets", VM + "?api-version=2025-04-01#x",
                     VM.replace("/vm", "/%76m") + "?api-version=2025-04-01",
                     VM.replace("/vm", "/../vm") + "?api-version=2025-04-01",
                     VM.replace("/vm", "//vm") + "?api-version=2025-04-01",
                     VM + "?api-version=%FF", "/batch?api-version=2020-01-01",
                     VM + "?api-version=2025-04-01#", " " + VM + "?api-version=2025-04-01",
                     VM + "/providers/microsoft.insights/metrics?api-version=2018-01-01&metricnames=%GG",
                     "/subscriptions/" + SUB + "/resources?api-version=2024-11-01",
                     "/subscriptions/" + SUB + "/resources?api-version=2024-11-01&$filter=resourceType%20eq%20%27Microsoft.KeyVault/vaults%27"]:
            self.assertFalse(self.decision(path), path)
        self.assertFalse(self.decision(VM + "?api-version=2025-04-01", upgrade=True))
        self.assertFalse(self.decision(VM + "?api-version=2025-04-01", host="graph.microsoft.com"))
        self.assertEqual(self.source.calls, [])

    def test_scope_ceiling_and_grant_intersect_independently(self):
        narrow = "arm:" + VM
        grant = {"materialization": "header-inject", "resources": [narrow], "authorization": observe([narrow])}
        self.assertTrue(self.decision(VM + "?api-version=2025-04-01", grant=grant))
        self.assertFalse(self.decision(VM + "-other?api-version=2025-04-01", grant=grant))
        self.assertFalse(self.decision(VM.rsplit("/", 1)[0] + "?api-version=2025-04-01", grant=grant))
        config = configuration()
        config["allow"] = {"resources": [narrow], "authorization": observe([narrow])}
        self.provider = p.AzureProvider(config, self.source)
        self.assertTrue(self.decision(VM + "?api-version=2025-04-01"))
        self.assertFalse(self.decision(VM + "-other?api-version=2025-04-01"))
        unrestricted = copy.deepcopy(self.grant)
        unrestricted.pop("authorization")
        self.assertFalse(self.decision(VM + "/start?api-version=2025-04-01", "POST", grant=unrestricted))

    def test_omission_allows_reviewed_mutation_but_not_scope_or_credential_escape(self):
        config = configuration()
        config["allow"].pop("authorization")
        self.provider = p.AzureProvider(config, self.source)
        grant = copy.deepcopy(self.grant)
        grant.pop("authorization")
        self.assertTrue(self.decision(VM + "/start?api-version=2025-04-01", "POST", grant=grant))
        self.assertFalse(self.decision(VM + "/listKeys?api-version=2025-04-01", "POST", grant=grant))
        self.assertFalse(self.decision(VM.replace(SUB, WORKSPACE) + "?api-version=2025-04-01", grant=grant))
        self.assertFalse(self.decision(VM + "/start?api-version=2025-04-01", "POST"))

    def test_query_identity_scope_and_no_url_workspace_isolation_claim(self):
        path = "/v1/workspaces/" + WORKSPACE + "/query"
        self.assertTrue(self.decision(path, "POST", p.LOGS))
        # A different URL workspace is allowed only because the grant explicitly
        # acknowledges identity-wide RBAC. Body targets and KQL share this scope.
        self.assertTrue(self.decision(path.replace(WORKSPACE, SUB), "POST", p.LOGS))
        for resources in [["workspace/" + WORKSPACE], [ARM_SCOPE], [QUERY_SCOPE, "workspace/" + WORKSPACE]]:
            grant = {"materialization": "header-inject", "resources": resources, "authorization": observe(resources)}
            self.assertFalse(self.decision(path, "POST", p.LOGS, grant))
        for tail in ["?query=secret-query", "/batch", "?workspaces=" + SUB]:
            self.assertFalse(self.decision(path + tail, "POST", p.LOGS))
        self.assertFalse(self.decision(path, "GET", p.LOGS))

    def test_fixed_audiences_refresh_failure_and_no_stale_fallback(self):
        for host, audience in p.AUDIENCES.items():
            self.provider.injection_headers({"host": host})
            self.assertEqual(self.source.calls[-1], audience)
        self.source.fail = True
        with self.assertRaises(p.Failure):
            self.provider.injection_headers({"host": p.ARM})
        with self.assertRaises(p.Failure):
            self.provider.injection_headers({"host": "login.microsoftonline.com"})
        with patch.object(self.source, "acquire", return_value=("expired", int(time.time()) - 1)):
            with self.assertRaises(p.Failure):
                self.provider.injection_headers({"host": p.ARM})

    def test_identity_state_isolation_invalid_clouds_and_scopes(self):
        config = configuration()
        a = p.AzureProvider(config)
        config["provider_instance_name"] = "azure-two"
        config["config"]["state-dir"] = "/private/two"
        b = p.AzureProvider(config)
        self.assertNotEqual(a.source.directory, b.source.directory)
        self.assertEqual(a.initialize_result()["injection_hosts"], b.initialize_result()["injection_hosts"])
        for changes in [{"cloud": "unapproved"}, {"tenant": "*"}, {"subscriptions": [WORKSPACE]}, {"audience": "https://evil.invalid"}]:
            config = configuration()
            config["config"].update(changes)
            with self.assertRaises(p.Failure):
                p.AzureProvider(config)

    def test_real_subprocess_source_bounds_output_and_sanitizes_failures(self):
        with tempfile.TemporaryDirectory() as tmp:
            helper = Path(tmp) / "az-fixture"
            result = {"accessToken": "fixture-private-token", "tokenType": "Bearer", "tenant": TENANT,
                      "expires_on": int(time.time()) + 3600}
            def script(body):
                helper.write_text("#!/usr/bin/python3\nimport json,sys,os\n" + body)
                helper.chmod(0o700)
            script("assert sys.argv[1].endswith('/token_source.py')\n"
                   "assert sys.argv[2:] == [" + repr(TENANT) + ", 'https://management.azure.com/']\n"
                   "assert 'NVT_AZURE_PRIVATE_TEST' not in os.environ\n"
                   "print(" + repr(json.dumps(result)) + ")\n")
            source = p.AzureCLITokenSource(tmp, TENANT, str(helper))
            with patch.dict("os.environ", {"NVT_AZURE_PRIVATE_TEST": "do-not-inherit"}):
                self.assertEqual(source.acquire(p.AUDIENCES[p.ARM])[0], result["accessToken"])
            for broken in [{**result, "tenant": WORKSPACE}, {**result, "expires_on": 1}, {**result, "accessToken": "bad\nheader"}]:
                script("print(" + repr(json.dumps(broken)) + ")\n")
                with self.assertRaises(p.Failure) as failure:
                    source.acquire(p.AUDIENCES[p.ARM])
                self.assertEqual(failure.exception.reason, "azure-credentials-unavailable")
            script("print('private-output-canary' * 100000)\n")
            with self.assertRaises(p.Failure):
                source.acquire(p.AUDIENCES[p.ARM])
            script("print('private-error-canary',file=sys.stderr)\nsys.exit(1)\n")
            with self.assertRaises(p.Failure) as failure:
                source.acquire(p.AUDIENCES[p.ARM])
            self.assertNotIn("private-error", str(failure.exception))
        for resources in [["*"], [ARM_SCOPE + "/*"], ["query-identity/" + WORKSPACE], []]:
            config = configuration()
            config["allow"]["resources"] = resources
            with self.assertRaises(p.Failure):
                p.AzureProvider(config)


if __name__ == "__main__":
    unittest.main()
