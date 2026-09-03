import base64
import datetime
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path

import yaml


MODULE_PATH = Path(__file__).with_name("provider.py")
SPEC = importlib.util.spec_from_file_location("nvt_kubeconfig_provider", MODULE_PATH)
provider_module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(provider_module)


CA = """-----BEGIN CERTIFICATE-----
MIIDFTCCAf2gAwIBAgIUPx17Hd63iAmiPI8cJl4gykAppSYwDQYJKoZIhvcNAQEL
BQAwGjEYMBYGA1UEAwwPa3ViZXJuZXRlcy50ZXN0MB4XDTI2MDkwMjIzMzYyMloX
DTM2MDgzMDIzMzYyMlowGjEYMBYGA1UEAwwPa3ViZXJuZXRlcy50ZXN0MIIBIjAN
BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnXgPpqHukq/WVndzrqUcsYMCwNfF
THbbJfY+smn2ERX0OtYNPpBZuouyUdFhRq5qoHA8J0/Iq5lV5Yqeu7YHvIFPPmfV
E4gp9bi3vpKMWTvxwvVPItaR7JYHdELnqICJHVDrHm8QBkMaDPTYYL3aA8yM+Ub3
tI5bSdkW8ImxvNA7DVs59OsZO1ZL92l0vQFoG2mSk2W1FQugbdTsN+rg52LI3hKN
BfVMHGfh4Z2EGqcNo38ExpMzh8RbiwqErOwMnhvDgZZ+a1HwxmNvbEx6G5nJ9bsS
RzSr3ffhaU7/F9Z1swjt2rCq80TSPZG8k3KXB+4iLh9Ga4WyuxeZ/aQb8QIDAQAB
o1MwUTAdBgNVHQ4EFgQUuLSECsJdYO4XYAGhQZU5XhinrJowHwYDVR0jBBgwFoAU
uLSECsJdYO4XYAGhQZU5XhinrJowDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0B
AQsFAAOCAQEAdhjsMBCygCSBLuGl62sqjurycifi8ezqMarWuoNoAbXw6aNNl7ZO
hF14c8Ar3ITUYkEg+IqBGu29kC2oANmBmT1WAGEpuWSddQ+m6Ma4lCjVK48nFHqH
MCjuvhFPo+QuCbjZPrk9O7T7ow/aknA+ueCRls71em+K4SzriUpPEQq7h1I/nia8
mfmw2jtaM1EZdUUB3i+38VXjYwZ127y0K2qd+Tx0JgSdAOAtNyzzrzLalbZq7qKN
3vCjF8ECZQPIoRHDImumImIlYI+SuDhBfrOlDXZ48YCtcXc3/L5iK1ZK2GzOfzCj
F1Pc0azl1YVeuuP+URvLRmF+Pp1HSFWLog==
-----END CERTIFICATE-----
"""


def document(context_count=1, user=None):
    user = user or {"token": "real-static-token"}
    return {
        "apiVersion": "v1",
        "kind": "Config",
        "current-context": "context-000",
        "clusters": [{
            "name": f"cluster-{index:03d}",
            "cluster": {
                "server": f"https://10.20.{index // 250}.{index % 250 + 1}:6443",
                "certificate-authority-data": base64.b64encode(CA.encode()).decode(),
                "tls-server-name": "kubernetes.internal",
            },
        } for index in range(context_count)],
        "users": [{"name": "shared-user", "user": user}],
        "contexts": [{
            "name": f"context-{index:03d}",
            "context": {"cluster": f"cluster-{index:03d}", "user": "shared-user", "namespace": "default"},
        } for index in range(context_count)],
    }


class KubeconfigProviderTest(unittest.TestCase):
    def make_provider(self, doc, resources, extra_config=None, authorization=None):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        kubeconfig = root / "private.yaml"
        kubeconfig.write_text(yaml.safe_dump(doc), encoding="utf-8")
        config = {
            "private-kubeconfig": str(kubeconfig),
            "state-dir": str(root / "state"),
            **(extra_config or {}),
        }
        allow = {"resources": resources}
        if authorization is not None:
            allow["authorization"] = authorization
        value = provider_module.KubeconfigProvider({
            "provider_instance_name": "clusters",
            "config": config,
            "allow": allow,
        })
        return value, root

    def test_catalog_of_more_than_one_hundred_contexts_is_sanitized_and_bounded(self):
        resources = [f"context-{index:03d}" for index in range(125)]
        provider, _ = self.make_provider(document(125), resources)
        result = provider.catalog({"grant": {"resources": resources}})
        self.assertEqual(len(result["routes"]), 125)
        sanitized = result["files"][0]["content"]
        self.assertNotIn("real-static-token", sanitized)
        self.assertNotIn("exec:", sanitized)
        self.assertNotIn("client-key", sanitized)
        parsed = yaml.safe_load(sanitized)
        self.assertEqual(len(parsed["contexts"]), 125)
        self.assertEqual(parsed["current-context"], "context-000")
        self.assertEqual([entry["name"] for entry in parsed["users"]], ["shared-user"])
        self.assertEqual(parsed["users"][0]["user"], {})

    def test_injection_is_resource_scoped_and_never_uses_agent_headers(self):
        provider, _ = self.make_provider(document(2), ["context-000", "context-001"])
        host = provider_module.route_host("clusters", "context-000")
        result = provider.injection_headers({"host": host, "grant": {"resources": ["context-000"]}})
        self.assertEqual(result["headers"]["authorization"], "Bearer real-static-token")
        other = provider_module.route_host("clusters", "context-001")
        with self.assertRaisesRegex(provider_module.ProviderFailure, "resource-not-granted"):
            provider.injection_headers({"host": other, "grant": {"resources": ["context-000"]}})

    def test_observe_policy_classifies_safe_reads_for_arbitrary_resources(self):
        policy = {"defaultAction": "deny", "rules": [{"operation": "observe", "resource": "context/context-000"}]}
        provider, _ = self.make_provider(document(), ["context-000"], authorization=policy)
        request = {
            "host": provider_module.route_host("clusters", "context-000"),
            "grant": {"resources": ["context-000"], "authorization": policy},
        }
        paths = [
            "/version", "/api", "/apis", "/api/v1", "/apis/apps/v1",
            "/openapi/v3/apis/example.dev/v1", "/readyz?verbose=true",
            "/readyz?verbose", "/readyz?verbose&exclude=etcd",
            "/api/v1/pods", "/api/v1/namespaces/team/pods?watch=true&resourceVersion=10",
            "/api/v1/watch/namespaces/team/pods?resourceVersion=10",
            "/api/v1/namespaces/team/pods/api/log?follow=true",
            "/api/v1/namespaces/team/events?fieldSelector=involvedObject.name%3Dapi",
            "/apis/widgets.example.dev/v1/namespaces/team/widgets",
            "/apis/widgets.example.dev/v1/namespaces/team/secrets",
            "/apis/rbac.authorization.k8s.io/v1/clusterroles/system:aggregate-to-admin",
            "/apis/widgets.example.dev/v1/widgets/sample/status",
        ]
        for path in paths:
            with self.subTest(path=path):
                decision = provider.injection_authorization({**request, "method": "GET", "path": path})
                self.assertEqual(decision, {"allowed": True, "operation": "observe", "resource": "context/context-000"})

    def test_observe_policy_fails_closed_before_credential_materialization(self):
        policy = {"defaultAction": "deny", "rules": [{"operation": "observe", "resource": "context/context-000"}]}
        provider, _ = self.make_provider(document(), ["context-000"], authorization=policy)
        request = {
            "host": provider_module.route_host("clusters", "context-000"),
            "grant": {"resources": ["context-000"], "authorization": policy},
        }
        denied = [
            ("GET", "/api/v1/secrets"),
            ("GET", "/api/v1/namespaces/team/secrets/name"),
            ("POST", "/api/v1/namespaces/team/configmaps"),
            ("PUT", "/api/v1/namespaces/team/configmaps/name"),
            ("PATCH", "/api/v1/namespaces/team/pods/name/status"),
            ("DELETE", "/apis/example.dev/v1/widgets"),
            ("GET", "/api/v1/namespaces/team/pods/name/exec"),
            ("GET", "/api/v1/namespaces/team/pods/name/attach"),
            ("GET", "/api/v1/namespaces/team/pods/name/portforward"),
            ("GET", "/api/v1/nodes/name/proxy"),
            ("GET", "/api/v1/proxy"),
            ("GET", "/api/v1/namespaces/team/services/name/proxy"),
            ("GET", "/api/v1/namespaces/demo/finalize"),
            ("GET", "/api%2fv1/pods"),
            ("GET", "/api/v1/../secrets"),
            ("GET", "//api/v1/pods"),
            ("GET", "/api/v1/pods?watch=true&watch=false"),
            ("GET", "/readyz?verbose&&exclude=etcd"),
            ("GET", "/api/v1/pods?"),
            ("GET", "/api/v1/pods/one/unknown"),
        ]
        for method, path in denied:
            with self.subTest(method=method, path=path):
                decision = provider.injection_authorization({**request, "method": method, "path": path})
                self.assertEqual(decision, {"allowed": False, "operation": "unclassified", "resource": "context/context-000"})
        decision = provider.injection_authorization({**request, "method": "GET", "path": "/api/v1/pods", "upgrade": True})
        self.assertFalse(decision["allowed"])
        self.assertEqual(decision["operation"], "unclassified")
        self.assertEqual(provider.token_cache, {})

    def test_provider_and_grant_authorization_intersect_for_exact_context(self):
        allow_first = {"defaultAction": "deny", "rules": [{"operation": "observe", "resource": "context/context-000"}]}
        deny_all = {"defaultAction": "deny", "rules": []}
        provider, _ = self.make_provider(document(), ["context-000"], authorization=allow_first)
        request = {"host": provider_module.route_host("clusters", "context-000"), "method": "GET", "path": "/api/v1/pods"}
        self.assertFalse(provider.injection_authorization({**request, "grant": {"resources": ["context-000"], "authorization": deny_all}})["allowed"])

        provider, _ = self.make_provider(document(), ["context-000"], authorization=deny_all)
        self.assertFalse(provider.injection_authorization({**request, "grant": {"resources": ["context-000"], "authorization": allow_first}})["allowed"])

    def test_absent_authorization_preserves_unrestricted_compatibility(self):
        provider, _ = self.make_provider(document(), ["context-000"])
        decision = provider.injection_authorization({
            "host": provider_module.route_host("clusters", "context-000"),
            "method": "POST", "path": "/api/v1/namespaces",
            "grant": {"resources": ["context-000"]},
        })
        self.assertTrue(decision["allowed"])
        self.assertEqual(decision["operation"], "unrestricted")

    def test_exec_helper_state_is_private_per_instance_and_cached(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        helper = Path(temporary.name) / "helper"
        helper.write_text(
            "#!/usr/bin/env python3\n"
            "import datetime,json,os,pathlib\n"
            "assert json.loads(os.environ['KUBERNETES_EXEC_INFO'])['spec']['cluster']['server'].startswith('https://10.20.')\n"
            "marker=pathlib.Path(os.environ['HOME'])/'helper-state'\n"
            "marker.write_text(str(int(marker.read_text())+1) if marker.exists() else '1')\n"
            "print(json.dumps({'apiVersion':'client.authentication.k8s.io/v1','kind':'ExecCredential','status':"
            "{'token':'short-lived-token','expirationTimestamp':(datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(minutes=10)).isoformat()}}))\n",
            encoding="utf-8",
        )
        helper.chmod(0o700)
        exec_user = {"exec": {"apiVersion": "client.authentication.k8s.io/v1", "command": str(helper), "interactiveMode": "Never", "provideClusterInfo": True}}
        first, first_root = self.make_provider(document(user=exec_user), ["context-000"], {"helper-allowlist": [str(helper)]})
        second, second_root = self.make_provider(document(user=exec_user), ["context-000"], {"helper-allowlist": [str(helper)]})
        host = provider_module.route_host("clusters", "context-000")
        grant = {"resources": ["context-000"]}
        first.injection_headers({"host": host, "grant": grant})
        first.injection_headers({"host": host, "grant": grant})
        second.injection_headers({"host": host, "grant": grant})
        self.assertEqual((first_root / "state" / "helper-state").read_text(), "1")
        self.assertEqual((second_root / "state" / "helper-state").read_text(), "1")

    def test_client_certificate_auth_fails_closed(self):
        user = {"client-certificate-data": "certificate", "client-key-data": "key"}
        provider, _ = self.make_provider(document(user=user), ["context-000"])
        host = provider_module.route_host("clusters", "context-000")
        with self.assertRaisesRegex(provider_module.ProviderFailure, "unsupported-kubeconfig-auth"):
            provider.injection_headers({"host": host, "grant": {"resources": ["context-000"]}})

    def test_exec_helper_without_expiry_has_bounded_cache(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        helper = Path(temporary.name) / "helper"
        helper.write_text(
            "#!/usr/bin/env python3\n"
            "import json,os,pathlib\n"
            "marker=pathlib.Path(os.environ['HOME'])/'calls'\n"
            "count=int(marker.read_text())+1 if marker.exists() else 1\n"
            "marker.write_text(str(count))\n"
            "print(json.dumps({'apiVersion':'client.authentication.k8s.io/v1','kind':'ExecCredential','status':{'token':'token-'+str(count)}}))\n",
            encoding="utf-8",
        )
        helper.chmod(0o700)
        exec_user = {"exec": {"apiVersion": "client.authentication.k8s.io/v1", "command": str(helper), "interactiveMode": "Never"}}
        provider, root = self.make_provider(document(user=exec_user), ["context-000"], {"helper-allowlist": [str(helper)]})
        request = {"host": provider_module.route_host("clusters", "context-000"), "grant": {"resources": ["context-000"]}}
        self.assertEqual(provider.injection_headers(request)["headers"]["authorization"], "Bearer token-1")
        self.assertEqual(provider.injection_headers(request)["headers"]["authorization"], "Bearer token-1")
        key = ("shared-user", "cluster-000")
        token, expiry, _ = provider.token_cache[key]
        provider.token_cache[key] = (token, expiry, datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=61))
        self.assertEqual(provider.injection_headers(request)["headers"]["authorization"], "Bearer token-2")
        self.assertEqual((root / "state" / "calls").read_text(), "2")

    def test_ca_bundle_rejects_private_key_or_trailing_content(self):
        self.assertEqual(provider_module.certificates_only_pem(("\n" + CA).encode()), CA)
        for suffix in (
            "-----BEGIN PRIVATE KEY-----\nZml4dHVyZS1rZXk=\n-----END PRIVATE KEY-----\n",
            "not-a-certificate\n",
        ):
            doc = document()
            doc["clusters"][0]["cluster"]["certificate-authority-data"] = base64.b64encode((CA + suffix).encode()).decode()
            with self.assertRaisesRegex(provider_module.ProviderFailure, "provider-config-invalid"):
                self.make_provider(doc, ["context-000"])


if __name__ == "__main__":
    unittest.main()
