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
    def make_provider(self, doc, resources, extra_config=None):
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
        value = provider_module.KubeconfigProvider({
            "provider_instance_name": "clusters",
            "config": config,
            "allow": {"resources": resources},
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
