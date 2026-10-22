import copy
import unittest
from unittest.mock import patch

from broker.core.errors import ProviderError
from broker.core.config import BrokerConfigError
from broker.plugins.static_token.provider import StaticTokenProvider
from broker.plugins.static_token.http_policy import policy


POLICY = {"defaultAction": "deny", "rules": [
    {"operation": "http.POST", "resource": "http/api.example.test/graphql"},
    {"operation": "http.POST", "resource": "http/api.example.test/designer/api/*/*/deployments/undeploy"},
]}


class HTTPPolicyTest(unittest.TestCase):
    def test_misspelled_ceiling_is_not_ignored(self):
        for allow in [{"authorizaton": POLICY}, {"authorization": None}, {"permissions": {"contents": "read"}}]:
            with self.subTest(allow=allow), self.assertRaises(BrokerConfigError):
                StaticTokenProvider({"name": "fixture", "allow": allow})

    def provider(self, authorization=POLICY, git=False):
        entry = {"name": "fixture", "config": {"token-env": "FIXTURE_TOKEN", "injection-hosts": ["api.example.test"], "injection-git": git}, "allow": {"repositories": ["api.example.test/org/repo"]}}
        if authorization is not None:
            entry["allow"]["authorization"] = authorization
        with patch.dict("os.environ", {"FIXTURE_TOKEN": "fake-http-pat"}):
            return StaticTokenProvider(entry)

    def test_patterns_and_canonical_request_target(self):
        provider = self.provider()
        for method, path, upgrade, allowed in [
            ("POST", "/graphql", False, True),
            ("POST", "/designer/api/org/app/deployments/undeploy", False, True),
            ("GET", "/graphql", False, False),
            ("POST", "/graphql?x=1", False, False),
            ("POST", "/graphql?", False, False),
            ("POST", "/graphql/", False, False),
            ("POST", "/%67raphql", False, False),
            ("POST", "/%2567raphql", False, False),
            ("POST", "/foo/../graphql", False, False),
            ("POST", "//graphql", False, False),
            ("POST", "/graphql#fragment", False, False),
            ("POST", "/graphql", True, False),
            ("POST", "/designer/api/org/app/extra/deployments/undeploy", False, False),
            ("POST", "/designer/api/org%2fother/app/deployments/undeploy", False, False),
            ("POST", "/designer/api/org/app;param/deployments/undeploy", False, False),
            ("POST", "/designer/api/org/é/deployments/undeploy", False, False),
        ]:
            with self.subTest(path=path, method=method, upgrade=upgrade):
                decision = provider.authorize_injection("api.example.test", method, path, upgrade, "agent", "request", {"authorization": POLICY})
                self.assertEqual(decision["allowed"], allowed)
        for host in ["other.example.test", "API.example.test", "api.example.test:443", "api.example.test."]:
            self.assertFalse(provider.authorize_injection(host, "POST", "/graphql", False, "a", "r", {"authorization": POLICY})["allowed"])

    def test_intersection_and_missing_policy_fail_closed(self):
        for ceiling, grant in [(POLICY, {}), (POLICY, {"authorization": {}}), (None, {"authorization": POLICY}), ({}, {"authorization": POLICY})]:
            self.assertFalse(self.provider(ceiling).authorize_injection("api.example.test", "POST", "/graphql", False, "a", "r", grant)["allowed"])
        self.assertIsNone(self.provider(None).authorize_injection("api.example.test", "POST", "/arbitrary", False, "a", "r", {}))

    def test_git_has_no_api_fallback(self):
        provider = self.provider(git=True)
        with self.assertRaises(ProviderError) as exported:
            provider.token_for_repo("api.example.test/org/repo", ["api.example.test/org/repo"])
        self.assertEqual(exported.exception.status, 403)
        self.assertFalse(provider.authorize_injection("api.example.test", "POST", "/graphql", False, "a", "r", {"authorization": POLICY, "repositories": ["*"]})["allowed"])
        legacy = self.provider(None, git=True)
        with self.assertRaises(ProviderError) as denied:
            legacy.injection_headers("api.example.test", "POST", "/graphql", "a", None, "r", {"repositories": ["*"]})
        self.assertEqual(denied.exception.status, 403)

    def test_policy_bounds(self):
        rules = [{"operation": "http.GET", "resource": "http/api.example.test/" + str(i)} for i in range(128)]
        self.assertEqual(len(policy({"rules": rules})), 128)
        with self.assertRaises(ProviderError):
            policy({"rules": rules + [{"operation": "http.GET", "resource": "http/api.example.test/extra"}]})
        for path, valid in [("/", True), ("/" + "a" * 2047, True), ("/" + "a" * 2048, False),
                            ("/" + "/".join(["a"] * 64), True), ("/" + "/".join(["a"] * 65), False)]:
            candidate = {"rules": [{"operation": "http.GET", "resource": "http/api.example.test" + path}]}
            if valid:
                self.assertEqual(len(policy(candidate)), 1)
            else:
                with self.assertRaises(ProviderError):
                    policy(candidate)

    def test_malformed_policy(self):
        invalid = [False, [], {"defaultAction": "allow"}, {"preset": "observe"}, {"rules": None}, {"rules": POLICY["rules"] * 65}]
        for operation, resource in [("http.*", "http/api.example.test/graphql"), ("http.get", "http/api.example.test/graphql"), ("http.CONNECT", "http/api.example.test/graphql"),
                                    ("http.POST", "http/*.example.test/graphql"), ("http.POST", "http/api.example.test/foo/**"), ("http.POST", "http/api.example.test/foo/pre*"),
                                    ("http.POST", "http/api.example.test/graphql/"), ("http.POST", "http/api.example.test/%67raphql"), ("http.POST", "http/api.example.test/graphql?q=1")]:
            invalid.append({"rules": [{"operation": operation, "resource": resource}]})
        duplicate = copy.deepcopy(POLICY)
        duplicate["rules"].append(duplicate["rules"][0])
        invalid.append(duplicate)
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(ProviderError):
                policy(value)
            with self.subTest(provider=value), self.assertRaises(ProviderError):
                self.provider(value)
            with self.subTest(grant=value), self.assertRaises(ProviderError):
                self.provider().authorize_injection("api.example.test", "POST", "/graphql", False, "a", "r", {"authorization": value})
