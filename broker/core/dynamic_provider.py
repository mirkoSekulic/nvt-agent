"""A stable, leased handle for replaceable dynamic provider generations."""

import threading

from broker.core.errors import ProviderError
from broker.core.provider_adapter import ProviderAdapter


class DynamicProviderAdapter(ProviderAdapter):
    """Keep an opaque provider id stable while safely replacing its adapter.

    Calls may run concurrently. A swap publishes the new adapter immediately,
    waits only for calls already leased to the old adapter, and then closes the
    old generation. A caller holding this stable handle across revoke fails
    closed instead of reaching the retired provider.
    """

    def __init__(self, adapter):
        self._name = adapter.name
        self._current = adapter
        self._leases = {}
        self._condition = threading.Condition()

    @property
    def name(self):
        return self._name

    @property
    def ready(self):
        return self._invoke_property("ready")

    @property
    def external(self):
        return self._invoke_property("external")

    @property
    def injection_hosts(self):
        return list(self._invoke_property("injection_hosts"))

    @property
    def injection_git(self):
        return self._invoke_property("injection_git")

    @property
    def bundle_ttl_seconds(self):
        return self._invoke_property("bundle_ttl_seconds")

    def close(self):
        with self._condition:
            adapter = self._current
            self._current = None
            while adapter is not None and self._leases.get(adapter, 0):
                self._condition.wait()
        if adapter is not None:
            try:
                adapter.close()
            except Exception:
                # Retirement is fail-closed at the handle before cleanup. A
                # broken trusted adapter cannot restore access by failing its
                # close hook.
                pass

    def swap(self, replacement):
        if replacement.name != self._name:
            raise ProviderError("provider-initialization-failed", "provider-initialization-failed", 503)
        with self._condition:
            previous = self._current
            if previous is None:
                raise ProviderError("provider-not-found")
            self._current = replacement
            while self._leases.get(previous, 0):
                self._condition.wait()
        try:
            previous.close()
        except Exception:
            # The replacement is already authoritative and the previous
            # generation has no remaining leases. Do not roll back into it.
            pass

    def validate_state(self):
        return self._invoke("validate_state")

    def supports(self, capability):
        return self._invoke("supports", capability)

    def http_request(self, method, url, headers, paginate, grants):
        return self._invoke("http_request", method, url, headers, paginate, grants)

    def normalize_target(self, target):
        return self._invoke("normalize_target", target)

    def target_from_repo(self, repo):
        return self._invoke("target_from_repo", repo)

    def token_for_repo(self, repo, effective_repositories):
        return self._invoke("token_for_repo", repo, effective_repositories)

    def identity_for_repo(self, repo, effective_repositories):
        return self._invoke("identity_for_repo", repo, effective_repositories)

    def identity_for_grant(self, effective_repositories):
        return self._invoke("identity_for_grant", effective_repositories)

    def headers_for_repo(self, repo, effective_repositories):
        return self._invoke("headers_for_repo", repo, effective_repositories)

    def files(self, agent_id, audit, request_id):
        return self._invoke("files", agent_id, audit, request_id)

    def placeholder_files(self, agent_id, audit, request_id, grant):
        return self._invoke("placeholder_files", agent_id, audit, request_id, grant)

    def catalog(self, agent_id, audit, request_id, grant):
        return self._invoke("catalog", agent_id, audit, request_id, grant)

    def authorize_injection(self, host, method, path, upgrade, agent_id, request_id, grant):
        return self._invoke("authorize_injection", host, method, path, upgrade, agent_id, request_id, grant)

    def injection_headers(self, host, method, path, agent_id, audit, request_id, grant):
        return self._invoke("injection_headers", host, method, path, agent_id, audit, request_id, grant)

    def _invoke_property(self, name):
        adapter = self._acquire()
        try:
            return getattr(adapter, name)
        finally:
            self._release(adapter)

    def _invoke(self, name, *args):
        adapter = self._acquire()
        try:
            return getattr(adapter, name)(*args)
        finally:
            self._release(adapter)

    def _acquire(self):
        with self._condition:
            adapter = self._current
            if adapter is None:
                raise ProviderError("provider-not-found")
            self._leases[adapter] = self._leases.get(adapter, 0) + 1
            return adapter

    def _release(self, adapter):
        with self._condition:
            remaining = self._leases[adapter] - 1
            if remaining:
                self._leases[adapter] = remaining
            else:
                del self._leases[adapter]
                self._condition.notify_all()
