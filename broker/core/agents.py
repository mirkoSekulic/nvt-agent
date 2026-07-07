import hashlib
import os
import sys
import threading
from pathlib import Path

import yaml

from broker.core.config import fail, list_value, string_value
from broker.plugins.github_app.provider import ProviderError


VALID_ROLES = {"agent", "egress"}
VALID_MATERIALIZATIONS = {"file-bundle", "header-inject", "placeholder-file"}
VALID_PERMISSION_VALUES = {"read", "write"}


class AgentRegistry:
    def __init__(self, path=None):
        raw_path = path or os.environ.get("NVT_BROKER_AGENTS_CONFIG", "")
        self.path = Path(raw_path) if raw_path else None
        self.lock = threading.Lock()
        self.mtime_ns = None
        self.agents_by_hash = {}
        self.agents_by_id = {}
        self.last_error = None
        self.reload_if_changed(force=True)

    def reload_if_changed(self, force=False):
        if not self.path:
            return
        with self.lock:
            try:
                stat = self.path.stat()
            except FileNotFoundError:
                if force:
                    self.agents_by_hash = {}
                    self.agents_by_id = {}
                return
            if not force and self.mtime_ns == stat.st_mtime_ns:
                return
            try:
                candidate = self._load_candidate()
            except Exception as error:
                self.last_error = str(error)
                print(f"broker agents config reload failed: {self.last_error}", file=sys.stderr)
                return
            self.agents_by_hash = candidate
            self.agents_by_id = {agent["id"]: agent for agent in candidate.values()}
            self.mtime_ns = stat.st_mtime_ns
            self.last_error = None

    def authenticate(self, authorization):
        self.reload_if_changed()
        if not authorization or not authorization.startswith("Bearer "):
            raise ProviderError("unauthorized", "missing broker bearer token", 401)
        token = authorization.removeprefix("Bearer ").strip()
        if not token:
            raise ProviderError("unauthorized", "empty broker bearer token", 401)
        token_hash = "sha256:" + hashlib.sha256(token.encode("utf-8")).hexdigest()
        agent = self.agents_by_hash.get(token_hash)
        if agent is None:
            raise ProviderError("unauthorized", "invalid broker bearer token", 401)
        return agent

    def effective_repositories(self, agent, provider_name):
        repos = []
        for grant in agent["grants"]:
            if grant["provider"] == provider_name:
                repos.extend(grant["repositories"])
        if not repos:
            raise ProviderError("provider-not-granted")
        return repos

    def ensure_provider_grant(self, agent, provider_name):
        for grant in agent["grants"]:
            if grant["provider"] == provider_name:
                return
        raise ProviderError("provider-not-granted")

    def grant(self, agent, provider_name):
        for grant in agent["grants"]:
            if grant["provider"] == provider_name:
                return grant
        return None

    def by_id(self, agent_id):
        return self.agents_by_id.get(agent_id)

    def _load_candidate(self):
        with self.path.open("r", encoding="utf-8") as file:
            data = yaml.safe_load(file) or {}
        if not isinstance(data, dict):
            fail(f"{self.path} must be a YAML object")
        output = {}
        seen_ids = set()
        seen_hashes = set()
        roles_by_id = {}
        pairings = []
        for index, raw in enumerate(list_value(data.get("agents"), "agents")):
            if not isinstance(raw, dict):
                fail(f"agents[{index}] must be a YAML object")
            agent_id = string_value(raw.get("id"), f"agents[{index}].id", required=True)
            if agent_id in seen_ids:
                fail(f"duplicate agent id: {agent_id}")
            seen_ids.add(agent_id)
            token_hash = string_value(raw.get("token-sha256"), f"agents[{index}].token-sha256", required=True)
            if not token_hash.startswith("sha256:") or len(token_hash) != len("sha256:") + 64:
                fail(f"agents[{index}].token-sha256 must be sha256:<hex>")
            try:
                int(token_hash.removeprefix("sha256:"), 16)
            except ValueError:
                fail(f"agents[{index}].token-sha256 must be sha256:<hex>")
            if token_hash in seen_hashes:
                fail(f"duplicate token hash for agent: {agent_id}")
            seen_hashes.add(token_hash)
            role = raw.get("role", "agent")
            if role not in VALID_ROLES:
                fail(f"agents[{index}].role must be one of: {', '.join(sorted(VALID_ROLES))}")
            paired_agent = raw.get("paired-agent")
            if role == "egress":
                raw_grants = raw.get("grants")
                if raw_grants not in (None, []):
                    fail(f"agents[{index}] ({agent_id}): egress identities must not hold grants")
                paired_agent = string_value(paired_agent, f"agents[{index}].paired-agent", required=True)
                pairings.append((index, agent_id, paired_agent))
                output[token_hash] = {"id": agent_id, "role": "egress", "paired_agent": paired_agent, "grants": []}
                roles_by_id[agent_id] = "egress"
                continue
            if paired_agent is not None:
                fail(f"agents[{index}] ({agent_id}): paired-agent is only valid for egress identities")
            grants = []
            for grant_index, grant in enumerate(list_value(raw.get("grants"), f"agents[{index}].grants")):
                if not isinstance(grant, dict):
                    fail(f"agents[{index}].grants[{grant_index}] must be a YAML object")
                provider = string_value(grant.get("provider"), f"agents[{index}].grants[{grant_index}].provider", required=True)
                materialization = grant.get("materialization", "file-bundle")
                if materialization not in VALID_MATERIALIZATIONS:
                    fail(
                        f"agents[{index}].grants[{grant_index}].materialization must be one of: "
                        f"{', '.join(sorted(VALID_MATERIALIZATIONS))}"
                    )
                repositories = []
                for repo_index, repo in enumerate(list_value(grant.get("repositories"), f"agents[{index}].grants[{grant_index}].repositories")):
                    if not isinstance(repo, str) or not repo:
                        fail(f"agents[{index}].grants[{grant_index}].repositories[{repo_index}] must be a non-empty string")
                    repositories.append(repo)
                raw_permissions = grant.get("permissions")
                permissions = {}
                if raw_permissions is not None:
                    if not isinstance(raw_permissions, dict):
                        fail(f"agents[{index}].grants[{grant_index}].permissions must be a YAML object")
                    for key, value in raw_permissions.items():
                        if not isinstance(key, str) or not key or value not in VALID_PERMISSION_VALUES:
                            fail(
                                f"agents[{index}].grants[{grant_index}].permissions must map permission names to one of: "
                                f"{', '.join(sorted(VALID_PERMISSION_VALUES))}"
                            )
                        permissions[key] = value
                # Quota is validated for schema strictness but NOT enforced
                # broker-side: enforcement is per egressd process
                # (docs/phase5-6b-observability-pr-plan.md decision 3).
                quota = self._grant_quota(grant.get("quota"), index, grant_index)
                grant_entry = {"provider": provider, "repositories": repositories, "materialization": materialization, "permissions": permissions}
                if quota is not None:
                    grant_entry["quota"] = quota
                grants.append(grant_entry)
            # A provider may appear in multiple grants (repository aggregation),
            # but they must agree on materialization: grant() returns the first
            # match, so conflicting modes for one provider would be resolved
            # order-dependently.
            materialization_by_provider = {}
            for grant_entry in grants:
                existing = materialization_by_provider.get(grant_entry["provider"])
                if existing is not None and existing != grant_entry["materialization"]:
                    fail(f"agents[{index}] ({agent_id}): provider {grant_entry['provider']} has conflicting materializations {existing} and {grant_entry['materialization']}")
                materialization_by_provider[grant_entry["provider"]] = grant_entry["materialization"]
            output[token_hash] = {"id": agent_id, "role": "agent", "paired_agent": None, "grants": grants}
            roles_by_id[agent_id] = "agent"
        for index, agent_id, paired_agent in pairings:
            if roles_by_id.get(paired_agent) != "agent":
                fail(f"agents[{index}] ({agent_id}): paired-agent must reference an agent-role identity")
        return output

    def _grant_quota(self, raw_quota, index, grant_index):
        if raw_quota is None:
            return None
        if not isinstance(raw_quota, dict):
            fail(f"agents[{index}].grants[{grant_index}].quota must be a YAML object")
        requests = raw_quota.get("requests")
        if not isinstance(requests, int) or isinstance(requests, bool) or requests < 1:
            fail(f"agents[{index}].grants[{grant_index}].quota.requests must be a positive integer")
        return {"requests": requests}
