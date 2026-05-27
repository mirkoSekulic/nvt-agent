import hashlib
import os
import sys
import threading
from pathlib import Path

import yaml

from broker.core.config import fail, list_value, string_value
from broker.plugins.github_app.provider import ProviderError


class AgentRegistry:
    def __init__(self, path=None):
        raw_path = path or os.environ.get("NVT_BROKER_AGENTS_CONFIG", "")
        self.path = Path(raw_path) if raw_path else None
        self.lock = threading.Lock()
        self.mtime_ns = None
        self.agents_by_hash = {}
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

    def _load_candidate(self):
        with self.path.open("r", encoding="utf-8") as file:
            data = yaml.safe_load(file) or {}
        if not isinstance(data, dict):
            fail(f"{self.path} must be a YAML object")
        output = {}
        seen_ids = set()
        seen_hashes = set()
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
            grants = []
            for grant_index, grant in enumerate(list_value(raw.get("grants"), f"agents[{index}].grants")):
                if not isinstance(grant, dict):
                    fail(f"agents[{index}].grants[{grant_index}] must be a YAML object")
                provider = string_value(grant.get("provider"), f"agents[{index}].grants[{grant_index}].provider", required=True)
                repositories = []
                for repo_index, repo in enumerate(list_value(grant.get("repositories"), f"agents[{index}].grants[{grant_index}].repositories")):
                    if not isinstance(repo, str) or not repo:
                        fail(f"agents[{index}].grants[{grant_index}].repositories[{repo_index}] must be a non-empty string")
                    repositories.append(repo)
                grants.append({"provider": provider, "repositories": repositories})
            output[token_hash] = {"id": agent_id, "grants": grants}
        return output
