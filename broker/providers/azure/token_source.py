"""Trusted fixed Azure CLI token acquisition entrypoint; stdout is broker-only."""
import copy
import importlib.metadata
import json
import re
import sys
from urllib.parse import parse_qsl, urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

LIMIT = 1024 * 1024
UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ValueError("discovery redirect denied")


def discovery_url(url):
    parsed = urlsplit(url)
    pairs = parse_qsl(parsed.query, strict_parsing=True, max_num_fields=2)
    query = dict(pairs)
    if (parsed.scheme != "https" or parsed.netloc != "management.azure.com" or parsed.path != "/subscriptions"
            or parsed.fragment or len(url) > 8192 or len(query) != len(pairs)
            or set(query) - {"api-version", "$skiptoken"} or query.get("api-version") != "2022-12-01"):
        raise ValueError("invalid discovery continuation")
    return url


def discover(tenant):
    # Fixed ARM inventory read authenticated ONLY for the configured tenant.
    # Never refresh the CLI's multi-tenant account cache or invoke agent commands.
    token = acquire(tenant, "https://management.azure.com/")
    if token["tenant"].lower() != tenant or token["tokenType"] != "Bearer":
        raise ValueError("invalid discovery identity")
    opener = build_opener(ProxyHandler({}), NoRedirect())
    url = "https://management.azure.com/subscriptions?api-version=2022-12-01"
    accounts, seen, consumed, count = [], set(), 0, 0
    for _ in range(8):
        request = Request(discovery_url(url), headers={"Authorization": "Bearer " + token["accessToken"]})
        with opener.open(request, timeout=10) as response:
            raw = response.read(LIMIT + 1 - consumed)
        consumed += len(raw)
        if consumed > LIMIT:
            raise ValueError("discovery exceeds byte limit")
        page = json.loads(raw)
        if not isinstance(page, dict) or not isinstance(page.get("value"), list):
            raise ValueError("invalid discovery page")
        for item in page["value"]:
            count += 1
            if count > 256 or not isinstance(item, dict):
                raise ValueError("discovery exceeds subscription limit")
            identifier, home_tenant = item.get("subscriptionId"), item.get("tenantId")
            if not isinstance(identifier, str) or not isinstance(home_tenant, str) or not re.fullmatch(UUID, identifier.lower()) or not re.fullmatch(UUID, home_tenant.lower()):
                raise ValueError("invalid discovery identity")
            identifier = identifier.lower()
            if identifier in seen:
                raise ValueError("duplicate discovery identity")
            seen.add(identifier)
            if item.get("state") not in {"Enabled", "Warned", "PastDue", "Disabled", "Deleted"}:
                raise ValueError("invalid subscription state")
            # Cross-tenant delegated subscriptions are intentionally not included.
            if home_tenant.lower() != tenant or item.get("state") != "Enabled":
                continue
            name = item.get("displayName")
            if not isinstance(name, str) or not 0 < len(name.encode()) <= 512 or any(ord(c) < 32 or ord(c) == 127 for c in name):
                raise ValueError("invalid public subscription name")
            accounts.append({"id": identifier, "name": name})
        url = page.get("nextLink")
        if url is None or url == "":
            return {"tenant": tenant, "subscriptions": sorted(accounts, key=lambda s: s["id"])}
        if not isinstance(url, str):
            raise ValueError("invalid discovery continuation")
    raise ValueError("discovery exceeds page limit")


def acquire(tenant, audience):
    if not re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", tenant):
        raise ValueError("invalid tenant")
    if audience not in {"https://management.azure.com/", "https://api.loganalytics.io"}:
        raise ValueError("invalid audience")
    if importlib.metadata.version("azure-cli-core") != "2.89.1":
        raise ValueError("unsupported CLI version")
    from azure.cli.core import get_default_cli
    from azure.cli.core.cloud import AZURE_PUBLIC_CLOUD
    from azure.cli.core._profile import Profile
    cli = get_default_cli()
    # Pin endpoints and authentication authority, even if the enrolled CLI state
    # has changed its active cloud or has custom endpoint overrides.
    cli.cloud = copy.deepcopy(AZURE_PUBLIC_CLOUD)
    token, _, selected_tenant = Profile(cli_ctx=cli).get_raw_token(resource=audience, tenant=tenant)
    return {"tokenType": token[0], "accessToken": token[1], "expires_on": token[2]["expires_on"], "tenant": selected_tenant}


if __name__ == "__main__":
    try:
        if len(sys.argv) != 3:
            raise ValueError("invalid token request")
        print(json.dumps(discover(sys.argv[1]) if sys.argv[2] == "subscriptions" else acquire(sys.argv[1], sys.argv[2])))
    except Exception:
        sys.exit(1)
