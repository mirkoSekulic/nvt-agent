"""Trusted fixed Azure CLI token acquisition entrypoint; stdout is broker-only."""
import copy
import importlib.metadata
import json
import re
import sys


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
        print(json.dumps(acquire(sys.argv[1], sys.argv[2])))
    except Exception:
        sys.exit(1)
