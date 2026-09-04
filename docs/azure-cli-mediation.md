# Broker-mediated Azure CLI

The optional `azure` executable provider supports ordinary Azure CLI resource
inspection and Log Analytics queries without putting a usable Azure credential
in the agent. Real Azure user enrollment, MSAL caches and token refresh stay in
a private, persistent broker directory for each identity. The runtime plugin
exports `az` and supplies only account metadata and
`NVT-PLACEHOLDER-NOT-A-KEY`. `az account get-access-token` returns that inert
value; broker token/file/header export endpoints are unavailable to the agent.

## Installation and compatibility

The supported release is **Azure CLI/core 2.89.1**, with **log-analytics
1.0.0b1** for `az monitor log-analytics query`. The CLI and extension are optional:
build the normal broker/runtime images, then apply
[`examples/azure/Dockerfile`](../examples/azure/Dockerfile) separately to each
using its `BASE_IMAGE` build argument. Select those image tags through the
existing local platform or Helm image configuration. Azure dependencies are
not installed in default images. The CLI Python environment lives at
`/opt/nvt-azure`; extensions live at `/opt/nvt-azure/extensions`.

The adapter uses the pinned CLI's managed-identity credential factory, replacing
it with an inert implementation. This covers both SDK `get_login_credentials`
and `get_raw_token`; it does not fake a real MSAL cache. It seeds a separate
`$HOME/.nvt-azure/<provider>/azureProfile.json` with public subscription metadata.
Each invocation preserves an account selection that still exists in that
metadata. Provider selection uses `NVT_AZURE_PROVIDER=azure-dev az ...`; omission
uses the plugin's `egress.provider`. It selects the exact provider-scoped proxy
URL exported by generic runtime bootstrap, never guesses from Azure's hosts.
Declare all selectable providers in plugin `config.providers` and grant each
in the run. Local `profiles[].azure` generates this plugin configuration.

No login is performed by this adapter. Its placeholder can be recreated after
expiry without contacting any authentication service. Broker-side CLI/MSAL
refreshes the real token. Dynamic extension installation, telemetry, automatic
version lookup and CLI command-file logging are disabled. Upgrades require
rerunning the actual-CLI matrix and reviewing new endpoint/version variants.
The adapter is untrusted convenience code: raw requests and edited/bypassed
wrappers encounter the same trusted egress authorization. A user can still
explicitly print their own query or enable debugging in modified agent code;
NVT's broker/egress audit never records query text, bodies or bearer values.

## Enrollment, refresh and failure

Enroll each user in its own broker-mounted directory, using the broker's
ordinary CLI rather than the runtime adapter. For the direct/Helm example,
run this in a trusted administrative container that mounts only that broker
state, or an administrator shell in the broker container:

```sh
umask 077
AZURE_CONFIG_DIR=/state/azure/azure-dev /opt/nvt-azure/bin/az login \
  --tenant 22222222-2222-2222-2222-222222222222 --use-device-code
```

For local YAML the compiler fixes the directory at
`/var/lib/nvt/broker/providers/<provider>`, in the existing broker-private
persistent volume. Create the directory with mode 0700 before enrollment.
Do not mount it into the agent, copy an existing workstation login cache, or
run enrollment in an agent container. Use separate directories/provider
instances for separate logins, even in the same tenant. The direct/Helm
administrator must maintain this directory separation and broker-only mounts.
Normal broker restart retains these directories and account selections.

The initial token source invokes only a fixed, pinned Azure CLI token helper
with the configured tenant and one of two fixed audiences. The helper uses
the CLI's `Profile.get_raw_token` refresh path and pins the built-in public
Azure cloud/authority in memory, overriding any enrolled CLI cloud selection.
It never executes agent commands or accepts a requested token audience. Child
environment, output size (1 MiB), token size (64 KiB) and time (30 seconds) are
bounded. Stderr and parsing/refresh errors are suppressed and replaced with
`azure-credentials-unavailable`. The tenant and expiry in the CLI result are
validated. The provider does not keep a second token cache. Egress material
expires within 60 seconds and at least 60 seconds before token expiry; failures
never fall back to stale material. Existing grant revocation has the same
bounded in-flight/cache window as other mediated providers (up to 60 seconds).

If consent, MFA, revocation or tenant policy prevents silent refresh, access
fails closed until the administrator reauthenticates the exact directory.
An existing access token's validity remains Azure's decision; the provider
cannot independently detect Entra revocation before Azure rejects it.
The internal `AzureCLITokenSource.acquire(audience)` seam can be replaced with
workload/managed identity without changing the agent or generic protocol.
Future sharing with a kubeconfig credential helper need not change kubeconfig.

## Scopes and optional observe authorization

See the complete [local YAML](../examples/azure/manifest.example.yaml),
[direct broker configuration](../examples/azure/broker.yaml) and
[Helm/operator overlay](../examples/azure/helm-values.yaml).

Resource selectors are explicit, lowercase, canonical strings:

- `arm:/subscriptions/<uuid>`: subscription scope.
- `arm:/subscriptions/<uuid>/resourcegroups/<name>`: resource-group scope.
- `arm:/subscriptions/<uuid>/resourcegroups/<name>/providers/<namespace>/<type>/<name>`:
  exact resource scope, including its reviewed read subresources.
- `query-identity/<tenant-uuid>`: explicit acceptance of that provider identity's
  complete Azure RBAC query boundary, described below.

ARM paths are case-insensitive but encoded paths, dot segments, repeated
slashes, duplicate/unsupported query options and upgrades are denied. A list
requires scope over its entire parent; individual-resource grants never imply
permission to list their parent. A tenant is fixed per provider, subscriptions
are administrator configured, and grant scopes intersect the provider ceiling.

Local `authorization: {preset: observe}` expands to a default-deny policy with
`{operation: observe, resource: azure/<selector>}` for each grant selector.
AgentSchedule profiles use the generic authoring field `resourcePrefix: azure/`
with that preset. Omission of the prefix preserves existing kubeconfig
`context/` expansion. The operator resolves both fields before creating the
AgentRun. Raw AgentRuns and direct broker agents use concrete rules only:

```yaml
provider: azure-dev
resources: [arm:/subscriptions/11111111-1111-1111-1111-111111111111]
materialization: header-inject
authorization:
  defaultAction: deny
  rules:
    - operation: observe
      resource: azure/arm:/subscriptions/11111111-1111-1111-1111-111111111111
```

Set an independent concrete `allow.authorization` ceiling on the provider.
Both the provider ceiling and selected grant must allow an actual operation.
Omitting authorization removes that layer's observe restriction, not resource
ceilings or credential isolation. The initial non-observe mutation coverage is
explicit resource DELETE and VM start/restart/deallocate POST; these still need
both policy layers to permit `mutate`. Other unclassified operations remain
denied even without a preset. This is deliberately finite service coverage,
not an unrestricted Azure API tunnel. No policy mode enables Azure credential
export endpoints, role changes, deployments, run-command, Key Vault values,
AKS get-credentials, storage keys/SAS or batch/proxy APIs.

## Query boundary

Log Analytics' POST query API accepts extra workspace targets in its body,
cross-workspace KQL and stored functions. The provider therefore does **not**
offer per-agent workspace data isolation using only the URL. A query requires
`query-identity/<tenant>` in both provider ceiling and agent grant, explicitly
acknowledging all data that identity can query according to Azure RBAC. The
allowed URL workspace is not an additional isolation boundary. The provider's
configured subscription list restricts ARM, not this query scope. Cross-workspace
KQL and body workspace targets are intentionally passed through under this
identity-wide grant, without inspecting or logging the body.

A `workspace/<uuid>` selector alone denies query operations; mixing a narrow
workspace selector with the identity-wide query selector is rejected as
misleading. Use separately enrolled identities with appropriately narrow Azure
RBAC if different agents need different query data boundaries. This delivery
does not change roles or assignments. Restriction of read data and prevention
of mutations are separate guarantees. The reviewed POST query endpoint is
read-only; arbitrary POSTs, GET query-string KQL and batch queries are denied.
No regex over arbitrary KQL is used as an isolation claim, and the existing
body-independent materializer/cache contract remains unchanged.

## Initial command/API coverage

All ARM entries below are under a granted subscription/resource-group/resource.
Only these version/type pairs and narrowly allowed query options are supported.

| Commands | Reviewed endpoint/version |
| --- | --- |
| `account list/show/set` | Local public metadata only |
| `group list/show` | ARM resourcegroups, `2024-11-01` |
| `resource list --resource-type <reviewed-type>` | ARM resources, `2024-11-01`; exact type filter, optional CLI metadata expansion |
| `resource show --ids ... --api-version ...` | Same reviewed concrete type/version GET as its native command; no generic wildcard bypass |
| `vm list/show/get-instance-view` | Microsoft.Compute/virtualMachines, `2024-11-01`, `2025-04-01`, `2025-11-01`; only instanceView expansion/subresource |
| `network vnet/nic/nsg/public-ip list/show` | Microsoft.Network virtualNetworks `2025-07-01`, networkInterfaces `2023-11-01`, networkSecurityGroups `2022-01-01`, publicIPAddresses `2024-07-01` |
| `aks list/show` | Microsoft.ContainerService/managedClusters, `2026-05-01` |
| `storage account list/show` | Microsoft.Storage/storageAccounts, `2025-08-01` |
| `deployment group list/show` | Microsoft.Resources/deployments, `2025-04-01`; inspection only |
| `monitor metrics list --resource ... --metric ...` | Reviewed resource + Microsoft.Insights/metrics, `2018-01-01` |
| `monitor activity-log list` | Subscription Microsoft.Insights/eventtypes/management/values, `2015-04-01`; requires whole-subscription scope |
| `monitor log-analytics query` | POST `api.loganalytics.io/v1/workspaces/<uuid>/query`, identity/RBAC scope |

Unknown types/versions, Resource Graph, automatic API-version discovery for
`resource show`, generic unfiltered resource lists, opaque continuation-token
pagination and other CLI extensions/data-plane services are unsupported and
fail closed. A paginated command may return an error after its first page;
this delivery does not claim fleet-wide listing completeness. Inspection APIs
can return user-supplied metadata or deployment outputs containing sensitive
data; observe is operation authorization, not response-content redaction.

Upstream references: [VM GET and expansion](https://learn.microsoft.com/en-us/rest/api/compute/virtual-machines/get?view=rest-compute-2025-11-01),
[query request format](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/api/request-format),
[cross-workspace queries](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/cross-workspace-query).

## Verification

The compatibility proof first exercised actual CLI command/SDK authentication
and serialization with an isolated HTTP fixture. A separate egress conformance
test exercises actual CLI processes over real CONNECT/TLS with two provider
selectors and fixture upstreams. Neither agent state contains a usable Azure
credential. Broker conformance separately exercises the real executable-provider
protocol, role boundaries, refresh failure and authorization-before-injection.

To run the optional actual-CLI checks, install the pinned CLI/extension in an
isolated environment, set `NVT_AZURE_CLI_PYTHON` to its Python executable and
`AZURE_EXTENSION_DIR` to its extension directory, then run `tests/runtime` and
`egressd` Go suites. Without this explicit environment these optional tests
report a skip; provider and inert-adapter tests still run normally.

**Live Azure validation was not run:** no authorized Azure enrollment was
supplied for this task. All success and denial tests use isolated fixtures;
no running workstation, cloud resource, role assignment or real credential was
changed. The fixture results prove CLI/proxy compatibility, not live Azure
permissions or service availability.
