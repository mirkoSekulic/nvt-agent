# Compact Azure subscription scope

The complete [two-identity local example](../examples/azure/compact.example.yaml)
is 43 lines, independent of subscription count. Providers retain separate enrolled
broker state even when they use the same tenant. No subscription inventory is
authored or generated into user-managed files.

Previously a subscription appeared four times: `config.subscriptions`,
`allow.resources`, provider authorization rules and profile resources:

```yaml
brokerProviders:
  azure-one:
    plugin: azure
    config:
      tenant: 22222222-2222-2222-2222-222222222222
      subscriptions: [11111111-1111-1111-1111-111111111111]
    allow:
      resources: [arm:/subscriptions/11111111-1111-1111-1111-111111111111]
      authorization:
        defaultAction: deny
        rules:
          - {operation: observe, resource: azure/arm:/subscriptions/11111111-1111-1111-1111-111111111111}
# profiles.<profile>.azure:
#   - provider: azure-one
#     resources: [arm:/subscriptions/11111111-1111-1111-1111-111111111111]
#     authorization: {preset: observe}
```

The corresponding deliberately broader, automatically discovered ARM scope is:

```yaml
brokerProviders:
  azure-one:
    plugin: azure
    config:
      tenant: 22222222-2222-2222-2222-222222222222
      allSubscriptions: true
    allow:
      authorization: {preset: observe}
# profiles.<profile>.azure:
#   - provider: azure-one
#     inheritProviderScope: true
#     authorization: {preset: observe}
```

## Explicit choices and independent policy

`allSubscriptions: true` replaces **both** `config.subscriptions` and
`allow.resources`. These explicit fields must be absent, not empty. The ARM
ceiling becomes every **Enabled** subscription accessible through the enrolled
identity's configured tenant whose home `tenantId` equals that tenant.
Cross-tenant delegated subscriptions are excluded. Existing explicit subscription
and resource forms remain supported and are how to retain a narrower provider
ceiling. An all-subscriptions provider can still serve an explicitly narrowed
profile resource list. False/non-boolean flags and contradictory settings fail
validation; there is no implicit all mode.

Profile `inheritProviderScope: true` replaces its `resources` list and inherits
only the provider's ARM scope, never a resource wildcard. Omission grants nothing:
choose inheritance or a nonempty explicit list. Inheritance also works with an
existing explicit resource-group/resource-level provider ceiling. Provider
`allow.authorization: {preset: observe}` applies observe over its current ceiling;
concrete policies remain supported. Agent observe presets compile to concrete
rules over their selected scope. Both policies must allow the actual operation.
A preset cannot be combined with concrete policy fields. Endpoint/method/version
classification is unchanged; unknown endpoints remain denied even without observe.

Identity-wide Log Analytics is separate: set provider `allow.queryIdentity: true`
and profile `queryIdentity: true` alongside inheritance. Both are required in
compact form. Existing explicit `query-identity/<tenant>` selectors remain valid;
do not duplicate a query selector with the shorthand. Inheritance and
`allSubscriptions` alone never authorize queries. Cross-workspace/app KQL, body
targets and stored functions follow the identity's **complete Azure RBAC query
boundary**, not URL/workspace isolation or the discovered ARM subscription set.
See the existing [query boundary](azure-cli-mediation.md#query-boundary).

## Discovery, refresh and revocation

The broker's fixed helper performs
[`GET /subscriptions?api-version=2022-12-01`](https://learn.microsoft.com/en-us/rest/api/resources/subscriptions/list?view=rest-resources-2022-12-01)
with an ARM token acquired for the configured tenant. It does not run agent
commands or refresh the CLI's multi-tenant account inventory. No caller-selected
audience, URL or tenant is accepted. HTTPS redirects are refused. Pagination must
retain the exact ARM host, `/subscriptions` path and API version; only `$skiptoken`
is permitted in addition to `api-version`. Unknown continuation shapes fail closed.

Limits: 256 total records, 8 pages, 1 MiB aggregate HTTP response, 10 seconds per
HTTP request and the existing 30-second helper deadline. Duplicate, malformed or
oversized inventories fail as a whole, never truncate. Names are bounded to 512
UTF-8 bytes. Only ID/name/tenant are projected into public metadata.

Discovery runs lazily on the first catalog/authorization request, caches a complete
snapshot in broker memory for 60 seconds, then refreshes on demand. Restart drops
the snapshot, not enrollment. Newly accessible subscriptions become usable after
the next successful refresh; removed/disabled subscriptions disappear then.
Inventory changes need no YAML update, reconciliation or workstation replacement.
The expired snapshot is cleared **before** refresh: failure denies authorization
and metadata until a later successful refresh, never reusing stale scope. Empty
discovery is valid and denies all ARM access. An inventory change in one provider
does not alter another identity's snapshot.

Discovery caching plus existing egress material caching can delay local removal
enforcement by up to 120 seconds, plus already in-flight work/Azure propagation.
This is not instantaneous revocation; Azure remains authoritative for upstream
RBAC and token validity. Existing credential refresh and fail-closed behavior are
unchanged. No token, login name, MSAL cache or raw discovery response enters the
agent or audit log.

## Public CLI account metadata

For discovered providers, each `az` invocation fetches `/_nvt/catalog` from its
existing per-workload egress proxy using the non-secret provider selector.
Egress authenticates to broker `/v1/injection/catalog` using its own egress-role
identity, and the broker applies the paired agent's grant. Broker URLs/tokens are
never added to the agent environment. The provider emits one validated public JSON file
and no routes. Subscription metadata is filtered by provider and selected grant
ARM scope; query-only grants do not expose ARM inventory. Failures stop the CLI
invocation instead of falling back to its previous local metadata. An empty list
does not manufacture an account; commands needing one cannot run until access
exists. A removed default selection switches to the first remaining account.

`account list/show/set` and `NVT_AZURE_PROVIDER` retain separate public state per
identity. The adapter never authenticates to discover accounts. Explicit provider
configurations keep their existing static metadata behavior. Catalog traffic
terminates at the trusted egress service, not Azure; redirects are refused and
responses are bounded to 1 MiB. Failures never reflect broker bodies/credentials.

## Direct broker / Helm / operator

No new service, AgentRun field, CRD or agentd responsibility is needed. The small
provider-neutral public-catalog relay extends the existing broker/egress contract;
the Azure adapter does not need a backend-specific credential or mount.
Use the same compact provider config in direct broker `providers[]` or Helm
`broker.config.providers[]`, adding the existing broker-only `state-dir` separately
for each identity. The local compiler translates inheritance into the Azure-only
opaque selector `provider-scope/<tenant>`, interpreted by the Azure provider, not
by generic routing. Raw AgentRuns use the existing grant shape:

```yaml
provider: azure-one
resources: [provider-scope/22222222-2222-2222-2222-222222222222]
materialization: header-inject
egressHosts: [management.azure.com:443, api.loganalytics.io:443]
authorization:
  defaultAction: deny
  rules:
    - {operation: observe, resource: azure/provider-scope/22222222-2222-2222-2222-222222222222}
```

For direct broker identity registries omit `egressHosts`, which is a run/egress
field. AgentSchedule profiles can use `{preset: observe, resourcePrefix: azure/}`
instead of concrete rules. Add `query-identity/<tenant>` and its observe rule to
the grant, plus provider `allow.queryIdentity: true`, only for intended query
access. A provider-scope marker cannot mix with explicit ARM/workspace selectors;
choose inherited or narrowed scope.

In the builtin azure-cli plugin `config.providers.<provider>`, replace static
`subscriptions` with `catalog: true`, retaining `tenant` and `egress.provider`.
Do **not** add catalog preparation: the adapter fetches metadata through egress, and
existing Kubernetes kubeconfig preparation/routes remain untouched. Traffic still
uses explicit provider-scoped proxy selection when identities share Azure hosts.
The [existing Helm overlay](../examples/azure/helm-values.yaml) remains valid;
these are field substitutions, not a chart/schema redesign.

Review and apply configuration separately through the administrator workflow.
This feature does not migrate live files, copy enrollment, reconcile services,
restart workstations or modify cloud resources.
