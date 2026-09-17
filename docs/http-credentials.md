# Broker-backed HTTP credentials

`profiles.<name>.httpCredentials` explicitly grants **host-scoped credential
use**, independently of Git checkout intent. It selects existing
`brokerProviders` with `mediation.materialization: header-inject` and
`mediation.git: false`. Ordinary HTTPS requests and manual Git smart-HTTP
clone/fetch need no repository, workflow, checkout, or new runtime plugin.

Real PATs remain in broker-only secret-file bindings and trusted egress. Agent
configuration contains provider names, hosts, public CA trust, and non-secret
proxy selectors. Never put the PAT in curl headers, Git URLs, environment
variables, instructions, or agent credential files.

## API-only

This complete manifest uses an illustrative secret path, not a supplied
credential. Provision the private file through the existing local secret
contract, including its 64 KiB limit, ownership, permissions, stable-file and
symlink protections.

```yaml
apiVersion: nvt.dev/local/v1
secrets:
  forge-pat:
    file: ./.nvt-local/secrets/forge-pat
brokerProviders:
  forge-api:
    plugin: token
    config:
      injection-hosts: [forge.example.test]
      injection-scheme: Bearer
    secrets: {token-file: forge-pat}
    mediation:
      hosts: [forge.example.test]
      materialization: header-inject
      git: false
retentionPolicies:
  persistent:
    persistence: {workspace: true, runtimeState: true, dockerData: true}
profiles:
  investigation:
    runtime: {preset: shell, autonomy: trusted-local}
    httpCredentials: [forge-api]
    egress:
      domainPolicy: {defaultAction: deny, allow: [forge.example.test]}
workstations:
  - {name: investigation, profile: investigation}
```

Use the provider-scoped URL already published by runtime bootstrap:

```sh
curl --noproxy '' --proxy "$NVT_EGRESS_FORWARD_PROXY_URL_FORGE_API" \
  https://forge.example.test/api/projects
```

The proxy URL's provider username and fixed placeholder password select a
route; they are not an upstream credential. HTTP libraries can use the same
HTTPS proxy and installed public CA trust. Existing plugins can select a bound
provider with `egress: {provider: forge-api}`. Do not disable TLS verification.

## Shared PAT for Git and API

One host-scoped provider can serve both if the upstream accepts the same wire
authentication. If the API needs Bearer and Git needs Basic, add another
provider referencing the **same** secret and select both in the profile:

```yaml
brokerProviders:
  # Keep forge-api from above.
  forge-git:
    plugin: token
    config:
      injection-hosts: [forge.example.test]
      injection-basic-username: git
    secrets: {token-file: forge-pat}
    mediation:
      hosts: [forge.example.test]
      materialization: header-inject
      git: false
profiles:
  investigation:
    # Keep runtime and egress settings from above.
    httpCredentials: [forge-api, forge-git]
```

The public Basic username must match the upstream's PAT authentication.
`injection-scheme` and `injection-basic-username` are mutually exclusive.
Both providers resolve to one broker-private secret input.

```sh
git -c http.proxyAuthMethod=basic \
  -c http.proxy="$NVT_EGRESS_FORWARD_PROXY_URL_FORGE_GIT" \
  clone https://forge.example.test/team/project.git

git -C project -c http.proxyAuthMethod=basic \
  -c http.proxy="$NVT_EGRESS_FORWARD_PROXY_URL_FORGE_GIT" fetch origin
```

`http.proxyAuthMethod=basic` sends the non-secret proxy selector on CONNECT
without waiting for a challenge. It does not supply upstream authentication;
egress injects that separately. Select a provider explicitly when credentials
share a hostname. These bindings add no automatic Git URL rewrites or checkout
helpers. See the complete [shared-PAT example](../examples/http-credentials/manifest.example.yaml).

## Authority, compatibility, and reconciliation

- Each binding covers **every path and HTTP operation** on its exact declared
  HTTPS hosts (port 443). This is not an NVT repository, path, method, read-only,
  or `observe` policy. Administrators must choose **upstream read-only PAT
  scopes**. A profile named `api-only` is not restricted to API URL paths.
- Broker grants and injection-host ceilings, plus egress route/destination
  checks, prevent ungranted or wrong-host credential use. Redirects cannot
  carry the PAT to an undeclared hostname. Within a granted host, the credential
  can access anything its upstream scopes permit.
- Omitting `httpCredentials` grants nothing. A provider/secret declaration
  alone is not profile access. Configured injection hosts and mediation hosts
  must agree. Wildcards, URL/path selectors, and conflicting Git modes fail
  validation. No new wildcard/path-prefix policy is introduced.
- Existing repository-scoped `credentialProviders` and `injection-git: true`
  retain their behavior; they do not gain arbitrary API access. To combine
  enumerated checkout and HTTP, use separate repository-scoped Git and
  host-scoped HTTP providers backed by one secret. Host-scoped providers cannot
  masquerade as repository-scoped checkout bindings.
- The generated contract is the existing grant with `provider`,
  `materialization: header-inject`, `capabilities: [injection.headers]`, and
  `egressHosts: [forge.example.test:443]`. No repository wildcard or credential
  export is generated. Direct broker and Kubernetes configuration already
  support this contract; no CRD, agentd, or wire-protocol change is needed.
  Runtime selection remains container-native, independent of Docker/host paths.
- Binding updates use existing controller-owned configuration rollouts. A
  controlled runtime restart may occur, but no destructive workstation
  replacement or workspace/runtime-state/Docker-data volume deletion is
  required. Same-host bindings leave CA constraints unchanged; actual name-set
  changes retain the existing validated CA lifecycle. Never manually edit
  generated broker/controller files.

## Verification

Fixtures use a fake PAT, real broker/static provider and egress TLS proxy,
local `git http-backend`, and actual Git clone/fetch and curl. Coverage includes
shared-secret routing, grant/host denial, redirects, raw-credential non-export,
and absence from agent files and broker logs. Manifest/reconciliation tests
cover no-checkout profiles, unchanged repository scope, deterministic
rendering, and persistent ownership. No live forge or real credential is used.
