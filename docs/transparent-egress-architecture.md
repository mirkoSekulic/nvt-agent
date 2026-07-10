# Transparent Mediated Egress Architecture

## Status

This document defines the target architecture for transparently routing an
AgentRun's internet-bound traffic through its paired `egressd` Pod while
keeping provider credentials outside the Agent Pod.

The following pieces already exist:

- broker-owned provider credentials and OAuth refresh;
- per-run broker grants and paired agent/egress identities;
- placeholder-file and header-inject materialization;
- explicit forward-proxy mediation for proxy-aware tools;
- a separate per-run `egressd` Pod in enforced Kubernetes mode;
- per-run NetworkPolicies and a durable per-run interception CA.

Transparent capture for tools that ignore proxy configuration is not yet
implemented. This document is the design contract for that work.

## Goals

1. Every permitted internet-bound TCP connection from an enforced AgentRun
   traverses that run's paired `egressd` Pod.
2. A connection that bypasses local capture is dropped by the CNI rather than
   reaching the internet directly.
3. Provider credentials and the interception CA private key never enter the
   Agent Pod.
4. Proxy-aware and proxy-unaware tools use the same broker authorization,
   injection, audit, quota, and revocation paths.
5. Normal traffic to non-injection hosts can pass through as an opaque TCP
   tunnel without being TLS-terminated.
6. Provider selection is explicit when multiple providers share a hostname;
   the system never guesses which credential to inject.
7. The implementation remains portable across Kubernetes CNIs and compatible
   with hardened `RuntimeClass` implementations such as Kata Containers.

The enforceable network invariant is:

> Every permitted internet-bound connection traverses the paired `egressd`
> Pod; attempted bypasses are dropped by the CNI.

This is deliberately narrower than "every packet traverses egressd". Loopback,
cluster DNS, and explicitly approved control-plane traffic are not internet
egress and may remain direct.

## Non-goals

- General-purpose data-loss prevention.
- Decrypting traffic that does not need credential injection.
- Supporting arbitrary UDP protocols in the first version.
- Inferring a provider credential from process names, request content, or
  ambiguous destination hosts.
- Making local Docker Compose enforcement equivalent to CNI enforcement.
- Replacing broker authorization with network location or a capability hint.

## Trust Boundaries

### Agent Pod: untrusted

The Agent Pod contains:

- the agent runtime;
- the DinD sidecar, when enabled;
- a credential-less `captured` sidecar;
- a one-shot `net-init` container that installs routing rules;
- public CA certificates and inert placeholder values.

`captured` is transport plumbing, not a security or credential boundary. It
must not receive:

- a provider access or refresh token;
- the egress broker identity;
- the per-run CA private key;
- permission to call broker injection endpoints.

Only `net-init` receives `NET_ADMIN`, and it exits before the agent starts.
The agent container receives no network capabilities. A privileged DinD
container can still modify the shared network namespace, so local iptables
rules are not the enforcement boundary.

### Egressd Pod: trusted

The separate per-run `egressd` Pod contains:

- the paired egress broker identity;
- the per-run interception CA private key;
- short-lived provider access material fetched from the broker;
- the immutable run routing and provider map.

It performs:

- destination and capability policy checks;
- selective TLS termination;
- placeholder stripping and header injection;
- pinned upstream connection establishment;
- audit reporting, quotas, and revocation checks;
- opaque tunnelling for permitted non-injection destinations.

The egressd Pod must run with a read-only root filesystem where practical,
drop all unnecessary capabilities, use `RuntimeDefault` seccomp, disable its
automatic Kubernetes service-account token, and mount only its own per-run
Secrets.

### Broker: trusted credential authority

The broker remains the only owner of static root credentials and OAuth refresh
tokens. It authorizes egressd against the egress identity's paired agent and
the requested provider, host, method, path class, repository, and grant.

A provider hint is only a selector. It is never authorization by itself.

## Component Topology

```text
Agent Pod / optional Kata VM                 Trusted egress Pod
+--------------------------------+           +---------------------------+
| agent                          |           | egressd                   |
| DinD                           |           | - egress broker identity  |
| captured                       |--CONNECT->| - interception CA key     |
| net-init (exits after setup)   |           | - injected access tokens  |
|                                |           | - policy and audit        |
| no provider credentials        |           +-------------+-------------+
+--------------------------------+                         |
                                                           +--> broker
                                                           +--> internet
```

The operator creates the egressd Pod, Service, CA material, broker policy, and
NetworkPolicies before creating the Agent Pod.

## Traffic Paths

### Proxy-aware clients

The runtime keeps `HTTPS_PROXY` and provider-scoped proxy URLs, pointing them
at an explicit local listener. `HTTP_PROXY`, lowercase `http_proxy`, and
generic `ALL_PROXY` remain unset in transparent mode because the downstream
explicit listener is CONNECT-only; ordinary HTTP takes the transparent TCP
path instead.

```text
tool
  -> captured 127.0.0.1:15002
  -> CONNECT host:port, preserving the non-secret provider hint
  -> paired egressd Service
```

Using a local explicit listener avoids a special iptables exclusion for the
egressd Service and preserves the current provider selector carried in proxy
userinfo or `X-NVT-Capability`.

### Proxy-unaware clients

Normal TCP connections are redirected to a separate transparent listener:

```text
tool
  -> connect to the original destination
  -> iptables REDIRECT
  -> captured 127.0.0.1:15001
  -> recover SO_ORIGINAL_DST
  -> inspect a bounded TLS ClientHello or HTTP Host when available
  -> CONNECT host-or-IP:port to paired egressd
```

Inspection is bounded by a small byte limit and timeout. `captured` does not
terminate TLS and must not log payload bytes, headers, cookies, or credentials.

When no hostname can be determined, the original IP and port may be used only
for an opaque tunnel after egressd applies its destination policy. Credential
injection requires a configured DNS hostname.

### Egressd decision

For each CONNECT request, egressd makes one of three decisions:

1. **Inject**: the host and capability match a configured injection route.
   Egressd terminates TLS under the per-run CA, obtains injectable material
   from the broker, strips placeholders, injects headers, and re-originates TLS
   to the pinned upstream.
2. **Blind tunnel**: the destination is allowed but has no selected injection
   route. Egressd relays opaque bytes and cannot see application content.
3. **Deny**: the destination, port, provider selector, or broker policy is not
   allowed. The connection fails closed.

An injectable host never falls back to an uncredentialed direct upstream after
an injection or broker error.

## Provider Selection

Destination host alone is insufficient when one AgentRun has multiple
credentials for the same host. This is a fundamental property of transparent
networking, not an implementation gap.

Rules:

- one configured provider for a host may be selected automatically;
- multiple providers for one host require an explicit non-secret provider
  hint from a runtime profile or tool wrapper;
- a missing or invalid required hint never causes a guessed injection;
- transparent traffic without a hint may blind-tunnel only when the route
  explicitly permits ordinary uncredentialed traffic to that shared host;
- broker authorization is always applied after route selection.

This preserves support for multiple Claude or Codex profiles and multiple
GitHub Apps in one run without making provider selection heuristic.

## Iptables Routing

Use `REDIRECT` for the first TCP-only implementation. `TPROXY` adds policy
routing and transparent-socket complexity that is not needed until UDP or
source-address preservation becomes a demonstrated requirement.

Conceptual IPv4 rules:

```text
nat/NVT_OUTPUT:
  RETURN loopback
  RETURN traffic created by captured
  REDIRECT remaining TCP to 15001

nat/OUTPUT:
  jump to NVT_OUTPUT

nat/PREROUTING:
  redirect TCP arriving from the DinD bridge to 15001
```

Equivalent IPv6 rules must be installed, or IPv6 must be explicitly denied.
Partial IPv4-only capture is not acceptable on a dual-stack cluster.

The container order is:

```text
captured native sidecar
  -> DinD native sidecar and startup probe
  -> net-init installs rules after Docker initialized its chains
  -> agent container starts
```

The captured UID exclusion prevents recursion but is not a security boundary:
a root workload can run under that UID. The CNI fence is what makes bypass
fail closed.

## CNI Enforcement

The Agent Pod NetworkPolicy permits only:

- cluster DNS on TCP/UDP 53;
- its paired egressd Pod and declared listener ports;
- narrowly defined internal control-plane endpoints that remain necessary.

There is no internet CIDR rule on the Agent Pod.

The egressd Pod NetworkPolicy permits:

- ingress from its paired Agent Pod only;
- broker access;
- DNS;
- approved external TCP ports.

NetworkPolicies are Pod-level and additive. AgentRuns therefore belong in a
dedicated namespace where untrusted users cannot create another policy that
adds direct egress. The production CNI must enforce NetworkPolicy; the operator
must create policies before the Agent Pod and an in-cluster smoke test must
prove that direct egress is denied.

The hard guarantee is preserved even when the privileged DinD sidecar flushes
local rules:

- transparent functionality may break;
- direct internet access remains denied by the CNI;
- the agent can still reach only the paired egressd and explicit internal
  exceptions.

## Local Docker Compose Backend

Docker Compose remains the development backend and supports two explicit
modes. The direct mode must remain unchanged. The mediated mode should exercise
the same capture, provider-selection, injection, and non-possession contracts
as Kubernetes, but it must not claim the same bypass-resistant enforcement as
a CNI NetworkPolicy.

### Direct mode

Direct mode preserves the current local workflow:

```text
agent or plugin
  -> brokerctl with the restricted agent broker identity
  -> broker
```

No `captured` or `net-init` container is required, and the existing local
file-bundle and broker-backed development paths remain available.

### Mediated transparent mode

The target Compose topology is:

```text
Agent/DinD network namespace                 Trusted egress namespace
+--------------------------------+           +---------------------------+
| agent                          |           | egressd                   |
| DinD                           |           | - egress broker identity  |
| captured                       |---------->| - interception CA key     |
| net-init (exits after setup)   |           | - provider access tokens  |
+--------------------------------+           +-------------+-------------+
                                                           |
                                                           +--> broker
                                                           +--> internet
```

- `agent`, DinD, and `captured` share the DinD service network namespace.
- `net-init` temporarily joins that namespace with `NET_ADMIN`, installs the
  IPv4/IPv6 redirect rules, and exits before the agent starts.
- `egressd` must not use `network_mode: service:docker`; it runs in a separate
  Compose network namespace and connects to `captured` over a private Compose
  network.
- Only the egressd-specific environment file contains the paired egress broker
  identity. The agent receives public CA certificates, inert placeholders,
  routes, and non-secret provider selectors only.
- HTTPS and provider-scoped explicit proxy variables continue to point to the
  local `captured` listener. Plain HTTP proxy variables remain unset, and
  transparent rules capture both HTTP and tools that ignore proxy variables.
- The current `MEDIATED=1`-style configuration may select this topology while
  direct mode remains the default local compatibility path.

For literal zero-secret mode, the trusted host-side `agent-init` flow prepares
placeholder files and routing metadata before the containers start. Plugins
that require ongoing broker operations must use a credential-less local
egressd contract or ordinary mediated network requests; they must not receive
`NVT_BROKER_TOKEN`. Lifecycle reporting must similarly avoid placing a reusable
callback bearer token in the agent container.

### Compose enforcement boundary

Compose can prove transparent functionality and provider-secret
non-possession, but ordinary Docker networking is not equivalent to a
Kubernetes CNI fence. A privileged DinD container shares the agent network
namespace and can alter local iptables rules. Networks used for inbound
Traefik/code-server routing may also provide outbound connectivity unless the
host applies additional firewall or namespace policy.

Therefore the supported claims are:

- Kubernetes enforced mode: attempted local-capture bypass is denied by the
  CNI, so permitted internet traffic must traverse the paired egressd Pod.
- Compose mediated mode: traffic is transparently routed through egressd and
  secrets remain outside the agent container, but bypass resistance is
  best-effort unless a separate host-level network enforcement mechanism is
  configured.

Local tests must describe which claim they prove and must not use a successful
Compose capture test as evidence of CNI-equivalent isolation.

## Destination and SSRF Protection

Allowing unmatched blind tunnels makes egressd a general egress gateway. It
must not become a path into cluster or cloud-internal networks.

Before dialling, egressd must reject:

- loopback and unspecified addresses;
- RFC1918 and other private ranges;
- link-local and cloud metadata addresses;
- Pod, Service, node, and VNet CIDRs;
- multicast, broadcast, and reserved ranges.

For hostname destinations, egressd resolves once, validates every candidate,
selects an allowed address, and dials that exact address. It must not validate
one resolution and let a later dial resolve the hostname again. TLS Host and
SNI remain the validated hostname.

The egressd NetworkPolicy must mirror these exclusions using `ipBlock.except`
for deployment-specific cluster and VNet ranges. Application validation and
CNI policy are separate layers.

## Protocol Coverage

The first version guarantees routing for permitted external TCP traffic.

The operator renders one external TCP port contract into both egressd and its
NetworkPolicy. It is configurable through Helm and defaults to ports 80 and
443 so normal HTTP package/bootstrap traffic and HTTPS work together.

- HTTPS, HTTP, Git-over-HTTPS, WebSocket, and SSE use TCP and are covered.
- Generic non-HTTP TCP can be blind-tunnelled when its port is explicitly
  allowed.
- Cluster DNS remains an explicit direct exception.
- Other UDP is denied initially. QUIC/HTTP3 clients must fall back to TCP.
- ICMP and raw sockets are unsupported and should be blocked by capabilities,
  seccomp, and network policy.
- TLS clients using certificate pinning can blind-tunnel, but cannot receive
  injected credentials through MITM unless they support the per-run CA.
- Encrypted ClientHello may hide the hostname from transparent capture;
  explicit proxy mode remains the reliable path for credentialed tools.

## Secret Inventory and Literal Zero-secret Mode

The current mediated invariant is **zero provider credentials in the agent**.
It is not yet literally zero bearer material: the Agent Pod currently receives
a restricted broker token and callback token, and Kubernetes mounts a service
account token unless explicitly disabled.

For a literal zero-secret Agent Pod:

1. Set `automountServiceAccountToken: false` on agent, captured, and egressd
   Pods unless a Pod explicitly needs Kubernetes workload identity.
2. Have the operator prepare inert placeholder files and routing metadata
   before the Agent Pod starts.
3. Remove `NVT_BROKER_TOKEN` from the agent environment. Agent tools use the
   paired egressd path and non-secret provider hints instead.
4. Replace the callback bearer token with operator-observed container status,
   termination messages, or a per-run source-isolated callback that carries no
   reusable credential.
5. Continue scanning agent filesystem, environment, and process arguments for
   provider tokens, broker tokens, callback tokens, CA private keys, and test
   canaries.

The public CA certificate, route metadata, provider names, and placeholders are
not secrets.

Zero possession does not mean zero authority. The agent can still ask egressd
to perform actions allowed by its broker grants; it cannot retrieve or export
the credential used for those actions.

## Response Reflection Boundary

An upstream that reflects an injected credential in its response can return a
secret to the agent even if request-side mediation is perfect. Injection grants
must therefore be limited to trusted hosts and path classes that do not mint or
reflect credentials.

Credential-issuing, token-inspection, echo, and arbitrary relay endpoints must
not be covered by broad injection routes. Response scanning or redaction can be
added for specific textual protocols, but it is not a complete generic defense
for compressed, binary, streaming, or WebSocket responses.

## CRD Shape

Do not add another independent boolean for transparent mode. The existing
booleans already form a growing state matrix. Introduce an explicit transport
enum while preserving old fields as compatibility inputs during migration:

```yaml
spec:
  egress: mediated
  egressEnforcement: true
  egressTransport: transparent # redirect | forward-proxy | transparent
```

Admission rules:

- `direct` permits only direct/file-bundle behavior;
- `forward-proxy` and `transparent` require `mediated` plus enforcement;
- `transparent` requires a NetworkPolicy-capable deployment;
- mediated modes reject usable credential bundles and runtime auth mounts;
- invalid combinations fail before any Agent Pod is created.

## Why This Design

### Egressd in the Agent Pod

Rejected for enforced production mode. It places the egress broker identity and
CA private key in the same Pod or Kata VM as untrusted code.

### Service mesh

A mesh can provide transparent capture and workload identity, but nvt would
still need custom provider selection, dynamic CA handling, broker integration,
placeholder stripping, and injection policy. Requiring a mesh would add a large
control plane and make the core deployment-specific.

### CNI/eBPF capture

This can provide stronger sidecar-less capture and is a reasonable future
operator transport driver. It should reuse the same captured-to-egressd and
broker contracts rather than becoming the only supported backend.

### Custom default gateway or secondary CNI

Making a per-run egress Pod the Agent Pod's layer-3 default gateway is strong,
but requires Multus, a custom CNI, or deployment-specific routing. It is not the
portable default.

### Proxy environment only

Retained as the explicit path because it carries exact host and provider
information, but insufficient on its own for tools that ignore proxy settings.

## Delivery Sequence

Deliver the architecture in two PRs. PR 1 establishes the external traffic
path and provider-credential non-possession. PR 2 removes the remaining
restricted control-plane bearer material and earns the stronger literal
zero-secret claim. Do not describe PR 1 as literal zero-secret.

### PR 1: transparent, enforced egress

This PR contains four reviewable commits. Each commit keeps its own tests and
must remain independently reviewable even though the feature merges as one
PR.

#### Commit 1: gateway hardening

- deny private, cluster, link-local, metadata, and reserved destinations;
- make hostname resolution and dial atomic against DNS rebinding;
- add deployment-configured CNI `except` ranges;
- add SSRF and destination-policy tests.

#### Commit 2: captured transport

- implement explicit and transparent local listeners;
- recover the original TCP destination;
- perform bounded SNI/Host detection;
- relay CONNECT to egressd without provider credentials;
- preserve provider hints on the explicit path;
- add hermetic TCP, TLS, half-close, timeout, and malformed-input tests.

#### Commit 3: operator and network wiring

- add the transport enum and admission;
- render captured as a native sidecar;
- install IPv4/IPv6 OUTPUT and DinD PREROUTING rules after Docker starts;
- update NetworkPolicies and lifecycle conditions;
- keep direct and existing forward-proxy modes unchanged.

#### Commit 4: enforced cluster proof

- prove a proxy-aware client succeeds;
- prove a client with proxy variables removed succeeds through transparent
  capture;
- prove raw TCP from the agent is captured;
- prove traffic from a DinD-spawned container is captured;
- prove direct bypass after removing local rules is denied by the CNI;
- prove cross-run egressd access is denied;
- prove private and metadata destinations are denied;
- prove the injected upstream receives the fixture credential while scans find
  no provider credential or CA private key in the Agent Pod;
- prove unmatched permitted HTTPS succeeds as a blind tunnel;
- prove ambiguous provider selection fails closed without a hint.

PR 1 is complete when every permitted external TCP path either reaches the
paired egressd or is denied by the CNI, including DinD traffic. The Agent Pod
may still contain its existing restricted broker, callback, and Kubernetes
service-account bearer material; none of those identities may retrieve a
provider credential.

### PR 2: literal zero-secret Agent Pod

- set `automountServiceAccountToken: false` on the Agent Pod and on other
  per-run Pods that do not require Kubernetes workload identity;
- remove the agent broker token and callback bearer token;
- move inert placeholder and routing preparation to the operator or another
  trusted control-plane component;
- replace bearer-authenticated lifecycle callbacks with operator-observed Pod
  status, termination messages, or a source-isolated non-credentialed event
  path;
- remove direct Agent Pod access to broker and callback endpoints when no
  longer needed;
- extend the non-possession CI scan to provider tokens, broker tokens, callback
  tokens, service-account tokens, CA private keys, environment, process
  arguments, filesystems, mounts, and logs;
- prove direct, existing non-enforced mediated, and local development modes do
  not change unless explicitly configured.

PR 2 is complete only when the Agent Pod contains public CA certificates,
inert placeholders, route metadata, and provider selectors, but no reusable
bearer or private-key material. Egressd and broker remain the only components
that possess provider credentials.

## Acceptance Criteria

The transparent architecture is complete only when all of the following are
machine-tested:

1. No provider credential or CA private key appears in the Agent Pod's
   filesystem, environment, process arguments, logs, or mounted volumes.
2. A proxy-unaware process reaches a permitted external TCP endpoint through
   the paired egressd.
3. The same connection fails when egressd is unavailable; it never falls back
   to direct internet access.
4. Removing or bypassing local iptables rules does not restore direct egress.
5. DinD traffic follows the same policy as agent-process traffic.
6. Only configured injection hosts are TLS-terminated.
7. Unmatched allowed hosts remain opaque blind tunnels.
8. Private and cluster destinations cannot be reached through blind tunnels.
9. Multiple providers sharing a host require and honor an explicit selector.
10. Broker denial, revocation, quota exhaustion, and refresh failure remain
    fail-closed and sanitized.
