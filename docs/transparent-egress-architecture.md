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

The runtime keeps `HTTP_PROXY`, `HTTPS_PROXY`, and provider-scoped proxy URLs,
but points them at an explicit local listener:

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

### PR 1: gateway hardening

- deny private, cluster, link-local, metadata, and reserved destinations;
- make hostname resolution and dial atomic against DNS rebinding;
- add deployment-configured CNI `except` ranges;
- disable unnecessary service-account token mounting;
- add SSRF and destination-policy tests.

### PR 2: captured transport

- implement explicit and transparent local listeners;
- recover original TCP destination;
- perform bounded SNI/Host detection;
- relay CONNECT to egressd without credentials;
- preserve provider hints on the explicit path;
- add hermetic TCP, TLS, half-close, timeout, and malformed-input tests.

### PR 3: operator and network wiring

- add the transport enum and admission;
- render captured as a native sidecar;
- install IPv4/IPv6 OUTPUT and DinD PREROUTING rules after Docker starts;
- update NetworkPolicies and lifecycle conditions;
- keep direct and existing forward-proxy modes unchanged.

### PR 4: enforced cluster proof

- proxy-aware client succeeds;
- client with proxy variables removed still succeeds through transparent
  capture;
- raw TCP from the agent is captured;
- traffic from a DinD-spawned container is captured;
- direct bypass after removing local rules is denied by the CNI;
- cross-run egressd access is denied;
- private and metadata destinations are denied;
- injected upstream receives the fixture credential while scans find no secret
  in the Agent Pod;
- unmatched permitted HTTPS succeeds as a blind tunnel;
- ambiguous provider selection fails closed without a hint.

### PR 5: literal zero-secret cleanup

- remove the agent broker and callback bearer tokens;
- move inert bootstrap preparation to the operator or another trusted
  control-plane component;
- extend the non-possession CI scan to every bearer-material canary.

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

