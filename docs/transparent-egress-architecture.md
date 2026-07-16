# Transparent Mediated Egress

## Purpose

Transparent mediated egress routes an AgentRun's permitted internet-bound TCP
traffic through its paired `egressd` endpoint while keeping provider
credentials outside the untrusted workload.

The enforceable invariant is:

> Every permitted internet-bound TCP connection traverses the paired
> `egressd` service; attempted bypasses are dropped by the CNI.

This is narrower than "every packet traverses egressd." Loopback, cluster DNS,
and explicitly approved control-plane traffic are excluded. UDP is not
currently proxied.

## Trust Boundaries

```mermaid
flowchart LR
    subgraph U[Untrusted workload]
        A[Agent and tools]
        D[Docker-in-Docker]
        C[captured]
        A --> C
        D --> C
    end

    subgraph T[Trusted runtime services]
        E[Paired egressd service]
        B[Broker]
    end

    C -->|CONNECT with destination and provider hint| E
    E -->|authorize and obtain material| B
    E -->|TLS with injected credential| X[External service]
```

- **Agent workload:** untrusted. It may contain source code, inert placeholders,
  public CA certificates, and route metadata, but not provider credentials or
  the interception CA private key.
- **`captured`:** credential-less transport plumbing for workload traffic. It is
  not a security boundary.
- **`egressd`:** trusted per-run egress service. It terminates only configured
  TLS destinations and injects only broker-approved material. Its deployment
  placement is owned by the operator or local renderer, not this contract.
- **Broker:** trusted credential, refresh, grant, quota, revocation, and audit
  authority.
- **CNI:** the bypass-prevention boundary. It must enforce NetworkPolicy.

## Modes

`AgentRun` keeps the feature optional:

```yaml
spec:
  egress: mediated
  egressEnforcement: true
  egressTransport: transparent
```

| Setting | Behavior |
| --- | --- |
| `egress: direct` | Existing direct networking and direct credential compatibility |
| `egress: mediated` | Broker-backed materialization and egressd routing |
| `egressEnforcement: true` | CNI-enforced guarantee that workload egress traverses the paired egress service |
| `egressTransport: redirect` | Tool-specific base URL or redirect configuration |
| `egressTransport: forward-proxy` | `HTTP(S)_PROXY` for proxy-aware tools |
| `egressTransport: transparent` | iptables capture for ordinary TCP clients |

The pre-1.0 compatibility field `spec.egressForwardProxy` has been removed.
Migrate `egressForwardProxy: true` to `egressTransport: forward-proxy`; use
`egressTransport: redirect` for the old false/default behavior.

## Traffic Capture

The transparent renderer installs IPv4 and IPv6 NAT rules in the workload
network namespace after Docker-in-Docker has initialized its chains. The setup
step receives only `NET_ADMIN`.

Conceptually:

```text
OUTPUT:
  allow loopback and capture-process traffic
  redirect remaining TCP to captured:15001

PREROUTING:
  redirect TCP arriving from the DinD bridge to captured:15001
```

The `captured` process recovers the original destination with
`SO_ORIGINAL_DST`. It inspects a bounded TLS ClientHello or HTTP preface to
recover the hostname when available, then opens a CONNECT tunnel to the paired
egress endpoint. It does not terminate TLS, inspect application payloads, or
hold credentials.

Proxy-aware clients may use `captured`'s explicit listener on port 15002. This
path preserves an explicit provider selector when more than one provider uses
the same hostname. Generic HTTP proxy variables remain unset in transparent
mode so normal HTTP also follows the transparent TCP path.

## Provider Selection

Hostname alone is not a credential selector. Multiple GitHub Apps, Codex
accounts, or Claude accounts may share one upstream host.

- Tool wrappers and runtime configuration select a broker provider explicitly.
- The selector is carried as non-secret routing metadata to egressd.
- Missing or ambiguous selection fails closed.
- `captured` never guesses a provider from host order or available grants.

Unmatched destinations may use an opaque blind tunnel only when destination
policy permits it. Credential injection always requires a configured hostname
and provider route.

## Credential Injection

For an injection route, egressd:

1. Matches the requested host and explicit capability to a configured route.
2. Asks the broker for injectable material under its egress identity.
3. Enforces grant, host, method, path, quota, and revocation decisions.
4. Terminates TLS using a per-run CA constrained to approved names.
5. Removes inert placeholders and injects the real header.
6. Re-originates TLS to a pinned upstream host and records a sanitized report.

The agent identity cannot call the injection endpoint. The egress identity is
paired to exactly one agent and cannot request capabilities not granted to
that agent. No credential values are logged.

The broker-to-egressd connection uses TLS because this is the internal leg that
carries real material. The interception CA private key is stored in a per-run
Secret and made available only to the trusted egress service, never the
untrusted workload.

## Bypass Prevention

iptables provides routing, not the final security boundary. A privileged
workload could alter local rules. Kubernetes enforcement therefore adds two
level-reconciled NetworkPolicies:

### Untrusted workload

Allows only:

- cluster DNS;
- the run's paired egress endpoint and declared listener ports;
- narrowly configured control-plane endpoints when required.

There is no internet CIDR rule. If local capture is removed, direct internet
traffic is denied by the CNI.

### Egress service

Allows:

- ingress from its paired workload;
- broker and DNS access;
- approved external TCP ports;
- explicitly labelled test fixtures when insecure upstreams are enabled for
  hermetic tests.

NetworkPolicy is additive. AgentRuns must use a namespace where untrusted users
cannot add policies that grant direct egress. The configured CNI must actually
enforce policy; the default kind networking does not provide that proof, so the
enforcement smoke uses Calico.

## Destination Safety

Blind tunnelling is constrained to prevent egressd becoming an SSRF gateway:

- loopback, private, link-local, metadata, multicast, reserved, benchmark, and
  deployment-supplied cluster CIDRs are denied;
- hostname resolution and dialing use one validated result to resist DNS
  rebinding;
- only configured external TCP ports are allowed, normally 80 and 443;
- injection routes pin hostname, port, TLS SNI, and outbound Host;
- only configured injection hosts are TLS-terminated.

Encrypted ClientHello can hide a hostname. When inspection cannot identify a
name, only an explicitly permitted opaque IP tunnel is possible; credentials
are never injected into that path.

## Local Compose

Compose uses the same `captured` process, redirect rules, provider selection,
and egressd behavior. The agent, DinD, and captured services share DinD's
network namespace; egressd uses a separate private Compose network.

This proves functionality and provider-secret non-possession. It is not equal
to Kubernetes enforcement: privileged local containers can modify iptables,
and Compose has no independent CNI NetworkPolicy fence. Do not use the Compose
capture test as evidence that bypass is impossible.

## Verification

The automated suites cover:

- proxy-aware, proxy-unaware, raw TCP, and DinD traffic;
- removal of local capture rules without restoration of direct egress;
- cross-run egressd denial;
- private and metadata destination denial;
- injection with provider-secret non-possession;
- blind tunnels for unmatched permitted hosts;
- explicit provider selection for shared hosts;
- broker denial, quota, revocation, and refresh failure.

See [Kubernetes smoke tests](../tests/operator/kind/README.md), the
[transparent transport contract](../protocol/transparent-egress.md), and the
[injection protocol](../protocol/injection.md).

## Limitations

- Transparent capture currently covers TCP, not arbitrary UDP or QUIC.
- DNS goes directly to the configured cluster resolver.
- Local Compose is a development backend, not an equivalent CNI security
  boundary.
- Direct and non-enforced mediated modes remain available for compatibility;
  they must not be described as enforced transparent egress.
