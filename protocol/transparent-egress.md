# Transparent egress relay

`captured` relays both local transport paths to egressd's CONNECT listener.

- The explicit listener preserves the client's standard CONNECT request,
  including a provider selector carried in proxy userinfo or
  `X-NVT-Capability`.
- The transparent listener recovers the original destination, inspects a
  bounded SNI or HTTP Host when available, and emits an ordinary
  `CONNECT host:port` request. It does not add a provenance or authorization
  marker.
- No header sent by the untrusted workload proves that traffic was transparently
  captured. The agent can forge every request header and can reach its paired
  egressd listener directly.

Egressd's trusted run configuration declares whether transparent routing is
enabled. An unambiguous route that does not require a hint may be selected
automatically. A `require_capability_hint` route always requires a valid
provider selector, regardless of any other request header. Multiple routes for
one host fail closed without a selector.

Provider selectors choose among already configured routes; broker grants remain
the authorization boundary.

Inspection is bounded. Malformed HTTP or TLS input, and a preface that reaches
the byte limit without completing, is denied. If a valid preface does not
reveal a hostname before the inspection timeout, captured may fall back only
to the recovered original IP; egressd still applies its full destination
policy. TLS credential injection therefore requires readable SNI. Fragmented
ClientHello records and ECH can take the opaque path and fail provider
authentication, but cannot cause a credential route to be guessed.

## Literal zero-secret workload

For enforced mediated runs, the operator resolves broker-owned inert
placeholder files before creating the workload and embeds them as ordinary
preseed entries. Route hosts and git flags come from the admitted AgentRun
grant. Runtime bootstrap treats `egress.operator-prepared: true` as a strict
contract: it never falls back to `brokerctl` for routing or placeholder files.

The workload disables Kubernetes service-account projection and carries no
broker, callback, egress, provider, or private-CA credential. Its NetworkPolicy
allows DNS and its paired egressd only. Egressd retains the paired egress
broker identity and CA key.

Lifecycle completion uses the agent container termination message:

```json
{"nvtLifecycleEvent":"plugin.agent.signal.done","outcome":"completed"}
```

The `outcome` is diagnostic. The operator derives the actual transition by
matching `nvtLifecycleEvent` against the owning AgentRun's `completeOn` and
`failOn` lists. Unmatched or malformed messages have no lifecycle authority.
