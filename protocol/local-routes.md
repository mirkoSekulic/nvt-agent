# Local route metadata

`nvt.local-routes/v1` is the bounded, provider-neutral controller-to-gateway
route document for local runs. It is non-secret metadata, not an authorization
credential and not a general reverse-proxy configuration format.

Each active run contains its immutable run ID and owner issuer+subject,
display-only name, optional display/navigation source URL, profile/workflow
names, lifecycle state, readiness, one session host/path, and up to 64 named
host-only application exposures. Each route also carries one bounded internal
DNS target and TCP port selected by the trusted controller from the
deterministic run stack. The source is bounded HTTPS provenance only and never
selects a proxy target or controller behavior. The document never carries a
credential, bearer, provider value, or browser-selectable proxy policy.
Only `running` is ready;
pending, preparing, and stopping routes remain visible but unavailable so a
stable persistent URL survives restart and cleanup is observable. Terminal
routes disappear only after the controller has committed backend cleanup.

The internal API is:

- `GET /v1/routes/{run-id}` for one exact active run;
- `GET /v1/routes?limit=8&after={run-id}` for a stable bounded page.

JSON decoding rejects duplicate or unknown fields, malformed identities,
noncanonical host/path names, malformed source URLs, inconsistent
state/readiness, duplicate exposure names, trailing data, and documents over
256 KiB. Source URLs are at most 2048 bytes, use HTTPS without userinfo or
control characters, and retain valid query strings and fragments exactly. A
page contains at most eight runs; a consumer may accumulate at most 500 runs
through bounded pagination.
Any malformed, unavailable, looping, or overflowing page fails the complete
operation closed without using partial results.
The gateway also recomputes every expected host and path from its own startup
configuration and the opaque run/exposure names; controller/gateway routing
configuration drift is unavailable rather than implicitly adopted.

The local controller API is reachable only on the private control-plane
network. Browser authorization remains the gateway's responsibility. Each run
has unique internal/private networks and its untrusted agent namespace never
joins the shared proxy bridge or another run network. The trusted controller
exact-label verifies the fixed gateway container and attaches only that gateway
to each run's internal network. The gateway then dials the bounded target from
the route document after its owner policy succeeds. There is no agent-reachable
private Traefik entrypoint and no direct sibling-run network path.

The shared public Traefik configuration exposes `/agents/<run-id>/`,
`<run-id>.agent.localhost`, and `<exposure>.<run-id>.agent.localhost` only
through the gateway. Path session routing removes only `/agents/<run-id>`, sets
the forwarded prefix, and preserves the remaining path/query and WebSocket
upgrade. Application exposure routing is host-only and never rewrites its root
path.
