# Local route metadata

`nvt.local-routes/v1` is the bounded, provider-neutral controller-to-gateway
route document for local runs. It is non-secret metadata, not an authorization
credential and not a general reverse-proxy configuration format.

Each active run contains its immutable run ID and owner issuer+subject,
display-only name, profile/workflow names, lifecycle state, readiness, one
session host/path, and up to 64 named host-only application exposures. The
controller never publishes an upstream URL, port, container address, Docker
resource, bearer, provider value, or proxy policy. Only `running` is ready;
pending, preparing, and stopping routes remain visible but unavailable so a
stable persistent URL survives restart and cleanup is observable. Terminal
routes disappear only after the controller has committed backend cleanup.

The internal API is:

- `GET /v1/routes/{run-id}` for one exact active run;
- `GET /v1/routes?limit=8&after={run-id}` for a stable bounded page.

JSON decoding rejects duplicate or unknown fields, malformed identities,
noncanonical host/path names, inconsistent state/readiness, duplicate exposure
names, trailing data, and documents over 256 KiB. A page contains at most eight
runs; a consumer may accumulate at most 500 runs through bounded pagination.
Any malformed, unavailable, looping, or overflowing page fails the complete
operation closed without using partial results.
The gateway also recomputes every expected host and path from its own startup
configuration and the opaque run/exposure names; controller/gateway routing
configuration drift is unavailable rather than implicitly adopted.

The local controller API is reachable only on the private control-plane
network. Browser authorization remains the gateway's responsibility. The
shared local Traefik configuration exposes public `/agents/<run-id>/`,
`<run-id>.agent.localhost`, and `<exposure>.<run-id>.agent.localhost` routes
only through the gateway. Per-run Docker routers listen on a separate private
Traefik entrypoint, preventing a public Host-header request from bypassing
gateway policy. Path session routing removes only `/agents/<run-id>`, sets the
forwarded prefix, and preserves the remaining path/query and WebSocket upgrade.
Application exposure routing is host-only and never rewrites its root path.
