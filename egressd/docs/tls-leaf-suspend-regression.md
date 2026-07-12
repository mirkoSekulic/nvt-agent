# TLS leaf renewal after suspend

Egressd caches short-lived TLS leaves for mediated upstream hosts. Cache
freshness must use wall time because X.509 `NotAfter` is a wall-clock value.

The failure was reproduced with a long-running local agent after its macOS
host and Docker VM had slept:

- egressd minted a `chatgpt.com` leaf expiring at `2026-07-11T22:23:09Z`;
- fresh CONNECT requests on the following day were allowed but failed during
  the mediated TLS handshake;
- a new OpenSSL connection through the transparent path received that same
  expired leaf, matching both its serial and `NotAfter` in the mint log;
- no remint event occurred, while restarting only egressd restored service.

Go `time.Now` values contain a monotonic clock reading, and `Add` preserves it.
When both operands have monotonic readings, comparisons use monotonic time.
Linux monotonic time excludes system suspend, while certificate wall time
continues advancing. A cached deadline derived directly from `time.Now().Add`
could therefore remain "fresh" after its X.509 certificate had expired.

The cache now uses the parsed certificate's `NotAfter` as its deadline and
normalizes CA clock reads to UTC wall time. Parsed X.509 timestamps contain no
monotonic reading and exactly match the validity clients enforce. Tests pin
that structural invariant for local and upstream leaves and exercise repeated
renewal through the real CONNECT/TLS path.

Go's public time API cannot construct a value whose wall clock jumps while its
monotonic reading remains unchanged. The regression therefore combines the
captured live suspend evidence with structural deadline assertions and
injected wall-clock renewal tests.
