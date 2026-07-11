# TLS leaf renewal regression note

This document captures the failure mode behind the forward-proxy TLS leaf
renewal fix.

Observed behavior in production-shaped traffic:

- a host-specific MITM leaf was minted successfully;
- it was later reminted once as expiry approached;
- after that second leaf expired, a brand-new CONNECT + TLS handshake to the
  same injected host could still reach `decision=allow` but fail the client
  handshake with an expired certificate;
- restarting egressd immediately restored correct renewal behavior.

Root cause category:

- the bug lives at the TLS server handshake boundary where TLS 1.3 session
  tickets interact with leaf freshness;
- the server must keep resumption working for a fresh leaf, but rotate the
  ticket key when the leaf remints so stale tickets stop at the renewal
  boundary;
- the fix is not in broker OAuth, not in the upstream request path, and not in
  the CA mint helper alone.

Regression coverage:

- `TestForwardProxyMITMRemintsExpiredLeafOnNextCONNECT`
- `TestForwardProxyMITMRemintsAcrossMultipleExpiryCycles`

These tests exercise the real CONNECT path with one shared TLS 1.3 client
config and a populated session cache, then verify that:

- the connection resumes before each freshness boundary;
- a remint invalidates the stale ticket and yields a fresh certificate;
- the behavior holds across multiple expiry cycles.
