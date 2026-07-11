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

- the bug lives at the TLS server handshake boundary, not in broker OAuth,
  not in the upstream request path, and not in the CA mint helper alone;
- each new handshake must consult current leaf freshness through a fresh
  server TLS configuration boundary.

Regression coverage:

- `TestForwardProxyMITMRemintsExpiredLeafOnNextCONNECT`
- `TestForwardProxyMITMRemintsAcrossMultipleExpiryCycles`

These tests exercise the real CONNECT path, terminate TLS through egressd, and
verify that successive handshakes receive fresh certificates across multiple
expiry cycles.
