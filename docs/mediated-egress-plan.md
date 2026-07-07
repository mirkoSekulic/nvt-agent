# Plan: Mediated Credential Egress

Status: living document — Phases 0–4 completed (#53, #54, Phase 2 gate, #56, #58, #59, Phase 4 git-over-HTTPS mediation)
Version: v3.7 (Phase 5 PR 6a landed: own-Pod egressd + CNI-enforced NetworkPolicies behind `spec.egressEnforcement`, egress-denied smoke on the Calico kind cluster)

## Goal

Not a single raw secret is available to the agent container — including short-lived derived credentials like GitHub App installation tokens. Today, providers like `codex-oauth` materialize a usable access token into the container as a file bundle; a prompt-injected agent can exfiltrate it for its lifetime. Target state: credentials are injected into outbound requests by a trusted sidecar at the network edge, while the broker keeps doing what it does today — policy, refresh, audit. On that choke point we add per-request audit, quotas, and mid-run revocation.

The invariant is a bright line, CI-enforced: inspect the container — filesystem, env, process args — and find zero secret material. No "small accepted exposures": exceptions accumulate and erode. Capabilities that cannot be mediated **at the current phase** are disallowed in mediated mode, not excepted — and coverage widens over phases (redirectable HTTP first; arbitrary/hardcoded-endpoint tools via transparent mode in Phase 6). Truly unmediable transports (git-SSH, file-native-TLS binaries) stay disallowed.

The feature is optional and per-grant: "off" is exactly today's system, not a degraded mode.

## Two guarantees, deliberately decoupled

The plan delivers two properties that defend different threats and must not gate each other:

| Guarantee | Threat defeated | Depends on | Ships in |
|---|---|---|---|
| **Credential non-possession** — no token in the container | credential theft / exfiltration | egressd + broker identity-split only | Phases 1–3 |
| **Egress default-deny** — agent cannot reach arbitrary hosts | data exfiltration (source, prompts) | enforcement outside the agent's privilege domain | Phase 5, independently |

Non-possession stands alone: with no token in the container, direct reach to an API host yields 401. Egress-deny is defense-in-depth against a different attack. Each gets its own CI smoke test; the achievable guarantee must never wait on the hard one.

## Architecture

### 1. Broker: materialization modes + generic injection capability

Each capability grant gets a materialization mode:

- **`file-bundle`** — current behavior (auth files written into the container via `/v1/files` + `broker-auth-files`). Stays supported as the dev/fallback path; its conformance tests remain required in CI for as long as the path exists.
- **`header-inject`** — the broker never releases the secret to the agent's identity. Only the egress sidecar's identity may fetch injectable material; the agent's identity requesting the same capability receives routing config only (base URL, allowed hosts) — no secret.

Modes are mutually exclusive per grant, enforced broker-side: no hybrid where a sidecar runs but bundles are also written ("cost of both paths, guarantee of neither").

The make-or-break lever: **header-inject is a provider-agnostic capability** — the sidecar asks "give me the injectable headers for (host, method, path)" and the broker returns headers. This is a **new endpoint** (e.g. `POST /v1/injection/headers`), not a reuse of the existing `/v1/headers`: that endpoint is a compatibility surface that returns secret-bearing headers *to the caller*, which is precisely the access model header-inject must invert. The response shape may mirror `/v1/headers`, but the new endpoint is callable only by egress-role identities (see identity model below) and its material is never obtainable by an agent identity. Existing `/v1/headers` remains unchanged for direct-mode compatibility. It is not a codex-shaped endpoint. Built this way, `token` / `headers` / `codex-oauth` / Anthropic / GitHub App all become config-only for egressd; new providers are broker plugins with zero sidecar changes. Pinned in Phase 0 with a conformance test before any implementation.

**Identity model — roles and pairing, not just two tokens.** Today's broker identities are agent token hashes plus provider grants; reusing that shape for the sidecar would produce "two bearer tokens with the same grants," which loses the load-bearing property. The broker config gains:

- a **role** per identity: `agent` or `egress`. Only `egress`-role identities may call `/v1/injection/headers`; only `agent`-role identities may hold capability grants.
- a **pairing** (audience): each `egress` identity is bound to exactly one agent identity. An injection request is authorized only if the caller's role is `egress` **and** the referenced capability is granted to the caller's paired agent. Agent A's sidecar cannot fetch material for agent B's grants, and no single identity can both run the workload and fetch secrets.

Both rules are enforced broker-side and pinned by the identity-split conformance test (Phase 0).

The broker remains the single refresh-token writer; refresh logic is unchanged — only *who may fetch the derived credential* changes. Protocol changes go in `protocol/broker.md`, pinned by conformance tests before implementation.

### 2. Egress sidecar (`egressd`)

A small trusted reverse proxy (Go, consistent with gateway/producer style) running alongside the agent — one service in `compose.agent.yaml` locally, one container in the AgentRun Pod in k8s (see §6 on placement).

- **Own broker identity, distinct from the agent's** — a separate bearer token locally; a projected ServiceAccount token validated via TokenReview in k8s. This is load-bearing: compromise of the agent container yields an identity that cannot obtain credentials. Built in from the first spike, pinned by an identity-split conformance test — never retrofitted.
- Listens on localhost; routes to configured upstreams; fetches injectable headers from brokerd on demand, caches until expiry, injects the header, re-originates TLS to pinned upstream hostnames.
- Passes SSE/streaming responses through cleanly (required for LLM APIs).
- **Fail closed**: if the broker is unreachable or a grant is revoked, requests fail — never fall back to cached-stale-beyond-TTL, never fall back to writing a bundle.
- **The egressd↔broker channel is TLS, non-negotiable.** egressd shares the agent's network namespace, and this is the one leg that carries real credentials in flight; over plain HTTP (today's local brokerd on `:7347`), an agent that gains netns privileges (§7: privileged dind allows this today) could sniff tokens and sidestep non-possession entirely. The localhost agent→egressd hop needs no such protection (it carries no credentials — the agent has none to send), and the egressd→upstream leg is TLS by nature; the broker leg is the gap and must be closed from Phase 1.
- Never logs header values or token material, including on error paths.
- Makes the `broker-auth-files-refresher` plugin unnecessary for injected providers — freshness becomes the sidecar's cache policy.
- **Placement-agnostic contract**: the injector protocol and grant descriptors reference egressd only by URL. Nothing in the contract assumes same-Pod/localhost, so placement can change later (see §6) as config, not rework.

**Review tier: trusted core.** egressd terminates TLS and injects credentials; its failure modes (request smuggling, upstream-host confusion / SSRF, SSE frame handling, header leakage on error paths) are invisible to functional tests. It gets line-by-line review alongside the broker changes — not "any code that passes."

### 3. Routing vs. enforcement

"All traffic through the sidecar" is two separate things:

- **Routing** — credentialed API traffic is pointed at egressd via base-URL/proxy config. DNS, brokerd, and the event-webhook callback always go direct (they are the allowlist).
- **Enforcement** — what stops the agent bypassing egressd and calling upstreams directly. This is the hard part (§7), and it is what separates non-possession (routing alone suffices) from exfil control (needs enforcement).

Routing without enforcement still delivers non-possession once a concrete tool
or request path is configured to use egressd. It does not deliver egress
control. Phase 3 wires the plumbing and metadata only; Phase 3.5 proves one
redirectable request path against fakes. Provider-specific production tool
redirect wiring still lands in focused provider PRs. Stated so nobody reads
"traffic goes through the sidecar" as a blanket property compose has.

### 4. Runtime wiring

`runtime/core/bootstrap.py` keys off what it's given, keeping the image mode-agnostic:

- Phase 3 mediated grant → validate the mediated grant metadata, write egress metadata/placeholders needed for non-possession ratchets, and write **no** auth files. It does not yet point concrete tools at the sidecar.
- Phase 3.5 redirectable-provider proof → add generic, grant-driven `redirect-env` wiring where a grant can persist selected environment variables from non-secret sources (`base-url` or the documented placeholder). The proof uses a fake/static bearer request path so CI needs no real provider subscription or key.
- Later provider PRs → add provider-specific redirect wiring such as `ANTHROPIC_BASE_URL` or Codex `config.toml` (`model_providers.*.base_url`, `chatgpt_base_url`) only when that concrete provider proof is in scope.
- Direct grant → today's behavior exactly (bundles / host-seeded `~/.codex`, `.agents/<name>/auth/claude`).

**Non-secret placeholders are allowed where a CLI demands one.** Some CLIs refuse to start without a syntactically present API key or auth file. Mediated mode may write a fixed, obviously-non-secret placeholder (e.g. `NVT-PLACEHOLDER-NOT-A-KEY`) to satisfy the parser. Two conditions, both test-enforced: (1) the placeholder value is a documented constant carrying zero secret entropy, allowlisted by the non-possession smoke test; (2) a conformance test proves the placeholder is inert upstream — a direct (sidecar-bypassing) request presenting it is rejected by the provider, so possession of the placeholder grants nothing. egressd strips or replaces the placeholder header on injection; it must never be forwarded alongside the real credential.

### 5. git-over-HTTPS mediation (its own phase — highest-risk surface)

Landed as Phase 4 (`docs/phase4-git-mediation-plan.md`): the `github_app`
provider serves git smart-HTTP injection with read/write permission mapping,
egressd generates a per-agent CA at boot and terminates TLS on the git route,
bootstrap installs the managed redirect wiring, and mediated runs support one
route per header-inject grant.

To honor the zero-secrets bright line for git, the token must be injected, not handed to git (the credential-helper path necessarily passes the token through agent-owned process memory, so it cannot satisfy the invariant):

- **GitHub App is mediatable** because the repo is in the URL (`/repos/owner/name/...`, `github.com/owner/repo.git`) → egressd extracts scope, fetches a per-repo installation token, injects `Authorization`. The REST half is already broker-mediated via `/v1/http/request`.
- **git-HTTPS forces egressd to be a TLS-terminating proxy** with a per-agent CA. Only the **CA certificate** enters the agent trust store; the **CA private key lives exclusively in egressd** and is itself subject to the zero-secrets invariant (a key in the container would let the agent impersonate any upstream to itself and harvest injected credentials). A hostile root agent deleting the CA cert or setting `GIT_SSL_NO_VERIFY` is self-DoS, not a bypass — it breaks the agent's own git and still yields no token.
- **Mediated bootstrap scrubs pre-existing git auth state**: existing credential helpers are unset (`credential.helper` cleared at system/global scope), `http.extraHeader` and `url.*.insteadOf` rewrites are removed, and `~/.git-credentials` / credential caches are absent. Otherwise stale local credentials — seeded homes, leftover helper config — silently violate the zero-secret invariant while all injection tests pass. The non-possession smoke test asserts this scrubbed state explicitly. After the scrub, Phase 4 bootstrap installs the one managed rewrite (`url."https://127.0.0.1:<git-port>/".insteadOf`) plus `http.sslCAInfo` for the published CA certificate; the smoke test distinguishes this managed local rewrite from retained foreign ones.
- **Interim honesty**: until Phase 5 lands, git mediation delivers non-possession only. The CA-deletion analysis is complete on its own (no CA → broken git, still no token), but "the agent cannot reach github.com directly at all" is a Phase-5 enforcement property — this doc must not be read as implying it holds at Phase-4 time.
- **git-SSH and file-native-TLS tools are disallowed in mediated mode.** Force HTTPS remotes.

This is a distinct phase because TLS termination is the single highest-risk surface in the design — it never rides along with the LLM-API work.

The per-agent CA built here is **not just for git**: it is the building block that closes the arbitrary-tool coverage gap (Phase 6). Once egressd can terminate TLS under a CA the agent trusts, extending mediation beyond redirectable clients is incremental, not a redesign.

### 6. Placement decision (resolved)

**Same-Pod/localhost for Phases 1–4; own-Pod is the declared candidate for Phase-5 enforcement in k8s.**

Same-Pod is right for the non-possession phases: localhost keeps the plaintext agent→egressd hop inside the netns, wiring is symmetric with compose, lifecycle is trivial. But same-Pod has a structural consequence for enforcement: host-side NetworkPolicy sees one endpoint, so it must allow the union of agent+sidecar destinations — the agent can always *reach* upstream hosts directly (credential-less, but reachable). And in-netns iptables live where the agent can gain NET_ADMIN. Kata does not fix this — inside the guest, the agent can still flush guest iptables; enforcement must live **outside the agent's privilege domain**.

Own-Pod egressd flips it: the agent Pod's NetworkPolicy ("egress only to egressd Pod + DNS + broker + callback") is enforced at the CNI on the host side, beyond the agent's reach even with full privileges in its netns — the one clean enforcement story available today. Costs: heavier lifecycle (two Pods per run, pairing), and the plaintext hop crosses the CNI (mitigate with same-node affinity; it carries no credentials either way, since the agent has none).

Because the contract is placement-agnostic (§2), this was a Phase-5 evaluation — own-Pod vs. deprivileged-dind — not a Phase-1 commitment.

**Phase 5 outcome (PR 6a): own-Pod is the implemented k8s enforcement shape.**
Opt-in per run via `spec.egressEnforcement: true` (requires `egress: mediated`);
same-Pod remains the default mediated shape and the compose shape. The
operator sequences provisioning as a status-condition state machine
(`BrokerPolicyReady`, `EgressdCreated`, `EgressdReady`, `EgressCAPublished`)
and the agent Pod is never created before the CA is published and the broker
policy holds. The per-agent CA is distributed by the operator: fetched once
from egressd's plain-HTTP `/ca.crt` endpoint (public material — the trust
anchor being bootstrapped), validated, and published into a per-run ConfigMap
mounted at the Phase 4 path.

### 7. Egress enforcement — the hard problem, stated honestly

Enforcement requires distinguishing the sidecar from the agent at the network layer. With same-Pod placement, NetworkPolicy cannot (it selects Pods, not containers; verified: the agent joins the dind netns via `network_mode: service:docker` locally, same-Pod in k8s).

The in-netns layer is iptables:

- **`-m owner --uid-owner` in OUTPUT** — allow the sidecar's UID out, deny the agent's UID — covers locally-generated traffic.
- **FORWARD-chain deny is also required**: traffic from containers spawned *inside* dind traverses FORWARD in the shared netns with no socket owner, so owner-match never sees it. Without the FORWARD rules, dind workloads bypass enforcement while all tests on agent-local traffic pass. This is a named Phase-5 spike item.
- Rules installed by a NET_ADMIN init step before the agent starts, in both backends. NetworkPolicy remains a coarse outer fence in k8s.

**Unstated precondition, now explicit**: in-netns enforcement only holds where the agent cannot obtain NET_ADMIN in that netns. Today it can — the agent controls a privileged dind daemon (`privileged: true` in `compose.agent.yaml`) and can `docker run --privileged --net container:…` to flush the rules. Therefore:

- Enforcement is a real control via **own-Pod egressd + CNI-enforced NetworkPolicy** (k8s — landed in Phase 5 PR 6a behind `spec.egressEnforcement`; the egress-denied smoke runs on a Calico kind cluster and covers the dind FORWARD-path case, since spawned-container traffic still exits the Pod and hits the CNI), or with **dind deprivileged/relocated** (either backend). In-netns iptables remains defense-in-depth gated on the deprivileged-dind workstream: it only holds where the agent cannot obtain NET_ADMIN in its netns, and today it can.
- Under today's compose + `danger-full-access` + per-agent privileged dind, egress-deny is a speed bump, not a control — a **documented gap**, acceptable under the local trust model ("you trust yourself"), not an implicit one.
- This inverts the naive asymmetry: compose is the hard side for enforcement, k8s the tractable side. Non-possession, by contrast, is clean in both.

**Compose decision (resolved): accept the documented gap.** Non-possession still holds locally, and the platform's real autonomous exposure is operator mode — that is where enforcement must be real. Deprivileging/relocating dind is tracked as an independent workstream that, when it lands, upgrades compose egress-deny from speed bump to control; it is not a prerequisite for anything in this plan.

### 8. Explicitly out of scope

- git-SSH, file-native-TLS binaries: disallowed in mediated mode, not mediated.
- **agentd is untouched.** It is session I/O and explicitly not a security boundary; egressd belongs with broker/operator/runtime wiring. Architectural invariant, not a preference.

## Configuration surface (optionality)

| Layer | Knob | Default |
|---|---|---|
| Broker | per-grant `materialization: file-bundle \| header-inject` | `file-bundle` |
| Operator | AgentRun/AgentSchedule spec `egress: mediated \| direct`, per-grant `egressHosts`, and explicit `egressAllowInsecureBroker` for local plaintext broker wiring | opt-in; Phase 5 adds a `defaultEgressMode` chart value (default `direct`); global flip deferred until after real-cluster soak |
| Compose | `agent-init MEDIATED=1` profile adding the sidecar (+ iptables when enforcement lands), skipping bundles; requires `NVT_EGRESS_ALLOW_INSECURE_BROKER=1` for the local plaintext broker | `direct` |

When `direct`, the operator renders exactly today's Pod — no sidecar, no NetworkPolicy, no iptables. Both paths stay conformance-tested for as long as both are supported; bundle-path tests (`broker_auth_files` etc.) do not decay while the path remains the documented fallback.

**Mode mismatch fails admission — both directions, no downgrade.** The run-level `egress` mode and per-grant `materialization` must agree, validated at AgentSchedule admission (and mirrored in compose `agent-init`):

- `egress: direct` + any `header-inject` grant → **admission failure** (the grant's secret would be unfetchable, or worse, an implementation might "helpfully" materialize it as a bundle).
- `egress: mediated` + any `file-bundle` grant → **admission failure** (a bundle written into a supposedly zero-secret container silently breaks the invariant).

Silent downgrade or ignore in either direction would violate risk #2 (silent fallback). The error is loud, names the offending grant, and the operator surfaces it on the AgentRun status.

In Phase 3, mediated egressd routes are rendered only from explicit route hosts
(`egressHosts` in AgentRun, `egress-hosts` in local `agents.yaml`). The local
compose and kind POC broker leg is plaintext, so mediated mode must opt into the
unsafe local-only setting. Production mediated mode must use the broker TLS path
instead of silently setting `allow_insecure_broker`.

## Phases

### Phase 0 — Contract and tests first (completed — PR #53)

Before any implementation is delegated; human-reviewed — this is where the security thinking lives.

- Injection protocol doc in `protocol/` — the new `/v1/injection/headers` endpoint (distinct from compatibility `/v1/headers`), the identity role/pairing model (`agent` vs `egress`, one-to-one pairing), materialization modes, admission mismatch rules, and the placeholder convention; placement-agnostic (egressd referenced by URL only).
- Identity-split conformance test: mediated grant → the paired `egress` identity gets injectable material; the `agent` identity requesting the same capability gets routing config only, no secret; an `egress` identity paired to a *different* agent is refused.
- Admission conformance test: `direct` run × `header-inject` grant and `mediated` run × `file-bundle` grant both fail admission loudly — no downgrade path exists.
- Placeholder-inertness test: where a CLI requires a syntactic key, the placeholder constant carries no entropy, is allowlisted by the non-possession test, and is rejected upstream when presented without sidecar injection.
- Two separate smoke tests: **(a) non-possession** — boot mediated → assert zero secret material anywhere in the container (filesystem, env, process args), for all providers, including scrubbed git credential state (no helpers, no `http.extraHeader`, no stored credentials); **(b) egress-denied** — assert direct egress to upstream hosts is refused. Both mode-aware (skip *visibly* for direct runs so a misconfigured default can't pass silently). Split so (a) lands independent of the hard §7 work.

### Phase 1 — egressd + injection endpoints, proven against fakes (completed — PR #54)

As executed — adjusted from the original "Codex API-key mode" wording: no OpenAI API key exists in this deployment, and **no phase requires one**. The "API-key mode" was reinterpreted as the *simple bearer-injection shape*, proven with fakes:

1. **Fake upstream proof**: egressd built and tested against a fake broker and fake upstream — client sends the placeholder, upstream receives exactly the injected real token, the placeholder never reaches the upstream; fail-closed on broker denial and on expired-at-fetch material; material cached per `(method, path)` (the scope the broker authorized); SSE passthrough; bare-`host[:port]` upstream validation (SSRF guard).
2. **Static bearer provider**: the `token` plugin supports injection via `injection-hosts` config — no real credential anywhere.
3. **Real codex-oauth wired**: the `codex-oauth` provider supports injection through the same refresh flow as file vending, so the broker-owned `auth.json` is injectable with zero new credentials. Real-path validation is Phase 2's gate.

Broker side shipped with it: identity roles + one-to-one pairing (grants on an egress identity are unrepresentable), `/v1/injection/headers` and `/v1/injection/routing` with authorization order role → pairing → grant → materialization → host, egress identities denied on all secret-bearing endpoints, header-inject grants excluding bundle/token/header paths, denial audit with full caller context, and optional broker TLS serving (`NVT_BROKER_TLS_CERT/KEY`). All 12 injection conformance tests live in CI.

### Phase 2 — ChatGPT-plan flow as the go/no-go gate (completed — NO-GO for redirect-only)

**Implementation spec: `docs/phase2-codex-gate-plan.md`** — an empirical gate run in an internal-only compose topology (agent on an `internal: true` network, egressd the only path out, broker owning the real `auth.json` in a throwaway state dir). Deliverable is `docs/phase2-codex-gate.md` recording required hosts, the minimal placeholder `auth.json`/JWT shape, any claim-derived headers (e.g. account-id) the provider must compute from the real token, cert-pinning observations, and the go/no-go decision. Real refresh is forced by setting `refresh-margin-seconds` beyond the token's remaining lifetime — no short-lived fixture needed against the real token URL.

Switch the working harness to the plan-auth path (`codex-oauth` grant in `header-inject` mode, `chatgpt_base_url` redirection). Required spike outputs:

1. Does `chatgpt_base_url` cover every host the plan-auth flow touches? The deny-all instrument from Phase 1 answers this empirically.
2. Does Codex pin certs on those hosts? Pinning defeats localhost TLS re-origination → design changes.

Test refresh deterministically with broker-issued artificially short-lived tokens; verify the true SSE guarantee — new requests use the refreshed token, in-flight streams complete on the old one.

**Go/no-go**: if plan-auth can't be redirected, plan-auth Codex stays on bundles and we reassess — bearer-shape mediation (Phase 1's result) ships independently either way for any redirectable provider. A NO-GO is a successful phase outcome (a documented answer), not a failure of the work.

### Phase 2b — CONNECT-only egressd forward proxy (low-risk plumbing)

Pulled forward after the Phase 2 NO-GO: current Codex plan-auth uses
hardcoded WebSocket endpoints, but a probe showed it honors proxy environment
variables and the container trust store. Full TLS termination/MITM remains
trusted-core work for a later phase, so this PR adds only the plumbing step.

- egressd gains a CONNECT-only forward-proxy listener with a configurable
  host allowlist and default-deny behavior.
- The proxy blind-tunnels allowed `host:port` targets; it does not implement
  plain HTTP proxying, TLS termination, WebSocket injection, or credential
  injection.
- The broker contract remains unchanged.
- Sanitized logs contain only CONNECT decision metadata:
  `event=connect`, `target_host`, `target_port`, `decision`, and optional
  `error_class`.
- These CONNECT decisions are sanitized egressd stdout logs in this phase, not
  broker `audit.jsonl` per-request audit entries.
- The Phase 2b harness runs real Codex through
  `HTTPS_PROXY=http://egressd:<port>` with the existing Codex auth bundle.
  This proves forward-proxy plumbing only. It is not credential-less Codex.

Credential-less Codex still waits for CA/TLS termination plus WebSocket
handshake injection. The next PR after this should focus on Codex fallback
hardening and short-TTL vended bundles.

### Phase 3 — Operator + compose wiring (non-possession ships)

AgentRun gains `egress: direct|mediated`; broker grants gain
`materialization: file-bundle|header-inject` and explicit mediated route hosts.
Direct remains the default and renders the existing Pod/compose behavior.
Mediated mode conditionally adds the egressd sidecar, a separate paired egress
broker identity, sidecar config, and bootstrap metadata for header-inject grants
only; mismatch in either direction fails admission before side effects. Phase 3
accepted exactly one header-inject grant; Phase 4 lifted that limit — a
mediated run now gets one route (and local port) per header-inject grant.
Codex plan-auth remains on the direct file-bundle fallback after the Phase 2
NO-GO.

Phase 3 is routing plumbing plus non-possession, not end-to-end tool routing.
`bootstrap.py` validates mediated grant metadata and writes egress metadata, but
it does not configure concrete tools such as Anthropic or Codex to use egressd.
Concrete tool redirect wiring is deferred to the first redirectable-provider
proof PR. Phase-0 non-possession tests land in CI here; egress-denied stays
skipped until Phase 5. (No enforcement yet — routing plumbing +
non-possession only, per §3.)

### Phase 3.5 — Redirectable-provider proof before Phase 4

Before the Phase 4 git/TLS work, prove that the existing broker, egressd,
sidecar, and bootstrap contract works end to end for one redirectable request
shape without external provider dependencies:

- Bootstrap supports generic `redirect-env` entries on mediated grants. Each
  entry may persist only the grant `base-url` or the documented inert
  placeholder into the agent env file; it cannot persist real credential
  material.
- The runtime non-possession smoke test verifies that the agent-visible config
  contains only the egressd base URL plus placeholder and still has zero planted
  broker/provider/git secrets in filesystem, generated env files, env snapshots,
  or argv snapshots.
- egressd has a static-bearer fake proof: the client sends the placeholder to
  egressd, egressd calls broker `/v1/injection/headers`, the fake upstream sees
  only the injected credential, and the placeholder never reaches upstream.
- The operator kind smoke gains a mediated case that validates a header-inject
  `AgentRun` with `egressHosts`, verifies the egressd sidecar and token
  isolation in kind mode, and rejects mediated runtimeAuth, missing route hosts,
  and file-bundle grants.

This phase does **not** add CA material, TLS termination, git-over-HTTPS
mediation, transparent proxying, NetworkPolicy, iptables, or a production
provider-specific redirect such as Anthropic or Codex. It is the Phase 3 tail
that proves the redirectable plumbing before Phase 4.

### Phase 4 — git-over-HTTPS mediation

Per-agent CA, egressd TLS termination, repo-scope extraction, GitHub App token injection. Its own phase for its own risk surface. Delivers non-possession for git tokens; the reachability half waits for Phase 5 (§5 interim note).

The per-agent CA built here is not only for git: it is the **building block that closes the generality gap with transparent interception** (Phase 6). Once egressd can terminate TLS with a CA the agent trusts, mediating an arbitrary hardcoded-endpoint tool becomes an incremental extension rather than a new design. Treat the CA as a general capability with git as its first consumer.

### Phase 5 — Egress enforcement + audit + quotas + revocation

May split into two PRs (enforcement; observability/control) even as one phase.

- **Enforcement**: evaluate own-Pod egressd + NetworkPolicy vs. deprivileged-dind as the k8s control (§6); iptables owner-match **plus FORWARD-chain deny** where in-netns rules apply; state the NET_ADMIN precondition and the compose gap explicitly. Egress-denied smoke test lands in CI here.
- **Per-request audit** appended to the broker's `audit.jsonl` (agent, capability, host, method, path class, status).
- **Per-grant request-count quotas** at the sidecar (spend quotas deferred — they need provider-response parsing, which couples the generic proxy to each provider).
- **Revocation**: broker revokes grant → sidecar's next fetch fails → agent loses API access within one cache TTL, without killing the Pod.
- **Anthropic as the provider-agnosticism proof**: adding `ANTHROPIC_BASE_URL` + a grant must be config-only with zero egressd changes — landing it *is* the test that the injector contract stayed provider-agnostic. If it requires sidecar code, that's a contract regression, not a feature.
- Default handling (revised, see [phase5-enforcement-plan.md](phase5-enforcement-plan.md)): Phase 5 adds a `defaultEgressMode` chart value **defaulting to `direct`**. The global flip to `mediated` is product behavior, not just hardening — it moves to its own later PR, gated on both smoke tests green in CI **and** real-cluster soak with consumers migrated.

### Phase 6 — Transparent mediation mode (arbitrary-tool coverage)

**This phase closes the main coverage gap between redirect-based mediation and transparent-MITM mediation: arbitrary/unmodifiable tools with hardcoded endpoints.** Everything through Phase 5 mediates *redirectable* HTTP tools (base URL / proxy env configurable) and hard-disallows the rest in mediated mode. Phase 6 extends coverage to tools that ignore configuration, reusing the Phase 4 TLS-termination machinery with **no broker-contract changes** (the injection endpoints are transport-agnostic by construction, §2).

Two steps, ordered by risk/coverage ratio:

1. **Forward-proxy mode (covers the bulk).** Set `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY` in the agent container and have egressd handle `CONNECT` with TLS termination using the per-agent CA from Phase 4. Most CLIs, language HTTP clients, and SDKs honor proxy env vars, so this covers the majority of "arbitrary tools" with zero per-tool config. egressd matches the CONNECT target host against configured routes / capability `injection-hosts`; unknown hosts are denied (still fail-closed). Requires per-grant policy for *which* hosts a tool may reach — reuses the existing grant model.
2. **True transparent mode (the residue).** For tools that ignore proxy env, iptables `REDIRECT`/`TPROXY` in the agent netns steers outbound 443 to egressd, which uses SNI to pick the route. This needs the Phase 5 netns/enforcement plumbing and the NET_ADMIN precondition (§7) to be a real control, so it is strictly after Phase 5 and only meaningful where enforcement holds.

Optional within this phase: **body placeholder substitution** as a grant option — because egressd sees the decrypted request in these modes, it can replace `NVT-PLACEHOLDER-*` tokens in bodies/query params for allowlisted hosts, covering APIs that carry the secret outside a header. This is the direct analogue of transparent-MITM secret substitution, but gated by the same grant/audit/quota layer.

Scope guard: Phase 6 is **coverage generality**, not a new security model. It must not weaken any Phase 1–5 property; every transparent-mode request flows through the same broker authorization, audit, and fail-closed paths as a redirected one.

## PR sequence

One phase per PR. This is load-bearing: line-by-line review of the trusted core is only realistic on phase-sized diffs; the Phase-2 gate must be able to stop the train before wiring investment; and the Phase-3 CI ratchet only protects later phases if phases merge sequentially. The constraint is on *merging*, not starting — Phase 0 can be reviewed while the Phase-1 spike runs against a draft of the contract.

| PR | Contents | Merge gate |
|---|---|---|
| 1 | Phase 0: protocol doc + conformance/smoke test skeletons | human review of the contract — slowest, most careful |
| 2 | Phase 1: egressd + identity split + Codex API-key mode | trusted-core review; timeboxed spike result |
| 3 | Phase 2: ChatGPT-plan flow + refresh/SSE tests | **go/no-go decision recorded in the PR** |
| 3b | Phase 2b: CONNECT-only egressd forward proxy, no TLS termination or injection | egressd CONNECT tests + Codex proxy harness |
| 4 | Phase 3: operator + compose wiring; direct/mediated admission, paired egress identity, sidecar config, bootstrap non-possession tests → CI | broker/runtime/operator conformance green in CI |
| 4b | Phase 3.5: redirectable static-bearer proof, generic `redirect-env`, mediated kind smoke | runtime/egressd fake proof + kind render smoke |
| 5 | Phase 4: git-HTTPS mediation (CA, TLS termination) | trusted-core review — highest-risk surface, deliberately alone |
| 6a | Phase 5: enforcement (own-Pod evaluation, iptables + FORWARD deny) | egress-denied test → CI |
| 6b | Phase 5: audit, quotas, revocation, Anthropic proof; `defaultEgressMode` knob (default stays `direct`) | both smoke tests green |
| 7 | Global default flip to `mediated` (one value + CRD defaults + producers) | smoke tests green in CI **and** real-cluster soak/migration |
| 7 | Phase 6: TLS-terminating forward-proxy mode (CONNECT + CA) for arbitrary-tool credential mediation | trusted-core review (reuses Phase 4 CA) |
| 8 | Phase 6: true transparent REDIRECT + optional body substitution | after Phase 5 enforcement; egress-denied still green |

## Division of labor

- **Spec + tests (Phase 0)**: written up front, human-reviewed. Once the contract and suites are pinned, implementation is "any code that passes."
- **Implementation**: delegated to the coding agent, one phase per PR. Phase-sized diffs keep review readable; the spikes suit an agent well (empirical trial-and-error against the Codex config surface under deny-all).
- **Review focuses where tests can't reach**: secret handling in error paths/logs, fail-closed behavior when the broker is down, identity checks enforced broker-side (not sidecar politeness), no mode mixing both auth paths.
- **Trusted core, line-by-line review**: broker identity/materialization changes and egressd itself — not test-trusting.

## Key risks

1. **ChatGPT-plan flow not redirectable or cert-pinned** — main empirical risk; front-loaded into Phases 1–2 with explicit fallback (plan-auth Codex stays on bundles; API-key-mode Codex mediation ships regardless).
2. **Silent fallback to bundles on error** — defeats the property while everything looks fine; countered by fail-closed design, broker-side mutual exclusion, and the non-possession CI test.
3. **Two-path rot** — the fallback suite decaying; countered by keeping both suites required in CI.
4. **Identity split retrofitted late** — countered by making it a Phase-1 requirement + pinned conformance test.
5. **Enforcement mistaken for shipped where the agent can flush it** — countered by stating the NET_ADMIN precondition, the FORWARD-chain requirement, and marking compose egress-deny a documented gap, not an implicit control.
6. **Phase-1 scope creep delaying the go/no-go verdict** — countered by the explicit timebox and "only what Phase 2 needs" scope guard.
7. **Credentials sniffed in flight on the egressd↔broker leg** — the one network path carrying real secrets through the shared netns; countered by requiring TLS on that channel from Phase 1 (§2).
8. **Secret-returning API endpoints reachable through a grant** — an allowed API that mints/returns credentials in a response body delivers a secret into the container legitimately; countered by excluding credential-minting endpoints from grant path-classes as a standing policy rule.

## Secret-protection comparison & defensible claim scope

This design is measured against transparent-MITM credential mediation, where a userspace network stack substitutes placeholder secrets in flight for allowlisted hosts. Recording the comparison so the security claim is stated precisely and survives an informed reviewer.

**Dimensions where this design (all phases) is stronger:**

- **Authorization** — per agent × capability × repo × method grants with ceiling∩grant intersection; transparent-MITM has only host allowlists. It limits *where* bytes go; this limits *where and what the credential may do*.
- **Audit & forensics** — every injection and every denial recorded with full context; transparent-MITM has no per-request credential-use audit.
- **Containment** — mid-run revocation within one cache TTL, plus per-grant quotas bounding blast radius on a *valid* credential; transparent-MITM offers neither.
- **Root-secret custody** — single-writer broker with audited derivation and OAuth refresh ownership; transparent-MITM keeps host-side static files.
- **Verifiability** — non-possession is CI-enforced (zero secret material in fs/env/args; agent identity cannot fetch secrets; placeholder inertness). A property re-checked every commit is categorically more trustworthy than a README assertion.

**Dimensions at parity once all phases land:**

- **Non-possession** — neither approach leaves a usable credential in the workload.
- **Coverage of arbitrary tools** — reached at **Phase 6** (forward-proxy + transparent mode). Before Phase 6, this design mediates redirectable tools and *disallows* the rest in mediated mode (never silently leaks), so it is narrower-but-honest on coverage until then.

**Dimension where transparent-MITM keeps an edge:**

- **Raw isolation substrate** — a per-VM boundary is a stronger cage than a container namespace. This design's answer is `RuntimeClass` (Kata/microVM), which closes it — but that is a *deployment choice*, not something the mediation design itself provides.

**The two conditions that make the strong claim unqualified:**

1. **Phase 6 lands** (transparent/forward-proxy mode) — converts "better on most axes" into "at least matching coverage, winning everywhere else."
2. **Deployment keeps enforcement outside the agent's privilege domain** — own-Pod egressd + CNI policy, or deprivileged dind, or a hardened `RuntimeClass`. In today's privileged-dind compose, non-possession holds but egress-deny is a documented speed bump (§7), so the unqualified claim does not hold there.

**Defensible claim wording:** *"nvt provides stronger secret protection — non-possession plus authorization, audit, quotas, and mid-run revocation, machine-verified in CI — on any deployment where enforcement lives outside the agent's privilege domain."* Do **not** make the unqualified "protects secrets better, full stop" while the flagship local mode is privileged-dind compose and Phase 6 is unshipped; an informed reviewer will point at the netns flush (§7) and the coverage gap. Both close on the two conditions above.

## End state

Agent containers hold zero credentials for mediated providers (LLM APIs, GitHub REST, git-HTTPS, and — from Phase 6 — arbitrary redirectable/interceptable tools); the broker decides *whether* (grants, quotas), the sidecar handles *how* (injection at the edge); every credentialed request is audited; a grant is revocable mid-run within one cache TTL. Where enforcement lives outside the agent's privilege domain (own-Pod egressd + CNI policy, or deprivileged dind), a static default-deny makes the sidecar the only way out; where it does not (today's compose), non-possession still holds and egress-deny is a documented gap. All optional per grant, with today's behavior the untouched default until the smoke tests say otherwise.
