# Plan: Mediated Credential Egress

Status: draft for review
Version: v3.2 (review findings 1–5 incorporated)

## Goal

Not a single raw secret is available to the agent container — including short-lived derived credentials like GitHub App installation tokens. Today, providers like `codex-oauth` materialize a usable access token into the container as a file bundle; a prompt-injected agent can exfiltrate it for its lifetime. Target state: credentials are injected into outbound requests by a trusted sidecar at the network edge, while the broker keeps doing what it does today — policy, refresh, audit. On that choke point we add per-request audit, quotas, and mid-run revocation.

The invariant is a bright line, CI-enforced: inspect the container — filesystem, env, process args — and find zero secret material. No "small accepted exposures": exceptions accumulate and erode. Capabilities that cannot be mediated (git-SSH, file-native-TLS tools) are disallowed in mediated mode, not excepted.

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
- Never logs header values or token material, including on error paths.
- Makes the `broker-auth-files-refresher` plugin unnecessary for injected providers — freshness becomes the sidecar's cache policy.
- **Placement-agnostic contract**: the injector protocol and grant descriptors reference egressd only by URL. Nothing in the contract assumes same-Pod/localhost, so placement can change later (see §6) as config, not rework.

**Review tier: trusted core.** egressd terminates TLS and injects credentials; its failure modes (request smuggling, upstream-host confusion / SSRF, SSE frame handling, header leakage on error paths) are invisible to functional tests. It gets line-by-line review alongside the broker changes — not "any code that passes."

### 3. Routing vs. enforcement

"All traffic through the sidecar" is two separate things:

- **Routing** — credentialed API traffic is pointed at egressd via base-URL/proxy config. DNS, brokerd, and the event-webhook callback always go direct (they are the allowlist).
- **Enforcement** — what stops the agent bypassing egressd and calling upstreams directly. This is the hard part (§7), and it is what separates non-possession (routing alone suffices) from exfil control (needs enforcement).

Routing without enforcement still delivers non-possession. It does not deliver egress control. Stated so nobody reads "traffic goes through the sidecar" as a property compose actually has.

### 4. Runtime wiring

`runtime/core/bootstrap.py` keys off what it's given, keeping the image mode-agnostic:

- Mediated grant → write `ANTHROPIC_BASE_URL` / Codex `config.toml` (`model_providers.*.base_url`, `chatgpt_base_url`) pointing at the sidecar; write **no** auth files.
- Direct grant → today's behavior exactly (bundles / host-seeded `~/.codex`, `.agents/<name>/auth/claude`).

**Non-secret placeholders are allowed where a CLI demands one.** Some CLIs refuse to start without a syntactically present API key or auth file. Mediated mode may write a fixed, obviously-non-secret placeholder (e.g. `NVT-PLACEHOLDER-NOT-A-KEY`) to satisfy the parser. Two conditions, both test-enforced: (1) the placeholder value is a documented constant carrying zero secret entropy, allowlisted by the non-possession smoke test; (2) a conformance test proves the placeholder is inert upstream — a direct (sidecar-bypassing) request presenting it is rejected by the provider, so possession of the placeholder grants nothing. egressd strips or replaces the placeholder header on injection; it must never be forwarded alongside the real credential.

### 5. git-over-HTTPS mediation (its own phase — highest-risk surface)

To honor the zero-secrets bright line for git, the token must be injected, not handed to git (the credential-helper path necessarily passes the token through agent-owned process memory, so it cannot satisfy the invariant):

- **GitHub App is mediatable** because the repo is in the URL (`/repos/owner/name/...`, `github.com/owner/repo.git`) → egressd extracts scope, fetches a per-repo installation token, injects `Authorization`. The REST half is already broker-mediated via `/v1/http/request`.
- **git-HTTPS forces egressd to be a TLS-terminating proxy** with a per-agent CA. Only the **CA certificate** enters the agent trust store; the **CA private key lives exclusively in egressd** and is itself subject to the zero-secrets invariant (a key in the container would let the agent impersonate any upstream to itself and harvest injected credentials). A hostile root agent deleting the CA cert or setting `GIT_SSL_NO_VERIFY` is self-DoS, not a bypass — it breaks the agent's own git and still yields no token.
- **Mediated bootstrap scrubs pre-existing git auth state**: existing credential helpers are unset (`credential.helper` cleared at system/global scope), `http.extraHeader` and `url.*.insteadOf` rewrites are removed, and `~/.git-credentials` / credential caches are absent. Otherwise stale local credentials — seeded homes, leftover helper config — silently violate the zero-secret invariant while all injection tests pass. The non-possession smoke test asserts this scrubbed state explicitly.
- **Interim honesty**: until Phase 5 lands, git mediation delivers non-possession only. The CA-deletion analysis is complete on its own (no CA → broken git, still no token), but "the agent cannot reach github.com directly at all" is a Phase-5 enforcement property — this doc must not be read as implying it holds at Phase-4 time.
- **git-SSH and file-native-TLS tools are disallowed in mediated mode.** Force HTTPS remotes.

This is a distinct phase because TLS termination is the single highest-risk surface in the design — it never rides along with the LLM-API work.

### 6. Placement decision (resolved)

**Same-Pod/localhost for Phases 1–4; own-Pod is the declared candidate for Phase-5 enforcement in k8s.**

Same-Pod is right for the non-possession phases: localhost keeps the plaintext agent→egressd hop inside the netns, wiring is symmetric with compose, lifecycle is trivial. But same-Pod has a structural consequence for enforcement: host-side NetworkPolicy sees one endpoint, so it must allow the union of agent+sidecar destinations — the agent can always *reach* upstream hosts directly (credential-less, but reachable). And in-netns iptables live where the agent can gain NET_ADMIN. Kata does not fix this — inside the guest, the agent can still flush guest iptables; enforcement must live **outside the agent's privilege domain**.

Own-Pod egressd flips it: the agent Pod's NetworkPolicy ("egress only to egressd Pod + DNS + broker + callback") is enforced at the CNI on the host side, beyond the agent's reach even with full privileges in its netns — the one clean enforcement story available today. Costs: heavier lifecycle (two Pods per run, pairing), and the plaintext hop crosses the CNI (mitigate with same-node affinity; it carries no credentials either way, since the agent has none).

Because the contract is placement-agnostic (§2), this is a Phase-5 evaluation — own-Pod vs. deprivileged-dind — not a Phase-1 commitment.

### 7. Egress enforcement — the hard problem, stated honestly

Enforcement requires distinguishing the sidecar from the agent at the network layer. With same-Pod placement, NetworkPolicy cannot (it selects Pods, not containers; verified: the agent joins the dind netns via `network_mode: service:docker` locally, same-Pod in k8s).

The in-netns layer is iptables:

- **`-m owner --uid-owner` in OUTPUT** — allow the sidecar's UID out, deny the agent's UID — covers locally-generated traffic.
- **FORWARD-chain deny is also required**: traffic from containers spawned *inside* dind traverses FORWARD in the shared netns with no socket owner, so owner-match never sees it. Without the FORWARD rules, dind workloads bypass enforcement while all tests on agent-local traffic pass. This is a named Phase-5 spike item.
- Rules installed by a NET_ADMIN init step before the agent starts, in both backends. NetworkPolicy remains a coarse outer fence in k8s.

**Unstated precondition, now explicit**: in-netns enforcement only holds where the agent cannot obtain NET_ADMIN in that netns. Today it can — the agent controls a privileged dind daemon (`privileged: true` in `compose.agent.yaml`) and can `docker run --privileged --net container:…` to flush the rules. Therefore:

- Enforcement is a real control via **own-Pod egressd + CNI-enforced NetworkPolicy** (k8s), or with **dind deprivileged/relocated** (either backend).
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
| Operator | AgentRun/AgentSchedule spec `egress: mediated \| direct`, defaultable via Helm values | opt-in; flip default to `mediated` once smoke tests are in CI |
| Compose | `agent-init MEDIATED=1` profile adding the sidecar (+ iptables when enforcement lands), skipping bundles | `direct` |

When `direct`, the operator renders exactly today's Pod — no sidecar, no NetworkPolicy, no iptables. Both paths stay conformance-tested for as long as both are supported; bundle-path tests (`broker_auth_files` etc.) do not decay while the path remains the documented fallback.

**Mode mismatch fails admission — both directions, no downgrade.** The run-level `egress` mode and per-grant `materialization` must agree, validated at AgentSchedule admission (and mirrored in compose `agent-init`):

- `egress: direct` + any `header-inject` grant → **admission failure** (the grant's secret would be unfetchable, or worse, an implementation might "helpfully" materialize it as a bundle).
- `egress: mediated` + any `file-bundle` grant → **admission failure** (a bundle written into a supposedly zero-secret container silently breaks the invariant).

Silent downgrade or ignore in either direction would violate risk #2 (silent fallback). The error is loud, names the offending grant, and the operator surfaces it on the AgentRun status.

## Phases

### Phase 0 — Contract and tests first

Before any implementation is delegated; human-reviewed — this is where the security thinking lives.

- Injection protocol doc in `protocol/` — the new `/v1/injection/headers` endpoint (distinct from compatibility `/v1/headers`), the identity role/pairing model (`agent` vs `egress`, one-to-one pairing), materialization modes, admission mismatch rules, and the placeholder convention; placement-agnostic (egressd referenced by URL only).
- Identity-split conformance test: mediated grant → the paired `egress` identity gets injectable material; the `agent` identity requesting the same capability gets routing config only, no secret; an `egress` identity paired to a *different* agent is refused.
- Admission conformance test: `direct` run × `header-inject` grant and `mediated` run × `file-bundle` grant both fail admission loudly — no downgrade path exists.
- Placeholder-inertness test: where a CLI requires a syntactic key, the placeholder constant carries no entropy, is allowlisted by the non-possession test, and is rejected upstream when presented without sidecar injection.
- Two separate smoke tests: **(a) non-possession** — boot mediated → assert zero secret material anywhere in the container (filesystem, env, process args), for all providers, including scrubbed git credential state (no helpers, no `http.extraHeader`, no stored credentials); **(b) egress-denied** — assert direct egress to upstream hosts is refused. Both mode-aware (skip *visibly* for direct runs so a misconfigured default can't pass silently). Split so (a) lands independent of the hard §7 work.

### Phase 1 — Spike egressd against Codex, API-key mode

Timeboxed and minimal. Build egressd, the identity role/pairing split, and bootstrap redirection using Codex with `model_providers.*.base_url` pointed at the sidecar and a plain bearer key injected from the broker (`token`-provider shape). This validates the entire chain — grant descriptor, identity split, header injection, TLS re-origination, SSE passthrough — on the simple auth mode of the provider actually in use. Separate `egress`-role broker identity from day one. Establish here whether Codex needs a syntactic placeholder key to start, and if so wire the placeholder convention (§4) including the inertness test. Run inside a crude deny-all netns as an *instrument*, not a control: any hardcoded-host call fails loudly, enumerating the real endpoint set Codex needs.

**Scope guard**: nothing beyond what Phase 2 needs to render its verdict — no operator work, no polish, no second provider.

### Phase 2 — ChatGPT-plan flow as the go/no-go gate

Switch the working harness to the plan-auth path (`codex-oauth` grant in `header-inject` mode, `chatgpt_base_url` redirection). Required spike outputs:

1. Does `chatgpt_base_url` cover every host the plan-auth flow touches? The deny-all instrument from Phase 1 answers this empirically.
2. Does Codex pin certs on those hosts? Pinning defeats localhost TLS re-origination → design changes.

Test refresh deterministically with broker-issued artificially short-lived tokens; verify the true SSE guarantee — new requests use the refreshed token, in-flight streams complete on the old one.

**Go/no-go**: if plan-auth can't be redirected, plan-auth Codex stays on bundles and we reassess — API-key-mode Codex mediation (Phase 1's result) ships independently either way, so the fallback still retires file bundles for any agent runnable on an API key.

### Phase 3 — Operator + compose wiring (non-possession ships)

AgentRun controller conditionally adds the egressd container, its identity Secret, and config; compose gets the sidecar behind the profile flag; bootstrap generates redirected config for mediated grants. Phase-0 non-possession + identity-split tests land in CI here — from now on, later phases cannot regress the core property. (No enforcement yet — routing + non-possession only, per §3.)

### Phase 4 — git-over-HTTPS mediation

Per-agent CA, egressd TLS termination, repo-scope extraction, GitHub App token injection. Its own phase for its own risk surface. Delivers non-possession for git tokens; the reachability half waits for Phase 5 (§5 interim note).

### Phase 5 — Egress enforcement + audit + quotas + revocation

May split into two PRs (enforcement; observability/control) even as one phase.

- **Enforcement**: evaluate own-Pod egressd + NetworkPolicy vs. deprivileged-dind as the k8s control (§6); iptables owner-match **plus FORWARD-chain deny** where in-netns rules apply; state the NET_ADMIN precondition and the compose gap explicitly. Egress-denied smoke test lands in CI here.
- **Per-request audit** appended to the broker's `audit.jsonl` (agent, capability, host, method, path class, status).
- **Per-grant request-count quotas** at the sidecar (spend quotas deferred — they need provider-response parsing, which couples the generic proxy to each provider).
- **Revocation**: broker revokes grant → sidecar's next fetch fails → agent loses API access within one cache TTL, without killing the Pod.
- **Anthropic as the provider-agnosticism proof**: adding `ANTHROPIC_BASE_URL` + a grant must be config-only with zero egressd changes — landing it *is* the test that the injector contract stayed provider-agnostic. If it requires sidecar code, that's a contract regression, not a feature.
- Then flip the operator default to `mediated`.

## PR sequence

One phase per PR. This is load-bearing: line-by-line review of the trusted core is only realistic on phase-sized diffs; the Phase-2 gate must be able to stop the train before wiring investment; and the Phase-3 CI ratchet only protects later phases if phases merge sequentially. The constraint is on *merging*, not starting — Phase 0 can be reviewed while the Phase-1 spike runs against a draft of the contract.

| PR | Contents | Merge gate |
|---|---|---|
| 1 | Phase 0: protocol doc + conformance/smoke test skeletons | human review of the contract — slowest, most careful |
| 2 | Phase 1: egressd + identity split + Codex API-key mode | trusted-core review; timeboxed spike result |
| 3 | Phase 2: ChatGPT-plan flow + refresh/SSE tests | **go/no-go decision recorded in the PR** |
| 4 | Phase 3: operator + compose wiring; non-possession tests → CI | conformance green in CI |
| 5 | Phase 4: git-HTTPS mediation (CA, TLS termination) | trusted-core review — highest-risk surface, deliberately alone |
| 6a | Phase 5: enforcement (own-Pod evaluation, iptables + FORWARD deny) | egress-denied test → CI |
| 6b | Phase 5: audit, quotas, revocation, Anthropic proof; flip operator default | both smoke tests green |

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

## End state

Agent containers hold zero credentials for mediated providers (LLM APIs, GitHub REST, git-HTTPS); the broker decides *whether* (grants, quotas), the sidecar handles *how* (injection at the edge); every credentialed request is audited; a grant is revocable mid-run within one cache TTL. Where enforcement lives outside the agent's privilege domain (own-Pod egressd + CNI policy, or deprivileged dind), a static default-deny makes the sidecar the only way out; where it does not (today's compose), non-possession still holds and egress-deny is a documented gap. All optional per grant, with today's behavior the untouched default until the smoke tests say otherwise.
