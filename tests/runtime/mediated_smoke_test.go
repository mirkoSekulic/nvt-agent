package runtime_test

// Phase 0 skeletons for the mediated-mode smoke tests
// (protocol/injection.md, docs/mediated-egress-plan.md).
//
// The plan defines two decoupled guarantees with one smoke test each:
//
//   (a) non-possession  - zero secret material in the agent container
//                         (ships with plan Phase 3, operator/compose wiring)
//   (b) egress-denied   - direct egress to upstream hosts is refused
//                         (ships with plan Phase 5, enforcement)
//
// plus the placeholder-inertness test from the placeholder convention.
// The tests are split so (a) lands and ratchets in CI independent of the
// harder enforcement work. All are skipped pending their phase; bodies pin
// the intended assertions. Both smoke tests are mode-aware by design: they
// run against mediated agents and must skip *visibly* for direct-mode runs.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	nonPossessionPending = "pending Phase 3 (docs/mediated-egress-plan.md): mediated operator/compose wiring not implemented"
	placeholderPending   = "pending Phase 3 (docs/mediated-egress-plan.md): protocol-level inertness is covered by egressd/internal/egress tests as of Phase 1; this container-level test lands with mediated wiring"
	egressDeniedPending  = "pending Phase 5 (docs/mediated-egress-plan.md): egress enforcement not implemented"
)

// mediatedPlaceholder is the documented zero-entropy constant from
// protocol/injection.md. It is the only credential-shaped string allowed to
// exist inside a mediated agent container.
const mediatedPlaceholder = "NVT-PLACEHOLDER-NOT-A-KEY"

// scanTreeForSecretMaterial walks root and fails the test if any known secret
// value appears in a regular file. Phase 3 points this at an export of the
// mediated agent container filesystem (state dir, home, git config, env
// snapshots) with the real fixture secrets as needles.
func scanTreeForSecretMaterial(t *testing.T, root string, secrets []string) {
	t.Helper()
	err := filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !info.Mode().IsRegular() || info.Size() > 8*1024*1024 {
			return nil
		}
		content, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		text := string(content)
		for _, secret := range secrets {
			if secret == "" || secret == mediatedPlaceholder {
				continue
			}
			if strings.Contains(text, secret) {
				t.Errorf("secret material found in %s", path)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// assertScrubbedGitState fails if the container's git configuration retains
// any credential path: helpers, extraHeader injection, URL rewrites, or
// stored credential files (protocol/injection.md, plan section 5).
func assertScrubbedGitState(t *testing.T, home string) {
	t.Helper()
	forbiddenConfig := []string{"credential.helper", "http.extraheader", "insteadof"}
	for _, name := range []string{".gitconfig", ".config/git/config"} {
		path := filepath.Join(home, name)
		content, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		text := strings.ToLower(string(content))
		for _, needle := range forbiddenConfig {
			if strings.Contains(text, needle) {
				t.Errorf("mediated git config %s retains %q", path, needle)
			}
		}
	}
	for _, name := range []string{".git-credentials", ".config/git/credentials"} {
		if _, err := os.Stat(filepath.Join(home, name)); err == nil {
			t.Errorf("mediated container retains stored git credentials: %s", name)
		}
	}
}

// TestMediatedNonPossession is smoke test (a): boot an agent in mediated
// mode, then assert zero secret material anywhere the agent can read.
//
// Phase 3 wiring for this skeleton:
//  1. Start broker + egressd fixtures with known fixture secrets.
//  2. Boot the agent container in mediated mode (MEDIATED=1 / egress:
//     mediated) with header-inject grants for all fixture providers.
//  3. Export the container-visible state: agent home, NVT state dir, env
//     (`/proc/1/environ` and shell env), process args (`ps axww`).
//  4. Assert none of the fixture secrets appear (scanTreeForSecretMaterial
//     over the export; direct checks over env and args).
//  5. Assert git state is scrubbed (assertScrubbedGitState).
//  6. Assert no auth bundles were materialized (no auth.json for mediated
//     providers).
//
// Mode-awareness: for a direct-mode agent this test must skip loudly, never
// pass silently — a misconfigured default that flips runs back to bundles
// must not turn the suite green.
func TestMediatedNonPossession(t *testing.T) {
	t.Skip(nonPossessionPending)

	exportRoot := t.TempDir() // Phase 3: replaced by the real container export
	fixtureSecrets := []string{
		// Phase 3: populated with the broker fixture's live values, e.g. the
		// codex access/refresh tokens and static provider secrets.
	}
	scanTreeForSecretMaterial(t, exportRoot, fixtureSecrets)
	assertScrubbedGitState(t, exportRoot)
}

// TestMediatedPlaceholderInert pins the placeholder convention: the constant
// satisfies CLI syntax checks but grants nothing upstream.
//
// Phase 1 wiring for this skeleton:
//  1. Start a fake upstream that accepts only the real fixture credential.
//  2. Issue a direct request (bypassing egressd) presenting the placeholder
//     as a bearer token; assert the upstream rejects it.
//  3. Issue the same request through egressd; assert the upstream sees the
//     real credential and never sees the placeholder
//     (strip_request_headers behavior).
func TestMediatedPlaceholderInert(t *testing.T) {
	t.Skip(placeholderPending)

	if mediatedPlaceholder != "NVT-PLACEHOLDER-NOT-A-KEY" {
		t.Fatal("placeholder constant must match protocol/injection.md")
	}
}

// TestMediatedEgressDenied is smoke test (b): direct egress from the agent
// to upstream hosts is refused; egressd is the only way out.
//
// Phase 5 wiring for this skeleton:
//  1. Boot a mediated agent with enforcement enabled.
//  2. From the agent process: direct connections to the mediated upstream
//     hosts must fail (connection refused/blocked, not 401).
//  3. From a container spawned inside dind: the same connections must fail
//     (FORWARD-chain coverage, plan section 7).
//  4. The same requests through egressd succeed.
//
// Where enforcement is not a real control (today's compose privileged-dind
// model), this test documents the gap by skipping with an explicit reason,
// never by passing.
func TestMediatedEgressDenied(t *testing.T) {
	t.Skip(egressDeniedPending)
}
