package portal

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

const (
	fakeCLIAccess     = "fake-cli-access-must-not-leak"
	fakeCLIRefresh    = "fake-cli-refresh-must-not-leak"
	scenarioSymlink   = "symlink"
	scenarioMalformed = "malformed"
)

//nolint:gocyclo // One subprocess fixture models every bounded CLI outcome used by conformance tests.
func TestEnrollmentCLIHelper(t *testing.T) {
	scenario := os.Getenv("NVT_FAKE_CLI_SCENARIO")
	if scenario == "" {
		return
	}
	for _, forbidden := range []string{
		"NVT_CREDENTIAL_PORTAL_SESSION_SECRET",
		"NVT_CREDENTIAL_PORTAL_CLIENT_SECRET",
		"KUBERNETES_SERVICE_HOST",
		"OPENAI_API_KEY",
	} {
		if os.Getenv(forbidden) != "" {
			os.Exit(14)
		}
	}
	home := os.Getenv("HOME")
	kind := os.Getenv("NVT_FAKE_CREDENTIAL_KIND")
	credentialPath := filepath.Join(home, ".codex", "auth.json")
	document := validCodex(fakeCLIAccess, fakeCLIRefresh)
	if kind == claudeCommand {
		credentialPath = filepath.Join(home, ".claude", ".credentials.json")
		document = validClaude(fakeCLIAccess, fakeCLIRefresh)
	}
	switch scenario {
	case "codex-success", scenarioSymlink:
		fakeCLIPrint("Open https://auth.openai.com/codex/device and enter ABCD-EFGH")
	case scenarioMalformed:
		fakeCLIPrint("Open https://untrusted.example/device and enter ABCD-EFGH")
	case "claude-success":
		fakeCLIPrint("Open https://claude.com/cai/oauth/authorize?state=fake-state")
		fakeCLIPrint("Paste code here if prompted")
		scanner := bufio.NewScanner(os.Stdin)
		if !scanner.Scan() || scanner.Text() != "fake-claude-callback-code" {
			os.Exit(9)
		}
	case testOversized:
		fakeCLIPrint("Open https://auth.openai.com/codex/device and enter ABCD-EFGH")
		fakeCLIPrint(strings.Repeat("x", 8192))
		select {}
	case reasonTimeout:
		if kind == claudeCommand {
			fakeCLIPrint("Open https://claude.com/cai/oauth/authorize?state=fake-state")
		} else {
			fakeCLIPrint("Open https://auth.openai.com/codex/device and enter ABCD-EFGH")
		}
		select {}
	case "failure":
		fakeCLIPrint("provider-secret-output-must-not-leak")
		os.Exit(7)
	default:
		os.Exit(8)
	}
	if err := os.MkdirAll(filepath.Dir(credentialPath), 0o700); err != nil {
		os.Exit(10)
	}
	if scenario == scenarioSymlink {
		outside := filepath.Join(home, "outside")
		if err := os.WriteFile(outside, document, 0o600); err != nil || os.Symlink(outside, credentialPath) != nil {
			os.Exit(11)
		}
		return
	}
	if err := os.WriteFile(credentialPath, document, 0o600); err != nil {
		os.Exit(12)
	}
}

func fakeCLIPrint(value string) {
	if _, err := fmt.Fprintln(os.Stdout, value); err != nil {
		os.Exit(13)
	}
}

func fakeEnrollmentManager(
	t *testing.T,
	adapterName, scenario string,
) (*EnrollmentManager, *memoryPatcher, *bytes.Buffer, string) {
	t.Helper()
	cfg := testConfig()
	patcher := &memoryPatcher{value: []byte("old-secret")}
	audit := &bytes.Buffer{}
	manager := NewEnrollmentManager(cfg, patcher, NewAuditLogger(audit))
	if scenario == testOversized {
		manager.config.MaxOutputBytes = 4096
	}
	root := t.TempDir()
	manager.tempRoot = root
	adapter := manager.adapters[adapterName]
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	adapter.Command = executable
	adapter.Args = []string{"-test.run=^TestEnrollmentCLIHelper$"}
	kind := codexCommand
	if adapterName == AdapterClaudeOAuthFile {
		kind = claudeCommand
	}
	adapter.Environment = []string{"NVT_FAKE_CLI_SCENARIO=" + scenario, "NVT_FAKE_CREDENTIAL_KIND=" + kind}
	manager.adapters[adapterName] = adapter
	return manager, patcher, audit, root
}

func waitEnrollmentStatus(
	t *testing.T,
	manager *EnrollmentManager,
	principal Principal,
	id string,
	wanted ...string,
) EnrollmentStatus {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		status, err := manager.Status(principal, id)
		if err != nil {
			t.Fatal(err)
		}
		if slices.Contains(wanted, status.Status) {
			return status
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("enrollment did not reach expected state")
	return EnrollmentStatus{}
}

func TestDefaultCommandAdaptersPinOfficialInvocationAndCredentialDiscovery(t *testing.T) {
	adapters := defaultEnrollmentAdapters()
	codex := adapters[AdapterCodexOAuthFile]
	if codex.Command != "codex" || strings.Join(codex.Args, " ") != "login --device-auth" ||
		codex.CredentialRelative != filepath.Join(".codex", "auth.json") {
		t.Fatal("Codex command adapter changed")
	}
	claude := adapters[AdapterClaudeOAuthFile]
	if claude.Command != "claude" || strings.Join(claude.Args, " ") != "auth login --claudeai" ||
		claude.CredentialRelative != filepath.Join(".claude", ".credentials.json") {
		t.Fatal("Claude command adapter changed")
	}
}

//nolint:gocyclo // This conformance test covers initial Connect and unconditional Reconnect in one lifecycle.
func TestCodexConnectBindsSlotPatchesValidatedFileAndCleansUp(t *testing.T) {
	t.Setenv("NVT_CREDENTIAL_PORTAL_SESSION_SECRET", "portal-session-secret-canary")
	t.Setenv("NVT_CREDENTIAL_PORTAL_CLIENT_SECRET", "portal-client-secret-canary")
	t.Setenv("KUBERNETES_SERVICE_HOST", "kubernetes-api-canary")
	t.Setenv("OPENAI_API_KEY", "ambient-provider-secret-canary")
	manager, patcher, audit, root := fakeEnrollmentManager(t, AdapterCodexOAuthFile, "codex-success")
	defer manager.Close()
	principal := Principal{Issuer: testIdentityIssuer, Subject: testAliceSubject}
	status, err := manager.Start(t.Context(), principal, testConfig().Slots[0], time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	action := waitEnrollmentStatus(t, manager, principal, status.ID, enrollmentActionRequired, enrollmentSucceeded)
	if action.Status == enrollmentActionRequired &&
		(action.AuthorizationURL != "https://auth.openai.com/codex/device" || action.UserCode != "ABCD-EFGH" || action.NeedsCode) {
		t.Fatal("unexpected Codex authorization handoff")
	}
	completed := waitEnrollmentStatus(t, manager, principal, status.ID, enrollmentSucceeded)
	if completed.AuthorizationURL != "" || completed.UserCode != "" || patcher.name != testPortalSeed ||
		patcher.key != testCodexAuthKey ||
		ValidateCredential(AdapterCodexOAuthFile, patcher.value) != nil {
		t.Fatal("Codex enrollment did not patch the exact validated destination")
	}
	entries, readErr := os.ReadDir(root)
	if readErr != nil || len(entries) != 0 {
		t.Fatal("ephemeral Codex home was not removed")
	}
	combined := audit.String()
	if strings.Contains(combined, fakeCLIAccess) || strings.Contains(combined, fakeCLIRefresh) {
		t.Fatal("credential appeared in audit output")
	}
	deadline := time.Now().Add(time.Second)
	for len(manager.semaphore) != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	reconnected, err := manager.Start(
		t.Context(), principal, testConfig().Slots[0], time.Now().Add(time.Hour),
	)
	if err != nil {
		t.Fatal(err)
	}
	waitEnrollmentStatus(t, manager, principal, reconnected.ID, enrollmentSucceeded)
	if patcher.calls != 2 {
		t.Fatal("reconnect did not replace the same exact slot")
	}
}

func TestClaudeConnectAcceptsOneCodeAndRejectsReplay(t *testing.T) {
	manager, patcher, _, root := fakeEnrollmentManager(t, AdapterClaudeOAuthFile, "claude-success")
	defer manager.Close()
	principal := Principal{Issuer: testIdentityIssuer, Subject: testBobSubject}
	status, err := manager.Start(t.Context(), principal, testConfig().Slots[1], time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	action := waitEnrollmentStatus(t, manager, principal, status.ID, enrollmentActionRequired)
	if action.AuthorizationURL == "" || !action.NeedsCode || action.UserCode != "" {
		t.Fatal("unexpected Claude authorization handoff")
	}
	if err := manager.ProvideCode(principal, status.ID, "fake-claude-callback-code"); err != nil {
		t.Fatal(err)
	}
	if err := manager.ProvideCode(principal, status.ID, "replayed-code"); !errors.Is(err, ErrEnrollmentState) {
		t.Fatal("Claude callback code replay was accepted")
	}
	waitEnrollmentStatus(t, manager, principal, status.ID, enrollmentSucceeded)
	if patcher.key != "credentials.json" || ValidateCredential(AdapterClaudeOAuthFile, patcher.value) != nil {
		t.Fatal("Claude enrollment did not patch the exact validated destination")
	}
	entries, readErr := os.ReadDir(root)
	if readErr != nil || len(entries) != 0 {
		t.Fatal("ephemeral Claude home was not removed")
	}
}

func TestEnrollmentRejectsCrossOwnerStatusCodeAndCancellation(t *testing.T) {
	manager, patcher, audit, root := fakeEnrollmentManager(t, AdapterClaudeOAuthFile, reasonTimeout)
	if patcher == nil || audit == nil || root == "" {
		t.Fatal("invalid fake enrollment manager")
	}
	defer manager.Close()
	owner := Principal{Issuer: testIdentityIssuer, Subject: testBobSubject}
	other := Principal{Issuer: testIdentityIssuer, Subject: testAliceSubject}
	status, err := manager.Start(t.Context(), owner, testConfig().Slots[1], time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	waitEnrollmentStatus(t, manager, owner, status.ID, enrollmentActionRequired)
	if _, err := manager.Status(other, status.ID); !errors.Is(err, ErrEnrollmentNotFound) {
		t.Fatal("cross-owner status was visible")
	}
	if err := manager.ProvideCode(other, status.ID, "other-code"); !errors.Is(err, ErrEnrollmentNotFound) {
		t.Fatal("cross-owner code was accepted")
	}
	if err := manager.Cancel(other, status.ID); !errors.Is(err, ErrEnrollmentNotFound) {
		t.Fatal("cross-owner cancellation was accepted")
	}
	if err := manager.Cancel(owner, status.ID); err != nil {
		t.Fatal(err)
	}
	waitEnrollmentStatus(t, manager, owner, status.ID, enrollmentCancelled)
}

func TestEnrollmentFailuresStaySanitizedAndPreserveSecret(t *testing.T) {
	cases := []struct {
		name, scenario, reason string
		patchFailure           bool
	}{
		{"process", "failure", reasonProcessFailed, false},
		{scenarioMalformed, scenarioMalformed, reasonMalformedOutput, false},
		{testOversized, testOversized, "output-too-large", false},
		{scenarioSymlink, scenarioSymlink, reasonCredentialUnsafe, false},
		{"Secret patch", "codex-success", "secret-update-failed", true},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			manager, patcher, audit, root := fakeEnrollmentManager(t, AdapterCodexOAuthFile, test.scenario)
			defer manager.Close()
			if test.patchFailure {
				patcher.err = errTestAPI
			}
			principal := Principal{Issuer: testIdentityIssuer, Subject: testAliceSubject}
			status, err := manager.Start(t.Context(), principal, testConfig().Slots[0], time.Now().Add(time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			failed := waitEnrollmentStatus(t, manager, principal, status.ID, enrollmentFailed)
			expectedCalls := 0
			if test.patchFailure {
				expectedCalls = 1
			}
			if failed.Reason != test.reason || string(patcher.value) != "old-secret" || patcher.calls != expectedCalls {
				t.Fatal("failed CLI enrollment changed the old Secret or returned an unexpected reason")
			}
			if strings.Contains(audit.String(), fakeCLIAccess) || strings.Contains(audit.String(), fakeCLIRefresh) ||
				strings.Contains(audit.String(), "provider-secret-output") {
				t.Fatal("CLI or credential content appeared in audit output")
			}
			entries, readErr := os.ReadDir(root)
			if readErr != nil || len(entries) != 0 {
				t.Fatal("failed CLI enrollment left its ephemeral home")
			}
		})
	}
}

func TestEnrollmentTimeoutAuthExpiryAndLogoutCancellation(t *testing.T) {
	manager, patcher, audit, root := fakeEnrollmentManager(t, AdapterCodexOAuthFile, reasonTimeout)
	if audit == nil || root == "" {
		t.Fatal("invalid fake enrollment manager")
	}
	manager.config.TimeoutSeconds = 1
	defer manager.Close()
	principal := Principal{Issuer: testIdentityIssuer, Subject: testAliceSubject}
	first, err := manager.Start(t.Context(), principal, testConfig().Slots[0], time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	waitEnrollmentStatus(t, manager, principal, first.ID, enrollmentFailed)
	nearExpiry, err := manager.Start(
		t.Context(), principal, testConfig().Slots[0], time.Now().Add(100*time.Millisecond),
	)
	if err != nil {
		t.Fatal(err)
	}
	expired := waitEnrollmentStatus(t, manager, principal, nearExpiry.ID, enrollmentFailed)
	if expired.Reason != reasonTimeout {
		t.Fatal("portal session expiry did not terminate enrollment")
	}
	second, err := manager.Start(t.Context(), principal, testConfig().Slots[0], time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	manager.CancelPrincipal(principal)
	waitEnrollmentStatus(t, manager, principal, second.ID, enrollmentCancelled)
	if patcher.calls != 0 {
		t.Fatal("timeout or logout cancellation patched a Secret")
	}
}
