package portal

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

type inProcessBlockingRunner struct{}

func (r inProcessBlockingRunner) Run(
	ctx context.Context,
	_, adapter string,
	_ <-chan string,
	publish func(providerAction),
) ([]byte, string) {
	if adapter == AdapterClaudeOAuthFile {
		publish(providerAction{AuthorizationURL: "https://claude.com/cai/oauth/authorize", NeedsCode: true})
	} else {
		publish(providerAction{AuthorizationURL: fakeCodexDeviceURL, UserCode: fakeDeviceCode})
	}
	<-ctx.Done()

	return nil, reasonTimeout
}

func (r inProcessBlockingRunner) Acknowledge(_ context.Context, _ string) error { return nil }
func (r inProcessBlockingRunner) Cancel(_ context.Context, _ string) error      { return nil }
func (r inProcessBlockingRunner) Ready(_ context.Context) error                 { return nil }

const (
	fakeCLIAccess      = "fake-cli-access-must-not-leak"
	fakeCLIRefresh     = "fake-cli-refresh-must-not-leak"
	scenarioSymlink    = "symlink"
	scenarioMalformed  = "malformed"
	fakeDeviceCode     = "ABCD-EFGH"
	fakeCodexDeviceURL = "https://auth.openai.com/codex/device"
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
		fakeCLIPrint("Open " + fakeCodexDeviceURL + " and enter " + fakeDeviceCode)
	case scenarioMalformed:
		fakeCLIPrint("Open https://untrusted.example/device and enter " + fakeDeviceCode)
	case "claude-success":
		fakeCLIPrint("Open https://claude.com/cai/oauth/authorize?state=fake-state")
		fakeCLIPrint("Paste code here if prompted")
		scanner := bufio.NewScanner(os.Stdin)
		if !scanner.Scan() || scanner.Text() != "fake-claude-callback-code" {
			os.Exit(9)
		}
	case testOversized:
		fakeCLIPrint("Open " + fakeCodexDeviceURL + " and enter " + fakeDeviceCode)
		fakeCLIPrint(strings.Repeat("x", 8192))
		select {}
	case reasonTimeout:
		if kind == claudeCommand {
			fakeCLIPrint("Open https://claude.com/cai/oauth/authorize?state=fake-state")
		} else {
			fakeCLIPrint("Open " + fakeCodexDeviceURL + " and enter " + fakeDeviceCode)
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
	runner := NewCLICredentialRunner(cfg.Enrollment)
	manager := NewEnrollmentManager(cfg, patcher, NewAuditLogger(audit), runner)
	if scenario == testOversized {
		manager.config.MaxOutputBytes = 4096
		runner.config.MaxOutputBytes = 4096
	}
	root := t.TempDir()
	runner.tempRoot = root
	adapter := runner.adapters[adapterName]
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
	runner.adapters[adapterName] = adapter
	return manager, patcher, audit, root
}

func blockingEnrollmentManager(t *testing.T) (*EnrollmentManager, *memoryPatcher) {
	t.Helper()
	cfg := testConfig()
	patcher := &memoryPatcher{value: []byte("old-secret")}
	manager := NewEnrollmentManager(
		cfg,
		patcher,
		NewAuditLogger(&bytes.Buffer{}),
		inProcessBlockingRunner{},
	)

	return manager, patcher
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

func TestCodexDeviceActionRecognizesANSIColoredHandoff(t *testing.T) {
	output := []byte(
		"Open \x1b[94mhttps://auth.openai.com/codex/device\x1b[0m and enter " +
			"\x1b[94mABCD-EFGHI\x1b[0m",
	)
	action, found, err := defaultEnrollmentAdapters()[AdapterCodexOAuthFile].action(output)
	if err != nil || !found || action.AuthorizationURL != fakeCodexDeviceURL ||
		action.UserCode != "ABCD-EFGHI" || action.NeedsCode {
		t.Fatal("ANSI-colored Codex handoff was not recognized")
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
		(action.AuthorizationURL != fakeCodexDeviceURL || action.UserCode != fakeDeviceCode || action.NeedsCode) {
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

func TestCodexConnectAndReconnectReplaceConfiguredLocalSlot(t *testing.T) {
	cfg := testConfig()
	root := t.TempDir()
	patcher, err := NewLocalFilePatcher(root, cfg.Namespace, cfg.Slots)
	if err != nil {
		t.Fatal(err)
	}
	runner := NewCLICredentialRunner(cfg.Enrollment)
	runner.tempRoot = t.TempDir()
	adapter := runner.adapters[AdapterCodexOAuthFile]
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	adapter.Command = executable
	adapter.Args = []string{"-test.run=^TestEnrollmentCLIHelper$"}
	adapter.Environment = []string{
		"NVT_FAKE_CLI_SCENARIO=codex-success",
		"NVT_FAKE_CREDENTIAL_KIND=" + codexCommand,
	}
	runner.adapters[AdapterCodexOAuthFile] = adapter
	manager := NewEnrollmentManager(cfg, patcher, NewAuditLogger(&bytes.Buffer{}), runner)
	defer manager.Close()

	principal := Principal{Issuer: testIdentityIssuer, Subject: testAliceSubject}
	for attempt := 0; attempt < 2; attempt++ {
		status, startErr := manager.Start(t.Context(), principal, cfg.Slots[0], time.Now().Add(time.Hour))
		if startErr != nil {
			t.Fatal(startErr)
		}
		waitEnrollmentStatus(t, manager, principal, status.ID, enrollmentSucceeded)
		deadline := time.Now().Add(time.Second)
		for len(manager.semaphore) != 0 && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
	}
	credential, err := os.ReadFile(filepath.Join(root, testAliceSubject))
	if err != nil || ValidateCredential(AdapterCodexOAuthFile, credential) != nil {
		t.Fatal("connect/reconnect did not persist the validated local slot")
	}
	if _, err := os.Stat(filepath.Join(root, testBobSubject)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("connect/reconnect changed another local slot")
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
	if patcher.key != testClaudeCredentialKey || ValidateCredential(AdapterClaudeOAuthFile, patcher.value) != nil {
		t.Fatal("Claude enrollment did not patch the exact validated destination")
	}
	entries, readErr := os.ReadDir(root)
	if readErr != nil || len(entries) != 0 {
		t.Fatal("ephemeral Claude home was not removed")
	}
}

func TestEnrollmentRejectsCrossOwnerStatusCodeAndCancellation(t *testing.T) {
	manager, _ := blockingEnrollmentManager(t)
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
		{"Secret patch", "codex-success", reasonSecretUpdateFailed, true},
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
	manager, patcher := blockingEnrollmentManager(t)
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

func TestCLICredentialRunnerCancellationStopsProcessAndCleansHome(t *testing.T) {
	cfg := testConfig()
	runner := NewCLICredentialRunner(cfg.Enrollment)
	root := t.TempDir()
	runner.tempRoot = root
	adapter := runner.adapters[AdapterCodexOAuthFile]
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	adapter.Command = executable
	adapter.Args = []string{"-test.run=^TestEnrollmentCLIHelper$"}
	adapter.Environment = []string{
		"NVT_FAKE_CLI_SCENARIO=" + reasonTimeout,
		"NVT_FAKE_CREDENTIAL_KIND=" + codexCommand,
	}
	runner.adapters[AdapterCodexOAuthFile] = adapter
	ctx, cancel := context.WithCancel(t.Context())
	actionSeen := make(chan struct{})
	done := make(chan string, 1)
	go func() {
		_, reason := runner.Run(ctx, "pty-cancel-test", AdapterCodexOAuthFile, nil, func(providerAction) {
			close(actionSeen)
		})
		done <- reason
	}()
	<-actionSeen
	cancel()
	if reason := <-done; reason != reasonTimeout {
		t.Fatalf("cancelled PTY returned reason %q", reason)
	}
	entries, readErr := os.ReadDir(root)
	if readErr != nil || len(entries) != 0 {
		t.Fatal("cancelled PTY runner left its temporary home")
	}
}
