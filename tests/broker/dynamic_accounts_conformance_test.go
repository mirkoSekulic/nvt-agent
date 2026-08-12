package broker_test

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const dynamicAccountNeedle = "DYNAMIC-ACCOUNT-SECRET-NEEDLE"

type dynamicAccountFixture struct {
	t               *testing.T
	root            string
	home            string
	url             string
	bind            string
	config          string
	audit           string
	key             []byte
	coordinationKey []byte
	command         *exec.Cmd
	output          bytes.Buffer
}

func newDynamicAccountFixture(t *testing.T, enabled bool) *dynamicAccountFixture {
	t.Helper()
	root := repoRoot(t)
	home := t.TempDir()
	port := freePort(t)
	f := &dynamicAccountFixture{
		t: t, root: root, home: home,
		bind:            fmt.Sprintf("127.0.0.1:%d", port),
		url:             fmt.Sprintf("http://127.0.0.1:%d", port),
		config:          filepath.Join(home, "broker.yaml"),
		audit:           filepath.Join(home, "audit.jsonl"),
		key:             []byte("0123456789abcdef0123456789abcdef"),
		coordinationKey: []byte("abcdef0123456789abcdef0123456789"),
	}
	config := "providers: []\n"
	if enabled {
		config += fmt.Sprintf(`dynamic-accounts:
  enabled: true
  state-dir: %q
  authentication:
    hmac-key-env: TEST_DYNAMIC_ACCOUNT_HMAC_KEY
    max-assertion-seconds: 120
  template-switching:
    enabled: true
    operator-hmac-key-env: TEST_DYNAMIC_COORDINATION_HMAC_KEY
    max-assertion-seconds: 60
    reservation-seconds: 30
    request-seconds: 120
  provider-templates:
    - name: approved-oauth
      plugin: codex-oauth
      credential-config-key: auth-file
      config: {}
  credential-templates:
    - name: approved-member
      label: Approved member
      enrollment-adapter: trusted-enrollment-adapter
      provider-template: approved-oauth
    - name: alternate-member
      label: Alternate member
      enrollment-adapter: alternate-enrollment-adapter
      provider-template: approved-oauth
`, filepath.Join(home, "dynamic-state"))
	}
	if err := os.WriteFile(f.config, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	f.start()
	t.Cleanup(f.stop)
	return f
}

func (f *dynamicAccountFixture) start() {
	f.t.Helper()
	f.command = exec.Command("python3", filepath.Join(f.root, "broker", "brokerd.py"))
	f.command.Env = append(os.Environ(),
		"NVT_BROKER_CONFIG="+f.config,
		"NVT_BROKER_BIND="+f.bind,
		"NVT_BROKER_AUDIT_LOG="+f.audit,
		"TEST_DYNAMIC_ACCOUNT_HMAC_KEY="+string(f.key),
		"TEST_DYNAMIC_COORDINATION_HMAC_KEY="+string(f.coordinationKey),
	)
	f.command.Stdout = &f.output
	f.command.Stderr = &f.output
	if err := f.command.Start(); err != nil {
		f.t.Fatal(err)
	}
	waitFor(f.t, 3*time.Second, func() bool {
		response, err := http.Get(f.url + "/health")
		if err != nil {
			return false
		}
		defer response.Body.Close()
		return response.StatusCode == http.StatusOK
	})
}

func (f *dynamicAccountFixture) stop() {
	if f.command == nil || f.command.Process == nil {
		return
	}
	_ = f.command.Process.Kill()
	_ = f.command.Wait()
	f.command = nil
}

func (f *dynamicAccountFixture) assertion(issuer, subject string) string {
	payload := struct {
		Audience             string `json:"audience"`
		EligibilityExpiresAt int64  `json:"eligibility_expires_at"`
		ExpiresAt            int64  `json:"expires_at"`
		Issuer               string `json:"issuer"`
		Subject              string `json:"subject"`
		Version              int    `json:"version"`
	}{
		Audience: "nvt.broker.principal-accounts/v1", ExpiresAt: time.Now().Add(time.Minute).Unix(),
		EligibilityExpiresAt: time.Now().Add(30 * time.Minute).Unix(),
		Issuer:               issuer, Subject: subject, Version: 1,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		f.t.Fatal(err)
	}
	mac := hmac.New(sha256.New, f.key)
	_, _ = mac.Write(raw)
	return "NVT-Principal-v1 " + base64.RawURLEncoding.EncodeToString(raw) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (f *dynamicAccountFixture) post(path, authorization string, body any) (map[string]any, int, string) {
	f.t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		f.t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPost, f.url+path, bytes.NewReader(raw))
	if err != nil {
		f.t.Fatal(err)
	}
	request.Header.Set("Authorization", authorization)
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		f.t.Fatal(err)
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		f.t.Fatal(err)
	}
	decoded := map[string]any{}
	if err := json.Unmarshal(responseBody, &decoded); err != nil {
		f.t.Fatalf("decode response %q: %v", responseBody, err)
	}
	return decoded, response.StatusCode, string(responseBody)
}

func (f *dynamicAccountFixture) coordinate(path, operation string, body any) (map[string]any, int, string) {
	f.t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		f.t.Fatal(err)
	}
	claims, err := json.Marshal(map[string]any{
		"audience":    "nvt.broker.principal-account-coordination/v1",
		"body_sha256": fmt.Sprintf("%x", sha256.Sum256(raw)),
		"expires_at":  time.Now().Add(30 * time.Second).Unix(),
		"operation":   operation,
		"version":     1,
	})
	if err != nil {
		f.t.Fatal(err)
	}
	mac := hmac.New(sha256.New, f.coordinationKey)
	_, _ = mac.Write(claims)
	authorization := "NVT-Principal-Coordination-v1 " + base64.RawURLEncoding.EncodeToString(claims) + "." +
		base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	request, err := http.NewRequest(http.MethodPost, f.url+path, bytes.NewReader(raw))
	if err != nil {
		f.t.Fatal(err)
	}
	request.Header.Set("Authorization", authorization)
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		f.t.Fatal(err)
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		f.t.Fatal(err)
	}
	decoded := map[string]any{}
	if err := json.Unmarshal(responseBody, &decoded); err != nil {
		f.t.Fatalf("decode coordination response %q: %v", responseBody, err)
	}
	return decoded, response.StatusCode, string(responseBody)
}

func (f *dynamicAccountFixture) get(path string) (map[string]any, int) {
	f.t.Helper()
	response, err := http.Get(f.url + path)
	if err != nil {
		f.t.Fatal(err)
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		f.t.Fatal(err)
	}
	decoded := map[string]any{}
	if err := json.Unmarshal(responseBody, &decoded); err != nil {
		f.t.Fatalf("decode response: %v", err)
	}
	return decoded, response.StatusCode
}

func (f *dynamicAccountFixture) credentialPathForSubject(subject string) string {
	f.t.Helper()
	accountsDir := filepath.Join(f.home, "dynamic-state", "accounts")
	entries, err := os.ReadDir(accountsDir)
	if err != nil {
		f.t.Fatal(err)
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		accountDir := filepath.Join(accountsDir, entry.Name())
		raw, err := os.ReadFile(filepath.Join(accountDir, "metadata.json"))
		if err != nil {
			f.t.Fatal(err)
		}
		metadata := struct {
			Subject        string `json:"subject"`
			CredentialFile string `json:"credential_file"`
		}{}
		if err := json.Unmarshal(raw, &metadata); err != nil {
			f.t.Fatal(err)
		}
		if metadata.Subject == subject {
			if metadata.CredentialFile == "" {
				f.t.Fatalf("active account for %q has no credential filename", subject)
			}
			return filepath.Join(accountDir, metadata.CredentialFile)
		}
	}
	f.t.Fatalf("account for %q not found", subject)
	return ""
}

func dynamicCodexCredential(t *testing.T, marker string) string {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"tokens": map[string]any{
			"access_token":  testJWT(time.Now().Add(time.Hour)),
			"refresh_token": dynamicAccountNeedle + "-refresh-" + marker,
			"id_token":      dynamicAccountNeedle + "-identity-" + marker,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func TestDynamicPrincipalAccountHTTPContract(t *testing.T) {
	f := newDynamicAccountFixture(t, true)
	alice := f.assertion("https://issuer.example", "alice-immutable")
	bob := f.assertion("https://issuer.example", "bob-immutable")

	enrollBody := map[string]any{
		"template": "approved-member", "operation_id": "enroll-one",
		"credential_base64": dynamicCodexCredential(t, "one"),
	}
	enrolled, status, body := f.post("/v1/principal-accounts/complete-enrollment", alice, enrollBody)
	if status != http.StatusOK || enrolled["state"] != "ready" || strings.Contains(body, dynamicAccountNeedle) {
		t.Fatalf("unexpected enrollment status=%d body=%s", status, body)
	}
	repeated, status, _ := f.post("/v1/principal-accounts/complete-enrollment", alice, enrollBody)
	if status != http.StatusOK || repeated["generation"] != enrolled["generation"] {
		t.Fatalf("idempotent enrollment mismatch status=%d payload=%v", status, repeated)
	}

	for _, path := range []string{"readiness", "resolve"} {
		payload, ownStatus, ownBody := f.post("/v1/principal-accounts/"+path, alice, map[string]any{})
		if ownStatus != http.StatusOK || payload["ok"] != true || strings.Contains(ownBody, dynamicAccountNeedle) {
			t.Fatalf("own %s failed status=%d body=%s", path, ownStatus, ownBody)
		}
		_, otherStatus, otherBody := f.post("/v1/principal-accounts/"+path, bob, map[string]any{})
		if otherStatus != http.StatusNotFound || strings.Contains(otherBody, "alice") {
			t.Fatalf("cross-principal %s leaked status=%d body=%s", path, otherStatus, otherBody)
		}
	}

	eligibilityRevoked, status, _ := f.post(
		"/v1/principal-accounts/revoke-eligibility", alice, map[string]any{},
	)
	if status != http.StatusOK || eligibilityRevoked["ok"] != true {
		t.Fatalf("eligibility revocation failed status=%d payload=%v", status, eligibilityRevoked)
	}
	deniedResolution, status, deniedResolutionBody := f.post(
		"/v1/principal-accounts/resolve", alice, map[string]any{},
	)
	if status != http.StatusForbidden || deniedResolution["error"] != "principal-not-eligible" ||
		strings.Contains(deniedResolutionBody, dynamicAccountNeedle) {
		t.Fatalf("revoked eligibility did not deny resolution status=%d body=%s", status, deniedResolutionBody)
	}
	eligibilityRenewed, status, _ := f.post(
		"/v1/principal-accounts/renew-eligibility", alice, map[string]any{},
	)
	if status != http.StatusOK || eligibilityRenewed["ok"] != true {
		t.Fatalf("eligibility renewal failed status=%d payload=%v", status, eligibilityRenewed)
	}
	if _, status, _ = f.post("/v1/principal-accounts/resolve", alice, map[string]any{}); status != http.StatusOK {
		t.Fatalf("renewed eligibility did not restore resolution status=%d", status)
	}

	reconnected, status, _ := f.post("/v1/principal-accounts/reconnect", alice, map[string]any{
		"operation_id":      "reconnect-before-expiry",
		"credential_base64": dynamicCodexCredential(t, "two"),
	})
	if status != http.StatusOK || reconnected["generation"] != float64(2) {
		t.Fatalf("reconnect failed status=%d payload=%v", status, reconnected)
	}
	denied, status, deniedBody := f.post("/v1/principal-accounts/reconnect", bob, map[string]any{
		"operation_id": "cross-owner", "credential_base64": dynamicCodexCredential(t, "bob"),
	})
	if status != http.StatusNotFound || denied["error"] != "account-not-found" || strings.Contains(deniedBody, dynamicAccountNeedle) {
		t.Fatalf("cross-principal reconnect status=%d body=%s", status, deniedBody)
	}

	failed, status, failedBody := f.post("/v1/principal-accounts/reconnect", alice, map[string]any{
		"operation_id": "rejected", "credential_base64": base64.StdEncoding.EncodeToString([]byte("invalid " + dynamicAccountNeedle)),
	})
	if status != http.StatusServiceUnavailable || failed["error"] != "provider-initialization-failed" || strings.Contains(failedBody, dynamicAccountNeedle) {
		t.Fatalf("provider rejection status=%d body=%s", status, failedBody)
	}

	reserved, status, _ := f.coordinate(
		"/v1/principal-account-coordination/begin-admission", "begin-admission",
		map[string]any{"issuer": "https://issuer.example", "subject": "alice-immutable", "operation_id": "admission-one"},
	)
	if status != http.StatusOK || reserved["state"] != "reserved" {
		t.Fatalf("admission reservation failed status=%d payload=%v", status, reserved)
	}
	revoked, status, _ := f.post("/v1/principal-accounts/revoke", alice, map[string]any{"operation_id": "revoke-one"})
	if status != http.StatusOK || revoked["state"] != "revoked" {
		t.Fatalf("revoke failed status=%d payload=%v", status, revoked)
	}
	_, status, _ = f.post("/v1/principal-accounts/revoke", alice, map[string]any{"operation_id": "revoke-one"})
	if status != http.StatusOK {
		t.Fatalf("idempotent revoke failed status=%d", status)
	}
	_, status, _ = f.post("/v1/principal-accounts/resolve", alice, map[string]any{})
	if status != http.StatusNotFound {
		t.Fatalf("revoked resolution must fail closed, got %d", status)
	}
	revokedReadiness, status, _ := f.post("/v1/principal-accounts/readiness", alice, map[string]any{})
	if status != http.StatusOK || revokedReadiness["state"] != "revoked" ||
		revokedReadiness["template"] != "approved-member" || revokedReadiness["generation"] != float64(2) {
		t.Fatalf("revoked owner readiness lost its template lock status=%d payload=%v", status, revokedReadiness)
	}
	switchDenied, status, switchBody := f.post("/v1/principal-accounts/complete-enrollment", alice, map[string]any{
		"template": "alternate-member", "operation_id": "unauthorized-switch",
		"credential_base64": dynamicCodexCredential(t, "switch"),
	})
	if status != http.StatusConflict || switchDenied["error"] != "template-switch-not-authorized" ||
		strings.Contains(switchBody, dynamicAccountNeedle) {
		t.Fatalf("revoked template switch was not locked status=%d body=%s", status, switchBody)
	}
	pending, status, _ := f.post(
		"/v1/principal-accounts/request-template-switch", alice, map[string]any{"operation_id": "switch-request"},
	)
	if status != http.StatusOK || pending["state"] != "pending" || pending["request_id"] == "" {
		t.Fatalf("target-free switch request failed status=%d payload=%v", status, pending)
	}
	requestID := pending["request_id"].(string)
	conflict, status, _ := f.coordinate(
		"/v1/principal-account-coordination/begin-template-switch", "begin-template-switch",
		map[string]any{"operation_id": requestID, "request_id": requestID},
	)
	if status != http.StatusConflict || conflict["error"] != "coordination-conflict" {
		t.Fatalf("switch raced an admission reservation status=%d payload=%v", status, conflict)
	}
	_, status, _ = f.coordinate(
		"/v1/principal-account-coordination/end-admission", "end-admission",
		map[string]any{"issuer": "https://issuer.example", "subject": "alice-immutable", "operation_id": "admission-one"},
	)
	if status != http.StatusOK {
		t.Fatalf("admission release failed status=%d", status)
	}
	identity, status, _ := f.coordinate(
		"/v1/principal-account-coordination/begin-template-switch", "begin-template-switch",
		map[string]any{"operation_id": requestID, "request_id": requestID},
	)
	if status != http.StatusOK || identity["issuer"] != "https://issuer.example" || identity["subject"] != "alice-immutable" {
		t.Fatalf("switch proof did not recover exact principal status=%d payload=%v", status, identity)
	}
	authorized, status, authorizationBody := f.coordinate(
		"/v1/principal-account-coordination/commit-template-switch", "commit-template-switch",
		map[string]any{"issuer": "https://issuer.example", "subject": "alice-immutable", "operation_id": requestID},
	)
	if status != http.StatusOK || authorized["state"] != "authorized" || strings.Contains(authorizationBody, dynamicAccountNeedle) {
		t.Fatalf("switch authorization failed status=%d body=%s", status, authorizationBody)
	}
	switched, status, switchedBody := f.post("/v1/principal-accounts/complete-enrollment", alice, map[string]any{
		"template": "alternate-member", "operation_id": "authorized-switch",
		"credential_base64": dynamicCodexCredential(t, "authorized-switch"),
	})
	if status != http.StatusOK || switched["template"] != "alternate-member" || strings.Contains(switchedBody, dynamicAccountNeedle) {
		t.Fatalf("authorized switch failed status=%d body=%s", status, switchedBody)
	}
	reconnectedAfterSwitch, status, _ := f.post("/v1/principal-accounts/reconnect", alice, map[string]any{
		"operation_id": "same-template-reconnect", "credential_base64": dynamicCodexCredential(t, "same-template"),
	})
	if status != http.StatusOK || reconnectedAfterSwitch["template"] != "alternate-member" {
		t.Fatalf("current-template reconnect changed after switch status=%d payload=%v", status, reconnectedAfterSwitch)
	}

	f.stop()
	audit, err := os.ReadFile(f.audit)
	if err != nil {
		t.Fatal(err)
	}
	allObservable := string(audit) + f.output.String()
	if strings.Contains(allObservable, dynamicAccountNeedle) || strings.Contains(allObservable, enrollBody["credential_base64"].(string)) {
		t.Fatalf("credential appeared in logs or audit: %s", allObservable)
	}
}

func TestDynamicPrincipalAccountRestartFailureIsAccountLocalAndReconnectable(t *testing.T) {
	f := newDynamicAccountFixture(t, true)
	alice := f.assertion("https://issuer.example", "alice-restart")
	bob := f.assertion("https://issuer.example", "bob-restart")

	for _, enrollment := range []struct {
		authorization string
		operationID   string
		marker        string
	}{
		{alice, "alice-enroll", "alice-before-restart"},
		{bob, "bob-enroll", "bob-before-restart"},
	} {
		_, status, body := f.post("/v1/principal-accounts/complete-enrollment", enrollment.authorization, map[string]any{
			"template": "approved-member", "operation_id": enrollment.operationID,
			"credential_base64": dynamicCodexCredential(t, enrollment.marker),
		})
		if status != http.StatusOK {
			t.Fatalf("initial enrollment failed status=%d body=%s", status, body)
		}
	}

	f.stop()
	aliceCredential := f.credentialPathForSubject("alice-restart")
	if err := os.WriteFile(aliceCredential, []byte("invalid credential document"), 0o600); err != nil {
		t.Fatal(err)
	}
	f.start()

	ready, status := f.get("/ready")
	if status != http.StatusOK || ready["ok"] != true {
		t.Fatalf("account-local failure changed global readiness status=%d payload=%v", status, ready)
	}
	readiness, readinessStatus, _ := f.post("/v1/principal-accounts/readiness", alice, map[string]any{})
	if readinessStatus != http.StatusOK || readiness["state"] != "unready" ||
		readiness["template"] != "approved-member" || readiness["generation"] != float64(1) {
		t.Fatalf("degraded Alice readiness lost its template status=%d payload=%v", readinessStatus, readiness)
	}
	resolution, resolutionStatus, _ := f.post("/v1/principal-accounts/resolve", alice, map[string]any{})
	if resolutionStatus != http.StatusServiceUnavailable || resolution["error"] != "account-unready" {
		t.Fatalf("degraded Alice resolution did not fail closed status=%d payload=%v", resolutionStatus, resolution)
	}
	resolvedBob, status, _ := f.post("/v1/principal-accounts/resolve", bob, map[string]any{})
	if status != http.StatusOK || resolvedBob["ok"] != true {
		t.Fatalf("healthy Bob resolution failed status=%d payload=%v", status, resolvedBob)
	}

	reconnected, status, body := f.post("/v1/principal-accounts/reconnect", alice, map[string]any{
		"operation_id":      "alice-recover",
		"credential_base64": dynamicCodexCredential(t, "alice-after-restart"),
	})
	if status != http.StatusOK || reconnected["state"] != "ready" {
		t.Fatalf("degraded owner reconnect failed status=%d body=%s", status, body)
	}
	resolvedAlice, status, _ := f.post("/v1/principal-accounts/resolve", alice, map[string]any{})
	if status != http.StatusOK || resolvedAlice["ok"] != true {
		t.Fatalf("reconnected Alice resolution failed status=%d payload=%v", status, resolvedAlice)
	}
}

func TestDynamicPrincipalAccountsDisabledCompatibility(t *testing.T) {
	f := newDynamicAccountFixture(t, false)
	payload, status, _ := f.post(
		"/v1/principal-accounts/resolve",
		f.assertion("https://issuer.example", "principal"),
		map[string]any{},
	)
	if status != http.StatusNotFound || payload["error"] != "not-found" {
		t.Fatalf("disabled endpoint changed compatibility: status=%d payload=%v", status, payload)
	}
}
