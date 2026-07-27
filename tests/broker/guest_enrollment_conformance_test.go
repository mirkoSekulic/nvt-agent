package broker_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	guestEnrollmentVersion         = "nvt.guest-enrollment/v1"
	guestEnrollmentIssuePath       = "/v1/guest-enrollment/issue"
	guestEnrollmentExchangePath    = "/v1/guest-enrollment/exchange"
	guestEnrollmentRevokeBinding   = "/v1/guest-enrollment/revoke-binding"
	guestEnrollmentRevokeExecution = "/v1/guest-enrollment/revoke-execution"
	guestEnrollmentExchangeURL     = "https://broker.example/v1/guest-enrollment/exchange"
	guestEnrollmentOrchestrator    = "orchestrator-token-0123456789abcdef"
)

func newGuestEnrollmentBrokerFixture(t *testing.T) *brokerFixture {
	t.Helper()
	fixture := newBrokerFixtureBase(t, "", "")
	fixture.writeRoleIdentities(mediatedIdentities())
	tokenFile := filepath.Join(fixture.home, "guest-enrollment-orchestrator-token")
	if err := os.WriteFile(tokenFile, []byte(guestEnrollmentOrchestrator), 0o600); err != nil {
		t.Fatal(err)
	}
	fixture.extraEnv = []string{
		"NVT_BROKER_GUEST_ENROLLMENT_ENABLED=true",
		"NVT_BROKER_GUEST_ENROLLMENT_DB=" + filepath.Join(fixture.home, "guest-enrollment.sqlite3"),
		"NVT_BROKER_GUEST_ENROLLMENT_EXCHANGE_URL=" + guestEnrollmentExchangeURL,
		"NVT_BROKER_GUEST_ENROLLMENT_ORCHESTRATOR_TOKEN_FILE=" + tokenFile,
	}
	fixture.start()
	t.Cleanup(fixture.stop)
	return fixture
}

func TestGuestEnrollmentAPIExactLifecycleRestartAndScopeCleanup(t *testing.T) {
	fixture := newGuestEnrollmentBrokerFixture(t)
	firstRequest := enrollmentIssueRequest("run-uid", "execution-1", 1, "guest-first", 300)
	status, first := fixture.postJSONWithToken(guestEnrollmentOrchestrator, guestEnrollmentIssuePath, firstRequest)
	assertEnrollmentStatus(t, status, first, http.StatusOK, "")
	if first["exchange_url"] != guestEnrollmentExchangeURL {
		t.Fatalf("issuer returned caller-independent URL %v", first["exchange_url"])
	}
	firstToken := first["token"].(string)

	wrongExchange := enrollmentExchangeRequest(first)
	wrongBinding := cloneObject(wrongExchange["binding"])
	wrongBinding["guest_instance_id"] = "wrong-guest"
	wrongExchange["binding"] = wrongBinding
	status, body := fixture.postJSONWithToken("", guestEnrollmentExchangePath, wrongExchange)
	assertEnrollmentStatus(t, status, body, http.StatusForbidden, "binding-mismatch")

	fixture.stop()
	fixture.start()
	status, exchanged := fixture.postJSONWithToken("", guestEnrollmentExchangePath, enrollmentExchangeRequest(first))
	assertEnrollmentStatus(t, status, exchanged, http.StatusOK, "")
	identity := cloneObject(exchanged["runtime_identity"])["opaque"].(string)
	status, body = fixture.postJSONWithToken("", guestEnrollmentExchangePath, enrollmentExchangeRequest(first))
	assertEnrollmentStatus(t, status, body, http.StatusConflict, "already-consumed")

	secondRequest := enrollmentIssueRequest("run-uid", "execution-1", 2, "guest-replacement", 300)
	status, second := fixture.postJSONWithToken(guestEnrollmentOrchestrator, guestEnrollmentIssuePath, secondRequest)
	assertEnrollmentStatus(t, status, second, http.StatusOK, "")
	unrelatedRequest := enrollmentIssueRequest("other-uid", "other-execution", 1, "other-guest", 300)
	status, unrelated := fixture.postJSONWithToken(guestEnrollmentOrchestrator, guestEnrollmentIssuePath, unrelatedRequest)
	assertEnrollmentStatus(t, status, unrelated, http.StatusOK, "")
	status, _ = fixture.postJSONWithToken("", guestEnrollmentExchangePath, enrollmentExchangeRequest(unrelated))
	if status != http.StatusOK {
		t.Fatalf("unrelated exchange status = %d", status)
	}

	status, body = fixture.postJSONWithToken(guestEnrollmentOrchestrator, guestEnrollmentRevokeExecution, enrollmentRevokeExecutionRequest(firstRequest))
	assertEnrollmentStatus(t, status, body, http.StatusOK, "")
	for _, envelope := range []map[string]any{first, second} {
		status, body = fixture.postJSONWithToken("", guestEnrollmentExchangePath, enrollmentExchangeRequest(envelope))
		assertEnrollmentStatus(t, status, body, http.StatusConflict, "revoked")
	}
	status, body = fixture.postJSONWithToken(guestEnrollmentOrchestrator, guestEnrollmentIssuePath, enrollmentIssueRequest("run-uid", "execution-1", 3, "guest-third", 300))
	assertEnrollmentStatus(t, status, body, http.StatusConflict, "revoked")
	status, body = fixture.postJSONWithToken("", guestEnrollmentExchangePath, enrollmentExchangeRequest(unrelated))
	assertEnrollmentStatus(t, status, body, http.StatusConflict, "already-consumed")

	fixture.stop()
	for _, canary := range []string{firstToken, identity} {
		if strings.Contains(fixture.stdout.String(), canary) || strings.Contains(fixture.stderr.String(), canary) {
			t.Fatalf("sensitive enrollment canary entered broker output")
		}
		audit, err := os.ReadFile(fixture.audit)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(audit, []byte(canary)) {
			t.Fatal("sensitive enrollment canary entered broker audit")
		}
		matches, err := filepath.Glob(filepath.Join(fixture.home, "guest-enrollment.sqlite3*"))
		if err != nil {
			t.Fatal(err)
		}
		for _, match := range matches {
			content, err := os.ReadFile(match)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(content, []byte(canary)) {
				t.Fatalf("plaintext enrollment canary entered durable file %s", filepath.Base(match))
			}
		}
	}
	tokenDigest := fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(firstToken)))
	if strings.Contains(fixture.stdout.String(), tokenDigest) || strings.Contains(fixture.stderr.String(), tokenDigest) {
		t.Fatal("enrollment token digest entered broker output")
	}
	audit, err := os.ReadFile(fixture.audit)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(audit, []byte(tokenDigest)) {
		t.Fatal("enrollment token digest entered broker audit")
	}
}

func TestGuestEnrollmentDedicatedAuthorizationAndIssuerOwnedURL(t *testing.T) {
	fixture := newGuestEnrollmentBrokerFixture(t)
	request := enrollmentIssueRequest("auth-uid", "auth-execution", 1, "auth-guest", 300)
	for _, unauthorized := range []string{"frontend-token", "frontend-egress-token"} {
		status, body := fixture.postJSONWithToken(unauthorized, guestEnrollmentIssuePath, request)
		assertEnrollmentStatus(t, status, body, http.StatusUnauthorized, "unauthorized")
		status, body = fixture.postJSONWithToken(unauthorized, guestEnrollmentRevokeExecution, enrollmentRevokeExecutionRequest(request))
		assertEnrollmentStatus(t, status, body, http.StatusUnauthorized, "unauthorized")
	}

	redirect := cloneObject(request)
	redirect["issuer_url"] = "https://attacker.example/steal"
	status, body := fixture.postJSONWithToken(guestEnrollmentOrchestrator, guestEnrollmentIssuePath, redirect)
	assertEnrollmentStatus(t, status, body, http.StatusBadRequest, "invalid-request")

	status, envelope := fixture.postJSONWithToken(guestEnrollmentOrchestrator, guestEnrollmentIssuePath, request)
	assertEnrollmentStatus(t, status, envelope, http.StatusOK, "")
	if envelope["exchange_url"] != guestEnrollmentExchangeURL {
		t.Fatalf("exchange URL = %v", envelope["exchange_url"])
	}
	status, body = fixture.postJSONWithToken("", guestEnrollmentExchangePath, enrollmentExchangeRequest(envelope))
	assertEnrollmentStatus(t, status, body, http.StatusOK, "")
}

func TestGuestEnrollmentExactRevokeStrictBoundsAndDisabledDefault(t *testing.T) {
	fixture := newGuestEnrollmentBrokerFixture(t)
	request := enrollmentIssueRequest("revoke-uid", "revoke-execution", 1, "revoke-guest", 300)
	status, envelope := fixture.postJSONWithToken(guestEnrollmentOrchestrator, guestEnrollmentIssuePath, request)
	assertEnrollmentStatus(t, status, envelope, http.StatusOK, "")
	for range 2 {
		status, body := fixture.postJSONWithToken(guestEnrollmentOrchestrator, guestEnrollmentRevokeBinding, map[string]any{
			"contract_version": guestEnrollmentVersion,
			"binding":          request["binding"],
		})
		assertEnrollmentStatus(t, status, body, http.StatusOK, "")
	}
	status, body := fixture.postJSONWithToken("", guestEnrollmentExchangePath, enrollmentExchangeRequest(envelope))
	assertEnrollmentStatus(t, status, body, http.StatusConflict, "revoked")

	duplicate := []byte(`{"contract_version":"nvt.guest-enrollment/v1","contract_version":"nvt.guest-enrollment/v1"}`)
	status, body = fixture.postEnrollmentRaw(guestEnrollmentOrchestrator, guestEnrollmentIssuePath, duplicate)
	assertEnrollmentStatus(t, status, body, http.StatusBadRequest, "invalid-request")
	status, body = fixture.postEnrollmentRaw(guestEnrollmentOrchestrator, guestEnrollmentIssuePath, bytes.Repeat([]byte{' '}, 4097))
	assertEnrollmentStatus(t, status, body, http.StatusBadRequest, "invalid-request")
	status, body = fixture.postEnrollmentRaw(guestEnrollmentOrchestrator, guestEnrollmentIssuePath, []byte{'{', '"', 'x', '"', ':', '"', 0xff, '"', '}'})
	assertEnrollmentStatus(t, status, body, http.StatusBadRequest, "invalid-request")

	disabled := newBrokerFixture(t)
	status, body = disabled.postJSONWithToken(guestEnrollmentOrchestrator, guestEnrollmentIssuePath, request)
	assertEnrollmentStatus(t, status, body, http.StatusNotFound, "not-found")
	status, body = disabled.postEnrollmentRaw(guestEnrollmentOrchestrator, guestEnrollmentExchangePath, bytes.Repeat([]byte{'x'}, 32<<10))
	assertEnrollmentStatus(t, status, body, http.StatusNotFound, "not-found")
	if matches, _ := filepath.Glob(filepath.Join(disabled.home, "*enrollment*")); len(matches) != 0 {
		t.Fatalf("disabled broker created enrollment state: %v", matches)
	}
}

func (f *brokerFixture) postEnrollmentRaw(token, path string, payload []byte) (int, map[string]any) {
	f.t.Helper()
	request, err := http.NewRequest(http.MethodPost, f.url+path, bytes.NewReader(payload))
	if err != nil {
		f.t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		f.t.Fatal(err)
	}
	defer response.Body.Close()
	decoded := map[string]any{}
	if err := json.NewDecoder(response.Body).Decode(&decoded); err != nil {
		f.t.Fatal(err)
	}
	return response.StatusCode, decoded
}

func enrollmentIssueRequest(uid, execution string, generation int64, guest string, ttl int) map[string]any {
	return map[string]any{
		"contract_version": guestEnrollmentVersion,
		"binding": map[string]any{
			"agent_run_uid":       uid,
			"execution_id":        execution,
			"driver_registration": "qemu-lab",
			"desired_generation":  generation,
			"guest_instance_id":   guest,
		},
		"ttl_seconds": ttl,
	}
}

func enrollmentExchangeRequest(envelope map[string]any) map[string]any {
	return map[string]any{
		"contract_version": guestEnrollmentVersion,
		"binding":          cloneObject(envelope["binding"]),
		"token":            envelope["token"],
	}
}

func enrollmentRevokeExecutionRequest(issue map[string]any) map[string]any {
	binding := cloneObject(issue["binding"])
	return map[string]any{
		"contract_version": guestEnrollmentVersion,
		"execution_scope": map[string]any{
			"agent_run_uid":       binding["agent_run_uid"],
			"execution_id":        binding["execution_id"],
			"driver_registration": binding["driver_registration"],
		},
	}
}

func cloneObject(value any) map[string]any {
	encoded, _ := json.Marshal(value)
	output := map[string]any{}
	_ = json.Unmarshal(encoded, &output)
	return output
}

func assertEnrollmentStatus(t *testing.T, status int, body map[string]any, expectedStatus int, reason string) {
	t.Helper()
	if status != expectedStatus {
		t.Fatalf("status=%d want=%d body=%v", status, expectedStatus, body)
	}
	if reason != "" && body["error"] != reason {
		t.Fatalf("error=%v want=%s body=%v", body["error"], reason, body)
	}
	if encoded, _ := json.Marshal(body); len(encoded) > 128<<10 {
		t.Fatalf("enrollment response exceeded bound: %d", len(encoded))
	}
}

func Example_guestEnrollmentPaths() {
	fmt.Println(guestEnrollmentIssuePath)
	fmt.Println(guestEnrollmentExchangePath)
	// Output:
	// /v1/guest-enrollment/issue
	// /v1/guest-enrollment/exchange
}
