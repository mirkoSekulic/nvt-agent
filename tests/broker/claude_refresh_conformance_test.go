package broker_test

// Conformance for the hardened Claude Code OAuth refresh path (protocol/broker.md
// "Claude OAuth Provider Rules"). The broker refreshes the access token
// proactively, persists the returned access/refresh lifetime metadata,
// serializes refresh to a single upstream call, and backs off on transient
// failure so Claude Code retries cannot storm the OAuth endpoint. Token values
// must never appear in responses, audit, or broker logs.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func claudeInjectionRequest() map[string]any {
	return map[string]any{
		"capability": "claude-main",
		"host":       "api.anthropic.com",
		"method":     "POST",
		"path":       "/v1/messages",
	}
}

// rawPost performs a broker POST without touching *testing.T, so it is safe to
// call from a goroutine (t.Fatal must only run on the test goroutine).
func (f *brokerFixture) rawPost(token, path string, payload map[string]any) (int, map[string]any, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return 0, nil, err
	}
	request, err := http.NewRequest(http.MethodPost, f.url+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return 0, nil, err
	}
	defer response.Body.Close()
	var decoded map[string]any
	if err := json.NewDecoder(response.Body).Decode(&decoded); err != nil {
		return response.StatusCode, nil, err
	}
	return response.StatusCode, decoded, nil
}

func decodeClaudeCanonical(t *testing.T, f *brokerFixture) map[string]any {
	t.Helper()
	var canonical map[string]any
	decodeJSONFile(t, f.claudeCreds, &canonical)
	oauth, ok := canonical["claudeAiOauth"].(map[string]any)
	if !ok {
		t.Fatalf("claude credentials missing claudeAiOauth object: %#v", canonical)
	}
	return oauth
}

// TestClaudeRefreshProactivelyBeforeExpiry pins that a near-expiry access token
// is refreshed before it expires: the injected Bearer token is the refreshed
// one, exactly one upstream refresh occurs, and the canonical credential is
// rewritten with the new token and a later expiresAt.
func TestClaudeRefreshProactivelyBeforeExpiry(t *testing.T) {
	f := newBrokerFixture(t)
	f.writeRoleIdentities(claudePlaceholderIdentities())
	// Near expiry (inside the 900s refresh margin) but not yet expired.
	f.writeClaudeCredentialsExpiring("claude-access-near-expiry", "claude-refresh-real", time.Now().Add(5*time.Minute))

	status, body := f.postJSONWithToken("frontend-egress-token", "/v1/injection/headers", claudeInjectionRequest())
	if status != http.StatusOK || body["ok"] != true {
		t.Fatalf("proactive refresh injection failed: status=%d body=%v", status, body)
	}
	headers := body["headers"].(map[string]any)
	if headers["authorization"] != "Bearer refreshed-claude-access-1" {
		t.Fatalf("expected the refreshed access token to be injected, got %v", headers["authorization"])
	}
	if count := f.claudeOAuth.requestCount(); count != 1 {
		t.Fatalf("expected exactly one upstream refresh, got %d", count)
	}
	request := f.claudeOAuth.lastRequest()
	if request["grant_type"] != "refresh_token" || request["client_id"] != "claude-test-client" || request["refresh_token"] != "claude-refresh-real" ||
		request["scope"] != "user:profile user:inference user:sessions:claude_code user:mcp_servers user:file_upload" || request["body_key_count"] != 4 {
		t.Fatalf("unexpected refresh request metadata: %#v", request)
	}
	if request["header_accept"] != "application/json, text/plain, */*" ||
		request["header_content_type"] != "application/json" ||
		request["header_user_agent"] != "axios/1.15.2" || request["header_anthropic_beta"] != "" {
		t.Fatalf("refresh headers do not match the native request shape: %#v", request)
	}

	oauth := decodeClaudeCanonical(t, f)
	if oauth["accessToken"] != "refreshed-claude-access-1" {
		t.Fatalf("canonical access token was not refreshed: %#v", oauth["accessToken"])
	}
	expiresAt, ok := oauth["expiresAt"].(float64)
	if !ok || int64(expiresAt) <= time.Now().Add(30*time.Minute).UnixMilli() {
		t.Fatalf("canonical expiresAt was not advanced past the refresh margin: %#v", oauth["expiresAt"])
	}

	// The refresh is audited with metadata only.
	events := readAudit(t, f.audit)
	if !hasAuditOperation(events, "injection.refresh") {
		t.Fatalf("expected an injection.refresh audit entry, got %#v", events)
	}
	for _, event := range events {
		line, _ := json.Marshal(event)
		if strings.Contains(string(line), "claude-refresh-real") || strings.Contains(string(line), "refreshed-claude-access-1") {
			t.Fatalf("audit log leaked a Claude token: %s", line)
		}
	}
}

func TestClaudeRefreshSendsLiteralScopeOverride(t *testing.T) {
	f := newBrokerFixtureWithClaudeConfig(t, "      refresh-scope: literal-refresh-scope")
	f.writeRoleIdentities(claudePlaceholderIdentities())
	f.writeClaudeCredentialsExpiring("claude-access-near-expiry", "claude-refresh-fixture", time.Now().Add(5*time.Minute))

	status, body := f.postJSONWithToken("frontend-egress-token", "/v1/injection/headers", claudeInjectionRequest())
	if status != http.StatusOK || body["ok"] != true {
		t.Fatalf("literal-scope refresh failed: status=%d body=%v", status, body)
	}
	if got := f.claudeOAuth.lastRequest()["scope"]; got != "literal-refresh-scope" {
		t.Fatalf("endpoint received scope %v, want literal override", got)
	}
}

// TestClaudeRefreshPersistsRotatedToken pins refresh-token rotation: when the
// endpoint returns a new refresh_token, the canonical credential adopts it so
// the next refresh uses the rotated token.
func TestClaudeRefreshPersistsRotatedToken(t *testing.T) {
	f := newBrokerFixture(t)
	f.writeRoleIdentities(claudePlaceholderIdentities())
	f.claudeOAuth.configure(func(c *fakeClaudeOAuth) {
		c.rotate = true
		c.refreshExpiresIn = 30 * 24 * 60 * 60
		c.scope = "user:inference user:profile user:mcp_servers"
	})
	f.writeClaudeCredentialsExpiring("claude-access-near-expiry", "claude-refresh-real", time.Now().Add(5*time.Minute))

	status, body := f.postJSONWithToken("frontend-egress-token", "/v1/injection/headers", claudeInjectionRequest())
	if status != http.StatusOK || body["ok"] != true {
		t.Fatalf("rotation refresh failed: status=%d body=%v", status, body)
	}
	if count := f.claudeOAuth.requestCount(); count != 1 {
		t.Fatalf("expected one upstream refresh, got %d", count)
	}
	oauth := decodeClaudeCanonical(t, f)
	if oauth["refreshToken"] != "rotated-claude-refresh-1" {
		t.Fatalf("rotated refresh token was not persisted: %#v", oauth["refreshToken"])
	}
	if oauth["accessToken"] != "refreshed-claude-access-1" {
		t.Fatalf("access token was not refreshed alongside rotation: %#v", oauth["accessToken"])
	}
	refreshExpiresAt, ok := oauth["refreshTokenExpiresAt"].(float64)
	if !ok || int64(refreshExpiresAt) < time.Now().Add(29*24*time.Hour).UnixMilli() {
		t.Fatalf("refreshTokenExpiresAt was not advanced from refresh_token_expires_in: %#v", oauth["refreshTokenExpiresAt"])
	}
	if got := oauth["scopes"]; !reflect.DeepEqual(got, []any{"user:inference", "user:profile", "user:mcp_servers"}) {
		t.Fatalf("granted scopes were not persisted: %#v", got)
	}
	if oauth["clientId"] != "claude-test-client" {
		t.Fatalf("refresh client id was not persisted: %#v", oauth["clientId"])
	}
}

func TestClaudeRefreshPreservesOptionalMetadataWhenResponseOmitsIt(t *testing.T) {
	f := newBrokerFixture(t)
	f.writeRoleIdentities(claudePlaceholderIdentities())
	f.claudeOAuth.configure(func(c *fakeClaudeOAuth) {
		c.rotate = true
		c.scope = "   "
	})
	refreshExpiresAt := time.Now().Add(20 * 24 * time.Hour).UnixMilli()
	writeJSONFile(t, f.claudeCreds, map[string]any{
		"claudeAiOauth": map[string]any{
			"accessToken":           "claude-access-near-expiry",
			"refreshToken":          "claude-refresh-real",
			"expiresAt":             time.Now().Add(5 * time.Minute).UnixMilli(),
			"refreshTokenExpiresAt": refreshExpiresAt,
			"scopes":                []string{"user:inference", "user:profile"},
		},
	})

	status, body := f.postJSONWithToken("frontend-egress-token", "/v1/injection/headers", claudeInjectionRequest())
	if status != http.StatusOK || body["ok"] != true {
		t.Fatalf("refresh failed: status=%d body=%v", status, body)
	}
	oauth := decodeClaudeCanonical(t, f)
	if int64(oauth["refreshTokenExpiresAt"].(float64)) != refreshExpiresAt {
		t.Fatalf("refresh expiry changed when the response omitted it: %#v", oauth["refreshTokenExpiresAt"])
	}
	if got := oauth["scopes"]; !reflect.DeepEqual(got, []any{"user:inference", "user:profile"}) {
		t.Fatalf("scopes changed when the response omitted them: %#v", got)
	}
}

// TestClaudeRefreshRecoverySurvivesNextPersist pins the recovery contract: a
// failed canonical replacement leaves a unique 0600 copy, and the next persist
// uses another temporary name without deleting or overwriting that recovery.
func TestClaudeRefreshRecoverySurvivesNextPersist(t *testing.T) {
	out, err := runBrokerPython(t, `
import json
import os
import stat
import tempfile
from pathlib import Path
from unittest.mock import patch
from broker.plugins.claude_oauth.provider import ClaudeOAuthProvider

with tempfile.TemporaryDirectory() as directory:
    path = Path(directory) / ".credentials.json"
    path.write_text('{"claudeAiOauth":{"accessToken":"old","refreshToken":"old"}}')
    path.chmod(0o600)
    provider = ClaudeOAuthProvider({"name": "claude-main", "config": {
        "credentials-file": str(path),
        "injection-hosts": ["api.anthropic.com"],
    }})
    first = {"claudeAiOauth": {"accessToken": "first", "refreshToken": "first"}}
    second = {"claudeAiOauth": {"accessToken": "second", "refreshToken": "second"}}
    real_replace = os.replace
    def fail_canonical(source, target):
        if Path(target) == path:
            raise OSError("injected replace failure")
        return real_replace(source, target)
    try:
        with patch("broker.plugins.claude_oauth.provider.os.replace", side_effect=fail_canonical):
            provider._write_credentials(first)
    except OSError:
        pass
    else:
        raise SystemExit("expected replacement failure")
    recoveries = list(path.parent.glob(".credentials.json.recovery.*.tmp"))
    if len(recoveries) != 1:
        raise SystemExit(f"expected one recovery, got {recoveries}")
    recovery = recoveries[0]
    if json.loads(recovery.read_text()) != first or recovery.stat().st_mode & 0o777 != 0o600:
        raise SystemExit("recovery content or mode is wrong")
    provider._write_credentials(second)
    if not recovery.exists() or json.loads(recovery.read_text()) != first:
        raise SystemExit("next persist deleted or changed recovery")
    if json.loads(path.read_text()) != second:
        raise SystemExit("next canonical persist failed")
    third = {"claudeAiOauth": {"accessToken": "third", "refreshToken": "third"}}
    real_fsync = os.fsync
    def fail_directory_fsync(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError("directory fsync unsupported")
        return real_fsync(fd)
    with patch("broker.plugins.claude_oauth.provider.os.fsync", side_effect=fail_directory_fsync):
        provider._write_credentials(third)
    if json.loads(path.read_text()) != third:
        raise SystemExit("directory fsync failure misreported successful replacement")
print("OK")
`)
	if err != nil || !strings.Contains(out, "OK") {
		t.Fatalf("recovery persistence test failed: err=%v out=%s", err, out)
	}
}

func TestClaudePersistFailureServesOnlyValidCanonicalAccess(t *testing.T) {
	out, err := runBrokerPython(t, `
import json
import tempfile
import time
from pathlib import Path
from broker.plugins.claude_oauth.provider import ClaudeOAuthProvider
from broker.core.errors import ProviderError

with tempfile.TemporaryDirectory() as directory:
    path = Path(directory) / ".credentials.json"
    def write(exp):
        path.write_text(json.dumps({"claudeAiOauth": {
            "accessToken": "canonical-access",
            "refreshToken": "canonical-refresh",
            "expiresAt": exp,
        }}))
        path.chmod(0o600)
    provider = ClaudeOAuthProvider({"name": "claude-main", "config": {
        "credentials-file": str(path),
        "injection-hosts": ["api.anthropic.com"],
    }})
    provider._refresh = lambda data, oauth: {"claudeAiOauth": {
        "accessToken": "unpersisted-access",
        "refreshToken": "unpersisted-refresh",
        "expiresAt": int((time.time() + 3600) * 1000),
    }}
    def fail_persist(data):
        raise ProviderError("token-refresh-persist-failed", "injected", 502)
    provider._persist = fail_persist
    write(int((time.time() + 300) * 1000))
    _, _, token, _, refreshed = provider._fresh_credentials("agent", None, "request", "injection")
    if token != "canonical-access" or refreshed:
        raise SystemExit("valid canonical token was not served")
    write(int((time.time() - 60) * 1000))
    try:
        provider._fresh_credentials("agent", None, "request", "files", serve_expired=True)
    except ProviderError as error:
        if error.reason != "token-refresh-persist-failed":
            raise
    else:
        raise SystemExit("expired canonical token was served after persist failure")
print("OK")
`)
	if err != nil || !strings.Contains(out, "OK") {
		t.Fatalf("persist failure behavior test failed: err=%v out=%s", err, out)
	}
}

// TestClaudeRefreshIsSingleFlight pins that many concurrent injection callers
// collapse to a single upstream refresh call; the endpoint is slowed so all
// callers pile onto the refresh serialization point at once.
func TestClaudeRefreshIsSingleFlight(t *testing.T) {
	f := newBrokerFixture(t)
	f.writeRoleIdentities(claudePlaceholderIdentities())
	f.claudeOAuth.configure(func(c *fakeClaudeOAuth) { c.delay = 200 * time.Millisecond })
	f.writeClaudeCredentialsExpiring("claude-access-near-expiry", "claude-refresh-real", time.Now().Add(5*time.Minute))

	const callers = 8
	var wg sync.WaitGroup
	statuses := make([]int, callers)
	bearers := make([]string, callers)
	errs := make([]error, callers)
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			status, body, err := f.rawPost("frontend-egress-token", "/v1/injection/headers", claudeInjectionRequest())
			statuses[index] = status
			errs[index] = err
			if body != nil {
				if headers, ok := body["headers"].(map[string]any); ok {
					if value, ok := headers["authorization"].(string); ok {
						bearers[index] = value
					}
				}
			}
		}(i)
	}
	wg.Wait()

	for i := 0; i < callers; i++ {
		if errs[i] != nil {
			t.Fatalf("caller %d errored: %v", i, errs[i])
		}
		if statuses[i] != http.StatusOK {
			t.Fatalf("caller %d got status %d", i, statuses[i])
		}
		if bearers[i] != "Bearer refreshed-claude-access-1" {
			t.Fatalf("caller %d saw a non-single-flight token %q", i, bearers[i])
		}
	}
	if count := f.claudeOAuth.requestCount(); count != 1 {
		t.Fatalf("expected exactly one upstream refresh across %d concurrent callers, got %d", callers, count)
	}
}

// TestClaudeRefreshRateLimitBacksOff pins the 429 cooldown: the first near-expiry
// caller attempts one refresh, and while the token is still valid every caller
// is served the current token WITHOUT any further upstream call during cooldown.
func TestClaudeRefreshRateLimitBacksOff(t *testing.T) {
	f := newBrokerFixture(t)
	f.writeRoleIdentities(claudePlaceholderIdentities())
	f.claudeOAuth.configure(func(c *fakeClaudeOAuth) {
		c.status = http.StatusTooManyRequests
		c.errorType = "rate_limit_error"
	})
	// Near expiry (refresh attempted) but comfortably valid, so a transient
	// failure is served from the current token.
	f.writeClaudeCredentialsExpiring("claude-access-near-expiry", "claude-refresh-real", time.Now().Add(5*time.Minute))

	for i := 0; i < 3; i++ {
		status, body := f.postJSONWithToken("frontend-egress-token", "/v1/injection/headers", claudeInjectionRequest())
		if status != http.StatusOK || body["ok"] != true {
			t.Fatalf("call %d: valid token must still be served through a 429: status=%d body=%v", i, status, body)
		}
		headers := body["headers"].(map[string]any)
		if headers["authorization"] != "Bearer claude-access-near-expiry" {
			t.Fatalf("call %d: expected current valid token to be served, got %v", i, headers["authorization"])
		}
	}
	if count := f.claudeOAuth.requestCount(); count != 1 {
		t.Fatalf("expected the 429 to be cached for cooldown (one upstream call), got %d", count)
	}
}

// TestClaudeRefreshServesValidTokenOnTransientFailure pins that a non-429
// transient failure (HTTP 5xx) also serves a still-valid token rather than
// failing the request.
func TestClaudeRefreshServesValidTokenOnTransientFailure(t *testing.T) {
	f := newBrokerFixture(t)
	f.writeRoleIdentities(claudePlaceholderIdentities())
	f.claudeOAuth.configure(func(c *fakeClaudeOAuth) { c.status = http.StatusServiceUnavailable })
	f.writeClaudeCredentialsExpiring("claude-access-near-expiry", "claude-refresh-real", time.Now().Add(5*time.Minute))

	status, body := f.postJSONWithToken("frontend-egress-token", "/v1/injection/headers", claudeInjectionRequest())
	if status != http.StatusOK || body["ok"] != true {
		t.Fatalf("expected valid token to be served through a 5xx refresh failure: status=%d body=%v", status, body)
	}
	headers := body["headers"].(map[string]any)
	if headers["authorization"] != "Bearer claude-access-near-expiry" {
		t.Fatalf("expected current valid token, got %v", headers["authorization"])
	}
}

// TestClaudeRefreshExpiredFailsClosed pins fail-closed: once the access token is
// expired and refresh fails transiently, the request is denied (never serving a
// stale token) and the denial carries the sanitized transient reason.
func TestClaudeRefreshExpiredFailsClosed(t *testing.T) {
	f := newBrokerFixture(t)
	f.writeRoleIdentities(claudePlaceholderIdentities())
	f.claudeOAuth.configure(func(c *fakeClaudeOAuth) {
		c.status = http.StatusTooManyRequests
		c.errorType = "rate_limit_error"
	})
	f.writeClaudeCredentialsExpiring("claude-access-expired", "claude-refresh-real", time.Now().Add(-time.Minute))

	status, body := f.postJSONWithToken("frontend-egress-token", "/v1/injection/headers", claudeInjectionRequest())
	if status == http.StatusOK || body["ok"] == true {
		t.Fatalf("expired token with failed refresh must fail closed: status=%d body=%v", status, body)
	}
	if body["error"] != "token-refresh-rate-limited" {
		t.Fatalf("expected sanitized transient reason, got %v", body["error"])
	}
	message, _ := body["message"].(string)
	if !strings.Contains(message, "HTTP 429") || !strings.Contains(message, "rate_limit_error") {
		t.Fatalf("expected sanitized HTTP status and error class in message, got %q", message)
	}
	if strings.Contains(message, "claude-refresh-real") || strings.Contains(message, "claude-access-expired") {
		t.Fatalf("error message leaked a Claude token: %q", message)
	}
}

// TestClaudeRefreshInvalidGrantIsLoginRequired pins the re-auth classification:
// an expired token whose refresh is rejected with invalid_grant/401 surfaces the
// distinct token-refresh-login-required reason (not a generic transient error).
func TestClaudeRefreshInvalidGrantIsLoginRequired(t *testing.T) {
	f := newBrokerFixture(t)
	f.writeRoleIdentities(claudePlaceholderIdentities())
	f.claudeOAuth.configure(func(c *fakeClaudeOAuth) {
		c.status = http.StatusUnauthorized
		c.errorType = "invalid_grant"
	})
	f.writeClaudeCredentialsExpiring("claude-access-expired", "claude-refresh-real", time.Now().Add(-time.Minute))

	status, body := f.postJSONWithToken("frontend-egress-token", "/v1/injection/headers", claudeInjectionRequest())
	if status == http.StatusOK || body["ok"] == true {
		t.Fatalf("expired token with invalid_grant must fail closed: status=%d body=%v", status, body)
	}
	if body["error"] != "token-refresh-login-required" {
		t.Fatalf("expected login-required classification, got %v", body["error"])
	}
	message, _ := body["message"].(string)
	if !strings.Contains(message, "invalid_grant") {
		t.Fatalf("expected the safe OAuth error class in message, got %q", message)
	}
}

// TestClaudeRefreshNeverLeaksTokensToLogs pins that no Claude token value appears
// in the broker's own stdout/stderr, response, or audit while it exercises the
// refresh failure and cooldown-serve log paths.
func TestClaudeRefreshNeverLeaksTokensToLogs(t *testing.T) {
	f := newBrokerFixture(t)
	f.writeRoleIdentities(claudePlaceholderIdentities())
	f.claudeOAuth.configure(func(c *fakeClaudeOAuth) {
		c.status = http.StatusTooManyRequests
		c.errorType = "rate_limit_error"
	})
	f.writeClaudeCredentialsExpiring("claude-access-secret-value", "claude-refresh-secret-value", time.Now().Add(5*time.Minute))

	for i := 0; i < 3; i++ {
		f.postJSONWithToken("frontend-egress-token", "/v1/injection/headers", claudeInjectionRequest())
	}
	// Give the broker a moment to flush its refresh diagnostics.
	waitFor(t, 2*time.Second, func() bool { return f.claudeOAuth.requestCount() >= 1 })

	secrets := []string{"claude-refresh-secret-value"}
	logs := f.stdout.String() + f.stderr.String()
	for _, needle := range secrets {
		if strings.Contains(logs, needle) {
			t.Fatalf("broker logs leaked a Claude token: %s", logs)
		}
	}
	events := readAudit(t, f.audit)
	for _, event := range events {
		line, _ := json.Marshal(event)
		for _, needle := range secrets {
			if strings.Contains(string(line), needle) {
				t.Fatalf("audit leaked a Claude token: %s", line)
			}
		}
	}
}

// TestClaudeDirectFilesSelfRefreshVsInjectionFailsClosed distinguishes the two
// expiry contracts on the same expired credential whose refresh fails: the
// mediated injection path fails closed (never serves a stale token to the
// egress edge), while the direct /v1/files path still vends the well-formed
// expired real credential (with the refresh token) so Claude Code — which holds
// the refresh token in direct/possession mode — can self-refresh.
func TestClaudeDirectFilesSelfRefreshVsInjectionFailsClosed(t *testing.T) {
	f := newBrokerFixture(t)
	f.claudeOAuth.configure(func(c *fakeClaudeOAuth) {
		c.status = http.StatusTooManyRequests
		c.errorType = "rate_limit_error"
	})
	f.writeClaudeCredentialsExpiring("claude-access-expired", "claude-refresh-real", time.Now().Add(-time.Minute))

	// Mediated injection: expired token + failed refresh must fail closed.
	f.writeRoleIdentities(claudePlaceholderIdentities())
	status, body := f.postJSONWithToken("frontend-egress-token", "/v1/injection/headers", claudeInjectionRequest())
	if status == http.StatusOK || body["ok"] == true {
		t.Fatalf("mediated injection must fail closed on expired token + failed refresh: status=%d body=%v", status, body)
	}
	if body["error"] != "token-refresh-rate-limited" {
		t.Fatalf("expected sanitized transient reason on the mediated path, got %v", body["error"])
	}

	// Direct /v1/files: must still vend the well-formed expired real credential.
	f.writeAgents(map[string]agentGrant{
		"frontend": {Token: f.token, Grants: map[string][]string{"claude-main": {}}},
	})
	status, body = f.postJSONWithToken(f.token, "/v1/files", map[string]any{"provider": "claude-main"})
	if status != http.StatusOK || body["ok"] != true {
		t.Fatalf("direct /v1/files must vend an expired credential for self-refresh, not fail closed: status=%d body=%v", status, body)
	}
	files := body["files"].([]any)
	authFile := files[0].(map[string]any)
	var creds map[string]any
	if err := json.Unmarshal([]byte(authFile["content"].(string)), &creds); err != nil {
		t.Fatal(err)
	}
	oauth := creds["claudeAiOauth"].(map[string]any)
	if oauth["accessToken"] != "claude-access-expired" || oauth["refreshToken"] != "claude-refresh-real" {
		t.Fatalf("direct files must carry the real (expired) access+refresh token so Claude Code can self-refresh, got %v", oauth)
	}
}

// countRefreshAudits returns how many <prefix>.refresh audit events were written
// with the given allowed value.
func countRefreshAudits(events []map[string]any, operation string, allowed bool) int {
	count := 0
	for _, event := range events {
		if event["operation"] == operation && event["allowed"] == allowed {
			count++
		}
	}
	return count
}

// TestClaudeRefreshFailureIsAuditedOncePerAttempt pins finding 4: a proactive
// refresh that fails while the current access token is still valid is served
// (the request succeeds) but the failure is still audited exactly once as a
// sanitized injection.refresh (allowed=false) event — and cooldown-served
// requests that make no upstream call emit no further refresh audit events, so
// the cooldown cannot manufacture noisy duplicate upstream-refresh events.
func TestClaudeRefreshFailureIsAuditedOncePerAttempt(t *testing.T) {
	f := newBrokerFixture(t)
	f.writeRoleIdentities(claudePlaceholderIdentities())
	f.claudeOAuth.configure(func(c *fakeClaudeOAuth) {
		c.status = http.StatusTooManyRequests
		c.errorType = "rate_limit_error"
	})
	// Near expiry (refresh attempted) but comfortably valid, so the transient
	// failure is served from the current token across all three calls.
	f.writeClaudeCredentialsExpiring("claude-access-near-expiry", "claude-refresh-real", time.Now().Add(5*time.Minute))

	for i := 0; i < 3; i++ {
		status, body := f.postJSONWithToken("frontend-egress-token", "/v1/injection/headers", claudeInjectionRequest())
		if status != http.StatusOK || body["ok"] != true {
			t.Fatalf("call %d: valid token must still be served through a failed refresh: status=%d body=%v", i, status, body)
		}
	}
	if count := f.claudeOAuth.requestCount(); count != 1 {
		t.Fatalf("expected exactly one upstream refresh attempt (rest served from cooldown), got %d", count)
	}
	events := readAudit(t, f.audit)
	if got := countRefreshAudits(events, "injection.refresh", false); got != 1 {
		t.Fatalf("expected exactly one injection.refresh allowed=false audit event, got %d in %#v", got, events)
	}
	// The single failure event carries the sanitized reason and no token bytes.
	var failure map[string]any
	for _, event := range events {
		if event["operation"] == "injection.refresh" && event["allowed"] == false {
			failure = event
			break
		}
	}
	if failure == nil || failure["reason"] != "token-refresh-rate-limited" {
		t.Fatalf("expected sanitized token-refresh-rate-limited refresh audit reason, got %#v", failure)
	}
	for _, event := range events {
		line, _ := json.Marshal(event)
		if strings.Contains(string(line), "claude-refresh-real") || strings.Contains(string(line), "claude-access-near-expiry") {
			t.Fatalf("refresh audit leaked a Claude token: %s", line)
		}
	}
}

// TestClaudeRefreshProbeSerializesWithLiveBroker pins finding 5: the manual
// probe is safe against a running broker. Both the probe and the broker's own
// refresh take the same cross-process flock beside credentials-file, so their
// rotating refresh-token exchanges never overlap — two concurrent exchanges
// would otherwise spend the same refresh token and invalidate each other. The
// fake endpoint is slowed to widen the race window and records the high-water
// mark of concurrent in-flight refreshes, which must stay at 1.
func TestClaudeRefreshProbeSerializesWithLiveBroker(t *testing.T) {
	f := newBrokerFixture(t)
	f.writeRoleIdentities(claudePlaceholderIdentities())
	f.claudeOAuth.configure(func(c *fakeClaudeOAuth) {
		c.rotate = true
		c.delay = 250 * time.Millisecond
	})
	// Near expiry so the broker's injection path also attempts a refresh,
	// contending with the probes for the shared lock.
	f.writeClaudeCredentialsExpiring("claude-access-near-expiry", "claude-refresh-real", time.Now().Add(5*time.Minute))

	var wg sync.WaitGroup
	// A broker-side refresh (injection path) racing several manual probes, all
	// sharing the one credentials-file.
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _, _ = f.rawPost("frontend-egress-token", "/v1/injection/headers", claudeInjectionRequest())
	}()
	const probes = 3
	for i := 0; i < probes; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, _ = runClaudeProbe(t, f.root, f.config, "claude-main")
		}()
	}
	wg.Wait()

	if got := f.claudeOAuth.maxConcurrent(); got != 1 {
		t.Fatalf("cross-process refresh lock must serialize probe and broker refreshes, saw %d concurrent upstream exchanges", got)
	}
	if count := f.claudeOAuth.requestCount(); count < 1 {
		t.Fatalf("expected the probes to have driven at least one upstream refresh, got %d", count)
	}
	// The canonical credential is left internally consistent (a rotated refresh
	// token that matches the last accepted access-token rotation), not a
	// torn/interleaved write.
	oauth := decodeClaudeCanonical(t, f)
	access, _ := oauth["accessToken"].(string)
	refresh, _ := oauth["refreshToken"].(string)
	if !strings.HasPrefix(access, "refreshed-claude-access-") || !strings.HasPrefix(refresh, "rotated-claude-refresh-") {
		t.Fatalf("canonical credential is not a clean post-refresh state: access=%q refresh=%q", access, refresh)
	}
}

// runClaudeProbe runs scripts/claude-refresh-probe.py against a config, returning
// the decoded JSON summary, raw combined output, and exit code.
func runClaudeProbe(t *testing.T, root, configPath, provider string) (map[string]any, string, int) {
	t.Helper()
	cmd := exec.Command("python3", filepath.Join(root, "scripts", "claude-refresh-probe.py"), "--provider", provider)
	cmd.Env = append(os.Environ(), "NVT_BROKER_CONFIG="+configPath)
	output, err := cmd.CombinedOutput()
	status := 0
	if err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			status = exit.ExitCode()
		} else {
			t.Fatalf("probe failed to run: %v\n%s", err, output)
		}
	}
	var payload map[string]any
	trimmed := bytes.TrimSpace(output)
	if len(trimmed) > 0 && bytes.HasPrefix(trimmed, []byte("{")) {
		if decodeErr := json.Unmarshal(trimmed, &payload); decodeErr != nil {
			t.Fatalf("decode probe output %q: %v", output, decodeErr)
		}
	}
	return payload, string(output), status
}

// TestClaudeRefreshProbePersistsAndRedacts pins the manual probe: a one-shot
// refresh persists the rotated credential and prints only redacted metadata
// (status, field names, old/new expiresAt, rotation flag) — never token values.
func TestClaudeRefreshProbePersistsAndRedacts(t *testing.T) {
	f := newBrokerFixture(t)
	f.claudeOAuth.configure(func(c *fakeClaudeOAuth) {
		c.rotate = true
		c.refreshExpiresIn = 30 * 24 * 60 * 60
	})
	f.writeClaudeCredentialsExpiring("claude-access-secret-value", "claude-refresh-secret-value", time.Now().Add(time.Hour))

	payload, output, status := runClaudeProbe(t, f.root, f.config, "claude-main")
	if status != 0 {
		t.Fatalf("probe should succeed: status=%d output=%s", status, output)
	}
	if payload["status"] != "ok" || payload["refresh_token_rotated"] != true {
		t.Fatalf("unexpected probe summary: %#v", payload)
	}
	if payload["new_refresh_expires_at"] == nil {
		t.Fatalf("probe summary must report the refreshed credential lifetime: %#v", payload)
	}
	keys, ok := payload["keys"].([]any)
	if !ok || len(keys) == 0 {
		t.Fatalf("probe summary must list credential field names, got %#v", payload["keys"])
	}
	for _, needle := range []string{"claude-access-secret-value", "claude-refresh-secret-value", "refreshed-claude-access", "rotated-claude-refresh"} {
		if strings.Contains(output, needle) {
			t.Fatalf("probe output leaked a token value %q: %s", needle, output)
		}
	}
	// The rotation is actually persisted to the canonical credential.
	oauth := decodeClaudeCanonical(t, f)
	if oauth["refreshToken"] != "rotated-claude-refresh-1" || oauth["accessToken"] != "refreshed-claude-access-1" {
		t.Fatalf("probe did not persist the rotated credential: %#v", oauth)
	}
	info, err := os.Stat(f.claudeCreds)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("persisted Claude credential mode = %o, want 600", got)
	}
}

// TestClaudeRefreshProbeRefusesEnvSource pins that the probe refuses a
// credentials-env source, because a rotated credential cannot be written back to
// an env var and would be silently lost.
func TestClaudeRefreshProbeRefusesEnvSource(t *testing.T) {
	f := newBrokerFixture(t)
	config := "providers:\n" +
		"  - name: claude-env\n" +
		"    plugin: claude-oauth\n" +
		"    config:\n" +
		"      credentials-env: CLAUDE_CREDS_ENV\n" +
		"      injection-hosts:\n" +
		"        - api.anthropic.com\n"
	configPath := filepath.Join(f.home, "claude-env.yaml")
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	payload, output, status := runClaudeProbe(t, f.root, configPath, "claude-env")
	if status != 1 {
		t.Fatalf("probe must refuse a credentials-env source: status=%d output=%s", status, output)
	}
	if payload["status"] != "failed" || payload["reason"] != "refresh-source-unpersistable" {
		t.Fatalf("unexpected refusal summary: %#v", payload)
	}
	if f.claudeOAuth.requestCount() != 0 {
		t.Fatalf("probe must refuse before any upstream call, got %d", f.claudeOAuth.requestCount())
	}
}
