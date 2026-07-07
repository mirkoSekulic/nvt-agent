package broker_test

// Conformance for POST /v1/injection/report (protocol/injection.md): egress
// reports proxied requests for audit. Role + pairing gate it; entries are
// audited but never re-checked against grants; header values never appear.

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func reportEntry() map[string]any {
	return map[string]any{
		"capability": "codex-main",
		"host":       "chatgpt.com",
		"method":     "POST",
		"path_class": "backend-api",
		"status":     200,
	}
}

func readAuditEntries(t *testing.T, path string) []map[string]any {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var entries []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line == "" {
			continue
		}
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("audit line not JSON: %v (%q)", err, line)
		}
		entries = append(entries, entry)
	}
	return entries
}

// TestReportRequiresEgressRole pins role gating: the paired egress identity
// reports; the agent identity holding the grant is refused.
func TestReportRequiresEgressRole(t *testing.T) {
	f := newBrokerFixture(t)
	f.writeRoleIdentities(mediatedIdentities())

	status, body := f.postJSONWithToken("frontend-egress-token", "/v1/injection/report",
		map[string]any{"entries": []any{reportEntry()}})
	if status != http.StatusOK || body["ok"] != true {
		t.Fatalf("egress report must succeed: status=%d body=%v", status, body)
	}
	if body["reported"] != float64(1) {
		t.Fatalf("expected reported=1, got %v", body["reported"])
	}

	status, body = f.postJSONWithToken("frontend-token", "/v1/injection/report",
		map[string]any{"entries": []any{reportEntry()}})
	if status == http.StatusOK || body["ok"] == true {
		t.Fatalf("agent identity must be refused: status=%d body=%v", status, body)
	}
	if body["error"] != "role-not-allowed" {
		t.Fatalf("expected role-not-allowed, got %v", body["error"])
	}
}

// TestReportAuditEntryShape pins one audit line per entry with the documented
// fields and operation, and the CONNECT shape.
func TestReportAuditEntryShape(t *testing.T) {
	f := newBrokerFixture(t)
	f.writeRoleIdentities(mediatedIdentities())

	entries := []any{
		reportEntry(),
		map[string]any{"capability": "tunnel-main", "host": "example.com", "port": 443, "decision": "deny"},
	}
	status, body := f.postJSONWithToken("frontend-egress-token", "/v1/injection/report",
		map[string]any{"entries": entries})
	if status != http.StatusOK || body["reported"] != float64(2) {
		t.Fatalf("expected 2 reported: status=%d body=%v", status, body)
	}

	audit := readAuditEntries(t, f.audit)
	var httpEntry, connectEntry map[string]any
	for _, entry := range audit {
		if entry["operation"] != "injection.request" {
			continue
		}
		if entry["provider"] == "codex-main" {
			httpEntry = entry
		}
		if entry["provider"] == "tunnel-main" {
			connectEntry = entry
		}
	}
	if httpEntry == nil || connectEntry == nil {
		t.Fatalf("missing injection.request audit entries: %v", audit)
	}
	for key, want := range map[string]any{
		"agent":        "frontend-egress",
		"paired_agent": "frontend",
		"host":         "chatgpt.com",
		"method":       "POST",
		"path_class":   "backend-api",
		"status":       float64(200),
		"allowed":      true,
	} {
		if httpEntry[key] != want {
			t.Fatalf("http audit %s = %v, want %v (%v)", key, httpEntry[key], want, httpEntry)
		}
	}
	for key, want := range map[string]any{
		"host":     "example.com",
		"port":     float64(443),
		"decision": "deny",
	} {
		if connectEntry[key] != want {
			t.Fatalf("connect audit %s = %v, want %v (%v)", key, connectEntry[key], want, connectEntry)
		}
	}
}

// TestReportNotReCheckedAgainstGrants pins decision 1: a report for a
// capability the paired agent does not hold is still audited, not denied.
func TestReportNotReCheckedAgainstGrants(t *testing.T) {
	f := newBrokerFixture(t)
	f.writeRoleIdentities(mediatedIdentities())

	entry := reportEntry()
	entry["capability"] = "capability-never-granted"
	status, body := f.postJSONWithToken("frontend-egress-token", "/v1/injection/report",
		map[string]any{"entries": []any{entry}})
	if status != http.StatusOK || body["ok"] != true {
		t.Fatalf("ungranted-capability report must still be audited: status=%d body=%v", status, body)
	}
	audit := readAuditEntries(t, f.audit)
	found := false
	for _, e := range audit {
		if e["operation"] == "injection.request" && e["provider"] == "capability-never-granted" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected an audit entry for the ungranted capability: %v", audit)
	}
}

// TestReportRejectsOversizedBatch pins the entry cap: >100 entries deny with
// the standard error shape, not silent truncation.
func TestReportRejectsOversizedBatch(t *testing.T) {
	f := newBrokerFixture(t)
	f.writeRoleIdentities(mediatedIdentities())

	entries := make([]any, 101)
	for i := range entries {
		entries[i] = reportEntry()
	}
	status, body := f.postJSONWithToken("frontend-egress-token", "/v1/injection/report",
		map[string]any{"entries": entries})
	if status != http.StatusBadRequest || body["ok"] == true {
		t.Fatalf("oversized batch must deny: status=%d body=%v", status, body)
	}
	if body["error"] != "entries-too-many" {
		t.Fatalf("expected entries-too-many, got %v", body["error"])
	}
}

// TestReportRejectsMalformedEntryWhole pins that a malformed entry rejects the
// whole batch, so nothing is partially audited.
func TestReportRejectsMalformedEntryWhole(t *testing.T) {
	f := newBrokerFixture(t)
	f.writeRoleIdentities(mediatedIdentities())

	good := reportEntry()
	good["host"] = "good.example.com"
	bad := reportEntry()
	delete(bad, "path_class")
	status, body := f.postJSONWithToken("frontend-egress-token", "/v1/injection/report",
		map[string]any{"entries": []any{good, bad}})
	if status != http.StatusBadRequest || body["ok"] == true {
		t.Fatalf("malformed entry must reject the batch: status=%d body=%v", status, body)
	}
	for _, e := range readAuditEntries(t, f.audit) {
		if e["operation"] == "injection.request" && e["host"] == "good.example.com" {
			t.Fatalf("a rejected batch must not partially audit: %v", e)
		}
	}
}

// TestReportRejectsMissingEntries pins that the endpoint requires an entries
// list and rejects a missing/empty-token caller.
func TestReportRejectsMissingEntries(t *testing.T) {
	f := newBrokerFixture(t)
	f.writeRoleIdentities(mediatedIdentities())

	status, body := f.postJSONWithToken("frontend-egress-token", "/v1/injection/report",
		map[string]any{})
	if status != http.StatusBadRequest || body["error"] != "entries-required" {
		t.Fatalf("missing entries must deny with entries-required: status=%d body=%v", status, body)
	}

	status, body = f.postJSONWithToken("", "/v1/injection/report",
		map[string]any{"entries": []any{reportEntry()}})
	if status == http.StatusOK || body["ok"] == true {
		t.Fatalf("missing token must deny: status=%d body=%v", status, body)
	}
}

// TestBrokerLoadsGrantQuota pins that the broker accepts a grant carrying a
// quota block (schema strictness) and still serves injection for it — the
// broker parses quota but does not enforce it (enforcement is per egressd
// process, docs/phase5-6b-observability-pr-plan.md decision 3).
func TestBrokerLoadsGrantQuota(t *testing.T) {
	f := newBrokerFixture(t)
	identities := mediatedIdentities()
	frontend := identities["frontend"]
	frontend.Grants = []roleGrant{{Provider: "codex-main", Materialization: "header-inject", QuotaRequests: 3}}
	identities["frontend"] = frontend
	f.writeRoleIdentities(identities)

	status, body := f.postJSONWithToken("frontend-egress-token", "/v1/injection/headers", injectionRequest())
	if status != http.StatusOK || body["ok"] != true {
		t.Fatalf("injection must still succeed with a quota-bearing grant: status=%d body=%v", status, body)
	}
}

// TestRevocationFailsClosedOnGrantRemoval pins the broker half of the
// revocation chain (docs/phase5-6b-observability-pr-plan.md item 4): removing a
// grant from the agents config makes the next injection fetch fail closed via
// the mtime hot-reload — no broker restart.
func TestRevocationFailsClosedOnGrantRemoval(t *testing.T) {
	f := newBrokerFixture(t)
	f.writeRoleIdentities(mediatedIdentities())

	status, body := f.postJSONWithToken("frontend-egress-token", "/v1/injection/headers", injectionRequest())
	if status != http.StatusOK || body["ok"] != true {
		t.Fatalf("injection must succeed before revocation: status=%d body=%v", status, body)
	}

	// Revoke: rewrite the same config with the grant dropped. Atomic rename
	// changes mtime, so the running broker hot-reloads on the next request.
	revoked := mediatedIdentities()
	frontend := revoked["frontend"]
	frontend.Grants = nil
	revoked["frontend"] = frontend
	f.writeRoleIdentities(revoked)

	deadline := time.Now().Add(3 * time.Second)
	for {
		status, body = f.postJSONWithToken("frontend-egress-token", "/v1/injection/headers", injectionRequest())
		if status != http.StatusOK && body["ok"] != true {
			break // failed closed, as required
		}
		if time.Now().After(deadline) {
			t.Fatalf("injection still succeeds after revocation (no hot-reload): status=%d body=%v", status, body)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if body["error"] != "provider-not-granted" {
		t.Fatalf("revoked grant must deny provider-not-granted, got %v", body["error"])
	}
}
