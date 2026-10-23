package controller

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestRestartClientBoundedReadinessAndSanitizedFailures(t *testing.T) {
	for _, mode := range []string{"ready", "failed", "restart-backend-rejected", "timeout", "conflict", "gone", "missing", "denied", "unavailable", "redirect", "superseded", "lost-response"} {
		t.Run(mode, func(t *testing.T) {
			var calls atomic.Int32
			var firstID string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				n := calls.Add(1)
				if r.Header.Get("Authorization") != "Bearer "+apiAdminToken {
					t.Error("missing trusted admin authentication")
				}
				if r.Method == http.MethodPost {
					var input struct {
						APIVersion string `json:"api_version"`
						RequestID  string `json:"request_id"`
					}
					if json.NewDecoder(r.Body).Decode(&input) != nil || input.APIVersion != APIVersion || !validRestartID(input.RequestID) {
						t.Error("invalid request")
					}
					if firstID == "" {
						firstID = input.RequestID
					} else if input.RequestID != firstID {
						t.Error("retry changed idempotency key")
					}
					if !strings.HasSuffix(r.URL.Path, "/restart") {
						t.Error("incorrect request path")
					}
				}
				if mode == "lost-response" && n == 1 {
					conn, _, err := w.(http.Hijacker).Hijack()
					if err != nil {
						t.Error(err)
						return
					}
					_ = conn.Close()
					return
				}
				statuses := map[string]int{"conflict": 409, "gone": 410, "missing": 404, "denied": 401, "unavailable": 503, "redirect": 302}
				if status := statuses[mode]; status != 0 {
					w.Header().Set("Location", "http://credential-leak.invalid")
					http.Error(w, "PRIVATE-ERROR-CANARY", status)
					return
				}
				run := Run{APIVersion: APIVersion, RunID: "personal", State: StatePreparing, RestartID: firstID, RestartPhase: "preparing"}
				if mode == "failed" {
					run.State, run.RestartPhase = StateFailed, "failed"
				}
				if mode == "restart-backend-rejected" {
					run.State, run.RestartPhase, run.LastReason = StateFailed, "failed", mode
				}
				if n > 1 && mode != "timeout" {
					run.State, run.RestartPhase = StateRunning, "complete"
				}
				if n > 1 && mode == "superseded" {
					run.RestartID = strings.Repeat("f", 32)
				}
				w.WriteHeader(202)
				_ = json.NewEncoder(w).Encode(run)
			}))
			defer server.Close()
			timeout := 5 * time.Second
			if mode == "timeout" {
				timeout = 30 * time.Millisecond
			}
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			got := RestartAndWait(ctx, server.URL, writePrivateToken(t, "admin", apiAdminToken), "personal")
			want := map[string]string{"ready": "ready", "failed": "failed", "restart-backend-rejected": "restart-backend-rejected", "timeout": "timeout", "conflict": "restart-conflict", "gone": "gone", "missing": "not-found", "denied": "not-authorized", "unavailable": "unavailable", "redirect": "unavailable", "superseded": "superseded", "lost-response": "ready"}[mode]
			if got != want {
				t.Fatalf("result=%q want=%q", got, want)
			}
		})
	}
}
