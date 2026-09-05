package producer

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEpicClosingPRGitHubPaginationAndErrors(t *testing.T) {
	for _, bad := range []string{"", "http", "graphql", "malformed", "null-data", "null-repository", "null-issue", "null-connection", "wrong-child", "wrong-repository", "changed-repository-id", "missing-page-info", "missing-next-page", "null-nodes", "null-node", "repeating-cursor", "empty-cursor", "oversized"} {
		t.Run(bad, func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.URL.Path != "/graphql" || r.Method != http.MethodPost || r.Header.Get("Authorization") != "Bearer token" || r.Header.Get("User-Agent") != "test" {
					t.Errorf("bad request: %s %s", r.Method, r.URL)
				}
				var input struct {
					Query     string         `json:"query"`
					Variables map[string]any `json:"variables"`
				}
				if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
					t.Error(err)
				}
				if !strings.Contains(input.Query, "closedByPullRequestsReferences(first: 100, after: $after, includeClosedPrs: false)") || input.Variables["owner"] != "acme" || input.Variables["name"] != "widget" || input.Variables["number"] != float64(1) {
					t.Error("wrong native query or source")
				}
				if calls == 1 && input.Variables["after"] != nil {
					t.Error("unexpected initial cursor")
				}
				if calls > 1 && input.Variables["after"] != "next" {
					t.Error("missing pagination cursor")
				}
				// Fail only after a plausible unique first-page match. It must never be
				// returned when the remaining connection is unavailable or malformed.
				if calls > 1 {
					switch bad {
					case "http":
						w.WriteHeader(403)
						fmt.Fprint(w, "sensitive")
						return
					case "malformed":
						fmt.Fprint(w, "sensitive invalid JSON")
						return
					case "null-data":
						fmt.Fprint(w, `{"data":null}`)
						return
					case "oversized":
						fmt.Fprint(w, strings.Repeat("x", (8<<20)+1))
						return
					}
				}
				info := map[string]any{"hasNextPage": calls == 1, "endCursor": "next"}
				connection := map[string]any{"nodes": []EpicPRCandidate{nativePR(49 + calls)}, "pageInfo": info}
				issue := map[string]any{"fullDatabaseId": nativeIssue(1).ID, "number": 1, "closedByPullRequestsReferences": connection}
				repo := map[string]any{"id": "R_widget", "nameWithOwner": "acme/widget", "issue": issue}
				data := map[string]any{"repository": repo}
				reply := map[string]any{"data": data}
				if calls > 1 {
					switch bad {
					case "graphql":
						reply["errors"] = []any{map[string]any{"message": "sensitive"}}
					case "null-repository":
						data["repository"] = nil
					case "null-issue":
						repo["issue"] = nil
					case "null-connection":
						issue["closedByPullRequestsReferences"] = nil
					case "wrong-child":
						issue["fullDatabaseId"] = 9999
					case "wrong-repository":
						repo["nameWithOwner"] = "other/widget"
					case "changed-repository-id":
						repo["id"] = "R_changed"
					case "missing-page-info":
						delete(connection, "pageInfo")
					case "missing-next-page":
						delete(info, "hasNextPage")
					case "null-nodes":
						connection["nodes"] = nil
					case "null-node":
						connection["nodes"] = []any{nil}
					case "repeating-cursor":
						info["hasNextPage"] = true
					case "empty-cursor":
						info["hasNextPage"] = true
						info["endCursor"] = ""
					}
				}
				json.NewEncoder(w).Encode(reply)
			}))
			defer server.Close()
			client := NewGitHubAPIClient(server.URL, "test", staticTokenSource("token"), server.Client())
			candidates, err := client.ListEpicClosingPRs(context.Background(), epicTestRepo, nativeIssue(1))
			if calls != 2 {
				t.Fatalf("pages: %d", calls)
			}
			if bad == "" {
				if err != nil || len(candidates) != 2 {
					t.Fatalf("incomplete native links: %+v %v", candidates, err)
				}
				matches, err := epicPRCandidates(epicTestRepo, 42, nativeIssue(1), candidates, epicTestTime)
				if err != nil || len(matches) != 2 {
					t.Fatal("failed to preserve ambiguity across pages")
				}
			} else if err == nil || len(candidates) != 0 || strings.Contains(err.Error(), "sensitive") {
				t.Fatalf("partial candidates or unsafe error: %+v %v", candidates, err)
			}
		})
	}
}

func TestEpicClosingPREmptyConnectionAndEnterpriseEndpoint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/graphql" {
			t.Errorf("provider URL not preserved: %s", r.URL)
		}
		fmt.Fprint(w, `{"data":{"repository":{"id":"R_widget","nameWithOwner":"acme/widget","issue":{"fullDatabaseId":1001,"number":1,"closedByPullRequestsReferences":{"nodes":[],"pageInfo":{"hasNextPage":false,"endCursor":null}}}}}}`)
	}))
	defer server.Close()
	client := NewGitHubAPIClient(server.URL+"/api/v3", "test", staticTokenSource("token"), server.Client())
	candidates, err := client.ListEpicClosingPRs(context.Background(), epicTestRepo, nativeIssue(1))
	if err != nil || len(candidates) != 0 {
		t.Fatalf("empty native connection: %+v %v", candidates, err)
	}
}

func TestEpicClosingPRFullDatabaseIdentity(t *testing.T) {
	// GitHub BigInt fields may be serialized as strings and exceed GraphQL Int.
	child := nativeIssue(1)
	child.ID = 9007199254740993
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"data":{"repository":{"id":"R_widget","nameWithOwner":"acme/widget","issue":{"fullDatabaseId":"9007199254740993","number":1,"closedByPullRequestsReferences":{"nodes":[],"pageInfo":{"hasNextPage":false,"endCursor":null}}}}}}`)
	}))
	defer server.Close()
	client := NewGitHubAPIClient(server.URL, "test", staticTokenSource("token"), server.Client())
	if _, err := client.ListEpicClosingPRs(context.Background(), epicTestRepo, child); err != nil {
		t.Fatal(err)
	}
	child.ID--
	if _, err := client.ListEpicClosingPRs(context.Background(), epicTestRepo, child); err == nil {
		t.Fatal("rounded immutable issue identity")
	}
}
