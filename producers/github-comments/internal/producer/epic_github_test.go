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

func TestEpicGitHubGraphPagination(t *testing.T) {
	for _, suffix := range []string{"sub_issues", "dependencies/blocked_by"} {
		for _, failSecond := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/fail=%t", suffix, failSecond), func(t *testing.T) {
				calls := 0
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls++
					if r.URL.Path != "/repos/acme/widget/issues/42/"+suffix || r.URL.Query().Get("per_page") != "100" || r.Header.Get("Authorization") != "Bearer token" {
						t.Errorf("bad graph request %s", r.URL)
					}
					if r.URL.Query().Get("page") == "2" {
						if failSecond {
							w.WriteHeader(403)
							fmt.Fprint(w, "sensitive upstream response")
							return
						}
						json.NewEncoder(w).Encode([]GitHubIssue{nativeIssue(101)})
						return
					}
					var issues []GitHubIssue
					for i := 1; i <= 100; i++ {
						issues = append(issues, nativeIssue(i))
					}
					json.NewEncoder(w).Encode(issues)
				}))
				defer server.Close()
				client := NewGitHubAPIClient(server.URL, "test", staticTokenSource("token"), server.Client())
				var issues []GitHubIssue
				var err error
				if suffix == "sub_issues" {
					issues, err = client.ListSubIssues(context.Background(), epicTestRepo, 42)
				} else {
					issues, err = client.ListIssueBlockers(context.Background(), epicTestRepo, 42)
				}
				if calls != 2 {
					t.Fatalf("pages: %d", calls)
				}
				if failSecond {
					if err == nil || len(issues) != 0 || strings.Contains(err.Error(), "sensitive") {
						t.Fatalf("partial or unsafe error: %v %v", issues, err)
					}
				} else if err != nil || len(issues) != 101 || issues[100].Number != 101 {
					t.Fatalf("incomplete pages: %d %v", len(issues), err)
				}
			})
		}
	}
}

func TestEpicGitHubCommentCreateAndEdit(t *testing.T) {
	for _, id := range []int64{0, 123} {
		for _, bad := range []string{"", "wrong-id", "human", "malformed", "http", "too-large"} {
			t.Run(fmt.Sprintf("%d/%s", id, bad), func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					wantPath, method, status := "/repos/acme/widget/issues/42/comments", http.MethodPost, 201
					if id != 0 {
						wantPath, method, status = "/repos/acme/widget/issues/comments/123", http.MethodPatch, 200
					}
					if r.URL.Path != wantPath || r.Method != method || r.Header.Get("Authorization") != "Bearer token" {
						t.Errorf("bad comment request %s %s", r.Method, r.URL)
					}
					var payload struct {
						Body string `json:"body"`
					}
					if json.NewDecoder(r.Body).Decode(&payload) != nil || payload.Body != "status" {
						t.Error("wrong body")
					}
					if bad == "http" {
						w.WriteHeader(503)
						fmt.Fprint(w, "sensitive")
						return
					}
					w.WriteHeader(status)
					if bad == "malformed" {
						fmt.Fprint(w, "sensitive malformed")
						return
					}
					if bad == "too-large" {
						fmt.Fprint(w, strings.Repeat("x", maxGitHubIssueCommentResponseBytes+1))
						return
					}
					reply := GitHubIssueComment{ID: 123, User: GitHubUser{Type: "Bot"}}
					if bad == "wrong-id" {
						if id != 0 {
							reply.ID = 124
						} else {
							reply.ID = 0
						}
					}
					if bad == "human" {
						reply.User.Type = "User"
					}
					json.NewEncoder(w).Encode(reply)
				}))
				defer server.Close()
				client := NewGitHubAPIClient(server.URL, "test", staticTokenSource("token"), server.Client())
				comment, err := client.WriteEpicComment(context.Background(), epicTestRepo, 42, id, "status")
				if bad == "" {
					if err != nil || comment.ID != 123 {
						t.Fatalf("write: %+v %v", comment, err)
					}
				} else if err == nil || strings.Contains(err.Error(), "sensitive") {
					t.Fatalf("unsafe write error: %v", err)
				}
			})
		}
	}
}
