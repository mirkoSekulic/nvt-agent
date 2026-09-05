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

func TestEpicNativeGraphAPIAndAuthorization(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/o/r/issues/1/sub_issues":
			json.NewEncoder(w).Encode([]GitHubIssue{epicNode(2).Issue, epicNode(3).Issue})
		case "/repos/o/r/issues/2/dependencies/blocked_by":
			fmt.Fprint(w, `[]`)
		case "/repos/o/r/issues/3/dependencies/blocked_by":
			json.NewEncoder(w).Encode([]GitHubIssue{epicNode(2).Issue})
		case "/repos/o/r/collaborators/maintainer/permission":
			fmt.Fprint(w, `{"permission":"write","user":{"id":42}}`)
		default:
			t.Errorf("unexpected endpoint %s", r.URL)
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	c := NewGitHubAPIClient(server.URL, "test", staticTokenSource("token"), server.Client())
	repo := Repository{Owner: "o", Name: "r"}
	graph, err := c.LoadEpicGraph(context.Background(), repo, 1)
	if err != nil || len(graph) != 2 || len(graph[1].Dependencies) != 1 || graph[1].Dependencies[0] != 2 {
		t.Fatal(graph, err)
	}
	for _, id := range []int64{42, 43} {
		allowed, err := c.CanControlEpic(context.Background(), repo, GitHubUser{Login: "maintainer", ID: id})
		if err != nil || allowed != (id == 42) {
			t.Fatal(allowed, err)
		}
	}
}
func TestEpicCommentUpsertRecoversLostPostAndIgnoresSpoof(t *testing.T) {
	marker := "<!-- test-marker -->"
	var comments []GitHubIssueComment
	comments = append(comments, GitHubIssueComment{ID: 1, Body: marker, User: GitHubUser{ID: 42}})
	posts, patches := 0, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			json.NewEncoder(w).Encode(comments)
		case "POST":
			posts++
			var input struct {
				Body string `json:"body"`
			}
			json.NewDecoder(r.Body).Decode(&input)
			comments = append(comments, GitHubIssueComment{ID: 2, Body: input.Body, App: &struct {
				ID int64 `json:"id"`
			}{ID: 10}})
			w.WriteHeader(503) // Write succeeded, response was lost.
		case "PATCH":
			patches++
			if !strings.HasSuffix(r.URL.Path, "/2") {
				t.Error("adopted user comment")
			}
			var input struct {
				Body string `json:"body"`
			}
			json.NewDecoder(r.Body).Decode(&input)
			comments[1].Body = input.Body
			json.NewEncoder(w).Encode(comments[1])
		}
	}))
	defer server.Close()
	c := NewGitHubAPIClient(server.URL, "test", staticTokenSource("token"), server.Client())
	repo := Repository{Owner: "o", Name: "r"}
	if c.UpsertEpicComment(context.Background(), repo, 1, marker, "Running", 10) == nil {
		t.Fatal("lost response")
	}
	if err := c.UpsertEpicComment(context.Background(), repo, 1, marker, "Running", 10); err != nil {
		t.Fatal(err)
	}
	if err := c.UpsertEpicComment(context.Background(), repo, 1, marker, "Completed", 10); err != nil {
		t.Fatal(err)
	}
	if posts != 1 || patches != 1 {
		t.Fatal(posts, patches)
	}
}
