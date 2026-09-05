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

func epicPRFor(c EpicChild, n int) EpicPR {
	pr := EpicPR{ID: fmt.Sprintf("PR_%d", n), Number: n, URL: fmt.Sprintf("https://github.com/o/r/pull/%d", n), State: "OPEN", HeadRefName: c.Key}
	pr.Repository.NameWithOwner = "o/r"
	pr.HeadRepository = &struct {
		NameWithOwner string `json:"nameWithOwner"`
	}{NameWithOwner: "o/r"}
	return pr
}
func TestEpicPRUniqueAssociationAndRestart(t *testing.T) {
	calls := 0
	p, gh, read, restart := epicFixture(t, func(w http.ResponseWriter, r *http.Request) { calls++; acceptedEpic(w) })
	if err := p.PollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	e := read()
	prompt := e.Children[0].Prompt
	for _, required := range []string{"Closes #2", "Part of #1", e.Children[0].Key} {
		if !strings.Contains(prompt, required) {
			t.Fatal("missing prompt contract", required)
		}
	}
	// Agent prose and pasted links in issue comments do not supply candidates.
	gh.issueComments = []GitHubIssueComment{{Body: "Done: https://github.com/o/r/pull/9"}}
	if err := p.PollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if read().Children[0].PR != nil {
		t.Fatal("trusted prose")
	}
	gh.prs = map[int][]EpicPR{2: {epicPRFor(e.Children[0], 9)}}
	if err := p.PollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	e = read()
	if e.Children[0].PR == nil || e.Children[0].PR.ID != "PR_9" || e.Children[0].State != "PR open" {
		t.Fatal(e)
	}
	restart()
	if err := p.PollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || read().Children[0].PR.ID != "PR_9" || !strings.Contains(gh.displays[1], "/pull/9") {
		t.Fatal(calls, read())
	}
}
func TestEpicPRAmbiguityAndChangedAssociationPause(t *testing.T) {
	for _, change := range []bool{false, true} {
		t.Run(fmt.Sprint(change), func(t *testing.T) {
			p, gh, read, _ := epicFixture(t, func(w http.ResponseWriter, r *http.Request) { acceptedEpic(w) })
			if err := p.PollOnce(context.Background()); err != nil {
				t.Fatal(err)
			}
			c := read().Children[0]
			first := epicPRFor(c, 9)
			second := epicPRFor(c, 10)
			gh.prs = map[int][]EpicPR{2: {first}}
			if change {
				if err := p.PollOnce(context.Background()); err != nil {
					t.Fatal(err)
				}
				gh.prs[2] = []EpicPR{second}
			} else {
				gh.prs[2] = append(gh.prs[2], second)
			}
			if err := p.PollOnce(context.Background()); err != nil {
				t.Fatal(err)
			}
			e := read()
			if e.State != "paused" || e.Children[0].State != "Failed" || e.Children[1].Run != nil {
				t.Fatal(e)
			}
		})
	}
}
func TestEpicPRWrongBranchOrRepositoryDoesNotAssociate(t *testing.T) {
	p, gh, read, _ := epicFixture(t, func(w http.ResponseWriter, r *http.Request) { acceptedEpic(w) })
	_ = p.PollOnce(context.Background())
	c := read().Children[0]
	first := epicPRFor(c, 9)
	first.HeadRefName = "unrelated"
	second := epicPRFor(c, 10)
	second.Repository.NameWithOwner = "other/repo"
	third := epicPRFor(c, 11)
	third.HeadRepository.NameWithOwner = "fork/r"
	gh.prs = map[int][]EpicPR{2: {first, second, third}}
	if err := p.PollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if read().Children[0].PR != nil {
		t.Fatal("invalid association")
	}
}
func TestEpicPRGraphQLNativeContract(t *testing.T) {
	for _, body := range []string{
		`{"data":{"repository":{"issue":{"closedByPullRequestsReferences":{"nodes":[],"pageInfo":{"hasNextPage":false}}}}}}`,
		`{"errors":[{"type":"FORBIDDEN"}],"data":{"repository":null}}`,
		`{"data":{"repository":{"issue":{"closedByPullRequestsReferences":{"nodes":[],"pageInfo":{"hasNextPage":true}}}}}}`,
		`{"data":{"repository":{"issue":null}}}`,
	} {
		t.Run(body, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var req struct {
					Query     string         `json:"query"`
					Variables map[string]any `json:"variables"`
				}
				json.NewDecoder(r.Body).Decode(&req)
				if r.URL.Path != "/graphql" || !strings.Contains(req.Query, "includeClosedPrs:true,excludeUserLinked:true") || req.Variables["number"] != float64(2) {
					t.Error("wrong query", req)
				}
				fmt.Fprint(w, body)
			}))
			defer server.Close()
			c := NewGitHubAPIClient(server.URL, "test", staticTokenSource("token"), server.Client())
			_, err := c.LinkedEpicPRs(context.Background(), Repository{Owner: "o", Name: "r"}, 2)
			if (err == nil) != strings.Contains(body, `"hasNextPage":false`) {
				t.Fatal(err)
			}
		})
	}
}
