package producer

import (
	"strings"
	"testing"
)

func TestBuildPromptIncludesStructuredIssueCommentsAndTask(t *testing.T) {
	prompt := BuildPrompt(PromptInput{
		Owner: "acme",
		Repo:  "widget",
		Issue: Issue{
			Number:  7,
			HTMLURL: "https://github.com/acme/widget/issues/7",
			Title:   "Fix widget",
			Body:    "broken details",
		},
		Comments: []IssueComment{{
			ID:        11,
			UserLogin: "alice",
			Body:      "first comment",
		}},
		CommandComment: IssueComment{
			ID:        12,
			UserLogin: "bob",
			HTMLURL:   "https://github.com/acme/widget/issues/7#issuecomment-12",
			Body:      "/custom pr create\nextra",
		},
		Sender:                 "bob",
		AdditionalInstructions: "extra",
	})
	required := []string{
		"Repository: acme/widget",
		"Issue number: 7",
		"Issue title: Fix widget",
		"broken details",
		"Command comment:",
		"Sender: bob",
		"All issue comments, oldest to newest:",
		"Comment 11 by alice",
		"create a new branch",
		"open a pull request linked to the issue",
		"register the PR with `github-watch` if that command is available",
	}
	for _, needle := range required {
		if !strings.Contains(prompt, needle) {
			t.Fatalf("prompt missing %q:\n%s", needle, prompt)
		}
	}
}
