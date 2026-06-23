package producer

import (
	"fmt"
	"strings"
)

type Issue struct {
	Number  int
	URL     string
	Title   string
	Body    string
	HTMLURL string
}

type IssueComment struct {
	ID        int64
	Body      string
	UserLogin string
	HTMLURL   string
	CreatedAt string
	UpdatedAt string
}

type PromptInput struct {
	Owner                  string
	Repo                   string
	Issue                  Issue
	Comments               []IssueComment
	CommandComment         IssueComment
	Sender                 string
	AdditionalInstructions string
}

func BuildPrompt(input PromptInput) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# GitHub issue PR creation request\n\n")
	fmt.Fprintf(&b, "Repository: %s/%s\n", input.Owner, input.Repo)
	fmt.Fprintf(&b, "Issue number: %d\n", input.Issue.Number)
	fmt.Fprintf(&b, "Issue URL: %s\n", firstNonEmpty(input.Issue.HTMLURL, input.Issue.URL))
	fmt.Fprintf(&b, "Issue title: %s\n\n", input.Issue.Title)
	fmt.Fprintf(&b, "Issue body:\n%s\n\n", fenced(input.Issue.Body))
	fmt.Fprintf(&b, "Command comment:\n")
	fmt.Fprintf(&b, "- Sender: %s\n", firstNonEmpty(input.Sender, input.CommandComment.UserLogin))
	fmt.Fprintf(&b, "- URL: %s\n", input.CommandComment.HTMLURL)
	fmt.Fprintf(&b, "- Body:\n%s\n\n", fenced(input.CommandComment.Body))
	fmt.Fprintf(&b, "Additional instructions:\n%s\n\n", fenced(input.AdditionalInstructions))
	fmt.Fprintf(&b, "All issue comments, oldest to newest:\n")
	for _, comment := range input.Comments {
		fmt.Fprintf(&b, "\n## Comment %d by %s\n", comment.ID, comment.UserLogin)
		if comment.HTMLURL != "" {
			fmt.Fprintf(&b, "URL: %s\n", comment.HTMLURL)
		}
		if comment.CreatedAt != "" || comment.UpdatedAt != "" {
			fmt.Fprintf(&b, "Created: %s\nUpdated: %s\n", comment.CreatedAt, comment.UpdatedAt)
		}
		fmt.Fprintf(&b, "%s\n", fenced(comment.Body))
	}
	fmt.Fprintf(&b, "\nTask:\n")
	fmt.Fprintf(&b, "Read the issue and comments, create a new branch from the repository default branch, implement the requested fix, run relevant tests, commit the change, push the branch, open a pull request linked to the issue, comment on the issue with the PR link, and register the PR with `github-watch` if that command is available.\n")
	return b.String()
}

func fenced(value string) string {
	return "```\n" + strings.TrimSpace(value) + "\n```"
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
