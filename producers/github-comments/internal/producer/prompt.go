//nolint:govet // Prompt structs are ordered to match rendered prompt order.
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
	Intent                 CommandIntent
	CommandPrefix          string
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
	writePromptContext(&b, input)
	fmt.Fprint(&b, "\nTask:\n")
	switch input.Intent {
	case CommandIntentReview:
		fmt.Fprint(&b, strings.Join([]string{
			"Inspect the current pull request and report blocking findings first, ordered by severity and with file and line references where possible.",
			"`No findings` is a valid result.",
			"Report as findings only actionable correctness, security, or regression defects against a documented contract, requirement, or stated threat-model boundary.",
			"For every finding, identify the violated invariant or requirement and provide concrete evidence; do not promote speculative hardening to P1 or P2.",
			"Treat host root, the Docker daemon, and Docker administrators as trusted unless the reviewed contract explicitly states otherwise.",
			"Separate blocking findings from optional hardening or follow-up suggestions.",
			"On re-review, verify prior fixes first and report only remaining defects or regressions introduced by those fixes; do not manufacture a new concern merely because another review was requested.",
			"Before reviewing, resolve the current pull request head SHA and review that exact revision; include `Reviewed head: <full SHA>` in the posted result so the review is clearly stale after a push.",
			"Make no product-code changes. Do not approve the pull request or request changes.",
			"Post the review findings as a comment on this pull request using the existing mediated GitHub tooling.",
			"Only after that comment succeeds, invoke `nvt-work complete`.",
		}, " "))
	case CommandIntentRun:
		fmt.Fprint(&b, strings.Join([]string{
			"Perform the exact user instructions above in the context of this source issue or pull request.",
			"Post a final result to the same source thread using the existing mediated GitHub tooling.",
			"Only after that final comment succeeds, invoke `nvt-work complete`.",
		}, " "))
	case CommandIntentPRContinue:
		prefix := firstNonEmpty(input.CommandPrefix, "/nvtagent")
		repository := input.Owner + "/" + input.Repo
		fmt.Fprint(&b, strings.Join([]string{
			"Check out the PR branch and inspect the PR body, all existing PR comments, review threads, and checks.",
			"Address current actionable issues and continue iterating until the issue is fully resolved.",
			"After each maintenance pass, post a concise comment on the PR summarizing changes or explaining why no change was needed.",
			"Do not use `gh-auth auth status` to test access; mediated grants may intentionally deny account identity probes.",
			fmt.Sprintf("Run each required `gh-auth` repository command with an explicit `--repo %s`.", repository),
			"Register `github-watch` for ongoing PR activity using:",
			fmt.Sprintf("  github-watch register --repo %s --number %d --label work", repository, input.Issue.Number),
			"Keep the workflow alive until the pull request is merged or closed.",
			"Do not invoke `nvt-work complete` or `nvt-work fail`; maintenance ends only when the PR is merged or closed.",
			fmt.Sprintf("Ignore control comments in this PR thread (commands like `%s ...`) when handling watcher activity.", prefix),
		}, " "))
	default:
		fmt.Fprint(&b, strings.Join([]string{
			"Read the issue and comments, create a new branch from the repository default branch,",
			"implement the requested fix, run relevant tests, commit the change, push the branch,",
			fmt.Sprintf("open a pull request whose body includes `Refs #%d`,", input.Issue.Number),
			"do not create, edit, close, or comment on the source issue,",
			"put any follow-up status or completion comments on the pull request only,",
			"and register the PR with `github-watch register --repo OWNER/REPO --number PR_NUMBER` if that command is available.\n",
		}, " "))
	}
	return b.String()
}

func writePromptContext(b *strings.Builder, input PromptInput) {
	title, sourceKind := "GitHub issue PR creation request", "Issue"
	if input.Intent == CommandIntentReview {
		title, sourceKind = "GitHub pull request review request", "Pull request"
	} else if input.Intent == CommandIntentPRContinue {
		title, sourceKind = "GitHub pull request maintenance request", "Pull request"
	} else if input.Intent == CommandIntentRun {
		title, sourceKind = "GitHub cooperative work request", "Source"
	}
	fmt.Fprintf(b, "# %s\n\n", title)
	fmt.Fprintf(b, "Repository: %s/%s\n", input.Owner, input.Repo)
	fmt.Fprintf(b, "%s number: %d\n", sourceKind, input.Issue.Number)
	fmt.Fprint(b, "BEGIN UNTRUSTED GITHUB CONTENT\n")
	fmt.Fprintf(b, "%s URL: %s\n", sourceKind, firstNonEmpty(input.Issue.HTMLURL, input.Issue.URL))
	fmt.Fprintf(b, "%s title: %s\n\n", sourceKind, input.Issue.Title)
	fmt.Fprintf(b, "%s body:\n%s\n\n", sourceKind, fenced(input.Issue.Body))
	fmt.Fprint(b, "Command comment:\n")
	fmt.Fprintf(b, "- Sender: %s\n", firstNonEmpty(input.Sender, input.CommandComment.UserLogin))
	fmt.Fprintf(b, "- URL: %s\n", input.CommandComment.HTMLURL)
	fmt.Fprintf(b, "- Body:\n%s\n\n", fenced(input.CommandComment.Body))
	fmt.Fprintf(b, "Additional instructions:\n%s\n\n", fenced(input.AdditionalInstructions))
	fmt.Fprintf(b, "All %s comments, oldest to newest:\n", strings.ToLower(sourceKind))
	for _, comment := range input.Comments {
		fmt.Fprintf(b, "\n## Comment %d by %s\n", comment.ID, comment.UserLogin)
		if comment.HTMLURL != "" {
			fmt.Fprintf(b, "URL: %s\n", comment.HTMLURL)
		}
		if comment.CreatedAt != "" || comment.UpdatedAt != "" {
			fmt.Fprintf(b, "Created: %s\nUpdated: %s\n", comment.CreatedAt, comment.UpdatedAt)
		}
		fmt.Fprintf(b, "%s\n", fenced(comment.Body))
	}
	fmt.Fprint(b, "END UNTRUSTED GITHUB CONTENT\n")
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
