package producer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Kept separate so ordinary commands need no graph or status-edit capabilities.
type EpicGitHubClient interface {
	ListSubIssues(context.Context, Repository, int) ([]GitHubIssue, error)
	ListIssueBlockers(context.Context, Repository, int) ([]GitHubIssue, error)
	WriteEpicComment(context.Context, Repository, int, int64, string) (GitHubIssueComment, error)
}

func (c *GitHubAPIClient) ListSubIssues(ctx context.Context, repo Repository, number int) ([]GitHubIssue, error) {
	return c.getEpicIssuePages(ctx, repo, number, "sub_issues")
}

func (c *GitHubAPIClient) ListIssueBlockers(ctx context.Context, repo Repository, number int) ([]GitHubIssue, error) {
	return c.getEpicIssuePages(ctx, repo, number, "dependencies/blocked_by")
}

func (c *GitHubAPIClient) getEpicIssuePages(ctx context.Context, repo Repository, number int, suffix string) ([]GitHubIssue, error) {
	var all []GitHubIssue
	// Bound malformed/repeating pagination; never schedule from a partial list.
	for page := 1; page <= 100; page++ {
		path := fmt.Sprintf("/repos/%s/%s/issues/%d/%s?per_page=100&page=%d", url.PathEscape(repo.Owner), url.PathEscape(repo.Name), number, suffix, page)
		var issues []GitHubIssue
		if err := c.getJSON(ctx, path, &issues); err != nil {
			return nil, errors.New("github-epic-graph-unavailable")
		}
		all = append(all, issues...)
		if len(issues) < 100 {
			return all, nil
		}
	}
	return nil, errors.New("github-epic-graph-page-limit")
}

// commentID=0 creates; otherwise PATCH edits the exact persisted comment.
func (c *GitHubAPIClient) WriteEpicComment(ctx context.Context, repo Repository, number int, commentID int64, body string) (GitHubIssueComment, error) {
	if number <= 0 || commentID < 0 || strings.TrimSpace(body) == "" {
		return GitHubIssueComment{}, errors.New("github-epic-comment-invalid")
	}
	token, err := c.tokenSource.Token(ctx)
	if err != nil {
		return GitHubIssueComment{}, errors.New("github-epic-comment-token-unavailable")
	}
	data, err := json.Marshal(struct {
		Body string `json:"body"`
	}{body})
	if err != nil {
		return GitHubIssueComment{}, err
	}
	method, expected := http.MethodPost, http.StatusCreated
	path := fmt.Sprintf("/repos/%s/%s/issues/%d/comments", url.PathEscape(repo.Owner), url.PathEscape(repo.Name), number)
	if commentID != 0 {
		method, expected = http.MethodPatch, http.StatusOK
		path = fmt.Sprintf("/repos/%s/%s/issues/comments/%d", url.PathEscape(repo.Owner), url.PathEscape(repo.Name), commentID)
	}
	request, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bytes.NewReader(data))
	if err != nil {
		return GitHubIssueComment{}, errors.New("github-epic-comment-request-invalid")
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if c.userAgent != "" {
		request.Header.Set("User-Agent", c.userAgent)
	}
	response, err := c.httpClient.Do(request)
	if err != nil {
		return GitHubIssueComment{}, errors.New("github-epic-comment-request-failed")
	}
	defer closeBody(response.Body)
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxGitHubIssueCommentResponseBytes+1))
	if err != nil || len(raw) > maxGitHubIssueCommentResponseBytes || response.StatusCode != expected {
		return GitHubIssueComment{}, errors.New("github-epic-comment-write-failed")
	}
	var comment GitHubIssueComment
	if json.Unmarshal(raw, &comment) != nil || comment.ID <= 0 || (commentID != 0 && comment.ID != commentID) || comment.User.Type != "Bot" {
		return GitHubIssueComment{}, errors.New("github-epic-comment-response-invalid")
	}
	return comment, nil
}
