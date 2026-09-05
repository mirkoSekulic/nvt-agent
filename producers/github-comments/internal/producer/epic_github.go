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

func (c *GitHubAPIClient) CanControlEpic(ctx context.Context, repo Repository, user GitHubUser) (bool, error) {
	var response struct {
		Permission string     `json:"permission"`
		User       GitHubUser `json:"user"`
	}
	err := c.getJSON(ctx, fmt.Sprintf("/repos/%s/%s/collaborators/%s/permission", url.PathEscape(repo.Owner), url.PathEscape(repo.Name), url.PathEscape(user.Login)), &response)
	if err != nil {
		return false, err
	}
	return response.User.ID == user.ID && (response.Permission == "admin" || response.Permission == "write" || response.Permission == "maintain"), nil
}

func (c *GitHubAPIClient) epicIssuePages(ctx context.Context, path string) ([]GitHubIssue, error) {
	var all []GitHubIssue
	for page := 1; page <= 2; page++ {
		var batch []GitHubIssue
		if err := c.getJSON(ctx, fmt.Sprintf("%s?per_page=100&page=%d", path, page), &batch); err != nil {
			return nil, err
		}
		all = append(all, batch...)
		if len(all) > maxEpicChildren {
			return nil, errors.New("epic graph exceeds 100 entries")
		}
		if len(batch) < 100 {
			return all, nil
		}
	}
	return nil, errors.New("incomplete epic graph pagination")
}
func (c *GitHubAPIClient) LoadEpicGraph(ctx context.Context, repo Repository, parent int) ([]EpicGraphNode, error) {
	base := fmt.Sprintf("/repos/%s/%s/issues/", url.PathEscape(repo.Owner), url.PathEscape(repo.Name))
	children, err := c.epicIssuePages(ctx, fmt.Sprintf("%s%d/sub_issues", base, parent))
	if err != nil {
		return nil, err
	}
	var graph []EpicGraphNode
	for _, child := range children {
		deps, err := c.epicIssuePages(ctx, fmt.Sprintf("%s%d/dependencies/blocked_by", base, child.Number))
		if err != nil {
			return nil, err
		}
		n := EpicGraphNode{Issue: child}
		for _, dep := range deps {
			if dep.RepositoryURL != child.RepositoryURL {
				return nil, errors.New("cross-repository epic dependency is unsupported")
			}
			n.Dependencies = append(n.Dependencies, dep.Number)
		}
		graph = append(graph, n)
	}
	return graph, nil
}

// Recover a successful POST whose response was lost by finding the persisted marker
// on a comment authored by this GitHub App. User-pasted markers are never adopted.
func (c *GitHubAPIClient) UpsertEpicComment(ctx context.Context, repo Repository, number int, marker, body string, appID int64) error {
	comments, err := c.ListIssueComments(ctx, repo, number)
	if err != nil {
		return err
	}
	body = body + "\n" + marker
	var found *GitHubIssueComment
	for i := range comments {
		item := &comments[i]
		if item.App != nil && item.App.ID == appID && appID > 0 && strings.HasSuffix(item.Body, marker) {
			if found != nil {
				return errors.New("multiple producer epic status comments; remove duplicate projection")
			}
			found = item
		}
	}
	if found == nil {
		return c.CreateIssueComment(ctx, repo, number, body)
	}
	if found.Body == body {
		return nil
	}
	var result GitHubIssueComment
	return c.epicJSON(ctx, http.MethodPatch, fmt.Sprintf("/repos/%s/%s/issues/comments/%d", url.PathEscape(repo.Owner), url.PathEscape(repo.Name), found.ID), map[string]string{"body": body}, &result)
}

func (c *GitHubAPIClient) epicJSON(ctx context.Context, method, path string, input, output any) error {
	token, err := c.tokenSource.Token(ctx)
	if err != nil {
		return errors.New("epic GitHub token unavailable")
	}
	body, err := json.Marshal(input)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", c.userAgent)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return errors.New("epic GitHub request failed")
	}
	defer closeBody(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("epic GitHub HTTP %d", resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 4*1024*1024)).Decode(output)
}
