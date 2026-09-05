package producer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
)

// This connection is GitHub's native closing linkage, not a search of comments,
// timeline mentions, watcher events, or PR body text.
type EpicPRGitHubClient interface {
	ListEpicClosingPRs(context.Context, Repository, GitHubIssue) ([]EpicPRCandidate, error)
}

type EpicPRRepository struct {
	ID            string `json:"id"`
	NameWithOwner string `json:"nameWithOwner"`
}

type EpicPRCandidate struct {
	ID         string           `json:"id"`
	Number     int              `json:"number"`
	URL        string           `json:"url"`
	State      string           `json:"state"`
	Body       string           `json:"body"`
	Repository EpicPRRepository `json:"repository"`
}

const epicClosingPRQuery = `query EpicClosingPRs($owner: String!, $name: String!, $number: Int!, $after: String) {
 repository(owner: $owner, name: $name) {
  id nameWithOwner
  issue(number: $number) {
   fullDatabaseId number
   closedByPullRequestsReferences(first: 100, after: $after, includeClosedPrs: false) {
    nodes { id number url state body repository { id nameWithOwner } }
    pageInfo { hasNextPage endCursor }
   }
  }
 }
}`

func (c *GitHubAPIClient) ListEpicClosingPRs(ctx context.Context, repo Repository, child GitHubIssue) ([]EpicPRCandidate, error) {
	var all []EpicPRCandidate
	var after *string
	seen := map[string]bool{}
	repositoryID := ""
	for page := 0; page < 100; page++ {
		var result struct {
			Repository *struct {
				EpicPRRepository
				Issue *struct {
					DatabaseID json.Number `json:"fullDatabaseId"`
					Number     int         `json:"number"`
					PRs        *struct {
						Nodes    []EpicPRCandidate `json:"nodes"`
						PageInfo *struct {
							HasNextPage *bool  `json:"hasNextPage"`
							EndCursor   string `json:"endCursor"`
						} `json:"pageInfo"`
					} `json:"closedByPullRequestsReferences"`
				} `json:"issue"`
			} `json:"repository"`
		}
		if err := c.epicGraphQL(ctx, epicClosingPRQuery, map[string]any{"owner": repo.Owner, "name": repo.Name, "number": child.Number, "after": after}, &result); err != nil {
			return nil, err
		}
		r := result.Repository
		if r == nil || r.ID == "" || strings.ToLower(r.NameWithOwner) != canonicalEpicRepository(repo) ||
			r.Issue == nil || r.Issue.Number != child.Number ||
			r.Issue.PRs == nil || r.Issue.PRs.Nodes == nil || r.Issue.PRs.PageInfo == nil || r.Issue.PRs.PageInfo.HasNextPage == nil || (repositoryID != "" && repositoryID != r.ID) {
			return nil, errors.New("github-epic-pr-source-invalid")
		}
		issueID, err := r.Issue.DatabaseID.Int64()
		if err != nil || issueID <= 0 || issueID != child.ID {
			return nil, errors.New("github-epic-pr-child-identity-invalid")
		}
		repositoryID = r.ID
		for _, pr := range r.Issue.PRs.Nodes {
			if pr.ID == "" || pr.Number <= 0 || pr.URL == "" || pr.Repository.ID == "" || pr.Repository.NameWithOwner == "" || (pr.State != "OPEN" && pr.State != "CLOSED" && pr.State != "MERGED") {
				return nil, errors.New("github-epic-pr-metadata-invalid")
			}
			// Cross-repository closing links are not child delivery in this repository.
			if strings.EqualFold(pr.Repository.NameWithOwner, r.NameWithOwner) && pr.Repository.ID != r.ID {
				return nil, errors.New("github-epic-pr-repository-invalid")
			}
			all = append(all, pr)
		}
		info := r.Issue.PRs.PageInfo
		if !*info.HasNextPage {
			return all, nil
		}
		if info.EndCursor == "" || seen[info.EndCursor] {
			return nil, errors.New("github-epic-pr-pagination-invalid")
		}
		seen[info.EndCursor] = true
		cursor := info.EndCursor
		after = &cursor
	}
	return nil, errors.New("github-epic-pr-page-limit")
}

// Reuse the configured provider URL, token source and transport. Enterprise
// REST bases use /api/v3; their GraphQL endpoint is /api/graphql.
func (c *GitHubAPIClient) epicGraphQL(ctx context.Context, query string, variables map[string]any, target any) error {
	endpoint := c.baseURL + "/graphql"
	if strings.HasSuffix(c.baseURL, "/api/v3") {
		endpoint = strings.TrimSuffix(c.baseURL, "/api/v3") + "/api/graphql"
	}
	token, err := c.tokenSource.Token(ctx)
	if err != nil {
		return errors.New("github-epic-pr-token-unavailable")
	}
	data, err := json.Marshal(map[string]any{"query": query, "variables": variables})
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(data))
	if err != nil {
		return errors.New("github-epic-pr-request-invalid")
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/vnd.github+json")
	if c.userAgent != "" {
		request.Header.Set("User-Agent", c.userAgent)
	}
	response, err := c.httpClient.Do(request)
	if err != nil {
		return errors.New("github-epic-pr-request-failed")
	}
	defer closeBody(response.Body)
	const limit = 8 << 20
	raw, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil || len(raw) > limit || response.StatusCode != http.StatusOK {
		return errors.New("github-epic-pr-response-unavailable")
	}
	var envelope struct {
		Data   json.RawMessage   `json:"data"`
		Errors []json.RawMessage `json:"errors"`
	}
	if json.Unmarshal(raw, &envelope) != nil || len(envelope.Errors) != 0 || len(envelope.Data) == 0 || string(envelope.Data) == "null" {
		return errors.New("github-epic-pr-response-invalid")
	}
	if err := json.Unmarshal(envelope.Data, target); err != nil {
		return errors.New("github-epic-pr-data-invalid")
	}
	return nil
}
