package producer

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// EpicPR records GitHub's immutable node identity, not an agent-authored URL.
type EpicPR struct {
	ID          string `json:"id"`
	Number      int    `json:"number"`
	URL         string `json:"url"`
	State       string `json:"state"`
	HeadRefName string `json:"headRefName"`
	Repository  struct {
		NameWithOwner string `json:"nameWithOwner"`
	} `json:"repository"`
	HeadRepository *struct {
		NameWithOwner string `json:"nameWithOwner"`
	} `json:"headRepository"`
}

type epicPRGitHub interface {
	LinkedEpicPRs(context.Context, Repository, int) ([]EpicPR, error)
}

func epicImplementationPrompt(e Epic, child EpicChild, comments []GitHubIssueComment) string {
	prompt := buildPrompt(e.Repository, child.Issue, comments, GitHubIssueComment{User: e.Principal}, Command{Intent: CommandIntentPRCreate})
	return prompt + fmt.Sprintf("\n\nEpic delivery contract (producer-owned):\nImplement only child #%d of epic #%d. Use branch `%s` from the repository default branch; reuse it and any existing PR for this attempt after restart. Create exactly one PR in %s/%s. Include `Closes #%d` and `Part of #%d` in its body so GitHub records the native closing relationship. Push the branch and register that PR with github-watch if available. Do not merge or enable auto-merge. Do not schedule other epic children. The producer advances after GitHub verifies the merge.\n", child.Issue.Number, e.Parent, child.Key, e.Repository.Owner, e.Repository.Name, child.Issue.Number, e.Parent)
}

func (p *Poller) associateEpicPRs(ctx context.Context, e *Epic) error {
	gh, ok := p.GitHub.(epicPRGitHub)
	if !ok {
		return errors.New("epic PR discovery unavailable")
	}
	for i := range e.Children {
		child := &e.Children[i]
		if child.Run == nil || child.State == "Completed" {
			continue
		}
		candidates, err := gh.LinkedEpicPRs(ctx, e.Repository, child.Issue.Number)
		if err != nil {
			return err
		}
		var valid []EpicPR
		seen := map[string]bool{}
		for _, pr := range candidates {
			if err := validateEpicPR(pr); err != nil {
				return err
			}
			if !strings.EqualFold(pr.Repository.NameWithOwner, epicRepoKey(e.Repository)) || pr.HeadRepository == nil || !strings.EqualFold(pr.HeadRepository.NameWithOwner, epicRepoKey(e.Repository)) || pr.HeadRefName != child.Key {
				continue
			}
			if seen[pr.ID] {
				return errors.New("duplicate GitHub PR identity")
			}
			seen[pr.ID] = true
			valid = append(valid, pr)
		}
		if len(valid) > 1 {
			numbers := make([]string, 0, len(valid))
			for _, pr := range valid {
				numbers = append(numbers, fmt.Sprintf("#%d", pr.Number))
			}
			child.Failure = "mapping"
			child.State = "Failed"
			child.Reason = "Ambiguous linked PRs: " + strings.Join(numbers, ", ") + "; retain one native closing link, then retry"
			e.State = "paused"
			e.Reason = child.Reason
			continue
		}
		if child.PR != nil {
			if len(valid) != 1 || valid[0].ID != child.PR.ID || valid[0].Number != child.PR.Number {
				child.Failure = "mapping"
				child.State = "Failed"
				child.Reason = "Associated PR linkage changed; restore the original native closing link, then retry"
				e.State = "paused"
				e.Reason = child.Reason
			}
			continue
		}
		if len(valid) == 1 {
			pr := valid[0]
			child.PR = &pr
			if child.State != "Failed" {
				child.State = "PR open"
				child.Reason = "Uniquely associated through GitHub native closing linkage"
			}
		}
	}
	return nil
}

const epicLinkedPRQuery = `query($owner:String!,$repo:String!,$number:Int!){repository(owner:$owner,name:$repo){issue(number:$number){closedByPullRequestsReferences(first:100,includeClosedPrs:true,excludeUserLinked:true){nodes{id number url state headRefName repository{nameWithOwner} headRepository{nameWithOwner}} pageInfo{hasNextPage}}}}}`

func (c *GitHubAPIClient) LinkedEpicPRs(ctx context.Context, repo Repository, number int) ([]EpicPR, error) {
	var response struct {
		Errors []jsonGraphQLError `json:"errors"`
		Data   struct {
			Repository *struct {
				Issue *struct {
					PRs *struct {
						Nodes    []EpicPR `json:"nodes"`
						PageInfo *struct {
							HasNextPage bool `json:"hasNextPage"`
						} `json:"pageInfo"`
					} `json:"closedByPullRequestsReferences"`
				} `json:"issue"`
			} `json:"repository"`
		} `json:"data"`
	}
	err := c.epicJSON(ctx, "POST", "/graphql", map[string]any{"query": epicLinkedPRQuery, "variables": map[string]any{"owner": repo.Owner, "repo": repo.Name, "number": number}}, &response)
	if err != nil {
		return nil, err
	}
	for _, failure := range response.Errors {
		if failure.Type == "RATE_LIMITED" {
			return nil, &epicAPIError{Status: 429}
		}
	}
	if len(response.Errors) > 0 || response.Data.Repository == nil || response.Data.Repository.Issue == nil || response.Data.Repository.Issue.PRs == nil || response.Data.Repository.Issue.PRs.PageInfo == nil {
		return nil, errors.New("GitHub native PR linkage unavailable or incomplete")
	}
	prs := response.Data.Repository.Issue.PRs
	if prs.Nodes == nil {
		return nil, errors.New("incomplete native PR connection")
	}
	if prs.PageInfo.HasNextPage {
		return nil, errors.New("too many native PR links to associate safely")
	}
	return prs.Nodes, nil
}

type jsonGraphQLError struct {
	Type string `json:"type"`
}

func validateEpicPR(pr EpicPR) error {
	if pr.ID == "" || pr.Number <= 0 || pr.URL == "" || pr.Repository.NameWithOwner == "" || pr.HeadRefName == "" || (pr.State != "OPEN" && pr.State != "CLOSED" && pr.State != "MERGED") {
		return errors.New("malformed GitHub PR linkage")
	}
	return nil
}
