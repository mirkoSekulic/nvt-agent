package producer

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

type EpicGraphChild struct {
	Issue    GitHubIssue   `json:"issue"`
	Blockers []GitHubIssue `json:"blockers"`
}

func epicIssueRepository(issue GitHubIssue) (string, error) {
	u, err := url.Parse(issue.URL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("invalid issue URL")
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	// Accept the API path prefix used by GitHub Enterprise as well.
	if len(parts) < 5 {
		return "", errors.New("invalid issue URL")
	}
	parts = parts[len(parts)-5:]
	repo := strings.ToLower(parts[1] + "/" + parts[2])
	if parts[0] != "repos" || parts[3] != "issues" || parts[4] != strconv.Itoa(issue.Number) || !epicRepositoryPattern.MatchString(repo) || issue.ID <= 0 || issue.Number <= 0 || issue.PullRequest != nil || (issue.State != "open" && issue.State != "closed") {
		return "", errors.New("invalid native issue identity or state")
	}
	h, err := url.Parse(issue.HTMLURL)
	if err != nil || h.Scheme != "https" || h.Host == "" || h.RawQuery != "" || h.Fragment != "" || !strings.EqualFold(h.Path, "/"+repo+"/issues/"+strconv.Itoa(issue.Number)) {
		return "", errors.New("invalid issue source URL")
	}
	return repo, nil
}

func validateEpicGraph(repo Repository, parent int, children []EpicGraphChild) error {
	byID := map[int64]EpicGraphChild{}
	identities := map[string]int64{}
	issuesByID := map[int64]GitHubIssue{}
	for i, child := range children {
		key, err := epicIssueRepository(child.Issue)
		if err != nil || key != canonicalEpicRepository(repo) || child.Issue.Number == parent || (i > 0 && children[i-1].Issue.Number >= child.Issue.Number) {
			return errors.New("invalid or unsupported epic child")
		}
		if _, exists := byID[child.Issue.ID]; exists {
			return errors.New("duplicate epic child ID")
		}
		byID[child.Issue.ID] = child
	}
	for _, child := range children {
		seen := map[int64]bool{}
		for _, issue := range append([]GitHubIssue{child.Issue}, child.Blockers...) {
			key, err := epicIssueRepository(issue)
			if err != nil {
				return err
			}
			identity := fmt.Sprintf("%s#%d", key, issue.Number)
			if prior, ok := identities[identity]; ok && prior != issue.ID {
				return errors.New("conflicting issue identity")
			}
			identities[identity] = issue.ID
			if prior, ok := issuesByID[issue.ID]; ok {
				priorRepo, _ := epicIssueRepository(prior)
				if priorRepo != key || prior.Number != issue.Number || prior.State != issue.State {
					return errors.New("inconsistent dependency identity or state")
				}
			}
			issuesByID[issue.ID] = issue
			if member, ok := byID[issue.ID]; ok && (member.Issue.Number != issue.Number || key != canonicalEpicRepository(repo) || member.Issue.State != issue.State) {
				return errors.New("inconsistent graph snapshot")
			}
		}
		for _, blocker := range child.Blockers {
			key, _ := epicIssueRepository(blocker)
			if blocker.ID == child.Issue.ID || seen[blocker.ID] || (key == canonicalEpicRepository(repo) && blocker.Number == parent) {
				return errors.New("self, duplicate, or parent dependency")
			}
			seen[blocker.ID] = true
		}
	}
	visiting, visited := map[int64]bool{}, map[int64]bool{}
	var visit func(int64) error
	visit = func(id int64) error {
		if visiting[id] {
			return errors.New("cyclic epic dependencies")
		}
		if visited[id] {
			return nil
		}
		visiting[id] = true
		for _, dep := range byID[id].Blockers {
			if _, member := byID[dep.ID]; member {
				if err := visit(dep.ID); err != nil {
					return err
				}
			}
		}
		visiting[id], visited[id] = false, true
		return nil
	}
	for _, child := range children {
		if err := visit(child.Issue.ID); err != nil {
			return err
		}
	}
	return nil
}

func (p *Poller) loadEpicGraph(ctx context.Context, github EpicGitHubClient, repo Repository, parent int) ([]EpicGraphChild, error) {
	issue, err := p.GitHub.GetIssue(ctx, repo, parent)
	if err != nil {
		return nil, errors.New("parent-unavailable")
	}
	key, err := epicIssueRepository(issue)
	if err != nil || key != canonicalEpicRepository(repo) || issue.Number != parent || issue.State != "open" {
		return nil, errors.New("parent-not-open-or-invalid")
	}
	issues, err := github.ListSubIssues(ctx, repo, parent)
	if err != nil {
		return nil, errors.New("sub-issues-unavailable")
	}
	sort.Slice(issues, func(i, j int) bool { return issues[i].Number < issues[j].Number })
	children := make([]EpicGraphChild, 0, len(issues))
	for _, child := range issues {
		children = append(children, EpicGraphChild{Issue: child})
	}
	if err := validateEpicGraph(repo, parent, children); err != nil {
		return nil, err
	}
	for i := range children {
		blockers, err := github.ListIssueBlockers(ctx, repo, children[i].Issue.Number)
		if err != nil {
			return nil, errors.New("dependencies-unavailable")
		}
		sort.Slice(blockers, func(i, j int) bool { return blockers[i].URL < blockers[j].URL })
		children[i].Blockers = blockers
	}
	if err := validateEpicGraph(repo, parent, children); err != nil {
		return nil, err
	}
	return children, nil
}

func epicChildBlockReason(child EpicGraphChild) string {
	if child.Issue.State != "open" {
		return "issue is closed; completion is not verified"
	}
	var blocked []string
	for _, dep := range child.Blockers {
		if dep.State == "open" {
			repo, _ := epicIssueRepository(dep)
			blocked = append(blocked, fmt.Sprintf("%s#%d", repo, dep.Number))
		}
	}
	sort.Strings(blocked)
	if len(blocked) != 0 {
		return "depends on " + strings.Join(blocked, ", ")
	}
	return ""
}
