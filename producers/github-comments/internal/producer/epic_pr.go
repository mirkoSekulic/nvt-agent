package producer

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"
)

// The immutable node IDs accompany the human-facing repository/number/URL.
// Once committed, discovery cannot replace or erase this association.
type EpicPRAssociation struct {
	Repository   string    `json:"repository"`
	RepositoryID string    `json:"repositoryID"`
	NodeID       string    `json:"nodeID"`
	Number       int       `json:"number"`
	URL          string    `json:"url"`
	ObservedAt   time.Time `json:"observedAt"`
}

func (a EpicPRAssociation) validate(repo Repository, child GitHubIssue) error {
	sourceURL, sourceErr := url.Parse(child.HTMLURL)
	prURL, urlErr := url.Parse(a.URL)
	if a.Repository != canonicalEpicRepository(repo) || strings.TrimSpace(a.RepositoryID) == "" || strings.TrimSpace(a.NodeID) == "" || a.Number <= 0 ||
		a.ObservedAt.IsZero() || sourceErr != nil || urlErr != nil || prURL.Scheme != "https" || prURL.Host == "" || !strings.EqualFold(prURL.Host, sourceURL.Host) || prURL.User != nil || prURL.RawQuery != "" || prURL.Fragment != "" || !strings.EqualFold(prURL.Path, fmt.Sprintf("/%s/pull/%d", a.Repository, a.Number)) {
		return errors.New("invalid epic PR association")
	}
	return nil
}

func epicPRCandidates(repo Repository, parent int, child GitHubIssue, candidates []EpicPRCandidate, now time.Time) ([]EpicPRAssociation, error) {
	unique := map[string]EpicPRAssociation{}
	numbers := map[int]string{}
	for _, candidate := range candidates {
		if candidate.State != "OPEN" || !strings.EqualFold(candidate.Repository.NameWithOwner, canonicalEpicRepository(repo)) {
			continue
		}
		// Parent context is a strict PR metadata contract. It cannot establish the
		// child linkage: candidates must already come from the native connection.
		partOf := false
		for _, line := range strings.Split(candidate.Body, "\n") {
			if strings.TrimSpace(line) == fmt.Sprintf("Part of #%d", parent) {
				partOf = true
			}
		}
		if !partOf {
			continue
		}
		association := EpicPRAssociation{Repository: canonicalEpicRepository(repo), RepositoryID: candidate.Repository.ID, NodeID: candidate.ID, Number: candidate.Number, URL: candidate.URL, ObservedAt: now.UTC()}
		if err := association.validate(repo, child); err != nil {
			return nil, err
		}
		if previous, ok := unique[association.NodeID]; ok && previous != association {
			return nil, errors.New("conflicting native PR identity")
		}
		if id := numbers[association.Number]; id != "" && id != association.NodeID {
			return nil, errors.New("conflicting native PR number")
		}
		unique[association.NodeID] = association
		numbers[association.Number] = association.NodeID
	}
	result := make([]EpicPRAssociation, 0, len(unique))
	for _, association := range unique {
		result = append(result, association)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Number < result[j].Number })
	return result, nil
}

func (p *Poller) associateEpicPRs(ctx context.Context, store EpicSchedulingStore, repo Repository, epic *EpicRecord, record *EpicSchedule) error {
	if epic.State == EpicCanceled {
		return nil
	}
	for i := range record.Attempts {
		a := &record.Attempts[i]
		if a.State != "accepted" || a.PR != nil {
			continue
		}
		github, ok := p.GitHub.(EpicPRGitHubClient)
		if !ok {
			return errors.New("epics require native GitHub PR linkage support")
		}
		candidates, err := github.ListEpicClosingPRs(ctx, repo, a.Source)
		var matches []EpicPRAssociation
		if err == nil {
			matches, err = epicPRCandidates(repo, epic.ParentIssue, a.Source, candidates, p.now())
		}
		if err != nil {
			a.PRReason = "PR linkage unavailable; retrying GitHub verification"
			// An unavailable read cannot clear an existing ambiguity.
			return store.SaveEpicSchedule(ctx, repo, *epic, record)
		}
		a.PRReason = ""
		record.PRAmbiguity = ""
		switch len(matches) {
		case 0:
			a.PRReason = "awaiting a unique open PR with native child linkage and the epic reference"
		case 1:
			a.PR = &matches[0]
		default:
			urls := make([]string, len(matches))
			for j, pr := range matches {
				urls[j] = pr.URL
			}
			record.PRAmbiguity = fmt.Sprintf("Child #%d has multiple linked open PRs: %s. Close or unlink unintended PRs, then resume the epic", a.Source.Number, strings.Join(urls, ", "))
			return store.PauseEpicForPRAmbiguity(ctx, repo, epic, record)
		}
		return store.SaveEpicSchedule(ctx, repo, *epic, record)
	}
	return nil
}

func buildEpicPrompt(repo Repository, child GitHubIssue, comments []GitHubIssueComment, source GitHubIssueComment, parent int) string {
	prompt := buildPrompt(repo, child, comments, source, Command{Intent: CommandIntentPRCreate})
	return prompt + fmt.Sprintf("\nEpic child PR contract (producer-owned):\nImplement only child #%d of epic #%d. In the pull request body, include standalone lines `Closes #%d` and `Part of #%d`. Ensure GitHub shows the child as a linked issue that this PR will close; a pasted URL or completion claim is insufficient. Create exactly one delivery PR in %s. Register that PR using the existing github-watch command when available. Do not merge it, enable automatic merging, close the child manually, or start another epic child. The producer owns status comments and later scheduling.\n", child.Number, parent, child.Number, parent, canonicalEpicRepository(repo))
}
