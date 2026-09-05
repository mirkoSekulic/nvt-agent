package producer

import (
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

const maxEpicChildren = 100

type EpicGraphNode struct {
	Issue        GitHubIssue
	Dependencies []int
}

func validateEpicGraph(repo Repository, parent int, graph []EpicGraphNode) error {
	if len(graph) == 0 || len(graph) > maxEpicChildren {
		return errors.New("epic must have 1–100 native sub-issues")
	}
	nodes := map[int]EpicGraphNode{}
	ids := map[int64]bool{}
	for _, n := range graph {
		u, err := url.Parse(n.Issue.RepositoryURL)
		if err != nil || !strings.EqualFold(u.Path, "/repos/"+repo.Owner+"/"+repo.Name) || n.Issue.ID <= 0 || n.Issue.Number <= 0 || n.Issue.Number == parent || n.Issue.PullRequest != nil || (n.Issue.State != "open" && n.Issue.State != "closed") {
			return errors.New("unsupported epic child identity, repository, or state")
		}
		if _, ok := nodes[n.Issue.Number]; ok || ids[n.Issue.ID] {
			return errors.New("duplicate epic child")
		}
		nodes[n.Issue.Number] = n
		ids[n.Issue.ID] = true
	}
	colors := map[int]int{}
	var visit func(int) error
	visit = func(number int) error {
		if colors[number] == 1 {
			return errors.New("epic dependency cycle")
		}
		if colors[number] == 2 {
			return nil
		}
		colors[number] = 1
		seen := map[int]bool{}
		for _, dep := range nodes[number].Dependencies {
			if _, ok := nodes[dep]; !ok || dep == number || seen[dep] {
				return fmt.Errorf("child #%d has an external, duplicate, or self dependency", number)
			}
			seen[dep] = true
			if err := visit(dep); err != nil {
				return err
			}
		}
		colors[number] = 2
		return nil
	}
	for number := range nodes {
		if err := visit(number); err != nil {
			return err
		}
	}
	return nil
}

func installEpicGraph(e *Epic, graph []EpicGraphNode) error {
	if err := validateEpicGraph(e.Repository, e.Parent, graph); err != nil {
		return err
	}
	graph = append([]EpicGraphNode(nil), graph...)
	sort.Slice(graph, func(i, j int) bool { return graph[i].Issue.Number < graph[j].Issue.Number })
	for i := range graph {
		graph[i].Dependencies = append([]int(nil), graph[i].Dependencies...)
		sort.Ints(graph[i].Dependencies)
	}
	if len(e.Children) == 0 {
		for _, n := range graph {
			e.Children = append(e.Children, EpicChild{Issue: n.Issue, Dependencies: n.Dependencies, Attempt: 1, State: "Queued"})
		}
		return nil
	}
	if len(e.Children) != len(graph) {
		return errors.New("native sub-issue membership changed; restore the original graph before resume")
	}
	for i, n := range graph {
		c := &e.Children[i]
		if c.Issue.Number != n.Issue.Number || c.Issue.ID != n.Issue.ID || fmt.Sprint(c.Dependencies) != fmt.Sprint(n.Dependencies) {
			return errors.New("native child identity or dependencies changed; restore the original graph before resume")
		}
	}
	for i := range graph {
		e.Children[i].Issue = graph[i].Issue
	}
	return nil
}

func projectEligibility(e *Epic) {
	completed := map[int]bool{}
	for _, c := range e.Children {
		completed[c.Issue.Number] = c.State == "Completed"
	}
	for i := range e.Children {
		c := &e.Children[i]
		if c.State != "Queued" && c.State != "Blocked" {
			continue
		}
		c.State = "Queued"
		c.Reason = "Waiting for admission capacity"
		if c.Issue.State != "open" {
			c.State = "Blocked"
			c.Reason = "Issue is closed; closure does not prove a PR merge"
			continue
		}
		for _, dep := range c.Dependencies {
			if !completed[dep] {
				c.State = "Blocked"
				c.Reason = fmt.Sprintf("Waiting for verified merge of #%d", dep)
				break
			}
		}
	}
}
