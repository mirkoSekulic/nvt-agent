package producer

import (
	"strings"
	"testing"
)

func TestIdempotencyKey(t *testing.T) {
	got := IdempotencyKey("owner", "repo", 42)
	want := "github:owner/repo:issue:42:intent:create_pr"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestCommentIdempotencyKey(t *testing.T) {
	got := CommentIdempotencyKey("owner", "repo", 42, 9001)
	want := "github:owner/repo:issue:42:comment:9001:intent:create_pr"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestIssueScopeAgentRunNameCompatibility(t *testing.T) {
	got := AgentRunName("owner", "repo", 42)
	want := "gh-owner-repo-42-pr-create-7354cbc76a"
	if got != want {
		t.Fatalf("got %q want existing issue-scope name %q", got, want)
	}
}

func TestAgentRunNameIsDeterministicDNSLabel(t *testing.T) {
	first := AgentRunName("Owner.With.Symbols", "Repo_Name_With_A_Very_Long_Name_That_Will_Be_Truncated", 123)
	second := AgentRunName("Owner.With.Symbols", "Repo_Name_With_A_Very_Long_Name_That_Will_Be_Truncated", 123)
	if first != second {
		t.Fatalf("name was not deterministic: %q != %q", first, second)
	}
	if len(first) > 63 {
		t.Fatalf("name too long: %d", len(first))
	}
	if strings.Trim(first, "abcdefghijklmnopqrstuvwxyz0123456789-") != "" {
		t.Fatalf("name is not a DNS label: %q", first)
	}
}

func TestCommentAgentRunNameIncludesCommentScope(t *testing.T) {
	first := CommentAgentRunName("owner", "repo", 42, 9001)
	second := CommentAgentRunName("owner", "repo", 42, 9002)
	if first == second {
		t.Fatalf("comment-scoped names should differ: %q", first)
	}
	if !strings.Contains(first, "comment-9001") {
		t.Fatalf("comment-scoped name should include comment id before hashing: %q", first)
	}
	if len(first) > 63 || len(second) > 63 {
		t.Fatalf("comment-scoped names are too long: %q %q", first, second)
	}
}

func TestCommentAgentRunNameKeepsCommentIDWhenRepoIsLong(t *testing.T) {
	name := CommentAgentRunName("Owner.With.Symbols", "Repo_Name_With_A_Very_Long_Name_That_Will_Be_Truncated", 123, 9001)
	if !strings.Contains(name, "comment-9001") {
		t.Fatalf("comment-scoped name should keep comment id before truncation: %q", name)
	}
	if len(name) > 63 {
		t.Fatalf("name too long: %d", len(name))
	}
}
