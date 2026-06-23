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
