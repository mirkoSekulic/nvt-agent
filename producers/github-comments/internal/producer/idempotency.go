package producer

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

const (
	IdempotencyAnnotation = "nvt.dev/idempotency-key"
	AccessKeyAnnotation   = "nvt.dev/access-key"
	DisplayNameAnnotation = "nvt.dev/display-name"
	SourceURLAnnotation   = "nvt.dev/source-url"
	RequestedByAnnotation = "nvt.dev/requested-by"
	AccessPortAnnotation  = "nvt.dev/access-port"
)

var dnsLabelInvalid = regexp.MustCompile(`[^a-z0-9-]+`)

func IdempotencyKey(owner, repo string, issueNumber int) string {
	return fmt.Sprintf("github:%s/%s:issue:%d:intent:create_pr", owner, repo, issueNumber)
}

func CommentIdempotencyKey(owner, repo string, issueNumber int, commentID int64) string {
	return fmt.Sprintf("github:%s/%s:issue:%d:comment:%d:intent:create_pr", owner, repo, issueNumber, commentID)
}

func AgentRunName(owner, repo string, issueNumber int) string {
	base := strings.ToLower(fmt.Sprintf("gh-%s-%s-%d-pr-create", owner, repo, issueNumber))
	base = strings.Trim(dnsLabelInvalid.ReplaceAllString(base, "-"), "-")
	return agentRunNameFromBaseAndKey(base, IdempotencyKey(owner, repo, issueNumber))
}

func CommentAgentRunName(owner, repo string, issueNumber int, commentID int64) string {
	base := strings.ToLower(fmt.Sprintf("gh-%d-comment-%d-%s-%s-pr-create", issueNumber, commentID, owner, repo))
	base = strings.Trim(dnsLabelInvalid.ReplaceAllString(base, "-"), "-")
	return agentRunNameFromBaseAndKey(base, CommentIdempotencyKey(owner, repo, issueNumber, commentID))
}

func agentRunNameFromBaseAndKey(base, key string) string {
	sum := sha256.Sum256([]byte(key))
	suffix := hex.EncodeToString(sum[:])[:10]
	maxBase := 63 - len(suffix) - 1
	if len(base) > maxBase {
		base = strings.Trim(base[:maxBase], "-")
	}
	if base == "" {
		base = "github-pr-create"
	}
	return base + "-" + suffix
}
