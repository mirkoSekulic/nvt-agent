package producer

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

const IdempotencyAnnotation = "nvt.dev/idempotency-key"

var dnsLabelInvalid = regexp.MustCompile(`[^a-z0-9-]+`)

func IdempotencyKey(owner, repo string, issueNumber int) string {
	return fmt.Sprintf("github:%s/%s:issue:%d:intent:create_pr", owner, repo, issueNumber)
}

func AgentRunName(owner, repo string, issueNumber int) string {
	base := strings.ToLower(fmt.Sprintf("gh-%s-%s-%d-pr-create", owner, repo, issueNumber))
	base = strings.Trim(dnsLabelInvalid.ReplaceAllString(base, "-"), "-")
	sum := sha256.Sum256([]byte(IdempotencyKey(owner, repo, issueNumber)))
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
