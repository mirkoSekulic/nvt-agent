package executiondriver

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

// AgentRunExecutionID derives the stable opaque execution identity from the
// immutable AgentRun UID. It is shared by operator reconciliation and trusted
// gateway status validation; neither caller guesses a guest instance.
func AgentRunExecutionID(agentRunUID string) (string, error) {
	if agentRunUID == "" {
		return "", errors.New("AgentRun UID is unavailable")
	}
	digest := sha256.Sum256([]byte(agentRunUID))
	return "nvt-agentrun-" + hex.EncodeToString(digest[:]), nil
}
