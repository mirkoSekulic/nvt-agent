package portal

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestConfigStrictlyRejectsUnknownDuplicateAndUnsafeSlotPolicy(t *testing.T) {
	valid, err := json.Marshal(testConfig())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeConfig(strings.NewReader(string(valid))); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	invalid := []string{
		strings.Replace(string(valid), `"listenAddr":`, `"unknown":true,"listenAddr":`, 1),
		strings.Replace(string(valid), `"publicURL":`, `"publicURL":"https://duplicate.example","publicURL":`, 1),
		strings.Replace(string(valid), `"adapter":"codex-oauth-file"`, `"adapter":"auto-detect"`, 1),
		strings.Replace(string(valid), `"subject":"alice"`, `"subject":""`, 1),
		string(valid) + ` trailing`,
	}
	for index, raw := range invalid {
		if _, err := DecodeConfig(strings.NewReader(raw)); err == nil {
			t.Fatalf("invalid config %d accepted", index)
		}
	}
}
