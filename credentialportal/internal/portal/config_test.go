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

func TestConfigRejectsSharedSecretDestinationAcrossOwners(t *testing.T) {
	cfg := testConfig()
	cfg.Slots[1].DataKey = cfg.Slots[0].DataKey
	if cfg.Slots[0].Name == cfg.Slots[1].Name || cfg.Slots[0].Owner.Subject == cfg.Slots[1].Owner.Subject {
		t.Fatal("test requires distinct slot names and owners")
	}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "already assigned") {
		t.Fatal("shared Secret destination was accepted")
	}
}
