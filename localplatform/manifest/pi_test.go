package manifest

import (
	"os"
	"strings"
	"testing"
)

func TestPiPublicConfigurationValidation(t *testing.T) {
	raw, err := os.ReadFile("../../examples/pi/manifest.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(strings.NewReader(string(raw))); err != nil {
		t.Fatal(err)
	}
	tests := map[string][2]string{
		"approval":         {"autonomy: trusted-local", "autonomy: approval-required"},
		"unknown provider": {"credentialProvider: model-api", "credentialProvider: missing"},
		"endpoint":         {"https://models.example.test/v1", "https://other.example.test/v1"},
		"api key":          {"api: openai-completions", "api: openai-completions\n        apiKey: fake-secret"},
		"command resolver": {"api: openai-completions", "api: openai-completions\n        apiKey: '!touch /tmp/must-not-run'"},
		"header resolver":  {"api: openai-completions", "api: openai-completions\n        headers: {Authorization: '$TOKEN'}"},
		"url credentials":  {"https://models.example.test/v1", "https://fake-secret@models.example.test/v1"},
		"effort":           {"effort: \"off\"", "effort: max"},
		"missing secret":   {"token-file: model-key", "token-file: missing"},
		"wrong scheme":     {"injection-hosts: [models.example.test]", "injection-hosts: [models.example.test]\n      injection-scheme: Basic"},
	}
	for name, pair := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := Decode(strings.NewReader(strings.Replace(string(raw), pair[0], pair[1], 1)))
			if err == nil {
				t.Fatal("invalid Pi configuration accepted")
			}
			if strings.Contains(err.Error(), "fake-secret") {
				t.Fatal("credential entered validation error")
			}
		})
	}
}
