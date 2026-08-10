package portal

import (
	"encoding/base64"
	"fmt"
	"testing"
)

func validCodex(access, refresh string) []byte {
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"exp":4102444800}`))
	return fmt.Appendf(
		nil,
		`{"tokens":{"access_token":%q,"refresh_token":%q},"last_refresh":"kept"}`,
		access+"."+payload+".signature",
		refresh,
	)
}

func validClaude(access, refresh string) []byte {
	return fmt.Appendf(
		nil,
		`{"claudeAiOauth":{"accessToken":%q,"refreshToken":%q,"expiresAt":4102444800000}}`,
		access,
		refresh,
	)
}

func TestCredentialAdaptersAcceptOnlyTheirMinimumRealShape(t *testing.T) {
	if err := ValidateCredential(AdapterCodexOAuthFile, validCodex("access", "refresh")); err != nil {
		t.Fatal(err)
	}
	if err := ValidateCredential(AdapterClaudeOAuthFile, validClaude("access", "refresh")); err != nil {
		t.Fatal(err)
	}
	invalid := []struct {
		name, adapter string
		body          []byte
	}{
		{"cross codex", AdapterCodexOAuthFile, validClaude("a", "r")},
		{"cross claude", AdapterClaudeOAuthFile, validCodex("a", "r")},
		{"codex missing expiry", AdapterCodexOAuthFile, []byte(`{"tokens":{"access_token":"a","refresh_token":"r"}}`)},
		{"claude missing refresh", AdapterClaudeOAuthFile, []byte(`{"claudeAiOauth":{"accessToken":"a"}}`)},
		{
			"duplicate",
			AdapterClaudeOAuthFile,
			[]byte(`{"claudeAiOauth":{"accessToken":"a","accessToken":"b","refreshToken":"r"}}`),
		},
		{"array", AdapterClaudeOAuthFile, []byte(`[]`)},
	}
	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			if ValidateCredential(test.adapter, test.body) == nil {
				t.Fatal("accepted invalid credential")
			}
		})
	}
}
