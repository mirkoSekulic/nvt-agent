package producer

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestInstallationTokenSourceUsesGitHubAppJWT(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	var authHeader string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/app/installations/456/access_tokens" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		authHeader = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token":      "installation-token",
			"expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
		})
	}))
	defer server.Close()

	source, err := NewInstallationTokenSource(GitHubAppConfig{
		AppID:            123,
		InstallationID:   456,
		PrivateKeyBase64: base64.StdEncoding.EncodeToString(privateKeyPEM(key)),
	}, server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	token, err := source.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if token != "installation-token" {
		t.Fatalf("unexpected token %q", token)
	}
	if !strings.HasPrefix(authHeader, "Bearer ") {
		t.Fatalf("missing bearer JWT auth header: %q", authHeader)
	}
	if strings.Count(strings.TrimPrefix(authHeader, "Bearer "), ".") != 2 {
		t.Fatalf("auth header did not contain a JWT: %q", authHeader)
	}
}

func TestGitHubAPIClientListsUpdatedIssueComments(t *testing.T) {
	var gotPath string
	tokenSource := staticTokenSource("token")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.String()
		if r.Header.Get("Authorization") != "Bearer token" {
			t.Fatalf("unexpected auth %q", r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"id":1,"body":"/nvtagent pr create","issue_url":"https://api.github.com/repos/o/r/issues/9","updated_at":"2026-01-02T03:04:05Z","user":{"login":"octo"}}]`))
	}))
	defer server.Close()
	client := NewGitHubAPIClient(server.URL, "test-agent", tokenSource, server.Client())
	since := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	comments, err := client.ListUpdatedIssueComments(context.Background(), Repository{Owner: "o", Name: "r"}, &since)
	if err != nil {
		t.Fatal(err)
	}
	if len(comments) != 1 || comments[0].ID != 1 {
		t.Fatalf("unexpected comments %#v", comments)
	}
	if !strings.Contains(gotPath, "sort=updated") || !strings.Contains(gotPath, "direction=asc") || !strings.Contains(gotPath, "since=2026-01-01T00%3A00%3A00Z") {
		t.Fatalf("unexpected request path %s", gotPath)
	}
}

type staticTokenSource string

func (s staticTokenSource) Token(context.Context) (string, error) {
	return string(s), nil
}

func privateKeyPEM(key *rsa.PrivateKey) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
}
