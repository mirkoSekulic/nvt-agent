package portal

import (
	"bytes"
	"context"
	"crypto/sha512"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/securecookie"
)

type memoryPatcher struct {
	namespace, name, key string
	value                []byte
	err                  error
	calls                int
}

func (p *memoryPatcher) Patch(_ context.Context, namespace, name, key string, value []byte) error {
	p.calls++
	if p.err != nil {
		return p.err
	}
	p.namespace, p.name, p.key = namespace, name, key
	p.value = append([]byte(nil), value...)
	return nil
}

func testConfig() Config {
	cfg := Config{PublicURL: "https://portal.example/agents/credentials", ListenAddr: ":8080", Namespace: "nvt", MaxUploadBytes: 4096,
		Auth:  AuthConfig{Mode: "oauth2", Session: SessionConfig{CookieName: "nvt_credential_portal", MaxAgeSeconds: 3600, Secure: true}, OAuth2: OAuth2Config{Issuer: "https://identity.example", AuthorizationURL: "https://identity.example/auth", TokenURL: "https://identity.example/token", CallbackPath: "/oauth2/callback", IdentityEndpoint: "https://identity.example/me", AllowedHosts: []string{"identity.example"}, SubjectPath: "id"}},
		Slots: []Slot{{Name: "alice", Label: "Alice", Owner: Principal{Issuer: "https://identity.example", Subject: "alice"}, Adapter: AdapterCodexOAuthFile, BrokerProvider: "codex", SecretName: "portal-seed", DataKey: "auth.json"}, {Name: "bob", Label: "Bob", Owner: Principal{Issuer: "https://identity.example", Subject: "bob"}, Adapter: AdapterClaudeOAuthFile, BrokerProvider: "claude", SecretName: "portal-seed", DataKey: "credentials.json"}}}
	if err := cfg.Validate(); err != nil {
		panic(err)
	}
	return cfg
}

func authenticatedServer(t *testing.T, principal Principal, patcher SecretPatcher, audit *bytes.Buffer) (*Server, *http.Cookie, string) {
	t.Helper()
	cfg := testConfig()
	sum := sha512.Sum512([]byte(strings.Repeat("s", 64)))
	cookies := securecookie.New(sum[:32], sum[32:])
	cookies.MaxAge(3600)
	auth := &Authenticator{cfg: cfg, cookies: cookies, sessions: map[string]session{}, now: time.Now}
	csrf := "csrf-token"
	id := "opaque-session"
	auth.sessions[id] = session{Principal: principal, CSRF: csrf, ExpiresAt: time.Now().Add(time.Hour)}
	encoded, err := cookies.Encode(cfg.Auth.Session.CookieName, id)
	if err != nil {
		t.Fatal(err)
	}
	return NewServer(cfg, auth, patcher, NewAuditLogger(audit)), &http.Cookie{Name: cfg.Auth.Session.CookieName, Value: encoded}, csrf
}

func request(t *testing.T, server *Server, cookie *http.Cookie, csrf, method, path, contentType string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, "https://portal.example"+path, bytes.NewReader(body))
	req.AddCookie(cookie)
	if csrf != "" {
		req.Header.Set("Origin", "https://portal.example")
		req.Header.Set("X-CSRF-Token", csrf)
		req.Header.Set("X-NVT-Confirm", "replace")
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	w := httptest.NewRecorder()
	server.ServeHTTP(w, req)
	return w
}

func TestEnrollmentBindsPrincipalSlotAndDestinationAndDoesNotLeak(t *testing.T) {
	patcher := &memoryPatcher{}
	audit := &bytes.Buffer{}
	alice := Principal{Issuer: "https://identity.example", Subject: "alice", DisplayName: "Alice"}
	server, cookie, csrf := authenticatedServer(t, alice, patcher, audit)
	secretAccess, secretRefresh := "access-do-not-leak", "refresh-do-not-leak"
	body := validCodex(secretAccess, secretRefresh)
	body = []byte(strings.Replace(string(body), `,"last_refresh"`, `,"slot":"bob","adapter":"claude-oauth-file","secretName":"other-secret","dataKey":"other-key","last_refresh"`, 1))
	denied := request(t, server, cookie, csrf, http.MethodPut, "/agents/credentials/slots/bob/credential", "application/json", validClaude(secretAccess, secretRefresh))
	if denied.Code != http.StatusNotFound || patcher.calls != 0 {
		t.Fatalf("cross-owner request code=%d calls=%d", denied.Code, patcher.calls)
	}
	response := request(t, server, cookie, csrf, http.MethodPut, "/agents/credentials/slots/alice/credential", "application/json", body)
	if response.Code != http.StatusOK {
		t.Fatalf("enrollment failed with status %d", response.Code)
	}
	if patcher.namespace != "nvt" || patcher.name != "portal-seed" || patcher.key != "auth.json" || !bytes.Equal(patcher.value, body) {
		t.Fatalf("unexpected exact patch destination/content")
	}
	combined := response.Body.String() + audit.String()
	for index, secret := range []string{secretAccess, secretRefresh} {
		if strings.Contains(combined, secret) {
			t.Fatalf("credential marker %d leaked", index)
		}
	}
	if !strings.Contains(audit.String(), `"outcome":"attempt"`) || !strings.Contains(audit.String(), `"outcome":"success"`) {
		t.Fatalf("missing sanitized audit events: %s", audit.String())
	}
}

func TestDashboardListsOnlyOwnedSlotsAndNeverExistingValueOrHealth(t *testing.T) {
	server, cookie, _ := authenticatedServer(t, Principal{Issuer: "https://identity.example", Subject: "alice", DisplayName: "Alice"}, &memoryPatcher{value: []byte("existing-value")}, &bytes.Buffer{})
	response := request(t, server, cookie, "", http.MethodGet, "/agents/credentials/", "", nil)
	body := response.Body.String()
	if response.Code != http.StatusOK || !strings.Contains(body, "Alice") || strings.Contains(body, "Bob") || strings.Contains(body, "existing-value") || strings.Contains(strings.ToLower(body), "credential is healthy") {
		t.Fatalf("owner-filtered dashboard failed with status %d", response.Code)
	}
}

func TestCanonicalPublicURLRedirectMakesGatewayLinkUsable(t *testing.T) {
	server, cookie, _ := authenticatedServer(t, Principal{Issuer: "https://identity.example", Subject: "alice"}, &memoryPatcher{}, &bytes.Buffer{})
	response := request(t, server, cookie, "", http.MethodGet, "/agents/credentials", "", nil)
	if response.Code != http.StatusPermanentRedirect || response.Header().Get("Location") != "/agents/credentials/" {
		t.Fatalf("canonical redirect code=%d location=%q", response.Code, response.Header().Get("Location"))
	}
}

func TestEnrollmentFailsClosedBeforeSecretMutation(t *testing.T) {
	cases := []struct {
		name, csrf, path, contentType string
		body                          []byte
		want                          int
	}{
		{"csrf", "", "/agents/credentials/slots/alice/credential", "application/json", validCodex("a", "r"), http.StatusForbidden},
		{"query override", "csrf-token", "/agents/credentials/slots/alice/credential?secretName=other", "application/json", validCodex("a", "r"), http.StatusNotFound},
		{"multipart", "csrf-token", "/agents/credentials/slots/alice/credential", "multipart/form-data; boundary=x", validCodex("a", "r"), http.StatusUnsupportedMediaType},
		{"content params", "csrf-token", "/agents/credentials/slots/alice/credential", "application/json; charset=utf-8", validCodex("a", "r"), http.StatusUnsupportedMediaType},
		{"invalid JSON", "csrf-token", "/agents/credentials/slots/alice/credential", "application/json", []byte(`{"tokens":`), http.StatusBadRequest},
		{"oversized", "csrf-token", "/agents/credentials/slots/alice/credential", "application/json", bytes.Repeat([]byte("x"), 5000), http.StatusRequestEntityTooLarge},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			patcher := &memoryPatcher{}
			server, cookie, _ := authenticatedServer(t, Principal{Issuer: "https://identity.example", Subject: "alice"}, patcher, &bytes.Buffer{})
			response := request(t, server, cookie, test.csrf, http.MethodPut, test.path, test.contentType, test.body)
			if response.Code != test.want || patcher.calls != 0 {
				t.Fatalf("code=%d calls=%d", response.Code, patcher.calls)
			}
		})
	}
}

func TestMultipartFilenameAndTemporaryPersistenceAreNeverUsed(t *testing.T) {
	uploadTemp := t.TempDir()
	t.Setenv("TMPDIR", uploadTemp)
	outside := filepath.Join(t.TempDir(), "outside-canary")
	if err := os.WriteFile(outside, []byte("unchanged"), 0600); err != nil {
		t.Fatal(err)
	}
	patcher := &memoryPatcher{}
	server, cookie, csrf := authenticatedServer(t, Principal{Issuer: "https://identity.example", Subject: "alice"}, patcher, &bytes.Buffer{})
	multipart := []byte("--boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"../../outside-canary\"\r\nContent-Type: application/json\r\n\r\n" + string(validCodex("access", "refresh")) + "\r\n--boundary--\r\n")
	response := request(t, server, cookie, csrf, http.MethodPut, "/agents/credentials/slots/alice/credential", "multipart/form-data; boundary=boundary", multipart)
	contents, err := os.ReadFile(outside)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(uploadTemp)
	if err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusUnsupportedMediaType || patcher.calls != 0 || string(contents) != "unchanged" || len(entries) != 0 {
		t.Fatalf("multipart handling touched filesystem or Secret")
	}
}

func TestPatchFailureDoesNotClaimSuccessOrMutateOldValue(t *testing.T) {
	patcher := &memoryPatcher{value: []byte("old"), err: errors.New("api failed")}
	audit := &bytes.Buffer{}
	server, cookie, csrf := authenticatedServer(t, Principal{Issuer: "https://identity.example", Subject: "alice"}, patcher, audit)
	response := request(t, server, cookie, csrf, http.MethodPut, "/agents/credentials/slots/alice/credential", "application/json", validCodex("a", "r"))
	if response.Code != http.StatusBadGateway || string(patcher.value) != "old" || strings.Contains(response.Body.String(), "api failed") || !strings.Contains(audit.String(), `"reason":"secret-update-failed"`) {
		t.Fatalf("patch failure was not sanitized or did not preserve prior state")
	}
}
