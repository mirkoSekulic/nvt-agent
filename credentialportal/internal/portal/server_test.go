package portal

import (
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/json"
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

const (
	testIdentityIssuer      = "https://identity.example"
	testAliceSubject        = "alice"
	testBobSubject          = "bob"
	testAliceLabel          = "Alice"
	testCSRFToken           = "csrf-token"
	testCodexAuthKey        = "auth.json"
	testClaudeCredentialKey = "credentials.json"
	testUploadPath          = "/agents/credentials/slots/alice/credential"
	testOversized           = "oversized"
	testPortalSeed          = "portal-seed"
)

var errTestAPI = errors.New("api failed")

type memoryPatcher struct {
	err       error
	namespace string
	name      string
	key       string
	value     []byte
	calls     int
}

type readinessTestRunner struct {
	err error
}

func (r *readinessTestRunner) Run(
	_ context.Context,
	_, _ string,
	_ <-chan string,
	_ func(providerAction),
) ([]byte, string) {
	return nil, reasonRunnerUnavailable
}

func (r *readinessTestRunner) Acknowledge(_ context.Context, _ string) error { return nil }
func (r *readinessTestRunner) Cancel(_ context.Context, _ string) error      { return nil }
func (r *readinessTestRunner) Ready(_ context.Context) error                 { return r.err }

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
	cfg := Config{
		PublicURL:      "https://portal.example/agents/credentials",
		ListenAddr:     ":8080",
		Namespace:      "nvt",
		MaxUploadBytes: 4096,
		Enrollment:     EnrollmentConfig{ExperimentalCodexDeviceAuth: true},
		RecoveryUpload: RecoveryUploadConfig{Enabled: true},
		Auth: AuthConfig{
			Mode:    authModeOAuth2,
			Session: SessionConfig{CookieName: "nvt_credential_portal", MaxAgeSeconds: 3600, Secure: true},
			OAuth2: OAuth2Config{
				Issuer:           testIdentityIssuer,
				AuthorizationURL: testIdentityIssuer + "/auth",
				TokenURL:         testIdentityIssuer + "/token",
				CallbackPath:     testOAuthCallbackPath,
				IdentityEndpoint: testIdentityIssuer + "/me",
				AllowedHosts:     []string{"identity.example"},
				SubjectPath:      "id",
			},
		},
		Slots: []Slot{
			{
				Name:           testAliceSubject,
				Label:          testAliceLabel,
				Owner:          Principal{Issuer: testIdentityIssuer, Subject: testAliceSubject},
				Adapter:        AdapterCodexOAuthFile,
				BrokerProvider: codexCommand,
				SecretName:     testPortalSeed,
				DataKey:        testCodexAuthKey,
			},
			{
				Name:           testBobSubject,
				Label:          "Bob",
				Owner:          Principal{Issuer: testIdentityIssuer, Subject: testBobSubject},
				Adapter:        AdapterClaudeOAuthFile,
				BrokerProvider: claudeCommand,
				SecretName:     testPortalSeed,
				DataKey:        testClaudeCredentialKey,
			},
		},
	}
	if err := cfg.Validate(); err != nil {
		panic(err)
	}
	return cfg
}

func authenticatedServer(
	t *testing.T,
	principal Principal,
	patcher SecretPatcher,
	audit *bytes.Buffer,
) (*Server, *http.Cookie, string) {
	t.Helper()
	cfg := testConfig()
	sum := sha512.Sum512([]byte(strings.Repeat("s", 64)))
	cookies := securecookie.New(sum[:32], sum[32:])
	cookies.MaxAge(3600)
	auth := &Authenticator{cfg: cfg, cookies: cookies, sessions: map[string]session{}, now: time.Now}
	csrf := testCSRFToken
	id := "opaque-session"
	auth.sessions[id] = session{Principal: principal, CSRF: csrf, ExpiresAt: time.Now().Add(time.Hour)}
	encoded, err := cookies.Encode(cfg.Auth.Session.CookieName, id)
	if err != nil {
		t.Fatal(err)
	}
	return NewServer(
			cfg,
			auth,
			patcher,
			NewAuditLogger(audit),
			NewCLICredentialRunner(cfg.Enrollment),
		), &http.Cookie{
			Name:  cfg.Auth.Session.CookieName,
			Value: encoded,
		}, csrf
}

func request(
	t *testing.T,
	server *Server,
	cookie *http.Cookie,
	csrf, method, path, contentType string,
	body []byte,
) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), method, "https://portal.example"+path, bytes.NewReader(body))
	req.AddCookie(cookie)
	if csrf != "" {
		req.Header.Set("Origin", "https://portal.example")
		req.Header.Set(csrfHeader, csrf)
		req.Header.Set(confirmHeader, "replace")
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
	alice := Principal{Issuer: testIdentityIssuer, Subject: testAliceSubject, DisplayName: testAliceLabel}
	server, cookie, csrf := authenticatedServer(t, alice, patcher, audit)
	secretAccess, secretRefresh := "access-do-not-leak", "refresh-do-not-leak"
	body := validCodex(secretAccess, secretRefresh)
	body = []byte(
		strings.Replace(
			string(body),
			`,"last_refresh"`,
			`,"slot":"bob","adapter":"claude-oauth-file","secretName":"other-secret","dataKey":"other-key","last_refresh"`,
			1,
		),
	)
	denied := request(
		t,
		server,
		cookie,
		csrf,
		http.MethodPut,
		"/agents/credentials/slots/bob/credential",
		"application/json",
		validClaude(secretAccess, secretRefresh),
	)
	if denied.Code != http.StatusNotFound || patcher.calls != 0 {
		t.Fatalf("cross-owner request code=%d calls=%d", denied.Code, patcher.calls)
	}
	response := request(t, server, cookie, csrf, http.MethodPut, testUploadPath, jsonContentType, body)
	if response.Code != http.StatusOK {
		t.Fatalf("enrollment failed with status %d", response.Code)
	}
	if patcher.namespace != "nvt" || patcher.name != testPortalSeed || patcher.key != testCodexAuthKey ||
		!bytes.Equal(patcher.value, body) {
		t.Fatalf("unexpected exact patch destination/content")
	}
	combined := response.Body.String() + audit.String()
	for index, secret := range []string{secretAccess, secretRefresh} {
		if strings.Contains(combined, secret) {
			t.Fatalf("credential marker %d leaked", index)
		}
	}
	if !strings.Contains(audit.String(), `"outcome":"attempt"`) ||
		!strings.Contains(audit.String(), `"outcome":"success"`) {
		t.Fatalf("missing sanitized audit events: %s", audit.String())
	}
}

func TestDashboardListsOnlyOwnedSlotsAndNeverExistingValueOrHealth(t *testing.T) {
	server, cookie, csrf := authenticatedServer(
		t,
		Principal{Issuer: testIdentityIssuer, Subject: testAliceSubject, DisplayName: testAliceLabel},
		&memoryPatcher{value: []byte("existing-value")},
		&bytes.Buffer{},
	)
	response := request(t, server, cookie, "", http.MethodGet, "/agents/credentials/", "", nil)
	body := response.Body.String()
	if response.Code != http.StatusOK || !strings.Contains(body, testAliceLabel) ||
		!strings.Contains(response.Header().Get("Content-Security-Policy"), "connect-src 'self'") ||
		!strings.Contains(body, `const csrf="`+csrf+`",base="/agents/credentials"`) ||
		strings.Contains(body, `base="\"/agents/credentials\""`) ||
		!strings.Contains(body, "Option 1: Sign in with provider") ||
		!strings.Contains(body, "Option 2: Upload an existing credential file") ||
		!strings.Contains(body, "Use this instead of provider sign-in") ||
		!strings.Contains(body, "function setText(element,value)") ||
		!strings.Contains(body, "setText(document.getElementById('device')") ||
		!strings.Contains(body, "Connect / reconnect") ||
		!strings.Contains(body, "experimental device login") ||
		strings.Contains(body, "Bob") ||
		strings.Contains(body, "existing-value") ||
		strings.Contains(strings.ToLower(body), "credential is healthy") {
		t.Fatalf("owner-filtered dashboard failed with status %d", response.Code)
	}
}

func TestPortalReadinessRequiresAuthenticatedRunnerDependency(t *testing.T) {
	server, _, _ := authenticatedServer(
		t,
		Principal{Issuer: testIdentityIssuer, Subject: testAliceSubject},
		&memoryPatcher{},
		&bytes.Buffer{},
	)
	defer server.Close()
	runner := &readinessTestRunner{err: errTestAPI}
	server.runner = runner
	request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://portal.example/readyz", nil)
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable || strings.Contains(response.Body.String(), errTestAPI.Error()) {
		t.Fatal("portal readiness did not fail closed and sanitize runner failure")
	}
	runner.err = nil
	response = httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatal("portal readiness rejected a healthy runner")
	}
}

func TestRecoveryUploadIsDisabledAndHiddenUnlessExplicitlyEnabled(t *testing.T) {
	server, cookie, csrf := authenticatedServer(
		t,
		Principal{Issuer: testIdentityIssuer, Subject: testAliceSubject},
		&memoryPatcher{},
		&bytes.Buffer{},
	)
	server.cfg.RecoveryUpload.Enabled = false
	dashboard := request(t, server, cookie, "", http.MethodGet, "/agents/credentials/", "", nil)
	if strings.Contains(dashboard.Body.String(), "Option 2: Upload an existing credential file") ||
		strings.Contains(dashboard.Body.String(), `id="credential"`) {
		t.Fatal("disabled recovery upload appeared on the dashboard")
	}
	upload := request(t, server, cookie, csrf, http.MethodPut, testUploadPath, jsonContentType, validCodex("a", "r"))
	if upload.Code != http.StatusNotFound {
		t.Fatal("disabled recovery upload endpoint remained available")
	}
}

func TestConnectHTTPFlowReturnsOnlyProviderHandoffAndResult(t *testing.T) {
	patcher := &memoryPatcher{value: []byte("old-secret")}
	audit := &bytes.Buffer{}
	principal := Principal{Issuer: testIdentityIssuer, Subject: testAliceSubject}
	server, cookie, csrf := authenticatedServer(t, principal, patcher, audit)
	manager, _, _, root := fakeEnrollmentManager(t, AdapterCodexOAuthFile, "codex-success")
	manager.patcher = patcher
	manager.audit = NewAuditLogger(audit)
	server.enrollments.Close()
	server.enrollments = manager
	defer server.Close()

	denied := request(t, server, cookie, csrf, http.MethodPost, "/agents/credentials/slots/bob/connect", "", nil)
	if denied.Code != http.StatusNotFound {
		t.Fatal("cross-owner Connect was not hidden")
	}
	override := request(
		t, server, cookie, csrf, http.MethodPost,
		"/agents/credentials/slots/alice/connect?slot=bob&secretName=other", "", nil,
	)
	if override.Code != http.StatusNotFound {
		t.Fatal("Connect accepted request-controlled slot or destination parameters")
	}
	started := request(t, server, cookie, csrf, http.MethodPost, "/agents/credentials/slots/alice/connect", "", nil)
	if started.Code != http.StatusAccepted {
		t.Fatal("Connect did not start")
	}
	var initial EnrollmentStatus
	if err := json.Unmarshal(
		started.Body.Bytes(),
		&initial,
	); err != nil || initial.ID == "" ||
		initial.Slot != testAliceSubject {
		t.Fatal("Connect returned an invalid session document")
	}
	browserOutput := started.Body.String()
	action := waitEnrollmentStatus(t, manager, principal, initial.ID, enrollmentActionRequired, enrollmentSucceeded)
	if action.Status == enrollmentActionRequired {
		statusResponse := request(
			t,
			server,
			cookie,
			"",
			http.MethodGet,
			"/agents/credentials/enrollments/"+initial.ID,
			"",
			nil,
		)
		if statusResponse.Code != http.StatusOK || !strings.Contains(statusResponse.Body.String(), "auth.openai.com") {
			t.Fatal("provider authorization handoff was not available")
		}
		browserOutput += statusResponse.Body.String()
	}
	waitEnrollmentStatus(t, manager, principal, initial.ID, enrollmentSucceeded)
	completedResponse := request(
		t, server, cookie, "", http.MethodGet, "/agents/credentials/enrollments/"+initial.ID, "", nil,
	)
	browserOutput += completedResponse.Body.String()
	combined := browserOutput + audit.String()
	if strings.Contains(combined, fakeCLIAccess) || strings.Contains(combined, fakeCLIRefresh) ||
		strings.Contains(combined, string(patcher.value)) {
		t.Fatal("credential content appeared in a browser response or audit")
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 0 {
		t.Fatal("HTTP Connect left its ephemeral home")
	}
}

func TestEnrollmentCodeBodyIsBoundedStrictAndDuplicateFree(t *testing.T) {
	cases := [][]byte{
		[]byte(`{"code":"one","code":"two"}`),
		[]byte(`{"code":"one","slot":"bob"}`),
		[]byte(`{"code":42}`),
		[]byte(`{"code":" leading"}`),
		bytes.Repeat([]byte("x"), maxEnrollmentCodeBytes+65),
	}
	for _, body := range cases {
		recorder := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(
			t.Context(),
			http.MethodPost,
			"https://portal.example/code",
			bytes.NewReader(body),
		)
		req.Header.Set("Content-Type", jsonContentType)
		if _, ok := readEnrollmentCode(recorder, req); ok {
			t.Fatal("malformed enrollment code body was accepted")
		}
	}
}

func TestCanonicalPublicURLRedirectMakesGatewayLinkUsable(t *testing.T) {
	server, cookie, _ := authenticatedServer(
		t,
		Principal{Issuer: testIdentityIssuer, Subject: testAliceSubject},
		&memoryPatcher{},
		&bytes.Buffer{},
	)
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
		{"csrf", "", testUploadPath, jsonContentType, validCodex("a", "r"), http.StatusForbidden},
		{
			"query override",
			testCSRFToken,
			testUploadPath + "?secretName=other",
			jsonContentType,
			validCodex("a", "r"),
			http.StatusNotFound,
		},
		{
			"multipart",
			testCSRFToken,
			testUploadPath,
			"multipart/form-data; boundary=x",
			validCodex("a", "r"),
			http.StatusUnsupportedMediaType,
		},
		{
			"content params",
			testCSRFToken,
			testUploadPath,
			jsonContentType + "; charset=utf-8",
			validCodex("a", "r"),
			http.StatusUnsupportedMediaType,
		},
		{"invalid JSON", testCSRFToken, testUploadPath, jsonContentType, []byte(`{"tokens":`), http.StatusBadRequest},
		{
			testOversized,
			testCSRFToken,
			testUploadPath,
			jsonContentType,
			bytes.Repeat([]byte("x"), 5000),
			http.StatusRequestEntityTooLarge,
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			patcher := &memoryPatcher{}
			server, cookie, _ := authenticatedServer(
				t,
				Principal{Issuer: testIdentityIssuer, Subject: testAliceSubject},
				patcher,
				&bytes.Buffer{},
			)
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
	server, cookie, csrf := authenticatedServer(
		t,
		Principal{Issuer: testIdentityIssuer, Subject: testAliceSubject},
		patcher,
		&bytes.Buffer{},
	)
	multipart := []byte(
		"--boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"../../outside-canary\"\r\nContent-Type: application/json\r\n\r\n" + string(
			validCodex("access", "refresh"),
		) + "\r\n--boundary--\r\n",
	)
	response := request(
		t,
		server,
		cookie,
		csrf,
		http.MethodPut,
		testUploadPath,
		"multipart/form-data; boundary=boundary",
		multipart,
	)
	contents, err := os.ReadFile(outside)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(uploadTemp)
	if err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusUnsupportedMediaType || patcher.calls != 0 || string(contents) != "unchanged" ||
		len(entries) != 0 {
		t.Fatalf("multipart handling touched filesystem or Secret")
	}
}

func TestPatchFailureDoesNotClaimSuccessOrMutateOldValue(t *testing.T) {
	patcher := &memoryPatcher{value: []byte("old"), err: errTestAPI}
	audit := &bytes.Buffer{}
	server, cookie, csrf := authenticatedServer(
		t,
		Principal{Issuer: testIdentityIssuer, Subject: testAliceSubject},
		patcher,
		audit,
	)
	response := request(t, server, cookie, csrf, http.MethodPut, testUploadPath, jsonContentType, validCodex("a", "r"))
	if response.Code != http.StatusBadGateway || string(patcher.value) != "old" ||
		strings.Contains(response.Body.String(), "api failed") ||
		!strings.Contains(audit.String(), `"reason":"secret-update-failed"`) {
		t.Fatalf("patch failure was not sanitized or did not preserve prior state")
	}
}
