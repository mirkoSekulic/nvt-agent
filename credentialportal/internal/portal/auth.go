package portal

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/securecookie"
	"github.com/mirkoSekulic/nvt-agent/protocol/eligibility"
	"golang.org/x/oauth2"
)

var (
	errAuthConfiguration = errors.New("invalid authentication configuration")
	errMissingIDToken    = errors.New("missing ID token")
	errInvalidIDToken    = errors.New("invalid ID token")
	errInvalidIdentity   = errors.New("invalid identity")
	errIdentityLookup    = errors.New("identity lookup failed")
	errIdentitySubject   = errors.New("identity subject invalid")
	errIdentityDisplay   = errors.New("identity display name invalid")
)

type session struct {
	ExpiresAt            time.Time
	EligibilityExpiresAt time.Time
	Principal            Principal
	CSRF                 string
}

type loginState struct {
	State    string `json:"state"`
	Verifier string `json:"verifier"`
	Nonce    string `json:"nonce"`
	Expires  int64  `json:"expires"`
}

type Authenticator struct {
	provider            *oidc.Provider
	verifier            *oidc.IDTokenVerifier
	accessTokenVerifier *oidc.IDTokenVerifier
	cookies             *securecookie.SecureCookie
	client              *http.Client
	sessions            map[string]session
	now                 func() time.Time
	eligibility         EligibilityLeaseBroker
	oauth               oauth2.Config
	cfg                 Config
	mu                  sync.Mutex
}

type EligibilityLeaseBroker interface {
	RenewEligibility(ctx context.Context, principal Principal, expiresAt time.Time) error
	RevokeEligibility(ctx context.Context, principal Principal) error
}

//nolint:nestif // OIDC discovery and OAuth2 endpoint setup are explicit fail-closed branches.
func NewAuthenticator(
	ctx context.Context,
	cfg Config,
	sessionSecret, clientID, clientSecret string,
	client *http.Client,
	leaseBrokers ...EligibilityLeaseBroker,
) (*Authenticator, error) {
	if len(sessionSecret) < 32 || (cfg.Auth.Mode != authModeLocal && clientSecret == "") {
		return nil, fmt.Errorf(
			"%w: session secret must contain at least 32 bytes and client secret is required",
			errAuthConfiguration,
		)
	}
	if client == nil {
		client = http.DefaultClient
	}
	client = noRedirectClient(client)
	sum := sha512.Sum512([]byte(sessionSecret))
	a := &Authenticator{
		cfg:      cfg,
		cookies:  securecookie.New(sum[:32], sum[32:]),
		client:   client,
		sessions: map[string]session{},
		now:      time.Now,
	}
	if err := configureEligibilityLeaseBroker(a, cfg.Dynamic.Enabled, leaseBrokers); err != nil {
		return nil, err
	}
	a.cookies.MaxAge(cfg.Auth.Session.MaxAgeSeconds)
	if cfg.Auth.Mode == authModeLocal {
		return a, nil
	}
	redirect := cfg.PublicURL + callbackPath(cfg)
	if cfg.Auth.Mode == authModeOIDC {
		provider, err := oidc.NewProvider(oidc.ClientContext(ctx, client), cfg.Auth.OIDC.IssuerURL)
		if err != nil {
			return nil, fmt.Errorf("discover OIDC provider: %w", err)
		}
		a.provider = provider
		a.verifier = provider.Verifier(&oidc.Config{ClientID: cfg.Auth.OIDC.ClientID})
		audience := cfg.Auth.OIDC.AccessTokenAudience
		if audience == "" {
			audience = cfg.Auth.OIDC.ClientID
		}
		a.accessTokenVerifier = provider.Verifier(&oidc.Config{ClientID: audience})
		endpoint := provider.Endpoint()
		endpoint.AuthStyle = authStyle(cfg.Auth.OIDC.ClientAuthMethod)
		a.oauth = oauth2.Config{
			ClientID:     cfg.Auth.OIDC.ClientID,
			ClientSecret: clientSecret,
			Endpoint:     endpoint,
			RedirectURL:  redirect,
			Scopes:       uniqueScopes(append([]string{"openid"}, cfg.Auth.OIDC.Scopes...)),
		}
	} else {
		if clientID == "" {
			return nil, fmt.Errorf("%w: OAuth2 client ID is required", errAuthConfiguration)
		}
		a.oauth = oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Endpoint: oauth2.Endpoint{
				AuthURL:   cfg.Auth.OAuth2.AuthorizationURL,
				TokenURL:  cfg.Auth.OAuth2.TokenURL,
				AuthStyle: authStyle(cfg.Auth.OAuth2.ClientAuthMethod),
			},
			RedirectURL: redirect,
			Scopes:      cfg.Auth.OAuth2.Scopes,
		}
	}
	return a, nil
}

func configureEligibilityLeaseBroker(
	auth *Authenticator,
	dynamic bool,
	brokers []EligibilityLeaseBroker,
) error {
	if dynamic {
		if len(brokers) != 1 || brokers[0] == nil {
			return fmt.Errorf("%w: dynamic mode requires an eligibility lease broker", errAuthConfiguration)
		}
		auth.eligibility = brokers[0]
		return nil
	}
	if len(brokers) != 0 {
		return fmt.Errorf("%w: static mode must not configure an eligibility lease broker", errAuthConfiguration)
	}
	return nil
}

func authStyle(method string) oauth2.AuthStyle {
	if method == "client_secret_post" {
		return oauth2.AuthStyleInParams
	}
	if method == "client_secret_basic" {
		return oauth2.AuthStyleInHeader
	}
	return oauth2.AuthStyleAutoDetect
}

func uniqueScopes(scopes []string) []string {
	seen := map[string]bool{}
	result := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		if scope != "" && !seen[scope] {
			seen[scope] = true
			result = append(result, scope)
		}
	}
	return result
}

func callbackPath(cfg Config) string {
	if cfg.Auth.Mode == authModeOIDC {
		return cfg.Auth.OIDC.CallbackPath
	}
	return cfg.Auth.OAuth2.CallbackPath
}

func (a *Authenticator) Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet || r.URL.RawQuery != "" {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if a.cfg.Auth.Mode == authModeLocal {
		a.localLogin(w, r)
		return
	}
	state, stateErr := randomToken(32)
	verifier, verifierErr := randomToken(48)
	nonce, nonceErr := randomToken(32)
	if stateErr != nil || verifierErr != nil || nonceErr != nil {
		http.Error(w, "authentication unavailable", http.StatusInternalServerError)
		return
	}
	login := loginState{State: state, Verifier: verifier, Nonce: nonce, Expires: a.now().Add(5 * time.Minute).Unix()}
	encoded, err := a.cookies.Encode(a.cfg.Auth.Session.CookieName+"_login", login)
	if err != nil {
		http.Error(w, "authentication unavailable", http.StatusInternalServerError)
		return
	}
	http.SetCookie(
		w,
		&http.Cookie{
			Name:     a.cfg.Auth.Session.CookieName + "_login",
			Value:    encoded,
			Path:     a.cfg.Path("/oauth2/"),
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   300,
		},
	)
	challenge := sha256.Sum256([]byte(verifier))
	opts := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("code_challenge", base64.RawURLEncoding.EncodeToString(challenge[:])),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	}
	if a.cfg.Auth.Mode == authModeOIDC {
		opts = append(opts, oauth2.SetAuthURLParam("nonce", nonce))
	}
	http.Redirect(w, r, a.oauth.AuthCodeURL(state, opts...), http.StatusFound)
}

func (a *Authenticator) localLogin(w http.ResponseWriter, r *http.Request) {
	sessionID, sessionErr := randomToken(32)
	csrf, csrfErr := randomToken(32)
	if sessionErr != nil || csrfErr != nil {
		http.Error(w, "authentication unavailable", http.StatusInternalServerError)
		return
	}
	expiresAt := a.now().Add(time.Duration(a.cfg.Auth.Session.MaxAgeSeconds) * time.Second)
	a.mu.Lock()
	a.pruneLocked()
	if len(a.sessions) >= 4096 {
		a.mu.Unlock()
		http.Error(w, "authentication temporarily unavailable", http.StatusServiceUnavailable)
		return
	}
	a.sessions[sessionID] = session{Principal: a.cfg.Auth.Local.Principal, CSRF: csrf, ExpiresAt: expiresAt, EligibilityExpiresAt: expiresAt}
	a.mu.Unlock()
	encoded, err := a.cookies.Encode(a.cfg.Auth.Session.CookieName, sessionID)
	if err != nil {
		http.Error(w, "authentication unavailable", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: a.cfg.Auth.Session.CookieName, Value: encoded, Path: a.cfg.Path("/"), HttpOnly: true,
		Secure: a.cfg.Auth.Session.Secure, SameSite: http.SameSiteStrictMode, MaxAge: a.cfg.Auth.Session.MaxAgeSeconds,
	})
	http.Redirect(w, r, a.cfg.Path("/"), http.StatusFound)
}

//nolint:funlen,gocyclo,cyclop // Callback validation is intentionally linear and fail-closed before session creation.
func (a *Authenticator) Callback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	query := r.URL.Query()
	if len(query["state"]) != 1 || query.Get("state") == "" || len(query["code"]) != 1 || query.Get("code") == "" ||
		!a.validCallbackIssuer(query) {
		a.authFailure(w)
		return
	}
	cookie, err := r.Cookie(a.cfg.Auth.Session.CookieName + "_login")
	if err != nil {
		a.authFailure(w)
		return
	}
	var login loginState
	if a.cookies.Decode(a.cfg.Auth.Session.CookieName+"_login", cookie.Value, &login) != nil ||
		login.Expires < a.now().Unix() ||
		subtle.ConstantTimeCompare([]byte(login.State), []byte(r.URL.Query().Get("state"))) != 1 {
		a.authFailure(w)
		return
	}
	a.clearLoginCookie(w)
	ctx := context.WithValue(r.Context(), oauth2.HTTPClient, a.client)
	token, err := a.oauth.Exchange(
		ctx,
		r.URL.Query().Get("code"),
		oauth2.SetAuthURLParam("code_verifier", login.Verifier),
	)
	if err != nil {
		a.authFailure(w)
		return
	}
	principal, claims, err := a.principal(ctx, token, login.Nonce)
	identityVerified := err == nil
	if err == nil && a.cfg.Auth.Mode == authModeOIDC {
		claims, err = a.oidcEligibilityClaims(ctx, token, principal, claims)
	}
	if err == nil {
		sourceClaims := claims
		claims, err = eligibility.Enrich(
			ctx,
			a.cfg.Auth.ClaimEnrichment,
			token.AccessToken,
			claims,
			eligibility.EnrichOptions{Client: a.client, UserAgent: "nvt-credential-portal"},
		)
		clear(sourceClaims)
	}
	admitted := err == nil && a.admits(principal, claims)
	clear(claims)
	token.AccessToken = ""
	token.RefreshToken = ""
	now := a.now()
	sessionExpiresAt := now.Add(time.Duration(a.cfg.Auth.Session.MaxAgeSeconds) * time.Second)
	eligibilityExpiresAt := sessionExpiresAt
	if a.eligibility != nil {
		leaseExpiry := now.Add(time.Duration(a.cfg.Dynamic.Broker.EligibilityLeaseSeconds) * time.Second)
		if leaseExpiry.Before(eligibilityExpiresAt) {
			eligibilityExpiresAt = leaseExpiry
		}
	}
	if !a.updateEligibilityLease(ctx, principal, identityVerified, admitted, eligibilityExpiresAt) {
		a.authFailure(w)
		return
	}
	sessionID, sessionErr := randomToken(32)
	csrf, csrfErr := randomToken(32)
	if sessionErr != nil || csrfErr != nil {
		http.Error(w, "authentication unavailable", http.StatusInternalServerError)
		return
	}
	a.mu.Lock()
	a.pruneLocked()
	if len(a.sessions) >= 4096 {
		a.mu.Unlock()
		http.Error(w, "authentication temporarily unavailable", http.StatusServiceUnavailable)
		return
	}
	a.sessions[sessionID] = session{
		Principal: principal, CSRF: csrf,
		ExpiresAt: sessionExpiresAt, EligibilityExpiresAt: eligibilityExpiresAt,
	}
	a.mu.Unlock()
	encoded, err := a.cookies.Encode(a.cfg.Auth.Session.CookieName, sessionID)
	if err != nil {
		http.Error(w, "authentication unavailable", http.StatusInternalServerError)
		return
	}
	http.SetCookie(
		w,
		&http.Cookie{
			Name:     a.cfg.Auth.Session.CookieName,
			Value:    encoded,
			Path:     a.cfg.Path("/"),
			HttpOnly: true,
			Secure:   a.cfg.Auth.Session.Secure,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   a.cfg.Auth.Session.MaxAgeSeconds,
		},
	)
	http.Redirect(w, r, a.cfg.Path("/"), http.StatusFound)
}

func (a *Authenticator) updateEligibilityLease(
	ctx context.Context,
	principal Principal,
	identityVerified, admitted bool,
	expiresAt time.Time,
) bool {
	if a.eligibility == nil {
		return admitted
	}
	if !admitted {
		if identityVerified {
			a.invalidatePrincipalSessions(principal)
			// Exact verified identity may revoke its prior lease when current
			// policy evaluation denies it. The login remains denied regardless
			// of dependency state, so no broker detail is exposed.
			_ = a.eligibility.RevokeEligibility(ctx, principal) //nolint:errcheck // Already fail-closed.
		}
		return false
	}
	return a.eligibility.RenewEligibility(ctx, principal, expiresAt) == nil
}

func (a *Authenticator) invalidatePrincipalSessions(principal Principal) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for id, existing := range a.sessions {
		if existing.Principal.Issuer == principal.Issuer && existing.Principal.Subject == principal.Subject {
			delete(a.sessions, id)
		}
	}
}

func (a *Authenticator) validCallbackIssuer(query url.Values) bool {
	values, present := query["iss"]
	if !present {
		return true
	}
	if len(values) != 1 || values[0] == "" {
		return false
	}
	expected := a.cfg.Auth.OAuth2.Issuer
	if a.cfg.Auth.Mode == authModeOIDC {
		expected = a.cfg.Auth.OIDC.IssuerURL
	}
	return values[0] == expected
}

func (a *Authenticator) principal(
	ctx context.Context,
	token *oauth2.Token,
	nonce string,
) (Principal, map[string]any, error) {
	if a.cfg.Auth.Mode == authModeOIDC {
		return a.oidcPrincipal(ctx, token, nonce)
	}
	return a.oauth2Principal(ctx, token)
}

func (a *Authenticator) oidcPrincipal(
	ctx context.Context,
	token *oauth2.Token,
	nonce string,
) (Principal, map[string]any, error) {
	raw, ok := token.Extra("id_token").(string)
	if !ok {
		return Principal{}, nil, errMissingIDToken
	}
	idToken, err := a.verifier.Verify(ctx, raw)
	if err != nil || idToken.Nonce != nonce {
		return Principal{}, nil, errInvalidIDToken
	}
	var claims map[string]any
	if idToken.Claims(&claims) != nil || !validPrincipalIdentity(idToken.Issuer, idToken.Subject) {
		return Principal{}, nil, errInvalidIdentity
	}
	name, nameOK := claims["name"].(string)
	if !nameOK {
		name = ""
	}
	return Principal{
		Issuer: idToken.Issuer, Subject: idToken.Subject, DisplayName: safeDisplayName(name),
	}, claims, nil
}

func (a *Authenticator) oidcEligibilityClaims(
	ctx context.Context,
	token *oauth2.Token,
	principal Principal,
	idTokenClaims map[string]any,
) (map[string]any, error) {
	source := a.cfg.Auth.OIDC.EligibilityClaimSource
	if source == "" || source == eligibility.ClaimSourceIDToken {
		return idTokenClaims, nil
	}
	defer clear(idTokenClaims)
	if source == eligibility.ClaimSourceAccessToken {
		verified, err := a.accessTokenVerifier.Verify(ctx, token.AccessToken)
		if err != nil || verified.Subject == "" || verified.Subject != principal.Subject {
			return nil, errInvalidIDToken
		}
		claims := map[string]any{}
		if verified.Claims(&claims) != nil {
			return nil, errInvalidIDToken
		}
		return claims, nil
	}
	if source == eligibility.ClaimSourceUserInfo {
		userInfo, err := a.provider.UserInfo(ctx, oauth2.StaticTokenSource(token))
		if err != nil || userInfo.Subject == "" || userInfo.Subject != principal.Subject {
			return nil, errInvalidIdentity
		}
		claims := map[string]any{}
		if userInfo.Claims(&claims) != nil {
			return nil, errInvalidIdentity
		}
		return claims, nil
	}
	return nil, errAuthConfiguration
}

//nolint:gocyclo // OAuth2 identity validation stays linear and fail-closed.
func (a *Authenticator) oauth2Principal(
	ctx context.Context,
	token *oauth2.Token,
) (Principal, map[string]any, error) {
	req, requestErr := http.NewRequestWithContext(ctx, http.MethodGet, a.cfg.Auth.OAuth2.IdentityEndpoint, nil)
	if requestErr != nil {
		return Principal{}, nil, errIdentityLookup
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	req.Header.Set("Accept", jsonContentType)
	response, err := a.client.Do(req)
	req.Header.Del("Authorization")
	if err != nil {
		return Principal{}, nil, errIdentityLookup
	}
	body, responseErr := readIdentityResponse(response)
	if responseErr != nil {
		return Principal{}, nil, errIdentityLookup
	}
	defer clearBytes(body)
	if !json.Valid(body) || rejectDuplicateJSONKeys(body) != nil {
		return Principal{}, nil, errIdentityLookup
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var identity any
	if decoder.Decode(&identity) != nil {
		return Principal{}, nil, errIdentityLookup
	}
	subjectValue, ok := jsonValuePath(identity, a.cfg.Auth.OAuth2.SubjectPath)
	if !ok {
		return Principal{}, nil, errIdentitySubject
	}
	subject, ok := canonicalOAuth2Subject(subjectValue)
	if !ok || !validPrincipalIdentity(a.cfg.Auth.OAuth2.Issuer, subject) ||
		strings.Contains(subject, token.AccessToken) {
		return Principal{}, nil, errIdentitySubject
	}
	display := ""
	if a.cfg.Auth.OAuth2.DisplayNamePath != "" {
		if displayValue, found := jsonValuePath(identity, a.cfg.Auth.OAuth2.DisplayNamePath); found {
			display, ok = displayValue.(string)
			if !ok || !validOAuth2IdentityString(display, 256) || strings.Contains(display, token.AccessToken) {
				return Principal{}, nil, errIdentityDisplay
			}
		}
	}
	claims := map[string]any{"oauth2_subject": subject}
	if object, isObject := identity.(map[string]any); isObject {
		claims = object
	}
	if display != "" {
		claims["oauth2_display_name"] = display
	}
	return Principal{
		Issuer: a.cfg.Auth.OAuth2.Issuer, Subject: subject, DisplayName: safeDisplayName(display),
	}, claims, nil
}

func readIdentityResponse(response *http.Response) ([]byte, error) {
	mediaType, _, mediaErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if response.StatusCode != http.StatusOK || mediaErr != nil || mediaType != jsonContentType {
		_, copyErr := io.Copy(io.Discard, io.LimitReader(response.Body, 64*1024))
		closeErr := response.Body.Close()
		if copyErr != nil {
			return nil, fmt.Errorf("discard identity response: %w", copyErr)
		}
		if closeErr != nil {
			return nil, fmt.Errorf("close identity response: %w", closeErr)
		}
		return nil, errIdentityLookup
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, 64*1024+1))
	closeErr := response.Body.Close()
	if readErr != nil {
		return nil, fmt.Errorf("read identity response: %w", readErr)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("close identity response: %w", closeErr)
	}
	if len(body) > 64*1024 {
		clearBytes(body)
		return nil, errIdentityLookup
	}
	return body, nil
}

func canonicalOAuth2Subject(value any) (string, bool) {
	var subject string
	switch typed := value.(type) {
	case string:
		subject = typed
	case json.Number:
		integer := new(big.Int)
		if _, ok := integer.SetString(typed.String(), 10); !ok {
			return "", false
		}
		subject = integer.String()
	default:
		return "", false
	}
	return subject, validOAuth2IdentityString(subject, 512)
}

func validOAuth2IdentityString(value string, limit int) bool {
	if value == "" || len(value) > limit || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func validPrincipalIdentity(issuer, subject string) bool {
	return issuer != "" && subject != "" && len(issuer) <= 2048 && len(subject) <= 512
}

func safeDisplayName(value string) string {
	if len(value) > 256 || strings.ContainsAny(value, "\r\n") {
		return ""
	}
	return value
}

func jsonValuePath(value any, rawPath string) (any, bool) {
	if rawPath == "" {
		return nil, false
	}
	current := value
	for segment := range strings.SplitSeq(rawPath, ".") {
		object, ok := current.(map[string]any)
		if !ok || segment == "" {
			return nil, false
		}
		current, ok = object[segment]
		if !ok {
			return nil, false
		}
	}
	return current, true
}

func (a *Authenticator) Session(r *http.Request) (Principal, string, time.Time, time.Time, bool) {
	cookie, err := r.Cookie(a.cfg.Auth.Session.CookieName)
	if err != nil {
		return Principal{}, "", time.Time{}, time.Time{}, false
	}
	var id string
	if a.cookies.Decode(a.cfg.Auth.Session.CookieName, cookie.Value, &id) != nil {
		return Principal{}, "", time.Time{}, time.Time{}, false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	s, ok := a.sessions[id]
	now := a.now()
	if !ok || !s.ExpiresAt.After(now) || (a.cfg.Dynamic.Enabled && !s.EligibilityExpiresAt.After(now)) {
		delete(a.sessions, id)
		return Principal{}, "", time.Time{}, time.Time{}, false
	}
	return s.Principal, s.CSRF, s.ExpiresAt, s.EligibilityExpiresAt, true
}

func (a *Authenticator) Logout(w http.ResponseWriter, r *http.Request, csrf string) bool {
	if !sameOrigin(r, a.cfg.PublicOrigin()) ||
		subtle.ConstantTimeCompare([]byte(r.Header.Get(csrfHeader)), []byte(csrf)) != 1 {
		return false
	}
	cookie, err := r.Cookie(a.cfg.Auth.Session.CookieName)
	if err == nil {
		var id string
		if a.cookies.Decode(a.cfg.Auth.Session.CookieName, cookie.Value, &id) == nil {
			a.mu.Lock()
			delete(a.sessions, id)
			a.mu.Unlock()
		}
	}
	http.SetCookie(
		w,
		&http.Cookie{
			Name:     a.cfg.Auth.Session.CookieName,
			Value:    "",
			Path:     a.cfg.Path("/"),
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   -1,
		},
	)
	return true
}

func (a *Authenticator) hasOwnedSlot(p Principal) bool {
	return slices.ContainsFunc(a.cfg.Slots, p.Owns)
}
func (a *Authenticator) admits(p Principal, claims map[string]any) bool {
	if a.cfg.Auth.Eligibility == nil {
		return a.hasOwnedSlot(p)
	}
	return eligibility.Evaluate(*a.cfg.Auth.Eligibility, claims).Allowed
}
func (a *Authenticator) authFailure(w http.ResponseWriter) {
	http.Error(w, "authentication failed", http.StatusUnauthorized)
}
func (a *Authenticator) clearLoginCookie(w http.ResponseWriter) {
	http.SetCookie(
		w,
		&http.Cookie{
			Name:     a.cfg.Auth.Session.CookieName + "_login",
			Value:    "",
			Path:     a.cfg.Path("/oauth2/"),
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   -1,
		},
	)
}
func (a *Authenticator) pruneLocked() {
	now := a.now()
	for id, s := range a.sessions {
		if !s.ExpiresAt.After(now) {
			delete(a.sessions, id)
		}
	}
}

func randomToken(size int) (string, error) {
	raw := make([]byte, size)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate random token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func noRedirectClient(base *http.Client) *http.Client {
	return &http.Client{
		Transport:     base.Transport,
		Timeout:       base.Timeout,
		Jar:           base.Jar,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func sameOrigin(r *http.Request, expected string) bool {
	raw := r.Header.Get("Origin")
	u, err := url.Parse(raw)
	return err == nil && u.Scheme+"://"+u.Host == expected && u.User == nil && u.Path == "" && u.RawQuery == "" &&
		u.Fragment == ""
}
