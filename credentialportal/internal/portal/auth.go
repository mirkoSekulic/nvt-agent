package portal

import (
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
	"mime"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/securecookie"
	"golang.org/x/oauth2"
)

type session struct {
	Principal Principal
	CSRF      string
	ExpiresAt time.Time
}

type loginState struct {
	State    string `json:"state"`
	Verifier string `json:"verifier"`
	Nonce    string `json:"nonce"`
	Expires  int64  `json:"expires"`
}

type Authenticator struct {
	cfg      Config
	oauth    oauth2.Config
	verifier *oidc.IDTokenVerifier
	cookies  *securecookie.SecureCookie
	client   *http.Client
	sessions map[string]session
	mu       sync.Mutex
	now      func() time.Time
}

func NewAuthenticator(ctx context.Context, cfg Config, sessionSecret, clientID, clientSecret string, client *http.Client) (*Authenticator, error) {
	if len(sessionSecret) < 32 || clientSecret == "" {
		return nil, fmt.Errorf("session secret must contain at least 32 bytes and client secret is required")
	}
	if client == nil {
		client = http.DefaultClient
	}
	client = noRedirectClient(client)
	sum := sha512.Sum512([]byte(sessionSecret))
	a := &Authenticator{cfg: cfg, cookies: securecookie.New(sum[:32], sum[32:]), client: client, sessions: map[string]session{}, now: time.Now}
	a.cookies.MaxAge(cfg.Auth.Session.MaxAgeSeconds)
	redirect := cfg.PublicURL + callbackPath(cfg)
	if cfg.Auth.Mode == "oidc" {
		provider, err := oidc.NewProvider(oidc.ClientContext(ctx, client), cfg.Auth.OIDC.IssuerURL)
		if err != nil {
			return nil, fmt.Errorf("discover OIDC provider: %w", err)
		}
		a.verifier = provider.Verifier(&oidc.Config{ClientID: cfg.Auth.OIDC.ClientID})
		endpoint := provider.Endpoint()
		endpoint.AuthStyle = authStyle(cfg.Auth.OIDC.ClientAuthMethod)
		a.oauth = oauth2.Config{ClientID: cfg.Auth.OIDC.ClientID, ClientSecret: clientSecret, Endpoint: endpoint, RedirectURL: redirect, Scopes: uniqueScopes(append([]string{"openid"}, cfg.Auth.OIDC.Scopes...))}
	} else {
		if clientID == "" {
			return nil, fmt.Errorf("OAuth2 client ID is required")
		}
		a.oauth = oauth2.Config{ClientID: clientID, ClientSecret: clientSecret, Endpoint: oauth2.Endpoint{AuthURL: cfg.Auth.OAuth2.AuthorizationURL, TokenURL: cfg.Auth.OAuth2.TokenURL, AuthStyle: authStyle(cfg.Auth.OAuth2.ClientAuthMethod)}, RedirectURL: redirect, Scopes: cfg.Auth.OAuth2.Scopes}
	}
	return a, nil
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
	if cfg.Auth.Mode == "oidc" {
		return cfg.Auth.OIDC.CallbackPath
	}
	return cfg.Auth.OAuth2.CallbackPath
}

func (a *Authenticator) Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet || r.URL.RawQuery != "" {
		http.Error(w, "not found", http.StatusNotFound)
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
	http.SetCookie(w, &http.Cookie{Name: a.cfg.Auth.Session.CookieName + "_login", Value: encoded, Path: a.cfg.Path("/oauth2/"), HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode, MaxAge: 300})
	challenge := sha256.Sum256([]byte(verifier))
	opts := []oauth2.AuthCodeOption{oauth2.SetAuthURLParam("code_challenge", base64.RawURLEncoding.EncodeToString(challenge[:])), oauth2.SetAuthURLParam("code_challenge_method", "S256")}
	if a.cfg.Auth.Mode == "oidc" {
		opts = append(opts, oauth2.SetAuthURLParam("nonce", nonce))
	}
	http.Redirect(w, r, a.oauth.AuthCodeURL(state, opts...), http.StatusFound)
}

func (a *Authenticator) Callback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if len(r.URL.Query()) != 2 || len(r.URL.Query()["state"]) != 1 || len(r.URL.Query()["code"]) != 1 {
		a.authFailure(w)
		return
	}
	cookie, err := r.Cookie(a.cfg.Auth.Session.CookieName + "_login")
	if err != nil {
		a.authFailure(w)
		return
	}
	var login loginState
	if a.cookies.Decode(a.cfg.Auth.Session.CookieName+"_login", cookie.Value, &login) != nil || login.Expires < a.now().Unix() || subtle.ConstantTimeCompare([]byte(login.State), []byte(r.URL.Query().Get("state"))) != 1 {
		a.authFailure(w)
		return
	}
	a.clearLoginCookie(w)
	ctx := context.WithValue(r.Context(), oauth2.HTTPClient, a.client)
	token, err := a.oauth.Exchange(ctx, r.URL.Query().Get("code"), oauth2.SetAuthURLParam("code_verifier", login.Verifier))
	if err != nil {
		a.authFailure(w)
		return
	}
	principal, err := a.principal(ctx, token, login.Nonce)
	token.AccessToken = ""
	token.RefreshToken = ""
	if err != nil || !a.hasOwnedSlot(principal) {
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
	a.sessions[sessionID] = session{Principal: principal, CSRF: csrf, ExpiresAt: a.now().Add(time.Duration(a.cfg.Auth.Session.MaxAgeSeconds) * time.Second)}
	a.mu.Unlock()
	encoded, err := a.cookies.Encode(a.cfg.Auth.Session.CookieName, sessionID)
	if err != nil {
		http.Error(w, "authentication unavailable", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: a.cfg.Auth.Session.CookieName, Value: encoded, Path: a.cfg.Path("/"), HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode, MaxAge: a.cfg.Auth.Session.MaxAgeSeconds})
	http.Redirect(w, r, a.cfg.Path("/"), http.StatusFound)
}

func (a *Authenticator) principal(ctx context.Context, token *oauth2.Token, nonce string) (Principal, error) {
	if a.cfg.Auth.Mode == "oidc" {
		raw, ok := token.Extra("id_token").(string)
		if !ok {
			return Principal{}, errors.New("missing ID token")
		}
		idToken, err := a.verifier.Verify(ctx, raw)
		if err != nil || idToken.Nonce != nonce {
			return Principal{}, errors.New("invalid ID token")
		}
		var claims struct {
			Issuer  string `json:"iss"`
			Subject string `json:"sub"`
			Name    string `json:"name"`
		}
		if idToken.Claims(&claims) != nil || !validPrincipalIdentity(claims.Issuer, claims.Subject) {
			return Principal{}, errors.New("invalid identity")
		}
		return Principal{Issuer: claims.Issuer, Subject: claims.Subject, DisplayName: safeDisplayName(claims.Name)}, nil
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, a.cfg.Auth.OAuth2.IdentityEndpoint, nil)
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	req.Header.Set("Accept", "application/json")
	response, err := a.client.Do(req)
	req.Header.Del("Authorization")
	if err != nil {
		return Principal{}, errors.New("identity lookup failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(response.Body, 64*1024))
		return Principal{}, errors.New("identity lookup failed")
	}
	mediaType, _, mediaErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if mediaErr != nil || mediaType != "application/json" {
		io.Copy(io.Discard, io.LimitReader(response.Body, 64*1024))
		return Principal{}, errors.New("identity lookup failed")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 64*1024+1))
	if err != nil || len(body) > 64*1024 {
		return Principal{}, errors.New("identity lookup failed")
	}
	var identity any
	if !json.Valid(body) || rejectDuplicateJSONKeys(body) != nil || json.Unmarshal(body, &identity) != nil {
		return Principal{}, errors.New("identity lookup failed")
	}
	subject, ok := jsonStringPath(identity, a.cfg.Auth.OAuth2.SubjectPath)
	if !ok || !validPrincipalIdentity(a.cfg.Auth.OAuth2.Issuer, subject) {
		return Principal{}, errors.New("identity subject missing")
	}
	display, _ := jsonStringPath(identity, a.cfg.Auth.OAuth2.DisplayNamePath)
	return Principal{Issuer: a.cfg.Auth.OAuth2.Issuer, Subject: subject, DisplayName: safeDisplayName(display)}, nil
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

func jsonStringPath(value any, rawPath string) (string, bool) {
	if rawPath == "" {
		return "", false
	}
	current := value
	for _, segment := range strings.Split(rawPath, ".") {
		object, ok := current.(map[string]any)
		if !ok || segment == "" {
			return "", false
		}
		current, ok = object[segment]
		if !ok {
			return "", false
		}
	}
	result, ok := current.(string)
	return result, ok
}

func (a *Authenticator) Session(r *http.Request) (Principal, string, bool) {
	cookie, err := r.Cookie(a.cfg.Auth.Session.CookieName)
	if err != nil {
		return Principal{}, "", false
	}
	var id string
	if a.cookies.Decode(a.cfg.Auth.Session.CookieName, cookie.Value, &id) != nil {
		return Principal{}, "", false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	s, ok := a.sessions[id]
	if !ok || !s.ExpiresAt.After(a.now()) {
		delete(a.sessions, id)
		return Principal{}, "", false
	}
	return s.Principal, s.CSRF, true
}

func (a *Authenticator) Logout(w http.ResponseWriter, r *http.Request, csrf string) bool {
	if !sameOrigin(r, a.cfg.PublicOrigin()) || subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(csrf)) != 1 {
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
	http.SetCookie(w, &http.Cookie{Name: a.cfg.Auth.Session.CookieName, Value: "", Path: a.cfg.Path("/"), HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode, MaxAge: -1})
	return true
}

func (a *Authenticator) hasOwnedSlot(p Principal) bool {
	for _, slot := range a.cfg.Slots {
		if p.Owns(slot) {
			return true
		}
	}
	return false
}
func (a *Authenticator) authFailure(w http.ResponseWriter) {
	http.Error(w, "authentication failed", http.StatusUnauthorized)
}
func (a *Authenticator) clearLoginCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: a.cfg.Auth.Session.CookieName + "_login", Value: "", Path: a.cfg.Path("/oauth2/"), HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode, MaxAge: -1})
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
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func noRedirectClient(base *http.Client) *http.Client {
	return &http.Client{Transport: base.Transport, Timeout: base.Timeout, Jar: base.Jar, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
}

func sameOrigin(r *http.Request, expected string) bool {
	raw := r.Header.Get("Origin")
	u, err := url.Parse(raw)
	return err == nil && u.Scheme+"://"+u.Host == expected && u.User == nil && u.Path == "" && u.RawQuery == "" && u.Fragment == ""
}
