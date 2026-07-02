package gateway

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/securecookie"
	"golang.org/x/oauth2"
)

const (
	authModeOIDC         = "oidc"
	oidcClientSecretPost = "client_secret_post"
	defaultSessionCookie = "nvt_agent_gateway"
	defaultCallbackPath  = "/oauth2/callback"
	defaultSessionMaxAge = 24 * 60 * 60
	loginStateCookie     = "nvt_agent_gateway_login"
)

type Authenticator struct {
	config      Config
	cookieCodec *securecookie.SecureCookie
	oauthConfig *oauth2.Config
	verifier    *oidc.IDTokenVerifier
	now         func() time.Time
}

type sessionCookie struct {
	Subject   string `json:"sub"`
	ExpiresAt int64  `json:"exp"`
}

type loginStateCookieValue struct {
	State        string `json:"state"`
	Nonce        string `json:"nonce"`
	CodeVerifier string `json:"codeVerifier"`
	ReturnURL    string `json:"returnUrl"`
	ExpiresAt    int64  `json:"exp"`
}

type nonceClaims struct {
	Nonce string `json:"nonce"`
}

func NewAuthenticator(ctx context.Context, config Config) (*Authenticator, error) {
	if config.Auth.Mode == "" || config.Auth.Mode == "none" {
		return nil, nil
	}
	if config.Auth.Mode != authModeOIDC {
		return nil, fmt.Errorf("unsupported auth.mode %q", config.Auth.Mode)
	}
	if config.Auth.Session.CookieName == "" {
		config.Auth.Session.CookieName = defaultSessionCookie
	}
	if config.Auth.Session.MaxAgeSeconds == 0 {
		config.Auth.Session.MaxAgeSeconds = defaultSessionMaxAge
	}
	if config.Auth.OIDC.CallbackPath == "" {
		config.Auth.OIDC.CallbackPath = defaultCallbackPath
	}
	if len(config.Auth.OIDC.Scopes) == 0 {
		config.Auth.OIDC.Scopes = []string{oidc.ScopeOpenID, "profile"}
	}
	if config.Auth.OIDC.ClientAuthMethod == "" {
		config.Auth.OIDC.ClientAuthMethod = oidcClientSecretPost
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}
	secret, err := sessionSecretBytes(config.Auth.Session.Secret)
	if err != nil {
		return nil, err
	}
	provider, err := oidc.NewProvider(ctx, config.Auth.OIDC.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("discover OIDC provider: %w", err)
	}
	endpoint := provider.Endpoint()
	endpoint.AuthStyle = oauth2.AuthStyleInParams
	oauthConfig := &oauth2.Config{
		ClientID:     config.Auth.OIDC.ClientID,
		ClientSecret: config.Auth.OIDC.ClientSecret,
		Endpoint:     endpoint,
		Scopes:       config.Auth.OIDC.Scopes,
	}
	issuer := config.Auth.OIDC.IssuerURL
	if config.Auth.OIDC.ValidIssuer != "" {
		issuer = config.Auth.OIDC.ValidIssuer
	}
	verifier := provider.Verifier(&oidc.Config{ClientID: config.Auth.OIDC.ClientID, SkipIssuerCheck: issuer != config.Auth.OIDC.IssuerURL})
	return &Authenticator{
		config:      config,
		cookieCodec: securecookie.New(secret, secret[:32]),
		oauthConfig: oauthConfig,
		verifier:    verifier,
		now:         time.Now,
	}, nil
}

func sessionSecretBytes(raw string) ([]byte, error) {
	for _, decoder := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		decoded, err := decoder.DecodeString(raw)
		if err == nil && len(decoded) >= 32 {
			return decoded, nil
		}
	}
	if len([]byte(raw)) < 32 {
		return nil, fmt.Errorf("auth.session.secret must be at least 32 bytes")
	}
	return []byte(raw), nil
}

func (a *Authenticator) HandlePublic(w http.ResponseWriter, r *http.Request) bool {
	switch r.URL.Path {
	case "/oauth2/login":
		a.handleLogin(w, r)
	case a.config.Auth.OIDC.CallbackPath:
		a.handleCallback(w, r)
	case "/oauth2/logout":
		a.clearCookies(w)
		http.Redirect(w, r, "/", http.StatusFound)
	default:
		return false
	}
	return true
}

func (a *Authenticator) Authorize(w http.ResponseWriter, r *http.Request) bool {
	session, ok := a.readSession(r)
	if ok && session.ExpiresAt > a.now().Unix() {
		return true
	}
	if isBrowserRead(r) {
		loginURL := a.publicBaseURL(r) + "/oauth2/login?return_url=" + url.QueryEscape(a.safeReturnURL(r))
		http.Redirect(w, r, loginURL, http.StatusFound)
		return false
	}
	http.Error(w, "authentication required", http.StatusUnauthorized)
	return false
}

func isBrowserRead(r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	accept := r.Header.Get("Accept")
	return accept == "" || strings.Contains(accept, "text/html") || strings.Contains(accept, "*/*")
}

func (a *Authenticator) handleLogin(w http.ResponseWriter, r *http.Request) {
	returnURL, ok := a.validateReturnURL(r.URL.Query().Get("return_url"), r)
	if !ok {
		http.Error(w, "invalid return_url", http.StatusBadRequest)
		return
	}
	state := randomToken()
	nonce := randomToken()
	verifier := randomToken()
	loginState := loginStateCookieValue{
		State:        state,
		Nonce:        nonce,
		CodeVerifier: verifier,
		ReturnURL:    returnURL,
		ExpiresAt:    a.now().Add(10 * time.Minute).Unix(),
	}
	a.setCookie(w, loginStateCookie, loginState, 10*60)

	options := []oauth2.AuthCodeOption{
		oauth2.S256ChallengeOption(verifier),
		oauth2.SetAuthURLParam("nonce", nonce),
	}
	if a.config.Auth.OIDC.ACRValues != "" {
		options = append(options, oauth2.SetAuthURLParam("acr_values", a.config.Auth.OIDC.ACRValues))
	}
	if a.config.Auth.OIDC.AuthorizationDetails != "" {
		options = append(options, oauth2.SetAuthURLParam("authorization_details", a.config.Auth.OIDC.AuthorizationDetails))
	}
	for key, value := range a.config.Auth.OIDC.ExtraAuthParams {
		options = append(options, oauth2.SetAuthURLParam(key, value))
	}
	http.Redirect(w, r, a.oauthConfigForRequest(r).AuthCodeURL(state, options...), http.StatusFound)
}

func (a *Authenticator) handleCallback(w http.ResponseWriter, r *http.Request) {
	loginState, ok := a.readLoginState(r)
	if !ok || loginState.ExpiresAt <= a.now().Unix() {
		http.Error(w, "login state expired", http.StatusBadRequest)
		return
	}
	if subtle.ConstantTimeCompare([]byte(r.URL.Query().Get("state")), []byte(loginState.State)) != 1 {
		http.Error(w, "invalid state", http.StatusBadRequest)
		return
	}
	token, err := a.oauthConfigForRequest(r).Exchange(
		r.Context(),
		r.URL.Query().Get("code"),
		oauth2.VerifierOption(loginState.CodeVerifier),
	)
	if err != nil {
		http.Error(w, "exchange code", http.StatusBadGateway)
		return
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		http.Error(w, "missing id_token", http.StatusBadGateway)
		return
	}
	idToken, err := a.verifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		http.Error(w, "verify id_token", http.StatusUnauthorized)
		return
	}
	if a.config.Auth.OIDC.ValidIssuer != "" && idToken.Issuer != a.config.Auth.OIDC.ValidIssuer {
		http.Error(w, "invalid issuer", http.StatusUnauthorized)
		return
	}
	var claims nonceClaims
	if err := idToken.Claims(&claims); err != nil {
		http.Error(w, "parse id_token claims", http.StatusUnauthorized)
		return
	}
	if subtle.ConstantTimeCompare([]byte(claims.Nonce), []byte(loginState.Nonce)) != 1 {
		http.Error(w, "invalid nonce", http.StatusUnauthorized)
		return
	}
	a.setCookie(w, a.config.Auth.Session.CookieName, sessionCookie{
		Subject:   idToken.Subject,
		ExpiresAt: a.now().Add(time.Duration(a.config.Auth.Session.MaxAgeSeconds) * time.Second).Unix(),
	}, a.config.Auth.Session.MaxAgeSeconds)
	a.clearCookie(w, loginStateCookie)
	http.Redirect(w, r, loginState.ReturnURL, http.StatusFound)
}

func (a *Authenticator) readSession(r *http.Request) (sessionCookie, bool) {
	var session sessionCookie
	cookie, err := r.Cookie(a.config.Auth.Session.CookieName)
	if err != nil {
		return session, false
	}
	if err := a.cookieCodec.Decode(a.config.Auth.Session.CookieName, cookie.Value, &session); err != nil {
		return session, false
	}
	return session, true
}

func (a *Authenticator) readLoginState(r *http.Request) (loginStateCookieValue, bool) {
	var state loginStateCookieValue
	cookie, err := r.Cookie(loginStateCookie)
	if err != nil {
		return state, false
	}
	if err := a.cookieCodec.Decode(loginStateCookie, cookie.Value, &state); err != nil {
		return state, false
	}
	return state, true
}

func (a *Authenticator) setCookie(w http.ResponseWriter, name string, value any, maxAge int) {
	encoded, err := a.cookieCodec.Encode(name, value)
	if err != nil {
		http.Error(w, "encode cookie", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    encoded,
		Path:     "/",
		Domain:   a.config.Auth.Session.CookieDomain,
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   a.config.Auth.Session.Secure,
		SameSite: http.SameSiteLaxMode,
	})
}

func (a *Authenticator) clearCookies(w http.ResponseWriter) {
	a.clearCookie(w, a.config.Auth.Session.CookieName)
	a.clearCookie(w, loginStateCookie)
}

func (a *Authenticator) clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		Domain:   a.config.Auth.Session.CookieDomain,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   a.config.Auth.Session.Secure,
		SameSite: http.SameSiteLaxMode,
	})
}

func (a *Authenticator) safeReturnURL(r *http.Request) string {
	return a.requestBaseURL(r) + r.URL.RequestURI()
}

func (a *Authenticator) oauthConfigForRequest(r *http.Request) *oauth2.Config {
	config := *a.oauthConfig
	config.RedirectURL = a.publicBaseURL(r) + a.config.Auth.OIDC.CallbackPath
	return &config
}

func (a *Authenticator) publicBaseURL(r *http.Request) string {
	if a.config.PublicURL != "" {
		return strings.TrimRight(a.config.PublicURL, "/")
	}
	return a.requestBaseURL(r)
}

func (a *Authenticator) requestBaseURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if forwardedProto := forwardedHeaderValue(r.Header.Get("X-Forwarded-Proto")); forwardedProto == "https" || forwardedProto == "http" {
		scheme = forwardedProto
	}
	host := r.Host
	if forwardedHost := forwardedHeaderValue(r.Header.Get("X-Forwarded-Host")); forwardedHost != "" {
		host = forwardedHost
	}
	return scheme + "://" + host
}

func forwardedHeaderValue(raw string) string {
	value, _, _ := strings.Cut(raw, ",")
	return strings.TrimSpace(value)
}

func (a *Authenticator) validateReturnURL(raw string, r *http.Request) (string, bool) {
	if raw == "" {
		return "/", true
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", false
	}
	if parsed.IsAbs() {
		host := strings.ToLower(strings.TrimSuffix(stripPort(parsed.Host), "."))
		baseDomain := strings.ToLower(strings.TrimSuffix(a.config.BaseDomain, "."))
		if host != baseDomain && !strings.HasSuffix(host, "."+baseDomain) {
			return "", false
		}
		return parsed.String(), true
	}
	if strings.HasPrefix(raw, "/") && !strings.HasPrefix(raw, "//") {
		return raw, true
	}
	return "", false
}

func randomToken() string {
	randomBytes := make([]byte, 32)
	if _, err := rand.Read(randomBytes); err != nil {
		sum := sha256.Sum256([]byte(time.Now().String()))
		return base64.RawURLEncoding.EncodeToString(sum[:])
	}
	return base64.RawURLEncoding.EncodeToString(randomBytes)
}

// ParseExtraAuthParams parses a JSON object into OIDC authorization request parameters.
func ParseExtraAuthParams(raw string) (map[string]string, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	values := map[string]string{}
	if err := json.Unmarshal([]byte(raw), &values); err != nil {
		return nil, fmt.Errorf("parse OIDC extra auth params: %w", err)
	}
	return values, nil
}

// SplitScopes parses comma-separated OIDC scopes.
func SplitScopes(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	scopes := make([]string, 0, len(parts))
	for _, part := range parts {
		if scope := strings.TrimSpace(part); scope != "" {
			scopes = append(scopes, scope)
		}
	}
	return scopes
}
