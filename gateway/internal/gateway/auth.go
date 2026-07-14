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
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/securecookie"
	"golang.org/x/oauth2"
)

const (
	authModeNone          = "none"
	authModeOIDC          = "oidc"
	authModeGitHub        = "github"
	oidcClientSecretPost  = "client_secret_post"
	defaultSessionCookie  = "nvt_agent_gateway"
	defaultCallbackPath   = "/oauth2/callback"
	defaultGitHubIssuer   = "https://github.com"
	defaultGitHubAuthURL  = "https://github.com/login/oauth/authorize"
	defaultGitHubTokenURL = "https://github.com/login/oauth/access_token"
	defaultGitHubUserURL  = "https://api.github.com/user"
	defaultSessionMaxAge  = 24 * 60 * 60
	loginStateCookie      = "nvt_agent_gateway_login"
)

type Authenticator struct {
	config        Config
	cookieCodec   *securecookie.SecureCookie
	oauthConfig   *oauth2.Config
	verifier      *oidc.IDTokenVerifier
	tokenVerifier *oidc.IDTokenVerifier
	provider      *oidc.Provider
	httpClient    *http.Client
	sessions      map[string]storedSession
	mu            sync.Mutex
	now           func() time.Time
}

type sessionCookie struct {
	ID        string `json:"sid"`
	ExpiresAt int64  `json:"exp"`
}

type storedSession struct {
	Principal Principal
	ExpiresAt int64
}

type loginStateCookieValue struct {
	State        string `json:"state"`
	Nonce        string `json:"nonce"`
	CodeVerifier string `json:"codeVerifier"`
	ReturnURL    string `json:"returnUrl"`
	ExpiresAt    int64  `json:"exp"`
}

func NewAuthenticator(ctx context.Context, config Config) (*Authenticator, error) {
	if config.Auth.Mode == "" || config.Auth.Mode == authModeNone {
		return nil, nil
	}
	if config.Auth.Mode != authModeOIDC && config.Auth.Mode != authModeGitHub {
		return nil, fmt.Errorf("unsupported auth.mode %q", config.Auth.Mode)
	}
	if config.Auth.Session.CookieName == "" {
		config.Auth.Session.CookieName = defaultSessionCookie
	}
	if config.Auth.Session.MaxAgeSeconds == 0 {
		config.Auth.Session.MaxAgeSeconds = defaultSessionMaxAge
	}
	if config.Auth.Mode == authModeOIDC {
		if config.Auth.OIDC.CallbackPath == "" {
			config.Auth.OIDC.CallbackPath = defaultCallbackPath
		}
		if len(config.Auth.OIDC.Scopes) == 0 {
			config.Auth.OIDC.Scopes = []string{oidc.ScopeOpenID, "profile"}
		}
		if config.Auth.OIDC.ClientAuthMethod == "" {
			config.Auth.OIDC.ClientAuthMethod = oidcClientSecretPost
		}
	} else {
		applyGitHubDefaults(&config.Auth.GitHub)
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}
	secret, err := sessionSecretBytes(config.Auth.Session.Secret)
	if err != nil {
		return nil, err
	}
	authenticator := &Authenticator{
		config:      config,
		cookieCodec: securecookie.New(secret, secret[:32]),
		sessions:    map[string]storedSession{},
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		now: time.Now,
	}
	if config.Auth.Mode == authModeGitHub {
		authenticator.oauthConfig = &oauth2.Config{
			ClientID: config.Auth.GitHub.ClientID, ClientSecret: config.Auth.GitHub.ClientSecret,
			Endpoint: oauth2.Endpoint{AuthURL: config.Auth.GitHub.AuthorizationURL, TokenURL: config.Auth.GitHub.TokenURL, AuthStyle: oauth2.AuthStyleInParams},
		}
		return authenticator, nil
	}
	provider, err := oidc.NewProvider(ctx, config.Auth.OIDC.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("discover OIDC provider: %w", err)
	}
	endpoint := provider.Endpoint()
	endpoint.AuthStyle = oauth2.AuthStyleInParams
	authenticator.oauthConfig = &oauth2.Config{ClientID: config.Auth.OIDC.ClientID, ClientSecret: config.Auth.OIDC.ClientSecret, Endpoint: endpoint, Scopes: config.Auth.OIDC.Scopes}
	issuer := config.Auth.OIDC.IssuerURL
	if config.Auth.OIDC.ValidIssuer != "" {
		issuer = config.Auth.OIDC.ValidIssuer
	}
	authenticator.verifier = provider.Verifier(&oidc.Config{ClientID: config.Auth.OIDC.ClientID, SkipIssuerCheck: issuer != config.Auth.OIDC.IssuerURL})
	authenticator.tokenVerifier = provider.Verifier(&oidc.Config{SkipClientIDCheck: true, SkipIssuerCheck: issuer != config.Auth.OIDC.IssuerURL})
	authenticator.provider = provider
	return authenticator, nil
}

func applyGitHubDefaults(config *GitHubConfig) {
	if config.CallbackPath == "" {
		config.CallbackPath = defaultCallbackPath
	}
	if config.Issuer == "" {
		config.Issuer = defaultGitHubIssuer
	} else {
		config.Issuer = strings.TrimRight(config.Issuer, "/")
	}
	if config.AuthorizationURL == "" {
		config.AuthorizationURL = defaultGitHubAuthURL
	}
	if config.TokenURL == "" {
		config.TokenURL = defaultGitHubTokenURL
	}
	if config.UserURL == "" {
		config.UserURL = defaultGitHubUserURL
	}
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
	case a.callbackPath():
		a.handleCallback(w, r)
	case "/oauth2/logout":
		a.clearCookies(w)
		http.Redirect(w, r, "/", http.StatusFound)
	default:
		return false
	}
	return true
}

func (a *Authenticator) Authenticate(w http.ResponseWriter, r *http.Request) (Principal, bool) {
	session, ok := a.readSession(r)
	if ok && session.ExpiresAt > a.now().Unix() {
		stored, ok := a.lookupSession(session)
		if !ok {
			http.Error(w, "forbidden", http.StatusForbidden)
			return Principal{}, false
		}
		return stored.Principal, true
	}
	if isBrowserRead(r) {
		loginURL := a.publicBaseURL(r) + "/oauth2/login?return_url=" + url.QueryEscape(a.safeReturnURL(r))
		http.Redirect(w, r, loginURL, http.StatusFound)
		return Principal{}, false
	}
	http.Error(w, "authentication required", http.StatusUnauthorized)
	return Principal{}, false
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
	}
	if a.config.Auth.Mode == authModeOIDC {
		options = append(options, oauth2.SetAuthURLParam("nonce", nonce))
	}
	if a.config.Auth.Mode == authModeOIDC && a.config.Auth.OIDC.ACRValues != "" {
		options = append(options, oauth2.SetAuthURLParam("acr_values", a.config.Auth.OIDC.ACRValues))
	}
	if a.config.Auth.Mode == authModeOIDC && a.config.Auth.OIDC.AuthorizationDetails != "" {
		options = append(options, oauth2.SetAuthURLParam("authorization_details", a.config.Auth.OIDC.AuthorizationDetails))
	}
	if a.config.Auth.Mode == authModeOIDC {
		for key, value := range a.config.Auth.OIDC.ExtraAuthParams {
			options = append(options, oauth2.SetAuthURLParam(key, value))
		}
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
	if a.config.Auth.Mode == authModeGitHub {
		a.handleGitHubCallback(w, r, loginState)
		return
	}
	a.handleOIDCCallback(w, r, loginState)
}

func (a *Authenticator) handleOIDCCallback(w http.ResponseWriter, r *http.Request, loginState loginStateCookieValue) {
	oauthContext := context.WithValue(r.Context(), oauth2.HTTPClient, a.httpClient)
	token, err := a.oauthConfigForRequest(r).Exchange(
		oauthContext,
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
	var idClaims map[string]any
	if err := idToken.Claims(&idClaims); err != nil {
		http.Error(w, "parse id_token claims", http.StatusUnauthorized)
		return
	}
	nonce, _ := idClaims["nonce"].(string)
	if subtle.ConstantTimeCompare([]byte(nonce), []byte(loginState.Nonce)) != 1 {
		http.Error(w, "invalid nonce", http.StatusUnauthorized)
		return
	}
	claims, err := a.authorizationClaims(r.Context(), token, idToken, idClaims)
	if err != nil {
		http.Error(w, "load authorization claims", http.StatusUnauthorized)
		return
	}
	issuer := idToken.Issuer
	if a.config.Auth.OIDC.ValidIssuer != "" {
		issuer = a.config.Auth.OIDC.ValidIssuer
	}
	displayName, _ := idClaims["name"].(string)
	if displayName == "" {
		displayName, _ = idClaims["preferred_username"].(string)
	}
	a.finishLogin(w, r, loginState, Principal{Issuer: issuer, Subject: idToken.Subject, DisplayName: displayName, Claims: stripSensitiveClaims(claims)})
}

func (a *Authenticator) finishLogin(w http.ResponseWriter, r *http.Request, loginState loginStateCookieValue, principal Principal) {
	if strings.TrimSpace(principal.Issuer) == "" || strings.TrimSpace(principal.Subject) == "" {
		http.Error(w, "invalid authenticated principal", http.StatusUnauthorized)
		return
	}
	principal.Claims = stripSensitiveClaims(principal.Claims)
	sessionID := randomToken()
	expiresAt := a.now().Add(time.Duration(a.config.Auth.Session.MaxAgeSeconds) * time.Second).Unix()
	a.storeSession(sessionID, storedSession{Principal: principal, ExpiresAt: expiresAt})
	a.setCookie(w, a.config.Auth.Session.CookieName, sessionCookie{
		ID:        sessionID,
		ExpiresAt: expiresAt,
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

func (a *Authenticator) storeSession(id string, session storedSession) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now().Unix()
	for existingID, existing := range a.sessions {
		if existing.ExpiresAt <= now {
			delete(a.sessions, existingID)
		}
	}
	a.sessions[id] = session
}

func (a *Authenticator) lookupSession(cookie sessionCookie) (storedSession, bool) {
	if cookie.ID == "" {
		return storedSession{}, false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	session, ok := a.sessions[cookie.ID]
	if !ok || session.ExpiresAt != cookie.ExpiresAt || session.ExpiresAt <= a.now().Unix() {
		return storedSession{}, false
	}
	return session, true
}

func (a *Authenticator) authorizationClaims(ctx context.Context, token *oauth2.Token, idToken *oidc.IDToken, idClaims map[string]any) (map[string]any, error) {
	claimSource := a.config.Auth.Authorization.ClaimSource
	if claimSource == "" {
		claimSource = claimSourceIDToken
	}
	switch claimSource {
	case claimSourceIDToken:
		return idClaims, nil
	case claimSourceAccessToken:
		rawAccessToken := token.AccessToken
		if rawAccessToken == "" || strings.Count(rawAccessToken, ".") != 2 {
			return nil, fmt.Errorf("access_token claim source requires a JWT access token")
		}
		accessToken, err := a.tokenVerifier.Verify(ctx, rawAccessToken)
		if err != nil {
			return nil, fmt.Errorf("verify access_token JWT: %w", err)
		}
		if a.config.Auth.OIDC.ValidIssuer != "" && accessToken.Issuer != a.config.Auth.OIDC.ValidIssuer {
			return nil, fmt.Errorf("invalid access_token issuer")
		}
		var claims map[string]any
		if err := accessToken.Claims(&claims); err != nil {
			return nil, fmt.Errorf("parse access_token claims: %w", err)
		}
		return claims, nil
	case claimSourceUserInfo:
		userInfo, err := a.provider.UserInfo(ctx, oauth2.StaticTokenSource(token))
		if err != nil {
			return nil, fmt.Errorf("fetch userinfo: %w", err)
		}
		var claims map[string]any
		if err := userInfo.Claims(&claims); err != nil {
			return nil, fmt.Errorf("parse userinfo claims: %w", err)
		}
		return claims, nil
	default:
		return nil, fmt.Errorf("unsupported authorization claim source %q", claimSource)
	}
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
	config.RedirectURL = a.publicBaseURL(r) + a.callbackPath()
	return &config
}

func (a *Authenticator) callbackPath() string {
	if a.config.Auth.Mode == authModeGitHub {
		return a.config.Auth.GitHub.CallbackPath
	}
	return a.config.Auth.OIDC.CallbackPath
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

// ParseAuthorizationConfig parses the gateway authorization policy.
func ParseAuthorizationConfig(raw string) (AuthorizationConfig, error) {
	if strings.TrimSpace(raw) == "" {
		return AuthorizationConfig{}, nil
	}
	var config AuthorizationConfig
	if err := json.Unmarshal([]byte(raw), &config); err != nil {
		return AuthorizationConfig{}, fmt.Errorf("parse gateway authorization policy: %w", err)
	}
	return config, nil
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
