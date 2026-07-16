package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/oauth2"
)

const (
	maxOAuth2IdentityResponseBytes = 64 * 1024
	maxOAuth2SubjectBytes          = 1024
	maxOAuth2DisplayNameBytes      = 1024
	defaultOAuth2IdentityTimeout   = 5 * time.Second
)

func (a *Authenticator) handleOAuth2Callback(w http.ResponseWriter, r *http.Request, loginState loginStateCookieValue) {
	oauthContext := context.WithValue(r.Context(), oauth2.HTTPClient, a.httpClient)
	token, err := a.oauthConfigForRequest(r).Exchange(
		oauthContext,
		r.URL.Query().Get("code"),
		oauth2.VerifierOption(loginState.CodeVerifier),
	)
	if err != nil {
		a.clearCookie(w, loginStateCookie)
		http.Error(w, "login unavailable", http.StatusBadGateway)
		return
	}
	defer func() {
		token.AccessToken = ""
		token.RefreshToken = ""
	}()
	if token.AccessToken == "" {
		a.clearCookie(w, loginStateCookie)
		http.Error(w, "login unavailable", http.StatusBadGateway)
		return
	}
	timeout := a.oauth2IdentityTimeout
	if timeout <= 0 {
		timeout = defaultOAuth2IdentityTimeout
	}
	identityContext, cancel := context.WithTimeout(r.Context(), timeout)
	principal, err := a.fetchOAuth2Identity(identityContext, token.AccessToken)
	cancel()
	if err != nil {
		a.clearCookie(w, loginStateCookie)
		http.Error(w, "login unavailable", http.StatusUnauthorized)
		return
	}
	a.finishOAuthLogin(w, r, loginState, token, principal)
}

func (a *Authenticator) fetchOAuth2Identity(ctx context.Context, accessToken string) (Principal, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, a.config.Auth.OAuth2.Identity.Endpoint, nil)
	if err != nil {
		return Principal{}, errors.New("build OAuth2 identity request")
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+accessToken)
	request.Header.Set("User-Agent", "nvt-agent-gateway")
	response, err := a.httpClient.Do(request)
	if err != nil {
		return Principal{}, errors.New("request OAuth2 identity")
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return Principal{}, errors.New("OAuth2 identity request rejected")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxOAuth2IdentityResponseBytes+1))
	if err != nil || len(body) > maxOAuth2IdentityResponseBytes {
		return Principal{}, errors.New("read OAuth2 identity response")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var document map[string]any
	if err := decoder.Decode(&document); err != nil || document == nil {
		return Principal{}, errors.New("decode OAuth2 identity response")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Principal{}, errors.New("decode OAuth2 identity response")
	}
	subjectValues := selectClaimValues(document, a.config.Auth.OAuth2.Identity.SubjectPath)
	if len(subjectValues) != 1 {
		return Principal{}, errors.New("OAuth2 identity subject is missing or ambiguous")
	}
	subject, ok := canonicalOAuth2Subject(subjectValues[0])
	if !ok || strings.Contains(subject, accessToken) {
		return Principal{}, errors.New("OAuth2 identity subject is invalid")
	}
	displayName := ""
	if path := a.config.Auth.OAuth2.Identity.DisplayNamePath; path != "" {
		values := selectClaimValues(document, path)
		if len(values) > 1 {
			return Principal{}, errors.New("OAuth2 identity display name is ambiguous")
		}
		if len(values) == 1 {
			displayName, ok = oauth2DisplayName(values[0])
			if !ok || strings.Contains(displayName, accessToken) {
				return Principal{}, errors.New("OAuth2 identity display name is invalid")
			}
		}
	}
	claims := map[string]any{"oauth2_subject": subject}
	if displayName != "" {
		claims["oauth2_display_name"] = displayName
	}
	return Principal{Issuer: a.config.Auth.OAuth2.Issuer, Subject: subject, DisplayName: displayName, Claims: claims}, nil
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
	return subject, validOAuth2IdentityString(subject, maxOAuth2SubjectBytes)
}

func oauth2DisplayName(value any) (string, bool) {
	displayName, ok := value.(string)
	if !ok {
		return "", false
	}
	return displayName, validOAuth2IdentityString(displayName, maxOAuth2DisplayNameBytes)
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
