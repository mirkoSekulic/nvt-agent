package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"

	"golang.org/x/oauth2"
)

const maxGitHubUserResponseBytes = 64 * 1024

type githubUser struct {
	ID    int64  `json:"id"`
	Login string `json:"login"`
}

func (a *Authenticator) handleGitHubCallback(w http.ResponseWriter, r *http.Request, loginState loginStateCookieValue) {
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
	if token.AccessToken == "" {
		http.Error(w, "missing access token", http.StatusBadGateway)
		return
	}
	defer func() {
		token.AccessToken = ""
		token.RefreshToken = ""
	}()
	user, err := a.fetchGitHubUser(r, token.AccessToken)
	if err != nil {
		http.Error(w, "load GitHub user", http.StatusUnauthorized)
		return
	}
	if user.ID <= 0 {
		http.Error(w, "invalid GitHub user identity", http.StatusUnauthorized)
		return
	}
	principal := Principal{
		Issuer:      a.config.Auth.GitHub.Issuer,
		Subject:     strconv.FormatInt(user.ID, 10),
		DisplayName: user.Login,
		Claims:      map[string]any{"login": user.Login},
	}
	a.finishOAuthLogin(w, r, loginState, token, principal)
}

func (a *Authenticator) fetchGitHubUser(r *http.Request, accessToken string) (githubUser, error) {
	request, err := http.NewRequestWithContext(r.Context(), http.MethodGet, a.config.Auth.GitHub.UserURL, nil)
	if err != nil {
		return githubUser{}, errors.New("build GitHub user request")
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("Authorization", "Bearer "+accessToken)
	request.Header.Set("User-Agent", "nvt-agent-gateway")
	response, err := a.httpClient.Do(request)
	if err != nil {
		return githubUser{}, errors.New("request GitHub user")
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return githubUser{}, errors.New("GitHub user request rejected")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxGitHubUserResponseBytes+1))
	if err != nil || len(body) > maxGitHubUserResponseBytes {
		return githubUser{}, errors.New("read GitHub user response")
	}
	var user githubUser
	if json.Unmarshal(body, &user) != nil {
		return githubUser{}, errors.New("decode GitHub user response")
	}
	return user, nil
}
