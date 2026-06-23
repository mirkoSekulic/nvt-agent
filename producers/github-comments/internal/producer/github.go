//nolint:err113,inamedparam,wrapcheck,govet // GitHub API errors include response context and token-source interfaces stay minimal.
package producer

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type GitHubIssueComment struct {
	ID        int64      `json:"id"`
	Body      string     `json:"body"`
	HTMLURL   string     `json:"html_url"`
	IssueURL  string     `json:"issue_url"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
	User      GitHubUser `json:"user"`
}

type GitHubIssue struct {
	Number  int        `json:"number"`
	Title   string     `json:"title"`
	Body    string     `json:"body"`
	URL     string     `json:"url"`
	HTMLURL string     `json:"html_url"`
	User    GitHubUser `json:"user"`
	// PullRequest is set by GitHub when an issue resource represents a pull request.
	PullRequest *GitHubPullRequest `json:"pull_request,omitempty"`
}

type GitHubUser struct {
	Login string `json:"login"`
}

type GitHubPullRequest struct {
	URL     string `json:"url,omitempty"`
	HTMLURL string `json:"html_url,omitempty"`
}

type GitHubClient interface {
	ListUpdatedIssueComments(ctx context.Context, repo Repository, since *time.Time) ([]GitHubIssueComment, error)
	GetIssue(ctx context.Context, repo Repository, number int) (GitHubIssue, error)
	ListIssueComments(ctx context.Context, repo Repository, number int) ([]GitHubIssueComment, error)
}

type InstallationTokenSource struct {
	appID          int64
	installationID int64
	privateKey     *rsa.PrivateKey
	apiBaseURL     string
	httpClient     *http.Client
	now            func() time.Time
	mu             sync.Mutex
	cachedToken    string
	expiresAt      time.Time
}

func NewInstallationTokenSource(
	cfg GitHubAppConfig,
	apiBaseURL string,
	httpClient *http.Client,
) (*InstallationTokenSource, error) {
	keyPEM, err := loadPrivateKeyPEM(cfg)
	if err != nil {
		return nil, err
	}
	privateKey, err := parseRSAPrivateKey(keyPEM)
	if err != nil {
		return nil, err
	}
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &InstallationTokenSource{
		appID:          cfg.AppID,
		installationID: cfg.InstallationID,
		privateKey:     privateKey,
		apiBaseURL:     strings.TrimRight(apiBaseURL, "/"),
		httpClient:     httpClient,
		now:            time.Now,
	}, nil
}

func (s *InstallationTokenSource) Token(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cachedToken != "" && s.now().Before(s.expiresAt.Add(-1*time.Minute)) {
		return s.cachedToken, nil
	}
	jwt, err := s.signJWT()
	if err != nil {
		return "", err
	}
	endpoint := fmt.Sprintf("%s/app/installations/%d/access_tokens", s.apiBaseURL, s.installationID)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader([]byte("{}")))
	if err != nil {
		return "", fmt.Errorf("build installation token request: %w", err)
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("Authorization", "Bearer "+jwt)
	request.Header.Set("Content-Type", "application/json")
	response, err := s.httpClient.Do(request)
	if err != nil {
		return "", fmt.Errorf("create installation token: %w", err)
	}
	defer closeBody(response.Body)
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		body, readErr := io.ReadAll(io.LimitReader(response.Body, 4096))
		if readErr != nil {
			body = []byte(readErr.Error())
		}
		return "", fmt.Errorf(
			"create installation token: status %d: %s",
			response.StatusCode,
			strings.TrimSpace(string(body)),
		)
	}
	var decoded struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.NewDecoder(response.Body).Decode(&decoded); err != nil {
		return "", fmt.Errorf("decode installation token: %w", err)
	}
	if decoded.Token == "" {
		return "", errors.New("decode installation token: missing token")
	}
	s.cachedToken = decoded.Token
	s.expiresAt = decoded.ExpiresAt
	return decoded.Token, nil
}

func (s *InstallationTokenSource) signJWT() (string, error) {
	now := s.now()
	header := base64RawJSON(map[string]string{"alg": "RS256", "typ": "JWT"})
	claims := base64RawJSON(map[string]any{
		"iat": now.Add(-1 * time.Minute).Unix(),
		"exp": now.Add(9 * time.Minute).Unix(),
		"iss": strconv.FormatInt(s.appID, 10),
	})
	signingInput := header + "." + claims
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, s.privateKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("sign GitHub App JWT: %w", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

type GitHubAPIClient struct {
	baseURL     string
	userAgent   string
	httpClient  *http.Client
	tokenSource interface {
		Token(context.Context) (string, error)
	}
}

func NewGitHubAPIClient(baseURL, userAgent string, tokenSource interface {
	Token(context.Context) (string, error)
}, httpClient *http.Client) *GitHubAPIClient {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &GitHubAPIClient{
		baseURL:     strings.TrimRight(baseURL, "/"),
		userAgent:   userAgent,
		httpClient:  httpClient,
		tokenSource: tokenSource,
	}
}

func (c *GitHubAPIClient) ListUpdatedIssueComments(
	ctx context.Context,
	repo Repository,
	since *time.Time,
) ([]GitHubIssueComment, error) {
	values := url.Values{}
	values.Set("sort", "updated")
	values.Set("direction", "asc")
	values.Set("per_page", "100")
	if since != nil {
		values.Set("since", since.UTC().Format(time.RFC3339))
	}
	path := fmt.Sprintf("/repos/%s/%s/issues/comments", url.PathEscape(repo.Owner), url.PathEscape(repo.Name))
	return c.getIssueCommentPages(ctx, path, values)
}

func (c *GitHubAPIClient) GetIssue(ctx context.Context, repo Repository, number int) (GitHubIssue, error) {
	var issue GitHubIssue
	path := fmt.Sprintf("/repos/%s/%s/issues/%d", url.PathEscape(repo.Owner), url.PathEscape(repo.Name), number)
	if err := c.getJSON(ctx, path, &issue); err != nil {
		return GitHubIssue{}, err
	}
	return issue, nil
}

func (c *GitHubAPIClient) ListIssueComments(
	ctx context.Context,
	repo Repository,
	number int,
) ([]GitHubIssueComment, error) {
	values := url.Values{}
	values.Set("per_page", "100")
	path := fmt.Sprintf(
		"/repos/%s/%s/issues/%d/comments",
		url.PathEscape(repo.Owner),
		url.PathEscape(repo.Name),
		number,
	)
	return c.getIssueCommentPages(ctx, path, values)
}

func (c *GitHubAPIClient) getIssueCommentPages(
	ctx context.Context,
	path string,
	values url.Values,
) ([]GitHubIssueComment, error) {
	var all []GitHubIssueComment
	for page := 1; ; page++ {
		pageValues := url.Values{}
		for key, entries := range values {
			pageValues[key] = append([]string(nil), entries...)
		}
		pageValues.Set("page", strconv.Itoa(page))
		var comments []GitHubIssueComment
		if err := c.getJSON(ctx, path+"?"+pageValues.Encode(), &comments); err != nil {
			return nil, err
		}
		all = append(all, comments...)
		if len(comments) < 100 {
			return all, nil
		}
	}
}

func (c *GitHubAPIClient) getJSON(ctx context.Context, path string, output any) error {
	token, err := c.tokenSource.Token(ctx)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("X-Github-Api-Version", "2022-11-28")
	if c.userAgent != "" {
		request.Header.Set("User-Agent", c.userAgent)
	}
	response, err := c.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("send github api request: %w", err)
	}
	defer closeBody(response.Body)
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		body, readErr := io.ReadAll(io.LimitReader(response.Body, 4096))
		if readErr != nil {
			body = []byte(readErr.Error())
		}
		return fmt.Errorf("github api %s: status %d: %s", path, response.StatusCode, strings.TrimSpace(string(body)))
	}
	if err := json.NewDecoder(response.Body).Decode(output); err != nil {
		return fmt.Errorf("decode github api %s: %w", path, err)
	}
	return nil
}

func loadPrivateKeyPEM(cfg GitHubAppConfig) ([]byte, error) {
	switch {
	case cfg.PrivateKey != "":
		return []byte(cfg.PrivateKey), nil
	case cfg.PrivateKeyBase64 != "":
		decoded, err := base64.StdEncoding.DecodeString(cfg.PrivateKeyBase64)
		if err != nil {
			return nil, fmt.Errorf("decode github app private key base64: %w", err)
		}
		return decoded, nil
	case cfg.PrivateKeyEnv != "":
		value := os.Getenv(cfg.PrivateKeyEnv)
		if value == "" {
			return nil, fmt.Errorf("github app private key env %s is empty", cfg.PrivateKeyEnv)
		}
		return []byte(value), nil
	case cfg.PrivateKeyBase64Env != "":
		value := os.Getenv(cfg.PrivateKeyBase64Env)
		if value == "" {
			return nil, fmt.Errorf("github app private key base64 env %s is empty", cfg.PrivateKeyBase64Env)
		}
		decoded, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			return nil, fmt.Errorf("decode github app private key base64 env: %w", err)
		}
		return decoded, nil
	case cfg.PrivateKeyPath != "":
		data, err := os.ReadFile(cfg.PrivateKeyPath)
		if err != nil {
			return nil, fmt.Errorf("read github app private key: %w", err)
		}
		return data, nil
	default:
		return nil, errors.New("one github app private key source is required")
	}
}

func parseRSAPrivateKey(data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("decode github app private key PEM")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse github app private key: %w", err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("github app private key must be RSA")
	}
	return key, nil
}

func base64RawJSON(value any) string {
	data, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(data)
}

func closeBody(body io.Closer) {
	if err := body.Close(); err != nil {
		return
	}
}

func IssueNumberFromIssueURL(issueURL string) (int, bool) {
	parts := strings.Split(strings.TrimRight(issueURL, "/"), "/")
	if len(parts) == 0 {
		return 0, false
	}
	number, err := strconv.Atoi(parts[len(parts)-1])
	return number, err == nil && number > 0
}
