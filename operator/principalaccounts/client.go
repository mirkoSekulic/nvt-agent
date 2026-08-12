package principalaccounts

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

const (
	ConfigFileEnv        = "NVT_PRINCIPAL_ACCOUNT_BROKER_CONFIG_FILE"
	assertionAudience    = "nvt.broker.principal-accounts/v1"
	assertionScheme      = "NVT-Principal-v1"
	coordinationAudience = "nvt.broker.principal-account-coordination/v1"
	coordinationScheme   = "NVT-Principal-Coordination-v1"
	maxConfigBytes       = 64 * 1024
	maxCABytes           = 1024 * 1024
	maxKeyBytes          = 4096
	jsonContentType      = "application/json"
)

var (
	ErrNotEnrolled           = errors.New("principal account is not enrolled")
	ErrNotReady              = errors.New("principal credential is not ready")
	ErrNotEligible           = errors.New("principal is not currently eligible")
	ErrUnavailable           = errors.New("principal credential resolution unavailable")
	ErrCoordination          = errors.New("principal account coordination unavailable")
	ErrCoordinationConflict  = errors.New("principal account coordination conflict")
	ErrSwitchRequestNotFound = errors.New("template switch request not found")
	providerIDRE             = regexp.MustCompile(`^dpa_[A-Za-z0-9_-]{32}$`)
)

// Config is the bounded startup-only broker resolution configuration.
type Config struct {
	BaseURL               string              `json:"baseURL"`
	CAFile                string              `json:"caFile"`
	AssertionKeyFile      string              `json:"assertionKeyFile"`
	AssertionTTLSeconds   int                 `json:"assertionTTLSeconds"`
	RequestTimeoutSeconds int                 `json:"requestTimeoutSeconds"`
	MaxResponseBytes      int64               `json:"maxResponseBytes"`
	Version               int                 `json:"version"`
	Coordination          *CoordinationConfig `json:"coordination,omitempty"`
}

type CoordinationConfig struct {
	AssertionKeyFile    string `json:"assertionKeyFile"`
	AssertionTTLSeconds int    `json:"assertionTTLSeconds"`
}

// Principal is the canonical issuer plus immutable subject authorization key.
type Principal struct {
	Issuer  string
	Subject string
}

// Resolution is the exact non-secret broker account generation selected for a run.
type Resolution struct {
	Template           string
	ProviderInstanceID string
	Generation         int64
}

// Reservation is the broker-owned deadline for one serialized operator action.
type Reservation struct {
	ExpiresAt time.Time
}

// Resolver resolves a ready exact-principal broker account.
type Resolver interface {
	Resolve(ctx context.Context, principal Principal) (Resolution, error)
}

// Coordinator serializes dynamic admission with an operator-controlled template switch proof.
type Coordinator interface {
	BeginAdmission(ctx context.Context, principal Principal, operationID string) (Reservation, error)
	EndAdmission(ctx context.Context, principal Principal, operationID string) error
	BeginTemplateSwitch(ctx context.Context, requestID, operationID string) (Principal, Reservation, error)
	CommitTemplateSwitch(ctx context.Context, principal Principal, operationID string) error
	AbortTemplateSwitch(ctx context.Context, principal Principal, operationID string) error
}

// Client is a verified-TLS principal-account broker client.
type Client struct {
	httpClient      *http.Client
	baseURL         *url.URL
	now             func() time.Time
	assertionKey    []byte
	coordinationKey []byte
	assertionTTL    time.Duration
	coordinationTTL time.Duration
	requestTimeout  time.Duration
	maxResponse     int64
}

// CoordinationEnabled reports whether the optional template-switch contract is configured.
func (c *Client) CoordinationEnabled() bool {
	return c != nil && len(c.coordinationKey) >= 32 && c.coordinationTTL > 0
}

// LoadConfigured loads the optional client. An absent environment variable is disabled.
func LoadConfigured() (*Client, error) {
	path := os.Getenv(ConfigFileEnv)
	if path == "" {
		// A nil client is the explicit compatibility state: no optional resolver.
		//nolint:nilnil // Absence is not an error and preserves static startup.
		return nil, nil
	}
	raw, err := readBoundedFile(path, maxConfigBytes)
	if err != nil {
		return nil, fmt.Errorf("read principal account broker config: %w", ErrUnavailable)
	}
	defer clearBytes(raw)
	var cfg Config
	if err := decodeStrictJSON(raw, &cfg); err != nil {
		return nil, fmt.Errorf("decode principal account broker config: %w", ErrUnavailable)
	}
	return New(cfg)
}

// New constructs a verified client from explicit bounded configuration.
func New(cfg Config) (*Client, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	parsed, err := url.Parse(cfg.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse principal account broker URL: %w", ErrUnavailable)
	}
	ca, err := readBoundedFile(cfg.CAFile, maxCABytes)
	if err != nil {
		return nil, fmt.Errorf("read principal account broker CA: %w", ErrUnavailable)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		clearBytes(ca)
		return nil, fmt.Errorf("parse principal account broker CA: %w", ErrUnavailable)
	}
	clearBytes(ca)
	key, err := readBoundedFile(cfg.AssertionKeyFile, maxKeyBytes)
	if err != nil || len(key) < 32 {
		clearBytes(key)
		return nil, fmt.Errorf("read principal account assertion key: %w", ErrUnavailable)
	}
	var coordinationKey []byte
	if cfg.Coordination != nil {
		coordinationKey, err = readBoundedFile(cfg.Coordination.AssertionKeyFile, maxKeyBytes)
		if err != nil || len(coordinationKey) < 32 || hmac.Equal(key, coordinationKey) {
			clearBytes(key)
			clearBytes(coordinationKey)
			return nil, fmt.Errorf("read distinct coordination assertion key: %w", ErrUnavailable)
		}
	}
	transport := &http.Transport{
		Proxy:             http.ProxyFromEnvironment,
		TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots},
		ForceAttemptHTTP2: true,
	}
	return &Client{
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   time.Duration(cfg.RequestTimeoutSeconds) * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		baseURL: parsed, assertionKey: key, coordinationKey: coordinationKey,
		assertionTTL: time.Duration(cfg.AssertionTTLSeconds) * time.Second,
		coordinationTTL: func() time.Duration {
			if cfg.Coordination == nil {
				return 0
			}
			return time.Duration(cfg.Coordination.AssertionTTLSeconds) * time.Second
		}(),
		requestTimeout: time.Duration(cfg.RequestTimeoutSeconds) * time.Second,
		maxResponse:    cfg.MaxResponseBytes, now: time.Now,
	}, nil
}

//nolint:gocyclo // Every bounded startup field is intentionally checked in one fail-closed gate.
func (c Config) validate() error {
	parsed, err := url.Parse(c.BaseURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil ||
		parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" || c.BaseURL != parsed.String() {
		return fmt.Errorf("principal account broker baseURL must be a canonical HTTPS origin: %w", ErrUnavailable)
	}
	if c.Version != 1 || c.CAFile == "" || c.AssertionKeyFile == "" ||
		c.AssertionTTLSeconds < 1 || c.AssertionTTLSeconds > 900 ||
		c.RequestTimeoutSeconds < 1 || c.RequestTimeoutSeconds > 30 ||
		c.MaxResponseBytes < 1024 || c.MaxResponseBytes > 64*1024 {
		return fmt.Errorf("principal account broker config is outside safe bounds: %w", ErrUnavailable)
	}
	if c.Coordination != nil && (c.Coordination.AssertionKeyFile == "" ||
		c.Coordination.AssertionTTLSeconds < 1 || c.Coordination.AssertionTTLSeconds > 300) {
		return fmt.Errorf("principal account coordination config is outside safe bounds: %w", ErrUnavailable)
	}
	return nil
}

// Start owns cleanup for controller-runtime manager lifecycle.
func (c *Client) Start(ctx context.Context) error {
	<-ctx.Done()
	c.Close()
	return nil
}

// Close clears assertion material and closes idle broker connections.
func (c *Client) Close() {
	if c == nil {
		return
	}
	clearBytes(c.assertionKey)
	c.assertionKey = nil
	clearBytes(c.coordinationKey)
	c.coordinationKey = nil
	if transport, ok := c.httpClient.Transport.(*http.Transport); ok {
		transport.CloseIdleConnections()
	}
}

// Resolve checks readiness then resolves the same exact account generation.
//
//nolint:gocyclo,cyclop // The readiness/resolve state matrix is explicit and fail-closed.
func (c *Client) Resolve(ctx context.Context, principal Principal) (Resolution, error) {
	if !validPrincipal(principal) {
		return Resolution{}, ErrUnavailable
	}
	status, body, err := c.request(ctx, "/v1/principal-accounts/readiness", principal)
	if err != nil {
		return Resolution{}, ErrUnavailable
	}
	defer clearBytes(body)
	if status == http.StatusNotFound && brokerReason(body) == "account-not-found" {
		return Resolution{}, ErrNotEnrolled
	}
	if status == http.StatusForbidden && brokerReason(body) == "principal-not-eligible" {
		return Resolution{}, ErrNotEligible
	}
	if status != http.StatusOK {
		return Resolution{}, ErrUnavailable
	}
	var readiness struct {
		State      string `json:"state"`
		Template   string `json:"template"`
		Generation int64  `json:"generation"`
		OK         bool   `json:"ok"`
	}
	if decodeStrictJSON(body, &readiness) != nil || !readiness.OK ||
		readiness.Template == "" || readiness.Generation < 1 {
		return Resolution{}, ErrUnavailable
	}
	switch readiness.State {
	case "revoked":
		return Resolution{}, ErrNotEnrolled
	case "unready":
		return Resolution{}, ErrNotReady
	case "ready":
	default:
		return Resolution{}, ErrUnavailable
	}

	status, resolvedBody, err := c.request(ctx, "/v1/principal-accounts/resolve", principal)
	if err != nil {
		return Resolution{}, ErrUnavailable
	}
	defer clearBytes(resolvedBody)
	if status == http.StatusNotFound && brokerReason(resolvedBody) == "account-not-found" {
		return Resolution{}, ErrNotReady
	}
	if status == http.StatusServiceUnavailable && brokerReason(resolvedBody) == "account-unready" {
		return Resolution{}, ErrNotReady
	}
	if status == http.StatusForbidden && brokerReason(resolvedBody) == "principal-not-eligible" {
		return Resolution{}, ErrNotEligible
	}
	if status != http.StatusOK {
		return Resolution{}, ErrUnavailable
	}
	var resolved struct {
		Template           string `json:"template"`
		ProviderInstanceID string `json:"provider_instance_id"`
		Generation         int64  `json:"generation"`
		OK                 bool   `json:"ok"`
	}
	if decodeStrictJSON(resolvedBody, &resolved) != nil || !resolved.OK ||
		resolved.Template != readiness.Template || resolved.Generation != readiness.Generation ||
		!providerIDRE.MatchString(resolved.ProviderInstanceID) {
		return Resolution{}, ErrUnavailable
	}
	return Resolution{
		Template: resolved.Template, ProviderInstanceID: resolved.ProviderInstanceID,
		Generation: resolved.Generation,
	}, nil
}

func (c *Client) BeginAdmission(
	ctx context.Context,
	principal Principal,
	operationID string,
) (Reservation, error) {
	body, err := json.Marshal(map[string]string{
		"issuer": principal.Issuer, "subject": principal.Subject, "operation_id": operationID,
	})
	if err != nil || !validPrincipal(principal) || !validOperationID(operationID) {
		return Reservation{}, ErrCoordination
	}
	defer clearBytes(body)
	status, response, err := c.coordinationRequest(
		ctx, "/v1/principal-account-coordination/begin-admission", "begin-admission", body,
	)
	defer clearBytes(response)
	if err != nil {
		return Reservation{}, ErrCoordination
	}
	switch {
	case status == http.StatusNotFound && brokerReason(response) == "account-not-found":
		return Reservation{}, ErrNotEnrolled
	case status == http.StatusForbidden && brokerReason(response) == "principal-not-eligible":
		return Reservation{}, ErrNotEligible
	case status == http.StatusConflict && brokerReason(response) == "coordination-conflict":
		return Reservation{}, ErrCoordinationConflict
	}
	var result struct {
		ExpiresAt int64  `json:"expires_at"`
		State     string `json:"state"`
		OK        bool   `json:"ok"`
	}
	if status != http.StatusOK || decodeStrictJSON(response, &result) != nil || !result.OK || result.State != "reserved" {
		return Reservation{}, ErrCoordination
	}
	return c.reservation(result.ExpiresAt)
}

func (c *Client) EndAdmission(ctx context.Context, principal Principal, operationID string) error {
	body, err := json.Marshal(map[string]string{
		"issuer": principal.Issuer, "subject": principal.Subject, "operation_id": operationID,
	})
	if err != nil || !validPrincipal(principal) || !validOperationID(operationID) {
		return ErrCoordination
	}
	defer clearBytes(body)
	return c.coordinationMutation(ctx, "/v1/principal-account-coordination/end-admission", "end-admission", body, "released")
}

func (c *Client) BeginTemplateSwitch(
	ctx context.Context,
	requestID, operationID string,
) (Principal, Reservation, error) {
	body, err := json.Marshal(map[string]string{"request_id": requestID, "operation_id": operationID})
	if err != nil || !validOperationID(requestID) || !validOperationID(operationID) {
		return Principal{}, Reservation{}, ErrCoordination
	}
	defer clearBytes(body)
	status, response, err := c.coordinationRequest(
		ctx, "/v1/principal-account-coordination/begin-template-switch", "begin-template-switch", body,
	)
	defer clearBytes(response)
	if err != nil {
		return Principal{}, Reservation{}, ErrCoordination
	}
	if status == http.StatusNotFound && brokerReason(response) == "switch-request-not-found" {
		return Principal{}, Reservation{}, ErrSwitchRequestNotFound
	}
	if status == http.StatusConflict && brokerReason(response) == "coordination-conflict" {
		return Principal{}, Reservation{}, ErrCoordinationConflict
	}
	var result struct {
		Issuer    string `json:"issuer"`
		Subject   string `json:"subject"`
		ExpiresAt int64  `json:"expires_at"`
		OK        bool   `json:"ok"`
	}
	principal := Principal{}
	if status == http.StatusOK && decodeStrictJSON(response, &result) == nil && result.OK {
		principal = Principal{Issuer: result.Issuer, Subject: result.Subject}
	}
	if !validPrincipal(principal) {
		return Principal{}, Reservation{}, ErrCoordination
	}
	reservation, err := c.reservation(result.ExpiresAt)
	if err != nil {
		return Principal{}, Reservation{}, err
	}
	return principal, reservation, nil
}

func (c *Client) reservation(expiresAt int64) (Reservation, error) {
	deadline := time.Unix(expiresAt, 0)
	now := c.now()
	if !deadline.After(now.Add(time.Second)) || deadline.After(now.Add(5*time.Minute)) {
		return Reservation{}, ErrCoordination
	}
	return Reservation{ExpiresAt: deadline}, nil
}

func (c *Client) CommitTemplateSwitch(ctx context.Context, principal Principal, operationID string) error {
	return c.finishTemplateSwitch(ctx, principal, operationID, true)
}

func (c *Client) AbortTemplateSwitch(ctx context.Context, principal Principal, operationID string) error {
	return c.finishTemplateSwitch(ctx, principal, operationID, false)
}

func (c *Client) finishTemplateSwitch(
	ctx context.Context,
	principal Principal,
	operationID string,
	commit bool,
) error {
	body, err := json.Marshal(map[string]string{
		"issuer": principal.Issuer, "subject": principal.Subject, "operation_id": operationID,
	})
	if err != nil || !validPrincipal(principal) || !validOperationID(operationID) {
		return ErrCoordination
	}
	defer clearBytes(body)
	action, path, expected := "abort-template-switch", "/v1/principal-account-coordination/abort-template-switch", "released"
	if commit {
		action, path, expected = "commit-template-switch", "/v1/principal-account-coordination/commit-template-switch", "authorized"
	}
	return c.coordinationMutation(ctx, path, action, body, expected)
}

func (c *Client) coordinationMutation(
	ctx context.Context,
	path, action string,
	body []byte,
	expectedState string,
) error {
	status, response, err := c.coordinationRequest(ctx, path, action, body)
	defer clearBytes(response)
	if err != nil {
		return ErrCoordination
	}
	if status == http.StatusConflict && brokerReason(response) == "coordination-conflict" {
		return ErrCoordinationConflict
	}
	var result struct {
		State string `json:"state"`
		OK    bool   `json:"ok"`
	}
	if status != http.StatusOK || decodeStrictJSON(response, &result) != nil || !result.OK || result.State != expectedState {
		return ErrCoordination
	}
	return nil
}

func (c *Client) coordinationRequest(
	ctx context.Context,
	path, action string,
	body []byte,
) (int, []byte, error) {
	if len(c.coordinationKey) < 32 || c.coordinationTTL <= 0 {
		return 0, nil, ErrCoordination
	}
	var lastErr error
	for range 2 {
		requestContext, cancel := context.WithTimeout(ctx, c.requestTimeout)
		assertion, err := c.coordinationAssertion(action, body)
		if err != nil {
			cancel()
			return 0, nil, err
		}
		endpoint := *c.baseURL
		endpoint.Path = path
		request, err := http.NewRequestWithContext(requestContext, http.MethodPost, endpoint.String(), bytes.NewReader(body))
		if err == nil {
			request.Header.Set("Authorization", assertion)
			request.Header.Set("Content-Type", jsonContentType)
			request.Header.Set("Accept", jsonContentType)
			var response *http.Response
			response, err = c.httpClient.Do(request)
			request.Header.Del("Authorization")
			if err == nil {
				mediaType, parameters, mediaErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
				responseBody, readErr := io.ReadAll(io.LimitReader(response.Body, c.maxResponse+1))
				closeErr := response.Body.Close()
				cancel()
				if mediaErr == nil && mediaType == jsonContentType && len(parameters) == 0 &&
					readErr == nil && closeErr == nil && int64(len(responseBody)) <= c.maxResponse {
					return response.StatusCode, responseBody, nil
				}
				clearBytes(responseBody)
				err = ErrCoordination
			}
		}
		cancel()
		lastErr = err
		if ctx.Err() != nil {
			break
		}
	}
	return 0, nil, lastErr
}

func (c *Client) coordinationAssertion(action string, body []byte) (string, error) {
	payload, err := json.Marshal(struct {
		Audience   string `json:"audience"`
		BodySHA256 string `json:"body_sha256"`
		ExpiresAt  int64  `json:"expires_at"`
		Operation  string `json:"operation"`
		Version    int    `json:"version"`
	}{
		Audience:   coordinationAudience,
		BodySHA256: fmt.Sprintf("%x", sha256.Sum256(body)),
		ExpiresAt:  c.now().Add(c.coordinationTTL).Unix(), Operation: action, Version: 1,
	})
	if err != nil {
		return "", ErrCoordination
	}
	defer clearBytes(payload)
	mac := hmac.New(sha256.New, c.coordinationKey)
	_, _ = mac.Write(payload)
	signature := mac.Sum(nil)
	defer clearBytes(signature)
	return coordinationScheme + " " + base64.RawURLEncoding.EncodeToString(payload) + "." +
		base64.RawURLEncoding.EncodeToString(signature), nil
}

func validOperationID(value string) bool {
	return value != "" && len(value) <= 128 && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\x00\r\n")
}

func (c *Client) request(ctx context.Context, path string, principal Principal) (int, []byte, error) {
	var lastErr error
	for range 2 {
		status, body, err := c.requestOnce(ctx, path, principal)
		if err == nil {
			return status, body, nil
		}
		clearBytes(body)
		lastErr = err
		if ctx.Err() != nil {
			break
		}
	}
	return 0, nil, lastErr
}

func (c *Client) requestOnce(ctx context.Context, path string, principal Principal) (int, []byte, error) {
	requestContext, cancel := context.WithTimeout(ctx, c.requestTimeout)
	defer cancel()
	assertion, err := c.assertion(principal)
	if err != nil {
		return 0, nil, err
	}
	endpoint := *c.baseURL
	endpoint.Path = path
	request, err := http.NewRequestWithContext(
		requestContext, http.MethodPost, endpoint.String(), bytes.NewReader([]byte("{}")),
	)
	if err != nil {
		return 0, nil, fmt.Errorf("build broker request: %w", err)
	}
	request.Header.Set("Authorization", assertionScheme+" "+assertion)
	request.Header.Set("Content-Type", jsonContentType)
	request.Header.Set("Accept", jsonContentType)
	response, err := c.httpClient.Do(request)
	if err != nil {
		return 0, nil, fmt.Errorf("send broker request: %w", err)
	}
	mediaType, parameters, mediaErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if mediaErr != nil || mediaType != jsonContentType || len(parameters) != 0 {
		if closeErr := response.Body.Close(); closeErr != nil {
			return 0, nil, ErrUnavailable
		}
		return 0, nil, ErrUnavailable
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, c.maxResponse+1))
	closeErr := response.Body.Close()
	if err != nil || closeErr != nil || int64(len(body)) > c.maxResponse {
		clearBytes(body)
		return 0, nil, ErrUnavailable
	}
	return response.StatusCode, body, nil
}

func (c *Client) assertion(principal Principal) (string, error) {
	payload, err := json.Marshal(struct {
		Audience  string `json:"audience"`
		Issuer    string `json:"issuer"`
		Subject   string `json:"subject"`
		ExpiresAt int64  `json:"expires_at"`
		Version   int    `json:"version"`
	}{
		Audience: assertionAudience, ExpiresAt: c.now().Add(c.assertionTTL).Unix(),
		Issuer: principal.Issuer, Subject: principal.Subject, Version: 1,
	})
	if err != nil {
		return "", fmt.Errorf("encode principal assertion: %w", err)
	}
	mac := hmac.New(sha256.New, c.assertionKey)
	_, _ = mac.Write(payload)
	return base64.RawURLEncoding.EncodeToString(payload) + "." +
		base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func validPrincipal(principal Principal) bool {
	if principal.Issuer == "" || len(principal.Issuer) > 2048 ||
		principal.Subject == "" || len(principal.Subject) > 512 ||
		strings.TrimSpace(principal.Issuer) != principal.Issuer ||
		strings.TrimSpace(principal.Subject) != principal.Subject ||
		strings.ContainsAny(principal.Issuer+principal.Subject, "\x00\r\n") {
		return false
	}
	issuer, err := url.Parse(principal.Issuer)
	return err == nil && issuer.Scheme == "https" && issuer.Host != "" && issuer.User == nil &&
		issuer.RawQuery == "" && issuer.Fragment == "" && principal.Issuer == issuer.String()
}

func brokerReason(raw []byte) string {
	var result struct {
		Error   string `json:"error"`
		Message string `json:"message"`
		OK      bool   `json:"ok"`
	}
	if decodeStrictJSON(raw, &result) != nil || result.OK || result.Error == "" || result.Message != result.Error {
		return ""
	}
	return result.Error
}

func decodeStrictJSON(raw []byte, target any) error {
	if len(raw) == 0 || !json.Valid(raw) {
		return ErrUnavailable
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return ErrUnavailable
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return ErrUnavailable
	}
	if duplicateJSONKey(raw) {
		return ErrUnavailable
	}
	return nil
}

// duplicateJSONKey walks all nested JSON containers without materializing a
// second unbounded generic value.
//
//nolint:gocognit // The recursive object/array token state machine is deliberate.
func duplicateJSONKey(raw []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var parse func() bool
	parse = func() bool {
		token, err := decoder.Token()
		if err != nil {
			return true
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return false
		}
		switch delimiter {
		case '{':
			seen := map[string]struct{}{}
			for decoder.More() {
				keyToken, tokenErr := decoder.Token()
				key, valid := keyToken.(string)
				if tokenErr != nil || !valid {
					return true
				}
				if _, exists := seen[key]; exists {
					return true
				}
				seen[key] = struct{}{}
				if parse() {
					return true
				}
			}
		case '[':
			for decoder.More() {
				if parse() {
					return true
				}
			}
		default:
			return true
		}
		_, err = decoder.Token()
		return err != nil
	}
	return parse()
}

func readBoundedFile(path string, maximum int64) ([]byte, error) {
	// Startup paths are administrator-owned projected/configured files. Secret
	// projections are symlinks by design, so an openat no-follow policy would
	// reject the intended Kubernetes mount.
	//nolint:gosec // G304: path is trusted deployment configuration, not request input.
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open configured file: %w", err)
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	closeErr := file.Close()
	if err != nil || closeErr != nil || int64(len(data)) > maximum {
		clearBytes(data)
		return nil, ErrUnavailable
	}
	return data, nil
}

func clearBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
