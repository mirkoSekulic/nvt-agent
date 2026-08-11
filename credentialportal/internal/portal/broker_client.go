package portal

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
	"net/http"
	"net/url"
	"os"
	"time"
)

const (
	principalAssertionAudience = "nvt.broker.principal-accounts/v1"
	principalAssertionScheme   = "NVT-Principal-v1"
	accountStateNotEnrolled    = "not-enrolled"
	accountStateReady          = "ready"
	accountStateUnready        = "unready"
	brokerMaxRequestBytes      = 1028 * 1024
	maxBrokerKeyBytes          = 4096
	maxBrokerCABytes           = 256 * 1024
)

var (
	ErrBrokerUnavailable = errors.New("credential broker unavailable")
	ErrBrokerRejected    = errors.New("credential broker rejected operation")
)

type DynamicAccountState struct {
	State      string `json:"state"`
	Template   string `json:"template,omitempty"`
	Generation int    `json:"generation,omitempty"`
}

type PrincipalAccountBroker interface {
	Ready(ctx context.Context) error
	Account(ctx context.Context, principal Principal) (DynamicAccountState, error)
	CompleteEnrollment(ctx context.Context, principal Principal, template, operationID string, credential []byte) error
	Reconnect(ctx context.Context, principal Principal, operationID string, credential []byte) error
	Revoke(ctx context.Context, principal Principal, operationID string) error
}

type brokerOperationError struct {
	reason string
}

func (e *brokerOperationError) Error() string { return ErrBrokerRejected.Error() }
func (e *brokerOperationError) Unwrap() error { return ErrBrokerRejected }

//nolint:govet // Security-sensitive transport fields are grouped by purpose.
type HTTPPrincipalAccountBroker struct {
	client         *http.Client
	baseURL        *url.URL
	assertionKey   []byte
	assertionTTL   time.Duration
	requestTimeout time.Duration
	maxResponse    int64
	now            func() time.Time
}

func NewHTTPPrincipalAccountBroker(cfg DynamicBrokerConfig) (*HTTPPrincipalAccountBroker, error) {
	parsed, err := url.Parse(cfg.URL)
	if err != nil || parsed.Scheme != httpsScheme || parsed.Host == "" || parsed.User != nil || parsed.Path != "" ||
		parsed.RawPath != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("configure broker transport: %w", ErrBrokerUnavailable)
	}
	ca, err := readBoundedFile(cfg.CAFile, maxBrokerCABytes)
	if err != nil {
		return nil, fmt.Errorf("read broker CA: %w", ErrBrokerUnavailable)
	}
	defer clearBytes(ca)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return nil, fmt.Errorf("parse broker CA: %w", ErrBrokerUnavailable)
	}
	key, err := readBoundedFile(cfg.AssertionKeyFile, maxBrokerKeyBytes)
	if err != nil || len(key) < 32 {
		clearBytes(key)
		return nil, fmt.Errorf("read broker assertion key: %w", ErrBrokerUnavailable)
	}
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    roots,
		},
		ForceAttemptHTTP2: true,
	}
	return &HTTPPrincipalAccountBroker{
		client: &http.Client{
			Transport: transport,
			Timeout:   time.Duration(cfg.RequestTimeoutSeconds) * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		baseURL: parsed, assertionKey: key,
		assertionTTL:   time.Duration(cfg.AssertionTTLSeconds) * time.Second,
		requestTimeout: time.Duration(cfg.RequestTimeoutSeconds) * time.Second,
		maxResponse:    int64(cfg.MaxResponseBytes), now: time.Now,
	}, nil
}

func (c *HTTPPrincipalAccountBroker) Close() {
	clearBytes(c.assertionKey)
	c.assertionKey = nil
	if transport, ok := c.client.Transport.(*http.Transport); ok {
		transport.CloseIdleConnections()
	}
}

func (c *HTTPPrincipalAccountBroker) Ready(ctx context.Context) error {
	status, body, err := c.request(ctx, http.MethodGet, "/ready", nil, Principal{}, false)
	defer clearBytes(body)
	if err != nil || status != http.StatusOK {
		return ErrBrokerUnavailable
	}
	var response struct { //nolint:govet // Wire-field order mirrors the broker response contract.
		OK     bool   `json:"ok"`
		Status string `json:"status"`
	}
	if !strictBrokerJSON(body, &response) || !response.OK || response.Status != accountStateReady {
		return ErrBrokerUnavailable
	}
	return nil
}

func (c *HTTPPrincipalAccountBroker) Account(
	ctx context.Context,
	principal Principal,
) (DynamicAccountState, error) {
	status, body, err := c.request(
		ctx,
		http.MethodPost,
		"/v1/principal-accounts/readiness",
		[]byte("{}"),
		principal,
		false,
	)
	defer clearBytes(body)
	if err != nil {
		return DynamicAccountState{}, ErrBrokerUnavailable
	}
	if status == http.StatusOK {
		var response struct {
			State      string `json:"state"`
			Template   string `json:"template"`
			Generation int    `json:"generation"`
			OK         bool   `json:"ok"`
		}
		if !strictBrokerJSON(body, &response) || !response.OK ||
			(response.State != accountStateReady && response.State != accountStateUnready &&
				response.State != accountStateRevoked) ||
			response.Template == "" || response.Generation < 1 {
			return DynamicAccountState{}, ErrBrokerUnavailable
		}
		return DynamicAccountState{
			State: response.State, Template: response.Template, Generation: response.Generation,
		}, nil
	}
	reason, ok := strictBrokerError(body)
	if !ok {
		return DynamicAccountState{}, ErrBrokerUnavailable
	}
	if status == http.StatusNotFound && reason == reasonAccountNotFound {
		return DynamicAccountState{State: accountStateNotEnrolled}, nil
	}
	return DynamicAccountState{}, ErrBrokerUnavailable
}

func (c *HTTPPrincipalAccountBroker) CompleteEnrollment(
	ctx context.Context,
	principal Principal,
	template, operationID string,
	credential []byte,
) error {
	body, err := encodeBrokerCredentialRequest(template, operationID, credential)
	if err != nil {
		return ErrBrokerRejected
	}
	defer clearBytes(body)
	return c.mutate(
		ctx, "/v1/principal-accounts/complete-enrollment", body, principal, accountStateReady, true,
	)
}

func (c *HTTPPrincipalAccountBroker) Reconnect(
	ctx context.Context,
	principal Principal,
	operationID string,
	credential []byte,
) error {
	body, err := encodeBrokerCredentialRequest("", operationID, credential)
	if err != nil {
		return ErrBrokerRejected
	}
	defer clearBytes(body)
	return c.mutate(ctx, "/v1/principal-accounts/reconnect", body, principal, accountStateReady, true)
}

func (c *HTTPPrincipalAccountBroker) Revoke(
	ctx context.Context,
	principal Principal,
	operationID string,
) error {
	body, err := json.Marshal(map[string]string{"operation_id": operationID})
	if err != nil {
		return ErrBrokerRejected
	}
	defer clearBytes(body)
	return c.mutate(ctx, "/v1/principal-accounts/revoke", body, principal, accountStateRevoked, true)
}

func (c *HTTPPrincipalAccountBroker) mutate(
	ctx context.Context,
	path string,
	body []byte,
	principal Principal,
	expectedState string,
	retry bool,
) error {
	status, responseBody, err := c.request(ctx, http.MethodPost, path, body, principal, retry)
	defer clearBytes(responseBody)
	if err != nil {
		return ErrBrokerUnavailable
	}
	if status == http.StatusOK {
		var response struct {
			State      string `json:"state"`
			Template   string `json:"template,omitempty"`
			Generation int    `json:"generation,omitempty"`
			OK         bool   `json:"ok"`
		}
		if !strictBrokerJSON(responseBody, &response) || !response.OK || response.State != expectedState ||
			(expectedState == accountStateReady && (response.Template == "" || response.Generation < 1)) ||
			(expectedState == accountStateRevoked && (response.Template != "" || response.Generation != 0)) {
			return ErrBrokerUnavailable
		}
		return nil
	}
	reason, ok := strictBrokerError(responseBody)
	if !ok {
		return ErrBrokerUnavailable
	}
	return &brokerOperationError{reason: reason}
}

func (c *HTTPPrincipalAccountBroker) request(
	ctx context.Context,
	method, path string,
	body []byte,
	principal Principal,
	retry bool,
) (int, []byte, error) {
	attempts := 1
	if retry {
		attempts = 2
	}
	for range attempts {
		status, response, err := c.requestOnce(ctx, method, path, body, principal)
		if err == nil {
			return status, response, nil
		}
		clearBytes(response)
		if ctx.Err() != nil {
			break
		}
	}
	return 0, nil, ErrBrokerUnavailable
}

func (c *HTTPPrincipalAccountBroker) requestOnce(
	ctx context.Context,
	method, requestPath string,
	body []byte,
	principal Principal,
) (int, []byte, error) {
	requestContext, cancel := context.WithTimeout(ctx, c.requestTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(
		requestContext,
		method,
		c.baseURL.String()+requestPath,
		bytes.NewReader(body),
	)
	if err != nil {
		return 0, nil, ErrBrokerUnavailable
	}
	request.Header.Set("Accept", jsonContentType)
	if len(body) != 0 {
		request.Header.Set("Content-Type", jsonContentType)
	}
	if principal.Issuer != "" || principal.Subject != "" {
		assertion, assertionErr := c.assertion(principal)
		if assertionErr != nil {
			return 0, nil, ErrBrokerUnavailable
		}
		request.Header.Set("Authorization", assertion)
	}
	response, err := c.client.Do(request)
	request.Header.Del("Authorization")
	if err != nil {
		return 0, nil, ErrBrokerUnavailable
	}
	defer func() { ignoreCleanupError(response.Body.Close()) }()
	if response.StatusCode >= 300 && response.StatusCode < 400 {
		return 0, nil, ErrBrokerUnavailable
	}
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, c.maxResponse+1))
	if err != nil || int64(len(responseBody)) > c.maxResponse {
		clearBytes(responseBody)
		return 0, nil, ErrBrokerUnavailable
	}
	if mediaType := response.Header.Get("Content-Type"); mediaType != "" && mediaType != jsonContentType {
		clearBytes(responseBody)
		return 0, nil, ErrBrokerUnavailable
	}
	return response.StatusCode, responseBody, nil
}

func (c *HTTPPrincipalAccountBroker) assertion(principal Principal) (string, error) {
	if !validPrincipalIdentity(principal.Issuer, principal.Subject) {
		return "", ErrBrokerUnavailable
	}
	payload, err := json.Marshal(struct { //nolint:govet // Signed field order is stable and reviewable.
		Audience  string `json:"audience"`
		ExpiresAt int64  `json:"expires_at"`
		Issuer    string `json:"issuer"`
		Subject   string `json:"subject"`
		Version   int    `json:"version"`
	}{
		Audience: principalAssertionAudience, ExpiresAt: c.now().Add(c.assertionTTL).Unix(),
		Issuer: principal.Issuer, Subject: principal.Subject, Version: 1,
	})
	if err != nil {
		return "", ErrBrokerUnavailable
	}
	defer clearBytes(payload)
	mac := hmac.New(sha256.New, c.assertionKey)
	_, _ = mac.Write(payload)
	signature := mac.Sum(nil)
	defer clearBytes(signature)
	return principalAssertionScheme + " " + base64.RawURLEncoding.EncodeToString(payload) + "." +
		base64.RawURLEncoding.EncodeToString(signature), nil
}

func encodeBrokerCredentialRequest(template, operationID string, credential []byte) ([]byte, error) {
	if operationID == "" || len(credential) == 0 || len(credential) > maxBrokerCredential {
		return nil, ErrBrokerRejected
	}
	operationJSON, err := json.Marshal(operationID)
	if err != nil {
		return nil, ErrBrokerRejected
	}
	templateJSON, err := json.Marshal(template)
	if err != nil {
		return nil, ErrBrokerRejected
	}
	prefix := []byte(`{"operation_id":`)
	prefix = append(prefix, operationJSON...)
	if template != "" {
		prefix = append(prefix, []byte(`,"template":`)...)
		prefix = append(prefix, templateJSON...)
	}
	prefix = append(prefix, []byte(`,"credential_base64":"`)...)
	encodedLength := base64.StdEncoding.EncodedLen(len(credential))
	body := make([]byte, len(prefix)+encodedLength+2)
	copy(body, prefix)
	base64.StdEncoding.Encode(body[len(prefix):len(prefix)+encodedLength], credential)
	copy(body[len(prefix)+encodedLength:], []byte(`"}`))
	clearBytes(prefix)
	if len(body) > brokerMaxRequestBytes {
		clearBytes(body)
		return nil, ErrBrokerRejected
	}
	return body, nil
}

func strictBrokerError(body []byte) (string, bool) {
	var response struct {
		Error   string `json:"error"`
		Message string `json:"message"`
		OK      bool   `json:"ok"`
	}
	if !strictBrokerJSON(body, &response) || response.OK || response.Error == "" ||
		response.Message != response.Error {
		return "", false
	}
	return response.Error, true
}

func strictBrokerJSON(body []byte, target any) bool {
	if len(body) == 0 || !json.Valid(body) || rejectDuplicateJSONKeys(body) != nil {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	return decoder.Decode(target) == nil && decoder.Decode(&struct{}{}) == io.EOF
}

func readBoundedFile(path string, maximum int64) ([]byte, error) {
	file, err := os.Open(path) // #nosec G304 -- validated administrator-owned read-only Secret/CA path.
	if err != nil {
		return nil, fmt.Errorf("open bounded configuration file: %w", err)
	}
	info, statErr := file.Stat()
	if statErr != nil || !info.Mode().IsRegular() {
		ignoreCleanupError(file.Close())
		return nil, ErrBrokerUnavailable
	}
	body, readErr := io.ReadAll(io.LimitReader(file, maximum+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || len(body) == 0 || int64(len(body)) > maximum {
		clearBytes(body)
		return nil, ErrBrokerUnavailable
	}
	return body, nil
}

func brokerCompletionReason(err error) string {
	if errors.Is(err, ErrBrokerUnavailable) {
		return "broker-unavailable"
	}
	var rejected *brokerOperationError
	if !errors.As(err, &rejected) {
		return "broker-update-failed"
	}
	switch rejected.reason {
	case "account-already-enrolled", "operation-conflict", "template-switch-not-authorized":
		return "account-conflict"
	case reasonAccountNotFound:
		return reasonAccountNotFound
	case "provider-initialization-failed", "unknown-template":
		return "credential-rejected"
	case "unauthorized":
		return "broker-authorization-failed"
	default:
		return "broker-update-failed"
	}
}
