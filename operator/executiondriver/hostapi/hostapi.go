// Package hostapi exposes the topology-neutral execution-driver Client over a
// small authenticated HTTPS service. It never logs request bodies, responses,
// bearer tokens, or driver diagnostics.
package hostapi

import (
	"bytes"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/mirkoSekulic/nvt-agent/operator/executiondriver"
	"github.com/mirkoSekulic/nvt-agent/operator/executiondriver/host"
)

const (
	ProtocolVersion = "nvt.execution-driver-host/v1"
	MaxBodyBytes    = executiondriver.MaxMessageBytes
	maxTokenBytes   = 4096
)

type readiness interface {
	Ready() bool
}

type ServerConfig struct {
	Client           host.Client
	BearerToken      []byte
	OperationTimeout time.Duration
}

type Server struct {
	client           host.Client
	ready            readiness
	bearerToken      []byte
	operationTimeout time.Duration
}

type operationResponse struct {
	ProtocolVersion string                   `json:"protocol_version"`
	Status          *executiondriver.Status  `json:"status,omitempty"`
	Failure         *executiondriver.Failure `json:"failure,omitempty"`
}

type executionRequest struct {
	ExecutionID string `json:"execution_id"`
}

func NewServer(config ServerConfig) (*Server, error) {
	if config.Client == nil || config.OperationTimeout <= 0 || config.OperationTimeout > 10*time.Minute {
		return nil, errors.New("execution driver host server configuration is invalid")
	}
	if err := validateToken(config.BearerToken); err != nil {
		return nil, err
	}
	ready, ok := config.Client.(readiness)
	if !ok {
		return nil, errors.New("execution driver host client does not expose readiness")
	}
	return &Server{client: config.Client, ready: ready, bearerToken: append([]byte(nil), config.BearerToken...), operationTimeout: config.OperationTimeout}, nil
}

func (s *Server) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	switch request.URL.Path {
	case "/healthz":
		if request.Method != http.MethodGet && request.Method != http.MethodHead {
			response.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		response.Header().Set("Cache-Control", "no-store")
		if !s.ready.Ready() {
			response.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		response.WriteHeader(http.StatusOK)
		return
	case "/readyz":
		if request.Method != http.MethodGet && request.Method != http.MethodHead {
			response.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		response.Header().Set("Cache-Control", "no-store")
		if !s.ready.Ready() {
			response.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		response.WriteHeader(http.StatusOK)
		return
	case "/v1/reconcile", "/v1/observe", "/v1/delete":
	default:
		response.WriteHeader(http.StatusNotFound)
		return
	}
	if request.Method != http.MethodPost {
		response.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !s.authenticated(request.Header.Get("Authorization")) {
		response.Header().Set("WWW-Authenticate", "Bearer")
		response.WriteHeader(http.StatusUnauthorized)
		return
	}
	if request.Header.Get("Content-Type") != "application/json" {
		response.WriteHeader(http.StatusUnsupportedMediaType)
		return
	}
	body, err := readBounded(request.Body, MaxBodyBytes)
	if err != nil {
		writeFailure(response, http.StatusRequestEntityTooLarge)
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), s.operationTimeout)
	defer cancel()

	var status executiondriver.Status
	switch request.URL.Path {
	case "/v1/reconcile":
		var desired executiondriver.DesiredExecution
		if executiondriver.DecodeStrictJSON(body, &desired) != nil || executiondriver.ValidateReconcileParams(executiondriver.ReconcileParams{Desired: desired}) != nil {
			writeFailure(response, http.StatusBadRequest)
			return
		}
		status, err = s.client.Reconcile(ctx, desired)
	case "/v1/observe", "/v1/delete":
		var value executionRequest
		if executiondriver.DecodeStrictJSON(body, &value) != nil || executiondriver.ValidateExecutionParams(executiondriver.ExecutionParams{ExecutionID: value.ExecutionID}) != nil {
			writeFailure(response, http.StatusBadRequest)
			return
		}
		if request.URL.Path == "/v1/observe" {
			status, err = s.client.Observe(ctx, value.ExecutionID)
		} else {
			status, err = s.client.Delete(ctx, value.ExecutionID)
		}
	}
	if err != nil {
		var driverError *host.DriverError
		if errors.As(err, &driverError) && executiondriver.ValidateFailure(driverError.Failure) == nil {
			writeJSON(response, http.StatusUnprocessableEntity, operationResponse{ProtocolVersion: ProtocolVersion, Failure: &driverError.Failure})
			return
		}
		writeFailure(response, http.StatusServiceUnavailable)
		return
	}
	if executiondriver.ValidateStatus(status) != nil {
		writeFailure(response, http.StatusServiceUnavailable)
		return
	}
	writeJSON(response, http.StatusOK, operationResponse{ProtocolVersion: ProtocolVersion, Status: &status})
}

func (s *Server) authenticated(header string) bool {
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return false
	}
	provided := []byte(strings.TrimPrefix(header, prefix))
	return len(provided) == len(s.bearerToken) && subtle.ConstantTimeCompare(provided, s.bearerToken) == 1
}

func validateToken(token []byte) error {
	if len(token) < 32 || len(token) > maxTokenBytes || bytes.ContainsAny(token, "\r\n\x00") {
		return errors.New("execution driver host bearer token is invalid")
	}
	return nil
}

func LoadToken(path string) ([]byte, error) {
	value, err := os.ReadFile(path)
	if err != nil || validateToken(value) != nil {
		return nil, errors.New("execution driver host bearer token is unavailable")
	}
	return value, nil
}

func readBounded(reader io.Reader, maximum int64) ([]byte, error) {
	value, err := io.ReadAll(io.LimitReader(reader, maximum+1))
	if err != nil || int64(len(value)) > maximum {
		return nil, errors.New("execution driver host request exceeds its bound")
	}
	return value, nil
}

func writeFailure(response http.ResponseWriter, status int) {
	writeJSON(response, status, map[string]string{"error": "execution driver host request failed"})
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	payload, err := json.Marshal(value)
	if err != nil || len(payload) > MaxBodyBytes {
		response.WriteHeader(http.StatusInternalServerError)
		return
	}
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(status)
	_, _ = response.Write(payload)
}

type ClientConfig struct {
	BaseURL         string
	ServerName      string
	CAFile          string
	BearerTokenFile string
	RequestTimeout  time.Duration
}

type Client struct {
	baseURL        *url.URL
	token          []byte
	httpClient     *http.Client
	lifetime       context.Context
	cancelLifetime context.CancelFunc
	mu             sync.Mutex
	closed         bool
	active         int
	idle           chan struct{}
}

var _ host.Client = (*Client)(nil)

func NewClient(config ClientConfig) (*Client, error) {
	endpoint, err := url.Parse(config.BaseURL)
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.Path != "" || endpoint.RawQuery != "" || endpoint.Fragment != "" || endpoint.User != nil {
		return nil, errors.New("execution driver host endpoint is invalid")
	}
	if config.ServerName == "" || config.RequestTimeout <= 0 || config.RequestTimeout > 10*time.Minute {
		return nil, errors.New("execution driver host client configuration is invalid")
	}
	ca, err := os.ReadFile(config.CAFile)
	if err != nil {
		return nil, errors.New("execution driver host CA is unavailable")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return nil, errors.New("execution driver host CA is invalid")
	}
	token, err := LoadToken(config.BearerTokenFile)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{
		TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: config.ServerName},
		ForceAttemptHTTP2: true,
	}
	lifetime, cancelLifetime := context.WithCancel(context.Background())
	idle := make(chan struct{})
	close(idle)
	return &Client{
		baseURL:        endpoint,
		token:          token,
		httpClient:     &http.Client{Transport: transport, Timeout: config.RequestTimeout},
		lifetime:       lifetime,
		cancelLifetime: cancelLifetime,
		idle:           idle,
	}, nil
}

func (c *Client) Reconcile(ctx context.Context, desired executiondriver.DesiredExecution) (executiondriver.Status, error) {
	if err := executiondriver.ValidateReconcileParams(executiondriver.ReconcileParams{Desired: desired}); err != nil {
		return executiondriver.Status{}, errors.New("execution driver reconcile request is invalid")
	}
	return c.operation(ctx, "/v1/reconcile", desired)
}

func (c *Client) Observe(ctx context.Context, executionID string) (executiondriver.Status, error) {
	return c.executionOperation(ctx, "/v1/observe", executionID)
}

func (c *Client) Delete(ctx context.Context, executionID string) (executiondriver.Status, error) {
	return c.executionOperation(ctx, "/v1/delete", executionID)
}

func (c *Client) executionOperation(ctx context.Context, path, executionID string) (executiondriver.Status, error) {
	if err := executiondriver.ValidateExecutionParams(executiondriver.ExecutionParams{ExecutionID: executionID}); err != nil {
		return executiondriver.Status{}, errors.New("execution driver execution ID is invalid")
	}
	return c.operation(ctx, path, executionRequest{ExecutionID: executionID})
}

func (c *Client) operation(ctx context.Context, path string, value any) (executiondriver.Status, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return executiondriver.Status{}, host.ErrClosed
	}
	if c.active == 0 {
		c.idle = make(chan struct{})
	}
	c.active++
	token := append([]byte(nil), c.token...)
	lifetime := c.lifetime
	c.mu.Unlock()
	defer c.finishOperation()

	requestContext, cancelRequest := context.WithCancel(ctx)
	stopLifetimeCancellation := context.AfterFunc(lifetime, cancelRequest)
	defer func() {
		stopLifetimeCancellation()
		cancelRequest()
	}()
	payload, err := json.Marshal(value)
	if err != nil || len(payload) > MaxBodyBytes {
		return executiondriver.Status{}, errors.New("execution driver host request is invalid")
	}
	endpoint := c.baseURL.ResolveReference(&url.URL{Path: path})
	request, err := http.NewRequestWithContext(requestContext, http.MethodPost, endpoint.String(), bytes.NewReader(payload))
	if err != nil {
		return executiondriver.Status{}, errors.New("execution driver host request could not be created")
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+string(token))
	response, err := c.httpClient.Do(request)
	if err != nil {
		return executiondriver.Status{}, errors.New("execution driver host request failed")
	}
	defer response.Body.Close()
	if response.Header.Get("Content-Type") != "application/json" {
		return executiondriver.Status{}, errors.New("execution driver host response is invalid")
	}
	body, err := readBounded(response.Body, MaxBodyBytes)
	if err != nil {
		return executiondriver.Status{}, errors.New("execution driver host response is invalid")
	}
	var result operationResponse
	if executiondriver.DecodeStrictJSON(body, &result) != nil || result.ProtocolVersion != ProtocolVersion || (result.Status == nil) == (result.Failure == nil) {
		return executiondriver.Status{}, errors.New("execution driver host response is invalid")
	}
	if result.Failure != nil {
		if response.StatusCode != http.StatusUnprocessableEntity || executiondriver.ValidateFailure(*result.Failure) != nil {
			return executiondriver.Status{}, errors.New("execution driver host response is invalid")
		}
		return executiondriver.Status{}, &host.DriverError{Failure: *result.Failure}
	}
	if response.StatusCode != http.StatusOK || validateOperationStatus(path, *result.Status) != nil {
		return executiondriver.Status{}, errors.New("execution driver host response is invalid")
	}
	return *result.Status, nil
}

func (c *Client) finishOperation() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.active--
	if c.active == 0 {
		close(c.idle)
	}
}

func validateOperationStatus(path string, status executiondriver.Status) error {
	switch path {
	case "/v1/reconcile":
		return executiondriver.ValidateReconcileStatus(status)
	case "/v1/observe":
		return executiondriver.ValidateObserveStatus(status)
	case "/v1/delete":
		return executiondriver.ValidateDeleteStatus(status)
	default:
		return errors.New("execution driver host operation is invalid")
	}
}

func (c *Client) Shutdown(ctx context.Context) error {
	c.mu.Lock()
	if !c.closed {
		c.closed = true
		c.cancelLifetime()
		c.httpClient.CloseIdleConnections()
	}
	idle := c.idle
	c.mu.Unlock()
	select {
	case <-idle:
		return nil
	default:
	}
	select {
	case <-idle:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *Client) String() string {
	return fmt.Sprintf("execution-driver-host(%s)", c.baseURL.Host)
}
