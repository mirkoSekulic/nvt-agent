// Package brokerclient implements the trusted operator side of the broker
// guest-enrollment issuer API. It never logs request/response bodies or bearer
// material and exposes no guest exchange operation.
package brokerclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment"
)

const (
	EnvironmentConfigFile = "NVT_GUEST_ENROLLMENT_CONFIG_FILE"
	ConfigVersion         = 1
	maxConfigBytes        = 16 << 10
	maxTokenBytes         = 4096
	maxResponseBytes      = guestenrollment.MaxBootstrapEnvelopeBytes
)

var (
	ErrClosed      = errors.New("guest enrollment broker client is closed")
	ErrUnavailable = errors.New("guest enrollment broker is unavailable")
	ErrRejected    = errors.New("guest enrollment broker rejected the request")
)

type Config struct {
	BaseURL         string        `json:"baseURL"`
	ServerName      string        `json:"serverName"`
	CAFile          string        `json:"caFile"`
	BearerTokenFile string        `json:"bearerTokenFile"`
	RequestTimeout  time.Duration `json:"-"`
	HandoffTimeout  time.Duration `json:"-"`
	TTLSeconds      int32         `json:"ttlSeconds"`
}

type configDocument struct {
	Version         int    `json:"version"`
	BaseURL         string `json:"baseURL"`
	ServerName      string `json:"serverName"`
	CAFile          string `json:"caFile"`
	BearerTokenFile string `json:"bearerTokenFile"`
	RequestTimeout  int32  `json:"requestTimeoutSeconds"`
	HandoffTimeout  int32  `json:"handoffTimeoutSeconds"`
	TTLSeconds      int32  `json:"ttlSeconds"`
}

type Interface interface {
	Issue(context.Context, guestenrollment.IssueRequest) (guestenrollment.BootstrapEnvelope, error)
	RevokeBinding(context.Context, guestenrollment.RevokeBindingRequest) error
	RevokeExecution(context.Context, guestenrollment.RevokeExecutionRequest) error
	Shutdown(context.Context) error
}

type Client struct {
	baseURL *url.URL
	token   []byte
	http    *http.Client
	ttl     int32
	handoff time.Duration

	lifetime context.Context
	cancel   context.CancelFunc
	mu       sync.Mutex
	closed   bool
	active   int
	idle     chan struct{}
}

func LoadConfigured() (*Client, error) {
	path := os.Getenv(EnvironmentConfigFile)
	if path == "" {
		return nil, nil
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("guest enrollment client configuration is invalid")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("guest enrollment client configuration is unavailable")
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxConfigBytes+1))
	if err != nil || len(data) > maxConfigBytes {
		return nil, errors.New("guest enrollment client configuration is invalid")
	}
	var document configDocument
	if guestenrollment.DecodeStrictJSON(data, maxConfigBytes, &document) != nil || document.Version != ConfigVersion {
		return nil, errors.New("guest enrollment client configuration is invalid")
	}
	return New(Config{
		BaseURL: document.BaseURL, ServerName: document.ServerName, CAFile: document.CAFile,
		BearerTokenFile: document.BearerTokenFile, RequestTimeout: time.Duration(document.RequestTimeout) * time.Second,
		HandoffTimeout: time.Duration(document.HandoffTimeout) * time.Second, TTLSeconds: document.TTLSeconds,
	})
}

var serverNamePattern = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?)*$`)
var orchestratorTokenPattern = regexp.MustCompile(`^[A-Za-z0-9._~-]+$`)

func New(config Config) (*Client, error) {
	endpoint, err := url.Parse(config.BaseURL)
	if err != nil || endpoint == nil {
		return nil, errors.New("guest enrollment client configuration is invalid")
	}
	portValid := true
	if port := endpoint.Port(); port != "" {
		value, parseErr := strconv.Atoi(port)
		portValid = parseErr == nil && value >= 1 && value <= 65535
	}
	if len(config.BaseURL) > guestenrollment.MaxExchangeURLBytes || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.User != nil || endpoint.Opaque != "" ||
		endpoint.Path != "" || endpoint.RawPath != "" || endpoint.RawQuery != "" || endpoint.ForceQuery || endpoint.Fragment != "" ||
		len(config.ServerName) > 253 || !serverNamePattern.MatchString(config.ServerName) || !portValid || endpoint.String() != config.BaseURL ||
		!filepath.IsAbs(config.CAFile) || filepath.Clean(config.CAFile) != config.CAFile || !filepath.IsAbs(config.BearerTokenFile) || filepath.Clean(config.BearerTokenFile) != config.BearerTokenFile || config.RequestTimeout <= 0 ||
		config.RequestTimeout > guestenrollment.MaxOperationDuration || config.HandoffTimeout <= 0 || config.HandoffTimeout > guestenrollment.MaxOperationDuration ||
		config.TTLSeconds < 1 || config.TTLSeconds > guestenrollment.MaxEnrollmentTTLSeconds {
		return nil, errors.New("guest enrollment client configuration is invalid")
	}
	ca, err := os.ReadFile(config.CAFile)
	if err != nil {
		return nil, errors.New("guest enrollment broker CA is unavailable")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return nil, errors.New("guest enrollment broker CA is invalid")
	}
	token, err := os.ReadFile(config.BearerTokenFile)
	if err != nil || len(token) < 32 || len(token) > maxTokenBytes || bytes.ContainsAny(token, "\r\n\x00") || !orchestratorTokenPattern.Match(token) {
		return nil, errors.New("guest enrollment orchestrator bearer is unavailable")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: config.ServerName,
	}, ForceAttemptHTTP2: true}
	lifetime, cancel := context.WithCancel(context.Background())
	idle := make(chan struct{})
	close(idle)
	return &Client{
		baseURL: endpoint, token: token, http: &http.Client{Transport: transport, Timeout: config.RequestTimeout}, ttl: config.TTLSeconds, handoff: config.HandoffTimeout,
		lifetime: lifetime, cancel: cancel, idle: idle,
	}, nil
}

func (c *Client) TTLSeconds() int32 { return c.ttl }

func (c *Client) HandoffTimeout() time.Duration { return c.handoff }

func (c *Client) Issue(ctx context.Context, request guestenrollment.IssueRequest) (guestenrollment.BootstrapEnvelope, error) {
	if request.TTLSeconds == 0 {
		request.TTLSeconds = c.ttl
	}
	if guestenrollment.ValidateIssueRequest(request) != nil {
		return guestenrollment.BootstrapEnvelope{}, ErrRejected
	}
	body, status, err := c.request(ctx, "/v1/guest-enrollment/issue", request, guestenrollment.MaxIssueRequestBytes)
	if err != nil {
		return guestenrollment.BootstrapEnvelope{}, err
	}
	defer zero(body)
	if status != http.StatusOK {
		return guestenrollment.BootstrapEnvelope{}, classifyStatus(status)
	}
	envelope, err := guestenrollment.DecodeBootstrapEnvelope(body)
	if err != nil || envelope.Binding != request.Binding {
		return guestenrollment.BootstrapEnvelope{}, ErrUnavailable
	}
	return envelope, nil
}

func (c *Client) RevokeBinding(ctx context.Context, request guestenrollment.RevokeBindingRequest) error {
	if guestenrollment.ValidateRevokeBindingRequest(request) != nil {
		return ErrRejected
	}
	return c.revoke(ctx, "/v1/guest-enrollment/revoke-binding", request)
}

func (c *Client) RevokeExecution(ctx context.Context, request guestenrollment.RevokeExecutionRequest) error {
	if guestenrollment.ValidateRevokeExecutionRequest(request) != nil {
		return ErrRejected
	}
	return c.revoke(ctx, "/v1/guest-enrollment/revoke-execution", request)
}

func (c *Client) revoke(ctx context.Context, path string, request any) error {
	body, status, err := c.request(ctx, path, request, guestenrollment.MaxRevocationRequestBytes)
	if err != nil {
		return err
	}
	defer zero(body)
	if status != http.StatusOK {
		return classifyStatus(status)
	}
	var result struct {
		OK bool `json:"ok"`
	}
	if guestenrollment.DecodeStrictJSON(body, 64, &result) != nil || !result.OK {
		return ErrUnavailable
	}
	return nil
}

func (c *Client) request(ctx context.Context, path string, value any, maximum int) ([]byte, int, error) {
	lifetime, token, done, err := c.begin()
	if err != nil {
		return nil, 0, err
	}
	defer done()
	defer zero(token)
	payload, err := json.Marshal(value)
	if err != nil || len(payload) == 0 || len(payload) > maximum {
		return nil, 0, ErrRejected
	}
	defer zero(payload)
	requestContext, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(lifetime, cancel)
	defer func() { stop(); cancel() }()
	request, err := http.NewRequestWithContext(requestContext, http.MethodPost, c.baseURL.ResolveReference(&url.URL{Path: path}).String(), bytes.NewReader(payload))
	if err != nil {
		return nil, 0, ErrUnavailable
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+string(token))
	response, err := c.http.Do(request)
	if err != nil {
		return nil, 0, ErrUnavailable
	}
	defer response.Body.Close()
	if !strings.HasPrefix(response.Header.Get("Content-Type"), "application/json") {
		return nil, 0, ErrUnavailable
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil || len(body) > maxResponseBytes {
		zero(body)
		return nil, 0, ErrUnavailable
	}
	return body, response.StatusCode, nil
}

func classifyStatus(status int) error {
	if status >= 400 && status < 500 && status != http.StatusRequestTimeout && status != http.StatusTooManyRequests {
		return ErrRejected
	}
	return ErrUnavailable
}

func (c *Client) begin() (context.Context, []byte, func(), error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, nil, nil, ErrClosed
	}
	if c.active == 0 {
		c.idle = make(chan struct{})
	}
	c.active++
	return c.lifetime, append([]byte(nil), c.token...), c.finish, nil
}

func (c *Client) finish() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.active--
	if c.active == 0 {
		close(c.idle)
	}
}

func (c *Client) Shutdown(ctx context.Context) error {
	c.mu.Lock()
	if !c.closed {
		c.closed = true
		c.cancel()
		c.http.CloseIdleConnections()
		zero(c.token)
		c.token = nil
	}
	idle := c.idle
	c.mu.Unlock()
	select {
	case <-idle:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *Client) Start(ctx context.Context) error {
	<-ctx.Done()
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return c.Shutdown(shutdown)
}

func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
