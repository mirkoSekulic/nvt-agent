// Package nativeegresspublication implements the trusted operator side of the
// native-egress relay's complete target-snapshot control contract.
package nativeegresspublication

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment"
	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment/nativeegress"
)

const (
	EnvironmentConfigFile = "NVT_NATIVE_EGRESS_PUBLICATION_CONFIG_FILE"
	ConfigVersion         = 1
	maxConfigBytes        = 16 << 10
	maxCredentialBytes    = 256
)

var (
	ErrUnavailable = errors.New("native egress target publication is unavailable")
	ErrConflict    = errors.New("native egress target publication conflicts")
	ErrRejected    = errors.New("native egress target publication was rejected")
	dnsNamePattern = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?)*$`)
)

type Config struct {
	BaseURL        string
	ServerName     string
	CAFile         string
	CredentialFile string
	Timeout        time.Duration
}

type configDocument struct {
	Version        int    `json:"version"`
	BaseURL        string `json:"baseURL"`
	ServerName     string `json:"serverName"`
	CAFile         string `json:"caFile"`
	CredentialFile string `json:"credentialFile"`
	TimeoutSeconds int    `json:"timeoutSeconds"`
}

type Interface interface {
	Status(context.Context) (nativeegress.TargetStatus, error)
	Publish(context.Context, nativeegress.TargetSnapshot) (nativeegress.TargetSnapshotAcknowledgement, error)
}

type Client struct {
	baseURL    *url.URL
	credential []byte
	http       *http.Client
	slots      chan struct{}
}

func LoadConfigured() (*Client, error) {
	path := os.Getenv(EnvironmentConfigFile)
	if path == "" {
		return nil, nil
	}
	if !canonicalAbsolutePath(path) {
		return nil, errors.New("native egress publication configuration is invalid")
	}
	data, err := os.ReadFile(path)
	if err != nil || len(data) > maxConfigBytes {
		return nil, errors.New("native egress publication configuration is unavailable")
	}
	defer zero(data)
	var document configDocument
	if guestenrollment.DecodeStrictJSON(data, maxConfigBytes, &document) != nil || document.Version != ConfigVersion {
		return nil, errors.New("native egress publication configuration is invalid")
	}
	return New(Config{
		BaseURL: document.BaseURL, ServerName: document.ServerName, CAFile: document.CAFile,
		CredentialFile: document.CredentialFile, Timeout: time.Duration(document.TimeoutSeconds) * time.Second,
	})
}

func New(config Config) (*Client, error) {
	endpoint, err := url.Parse(config.BaseURL)
	if err != nil || endpoint == nil || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.User != nil || endpoint.Opaque != "" ||
		endpoint.Path != "" || endpoint.RawPath != "" || endpoint.RawQuery != "" || endpoint.ForceQuery || endpoint.Fragment != "" || endpoint.String() != config.BaseURL ||
		endpoint.Hostname() != config.ServerName || !dnsNamePattern.MatchString(config.ServerName) || len(config.ServerName) > 253 ||
		!canonicalAbsolutePath(config.CAFile) || !canonicalAbsolutePath(config.CredentialFile) || config.CAFile == config.CredentialFile ||
		config.Timeout <= 0 || config.Timeout > nativeegress.TargetPublicationTimeout {
		return nil, errors.New("native egress publication configuration is invalid")
	}
	if port := endpoint.Port(); port != "" {
		parsed, parseErr := strconv.Atoi(port)
		if parseErr != nil || parsed < 1 || parsed > 65535 || port != strconv.Itoa(parsed) {
			return nil, errors.New("native egress publication configuration is invalid")
		}
	}
	ca, err := os.ReadFile(config.CAFile)
	if err != nil || len(ca) == 0 || len(ca) > 1<<20 {
		return nil, errors.New("native egress publication CA is unavailable")
	}
	defer zero(ca)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return nil, errors.New("native egress publication CA is invalid")
	}
	credential, err := os.ReadFile(config.CredentialFile)
	if err != nil || len(credential) > maxCredentialBytes || nativeegress.ValidateRelayControlCredential(string(credential)) != nil {
		zero(credential)
		return nil, errors.New("native egress publication credential is unavailable")
	}
	transport := &http.Transport{
		Proxy:             nil,
		TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: config.ServerName},
		ForceAttemptHTTP2: false,
	}
	return &Client{
		baseURL: endpoint, credential: credential,
		http:  &http.Client{Transport: transport, Timeout: config.Timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		slots: make(chan struct{}, nativeegress.MaxTargetPublicationConcurrency),
	}, nil
}

func (client *Client) Status(ctx context.Context) (nativeegress.TargetStatus, error) {
	payload, err := nativeegress.EncodeTargetStatusRequest(nativeegress.TargetStatusRequest{
		ContractVersion: nativeegress.TargetPublicationVersion, Type: nativeegress.TargetPublicationStatusRequest,
	})
	if err != nil {
		return nativeegress.TargetStatus{}, ErrRejected
	}
	body, status, err := client.request(ctx, nativeegress.TargetStatusPath, payload)
	if err != nil {
		return nativeegress.TargetStatus{}, err
	}
	defer zero(body)
	if status != http.StatusOK {
		return nativeegress.TargetStatus{}, classify(status, body)
	}
	result, err := nativeegress.DecodeTargetStatus(body)
	if err != nil {
		return nativeegress.TargetStatus{}, ErrUnavailable
	}
	return result, nil
}

func (client *Client) Publish(ctx context.Context, snapshot nativeegress.TargetSnapshot) (nativeegress.TargetSnapshotAcknowledgement, error) {
	payload, err := nativeegress.EncodeTargetSnapshot(snapshot)
	if err != nil {
		return nativeegress.TargetSnapshotAcknowledgement{}, ErrRejected
	}
	body, status, err := client.request(ctx, nativeegress.TargetSnapshotPath, payload)
	zero(payload)
	if err != nil {
		return nativeegress.TargetSnapshotAcknowledgement{}, err
	}
	defer zero(body)
	if status != http.StatusOK {
		return nativeegress.TargetSnapshotAcknowledgement{}, classify(status, body)
	}
	ack, err := nativeegress.DecodeTargetSnapshotAcknowledgement(body)
	if err != nil || ack.Generation != snapshot.Generation || ack.Digest != snapshot.Digest || ack.TargetCount != len(snapshot.Targets) {
		return nativeegress.TargetSnapshotAcknowledgement{}, ErrUnavailable
	}
	return ack, nil
}

func (client *Client) request(ctx context.Context, path string, payload []byte) ([]byte, int, error) {
	if client == nil || client.baseURL == nil || client.http == nil || len(client.credential) == 0 || cap(client.slots) != nativeegress.MaxTargetPublicationConcurrency {
		return nil, 0, ErrUnavailable
	}
	select {
	case client.slots <- struct{}{}:
		defer func() { <-client.slots }()
	default:
		return nil, 0, ErrUnavailable
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, client.baseURL.ResolveReference(&url.URL{Path: path}).String(), bytes.NewReader(payload))
	if err != nil {
		return nil, 0, ErrUnavailable
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+string(client.credential))
	response, err := client.http.Do(request)
	if err != nil {
		return nil, 0, ErrUnavailable
	}
	defer response.Body.Close()
	if response.Header.Get("Content-Type") != "application/json" {
		return nil, 0, ErrUnavailable
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, nativeegress.MaxTargetPublicationResponseBytes+1))
	if err != nil || len(body) > nativeegress.MaxTargetPublicationResponseBytes {
		zero(body)
		return nil, 0, ErrUnavailable
	}
	return body, response.StatusCode, nil
}

func classify(status int, body []byte) error {
	failure, err := nativeegress.DecodeTargetPublicationFailure(body)
	if err != nil {
		return ErrUnavailable
	}
	if status == http.StatusConflict && failure.Reason == nativeegress.TargetPublicationReasonConflict {
		return ErrConflict
	}
	if (status == http.StatusUnauthorized || status == http.StatusForbidden) && failure.Reason == nativeegress.TargetPublicationReasonDenied {
		return ErrRejected
	}
	if status == http.StatusBadRequest {
		return ErrRejected
	}
	return ErrUnavailable
}

func canonicalAbsolutePath(value string) bool {
	return filepath.IsAbs(value) && filepath.Clean(value) == value && filepath.Dir(value) != value && !strings.ContainsRune(value, 0)
}

func (config Config) String() string   { return "[native egress publication configuration]" }
func (config Config) GoString() string { return "[native egress publication configuration]" }
func (client Client) String() string   { return "[native egress publication client]" }
func (client Client) GoString() string { return "[native egress publication client]" }

func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
