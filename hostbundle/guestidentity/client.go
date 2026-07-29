package guestidentity

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment"
)

const (
	connectTimeout        = 5 * time.Second
	tlsHandshakeTimeout   = 5 * time.Second
	responseHeaderTimeout = 5 * time.Second
	overallRequestTimeout = 20 * time.Second
)

type httpDoer interface {
	Do(*http.Request) (*http.Response, error)
}

type Client struct {
	doer    httpDoer
	timeout time.Duration
}

func NewClient(caPEM []byte) (*Client, error) {
	return newClient(caPEM, overallRequestTimeout)
}

func NewClientFromFile(path string) (*Client, error) {
	data, err := readTrustFile(path)
	if err != nil {
		return nil, failure(ReasonTrustInvalid, false, false)
	}
	defer zero(data)
	return NewClient(data)
}

func newClient(caPEM []byte, timeout time.Duration) (*Client, error) {
	if len(caPEM) == 0 || len(caPEM) > 1<<20 || timeout <= 0 || timeout > guestenrollment.MaxOperationDuration {
		return nil, failure(ReasonTrustInvalid, false, false)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, failure(ReasonTrustInvalid, false, false)
	}
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: connectTimeout, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots},
		TLSHandshakeTimeout:   tlsHandshakeTimeout,
		ResponseHeaderTimeout: responseHeaderTimeout,
		ExpectContinueTimeout: 0,
		MaxIdleConns:          4,
		MaxIdleConnsPerHost:   2,
		IdleConnTimeout:       30 * time.Second,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return &Client{doer: client, timeout: timeout}, nil
}

func (client *Client) Exchange(ctx context.Context, envelope guestenrollment.BootstrapEnvelope) (guestenrollment.ExchangeResult, error) {
	if guestenrollment.ValidateBootstrapEnvelope(envelope) != nil {
		return guestenrollment.ExchangeResult{}, failure(ReasonProtocolInvalid, false, false)
	}
	if _, err := brokerURLFromExchange(envelope.ExchangeURL); err != nil {
		return guestenrollment.ExchangeResult{}, failure(ReasonProtocolInvalid, false, false)
	}
	request := guestenrollment.ExchangeRequest{
		ContractVersion: guestenrollment.Version, Binding: envelope.Binding, Token: envelope.Token,
	}
	payload, err := json.Marshal(request)
	if err != nil || len(payload) > guestenrollment.MaxExchangeRequestBytes {
		zero(payload)
		return guestenrollment.ExchangeResult{}, failure(ReasonProtocolInvalid, false, false)
	}
	defer zero(payload)
	body, err := client.post(ctx, envelope.ExchangeURL, "", payload, guestenrollment.MaxExchangeResultBytes, true)
	if err != nil {
		return guestenrollment.ExchangeResult{}, err
	}
	defer zero(body)
	result, err := guestenrollment.DecodeExchangeResult(body)
	if err != nil || result.Binding != envelope.Binding {
		result.RuntimeIdentity.Opaque = ""
		return guestenrollment.ExchangeResult{}, failure(ReasonProtocolInvalid, false, true)
	}
	return result, nil
}

func (client *Client) Status(ctx context.Context, brokerURL, identity string, binding guestenrollment.Binding) (guestenrollment.RuntimeIdentityStatus, error) {
	request := guestenrollment.RuntimeIdentityStatusRequest{ContractVersion: guestenrollment.RuntimeIdentityVersion, Binding: binding}
	if validateBrokerURL(brokerURL) != nil || guestenrollment.ValidateRuntimeIdentityStatusRequest(request) != nil || !validRuntimeIdentity(identity) {
		return guestenrollment.RuntimeIdentityStatus{}, failure(ReasonProtocolInvalid, false, false)
	}
	payload, _ := json.Marshal(request)
	body, err := client.post(ctx, brokerURL+guestenrollment.RuntimeIdentityStatusPath, identity, payload, guestenrollment.MaxRuntimeIdentityResponseBytes, false)
	zero(payload)
	if err != nil {
		return guestenrollment.RuntimeIdentityStatus{}, err
	}
	defer zero(body)
	status, err := guestenrollment.DecodeRuntimeIdentityStatus(body)
	if err != nil || status.Binding != binding {
		return guestenrollment.RuntimeIdentityStatus{}, failure(ReasonProtocolInvalid, false, false)
	}
	return status, nil
}

func (client *Client) Rotate(ctx context.Context, brokerURL, identity, successor string, binding guestenrollment.Binding) (guestenrollment.RuntimeIdentityStatus, error) {
	request := guestenrollment.RuntimeIdentityRotateRequest{
		ContractVersion: guestenrollment.RuntimeIdentityVersion, Binding: binding, Successor: successor,
	}
	if validateBrokerURL(brokerURL) != nil || !validRuntimeIdentity(identity) || guestenrollment.ValidateRuntimeIdentityRotateRequest(request) != nil {
		return guestenrollment.RuntimeIdentityStatus{}, failure(ReasonProtocolInvalid, false, false)
	}
	payload, _ := json.Marshal(request)
	body, err := client.post(ctx, brokerURL+guestenrollment.RuntimeIdentityRotatePath, identity, payload, guestenrollment.MaxRuntimeIdentityResponseBytes, true)
	zero(payload)
	if err != nil {
		return guestenrollment.RuntimeIdentityStatus{}, err
	}
	defer zero(body)
	status, err := guestenrollment.DecodeRuntimeIdentityStatus(body)
	if err != nil || status.Binding != binding {
		return guestenrollment.RuntimeIdentityStatus{}, failure(ReasonProtocolInvalid, false, true)
	}
	return status, nil
}

func (client *Client) IssueGuestSession(ctx context.Context, brokerURL, identity string, binding guestenrollment.Binding) (guestenrollment.GuestSessionIssueResult, error) {
	request := guestenrollment.GuestSessionIssueRequest{
		ContractVersion: guestenrollment.GuestSessionIdentityVersion,
		Binding:         binding,
		Audience:        guestenrollment.NativeGuestControlAudience,
	}
	if validateBrokerURL(brokerURL) != nil || !validRuntimeIdentity(identity) || guestenrollment.ValidateGuestSessionIssueRequest(request) != nil {
		return guestenrollment.GuestSessionIssueResult{}, failure(ReasonProtocolInvalid, false, false)
	}
	payload, _ := json.Marshal(request)
	body, err := client.post(ctx, brokerURL+guestenrollment.GuestSessionIdentityIssuePath, identity, payload, guestenrollment.MaxGuestSessionResponseBytes, true)
	zero(payload)
	if err != nil {
		return guestenrollment.GuestSessionIssueResult{}, err
	}
	defer zero(body)
	result, err := guestenrollment.DecodeGuestSessionIssueResult(body)
	if err != nil || result.Binding != binding {
		result.Credential.Opaque = ""
		return guestenrollment.GuestSessionIssueResult{}, failure(ReasonProtocolInvalid, false, true)
	}
	return result, nil
}

func (client *Client) post(ctx context.Context, endpoint, bearer string, payload []byte, maximum int, mutation bool) ([]byte, error) {
	if ctx == nil || client == nil || client.doer == nil {
		return nil, failure(ReasonProtocolInvalid, false, false)
	}
	requestContext, cancel := context.WithTimeout(ctx, client.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestContext, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, failure(ReasonProtocolInvalid, false, false)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	if bearer != "" {
		request.Header.Set("Authorization", "Bearer "+bearer)
	}
	response, err := client.doer.Do(request)
	if err != nil {
		return nil, failure(ReasonBrokerUnavailable, true, mutation)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, int64(maximum)+1))
		switch response.StatusCode {
		case http.StatusRequestTimeout, http.StatusTooManyRequests:
			return nil, failure(ReasonBrokerUnavailable, true, false)
		case http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
			return nil, failure(ReasonBrokerUnavailable, true, mutation)
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusConflict:
			return nil, failure(ReasonReplacementRequired, false, false)
		default:
			return nil, failure(ReasonProtocolInvalid, false, mutation)
		}
	}
	if response.Header.Get("Content-Type") != "application/json" {
		return nil, failure(ReasonProtocolInvalid, false, mutation)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, int64(maximum)+1))
	if err != nil || len(body) == 0 || len(body) > maximum {
		zero(body)
		return nil, failure(ReasonProtocolInvalid, false, mutation)
	}
	return body, nil
}

func validRuntimeIdentity(value string) bool {
	return guestenrollment.ValidateRuntimeIdentity(value) == nil
}

func readTrustFile(path string) ([]byte, error) {
	ownerUID := uint32(os.Geteuid())
	if !validAbsoluteFile(path) || validateDirectoryAncestors(filepath.Dir(path), ownerUID) != nil {
		return nil, errors.New("trust path is invalid")
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errors.New("trust file is invalid")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > 1<<20 || info.Mode().Perm()&0o022 != 0 {
		return nil, errors.New("trust file is invalid")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != ownerUID || stat.Nlink != 1 {
		return nil, errors.New("trust file is invalid")
	}
	data, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	if err != nil || len(data) == 0 || len(data) > 1<<20 || strings.TrimSpace(string(data)) == "" {
		zero(data)
		return nil, errors.New("trust file is invalid")
	}
	return data, nil
}
