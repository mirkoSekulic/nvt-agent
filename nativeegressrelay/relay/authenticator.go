package relay

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
	"time"

	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment"
	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment/nativeegress"
)

// BrokerAuthenticator performs the strict purpose-separated broker
// authentication. It retains only explicit trust configuration, never a guest
// credential.
type BrokerAuthenticator struct {
	baseURL string
	client  *http.Client
	now     func() time.Time
}

func NewBrokerAuthenticator(config Configuration) (*BrokerAuthenticator, error) {
	if config.validate() != nil {
		return nil, errors.New("native egress broker authentication configuration is invalid")
	}
	caPEM, err := readProcessOwnedFile(config.BrokerCAFile, maxTrustFileBytes, false)
	if err != nil {
		return nil, errors.New("native egress broker trust is invalid")
	}
	defer zero(caPEM)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("native egress broker trust is invalid")
	}
	timeout := time.Duration(config.AuthenticationTimeoutSeconds) * time.Second
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: config.BrokerServerName},
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		ExpectContinueTimeout: 0,
		DisableCompression:    true,
		MaxIdleConns:          maxPendingTLSHandshakes,
		MaxIdleConnsPerHost:   maxPendingTLSHandshakes,
		IdleConnTimeout:       time.Minute,
	}
	return &BrokerAuthenticator{
		baseURL: config.BrokerURL,
		client: &http.Client{
			Transport: transport,
			Timeout:   timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		now: time.Now,
	}, nil
}

func (authenticator *BrokerAuthenticator) AuthenticateNativeEgress(ctx context.Context, credential string, binding guestenrollment.Binding) (nativeegress.Authentication, error) {
	if authenticator == nil || authenticator.client == nil || ctx == nil || guestenrollment.ValidateBinding(binding) != nil ||
		guestenrollment.ValidateNativeEgressCredential(credential) != nil {
		return nativeegress.Authentication{}, nativeegress.ErrAuthenticationDenied
	}
	sequence, err := guestenrollment.NativeEgressCredentialSequence(credential)
	if err != nil {
		return nativeegress.Authentication{}, nativeegress.ErrAuthenticationDenied
	}
	payload, err := json.Marshal(guestenrollment.NativeEgressAuthenticateRequest{
		ContractVersion: guestenrollment.NativeEgressIdentityVersion,
		Binding:         binding,
		Audience:        guestenrollment.NativeEgressAudience,
	})
	if err != nil || len(payload) == 0 || len(payload) > guestenrollment.MaxNativeEgressIdentityRequestBytes {
		zero(payload)
		return nativeegress.Authentication{}, nativeegress.ErrAuthenticationTemporary
	}
	defer zero(payload)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, authenticator.baseURL+guestenrollment.NativeEgressIdentityAuthenticatePath, bytes.NewReader(payload))
	if err != nil {
		return nativeegress.Authentication{}, nativeegress.ErrAuthenticationTemporary
	}
	request.Header.Set("Authorization", "Bearer "+credential)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", defaultAuthenticationAgent)
	response, err := authenticator.client.Do(request)
	request.Header.Del("Authorization")
	credential = ""
	if err != nil {
		return nativeegress.Authentication{}, nativeegress.ErrAuthenticationTemporary
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
		drainBounded(response.Body)
		return nativeegress.Authentication{}, nativeegress.ErrAuthenticationDenied
	}
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "application/json" {
		drainBounded(response.Body)
		return nativeegress.Authentication{}, nativeegress.ErrAuthenticationTemporary
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, guestenrollment.MaxNativeEgressIdentityResponseBytes+1))
	if err != nil || len(body) == 0 || len(body) > guestenrollment.MaxNativeEgressIdentityResponseBytes {
		zero(body)
		return nativeegress.Authentication{}, nativeegress.ErrAuthenticationTemporary
	}
	status, err := guestenrollment.DecodeNativeEgressStatus(body)
	zero(body)
	if err != nil {
		return nativeegress.Authentication{}, nativeegress.ErrAuthenticationTemporary
	}
	if status.Binding != binding || status.Audience != guestenrollment.NativeEgressAudience || status.Sequence != sequence {
		return nativeegress.Authentication{}, nativeegress.ErrAuthenticationTemporary
	}
	issuedAt, issuedErr := time.Parse(time.RFC3339, status.IssuedAt)
	expiresAt, expiresErr := time.Parse(time.RFC3339, status.ExpiresAt)
	now := authenticator.now()
	if issuedErr != nil || expiresErr != nil || !issuedAt.Before(expiresAt) {
		return nativeegress.Authentication{}, nativeegress.ErrAuthenticationTemporary
	}
	if !now.Before(expiresAt) {
		return nativeegress.Authentication{}, nativeegress.ErrAuthenticationDenied
	}
	return nativeegress.Authentication{
		Binding: binding, Sequence: sequence, IssuedAt: issuedAt, ExpiresAt: expiresAt,
	}, nil
}

func drainBounded(reader io.Reader) {
	_, _ = io.Copy(io.Discard, io.LimitReader(reader, guestenrollment.MaxNativeEgressIdentityResponseBytes+1))
}

func (*BrokerAuthenticator) String() string   { return "[native egress broker authenticator]" }
func (*BrokerAuthenticator) GoString() string { return "[native egress broker authenticator]" }

var _ nativeegress.Authenticator = (*BrokerAuthenticator)(nil)
