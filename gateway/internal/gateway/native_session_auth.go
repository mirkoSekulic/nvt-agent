package gateway

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment"
)

const maxNativeSessionTrustFileBytes = 1 << 20

var (
	nativeSessionServerNamePattern       = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?)*$`)
	errNativeSessionAuthenticationDenied = errors.New("native session authentication denied")
	errNativeSessionAuthorityUnavailable = errors.New("native session authority unavailable")
)

// NativeSessionConfig is the opt-in production gateway listener. All
// credential-bearing values are read from files; this configuration contains
// only listener, trust, and bounded-lifecycle metadata.
type NativeSessionConfig struct {
	Enabled               bool
	ListenAddr            string
	TLSCertificateFile    string
	TLSKeyFile            string
	BrokerURL             string
	BrokerServerName      string
	BrokerCAFile          string
	AuthenticationTimeout time.Duration
	RevalidationInterval  time.Duration
}

func (config NativeSessionConfig) validate() error {
	if !config.Enabled {
		return nil
	}
	if err := validateNativeSessionListenAddress(config.ListenAddr); err != nil {
		return err
	}
	for name, value := range map[string]string{
		"nativeSession.tlsCertificateFile": config.TLSCertificateFile,
		"nativeSession.tlsKeyFile":         config.TLSKeyFile,
		"nativeSession.brokerCAFile":       config.BrokerCAFile,
	} {
		if !filepath.IsAbs(value) || filepath.Clean(value) != value {
			return fmt.Errorf("%s must be an absolute canonical path", name)
		}
	}
	if config.TLSCertificateFile == config.TLSKeyFile || config.TLSCertificateFile == config.BrokerCAFile || config.TLSKeyFile == config.BrokerCAFile {
		return errors.New("native session trust files must be distinct")
	}
	endpoint, err := url.Parse(config.BrokerURL)
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.User != nil || endpoint.Path != "" || endpoint.RawPath != "" || endpoint.RawQuery != "" || endpoint.Fragment != "" || endpoint.Opaque != "" || endpoint.String() != config.BrokerURL {
		return errors.New("nativeSession.brokerURL must be one canonical HTTPS origin")
	}
	if endpoint.Hostname() != config.BrokerServerName || net.ParseIP(config.BrokerServerName) != nil || len(config.BrokerServerName) > 253 || !nativeSessionServerNamePattern.MatchString(config.BrokerServerName) {
		return errors.New("nativeSession.brokerServerName must exactly match the broker URL DNS name")
	}
	if port := endpoint.Port(); port != "" {
		value, parseErr := strconv.Atoi(port)
		if parseErr != nil || value < 1 || value > 65535 {
			return errors.New("nativeSession.brokerURL port must be between 1 and 65535")
		}
	}
	if config.AuthenticationTimeout <= 0 || config.AuthenticationTimeout > guestenrollment.MaxOperationDuration {
		return errors.New("nativeSession.authenticationTimeout must be between 1 and 30 seconds")
	}
	if config.RevalidationInterval <= 0 || config.RevalidationInterval > time.Minute {
		return errors.New("nativeSession.revalidationInterval must be between 1 and 60 seconds")
	}
	return nil
}

func validateNativeSessionListenAddress(value string) error {
	host, port, err := net.SplitHostPort(value)
	if err != nil || strings.ContainsAny(host, "\x00\r\n") {
		return errors.New("nativeSession.listenAddr must be a TCP host and port")
	}
	parsed, err := strconv.Atoi(port)
	if err != nil || parsed < 1 || parsed > 65535 {
		return errors.New("nativeSession.listenAddr port must be between 1 and 65535")
	}
	return nil
}

type authenticatedNativeSession struct {
	Binding        guestenrollment.Binding
	Sequence       uint64
	IssuedAt       time.Time
	ExpiresAt      time.Time
	LocalExpiresAt time.Time
}

func nativeSessionCredentialSequence(credential string) (uint64, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(credential)
	if err != nil || len(decoded) != guestenrollment.GuestSessionCredentialBytes {
		zeroNativeSessionBytes(decoded)
		return 0, errNativeSessionAuthenticationDenied
	}
	defer zeroNativeSessionBytes(decoded)
	sequence := binary.BigEndian.Uint64(decoded[:8])
	if sequence == 0 || sequence > guestenrollment.MaxGuestSessionIssuanceSequence {
		return 0, errNativeSessionAuthenticationDenied
	}
	return sequence, nil
}

type nativeSessionAuthenticator interface {
	Authenticate(context.Context, string, guestenrollment.Binding) (authenticatedNativeSession, error)
}

type brokerNativeSessionAuthenticator struct {
	baseURL string
	client  *http.Client
	now     func() time.Time
}

func newBrokerNativeSessionAuthenticator(config NativeSessionConfig) (*brokerNativeSessionAuthenticator, error) {
	caPEM, err := readBoundedNativeSessionFile(config.BrokerCAFile)
	if err != nil {
		return nil, errors.New("load native session broker trust: invalid CA file")
	}
	defer zeroNativeSessionBytes(caPEM)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("load native session broker trust: invalid CA file")
	}
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: config.AuthenticationTimeout, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: config.BrokerServerName},
		TLSHandshakeTimeout:   config.AuthenticationTimeout,
		ResponseHeaderTimeout: config.AuthenticationTimeout,
		ExpectContinueTimeout: 0,
		MaxIdleConns:          16,
		MaxIdleConnsPerHost:   16,
		IdleConnTimeout:       time.Minute,
	}
	return &brokerNativeSessionAuthenticator{
		baseURL: config.BrokerURL,
		client: &http.Client{
			Transport: transport,
			Timeout:   config.AuthenticationTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		now: time.Now,
	}, nil
}

func (authenticator *brokerNativeSessionAuthenticator) Authenticate(ctx context.Context, credential string, binding guestenrollment.Binding) (authenticatedNativeSession, error) {
	if authenticator == nil || authenticator.client == nil || ctx == nil || guestenrollment.ValidateBinding(binding) != nil {
		return authenticatedNativeSession{}, errNativeSessionAuthenticationDenied
	}
	sequence, err := nativeSessionCredentialSequence(credential)
	if err != nil {
		return authenticatedNativeSession{}, err
	}
	payload, err := json.Marshal(guestenrollment.GuestSessionAuthenticateRequest{
		ContractVersion: guestenrollment.GuestSessionIdentityVersion,
		Binding:         binding,
		Audience:        guestenrollment.NativeGuestControlAudience,
	})
	if err != nil || len(payload) > guestenrollment.MaxGuestSessionAuthRequestBytes {
		return authenticatedNativeSession{}, errNativeSessionAuthorityUnavailable
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, authenticator.baseURL+guestenrollment.GuestSessionIdentityAuthenticatePath, bytes.NewReader(payload))
	if err != nil {
		return authenticatedNativeSession{}, errNativeSessionAuthorityUnavailable
	}
	request.Header.Set("Authorization", "Bearer "+credential)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "nvt-agent-gateway")
	response, err := authenticator.client.Do(request)
	request.Header.Del("Authorization")
	if err != nil {
		return authenticatedNativeSession{}, errNativeSessionAuthorityUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, guestenrollment.MaxGuestSessionResponseBytes+1))
		return authenticatedNativeSession{}, errNativeSessionAuthenticationDenied
	}
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "application/json" {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, guestenrollment.MaxGuestSessionResponseBytes+1))
		return authenticatedNativeSession{}, errNativeSessionAuthorityUnavailable
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, guestenrollment.MaxGuestSessionResponseBytes+1))
	if err != nil || len(body) == 0 || len(body) > guestenrollment.MaxGuestSessionResponseBytes {
		zeroNativeSessionBytes(body)
		return authenticatedNativeSession{}, errNativeSessionAuthorityUnavailable
	}
	var status guestenrollment.GuestSessionStatus
	err = guestenrollment.DecodeStrictJSON(body, guestenrollment.MaxGuestSessionResponseBytes, &status)
	zeroNativeSessionBytes(body)
	if err != nil {
		return authenticatedNativeSession{}, errNativeSessionAuthorityUnavailable
	}
	if guestenrollment.ValidateBinding(status.Binding) != nil {
		return authenticatedNativeSession{}, errNativeSessionAuthorityUnavailable
	}
	if status.Binding != binding || status.Audience != guestenrollment.NativeGuestControlAudience {
		return authenticatedNativeSession{}, errNativeSessionAuthenticationDenied
	}
	if guestenrollment.ValidateGuestSessionStatus(status) != nil {
		return authenticatedNativeSession{}, errNativeSessionAuthorityUnavailable
	}
	issuedAt, issuedErr := time.Parse(time.RFC3339, status.IssuedAt)
	expiresAt, expiresErr := time.Parse(time.RFC3339, status.ExpiresAt)
	now := authenticator.now()
	if issuedErr != nil || expiresErr != nil || !issuedAt.Before(expiresAt) || !now.Before(expiresAt) {
		return authenticatedNativeSession{}, errNativeSessionAuthenticationDenied
	}
	remaining := expiresAt.Sub(now)
	if window := expiresAt.Sub(issuedAt); remaining > window {
		remaining = window
	}
	if remaining <= 0 {
		return authenticatedNativeSession{}, errNativeSessionAuthenticationDenied
	}
	return authenticatedNativeSession{
		Binding: binding, Sequence: sequence, IssuedAt: issuedAt, ExpiresAt: expiresAt,
		LocalExpiresAt: time.Now().Add(remaining),
	}, nil
}

func readBoundedNativeSessionFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	value, err := io.ReadAll(io.LimitReader(file, maxNativeSessionTrustFileBytes+1))
	if err != nil || len(value) == 0 || len(value) > maxNativeSessionTrustFileBytes {
		zeroNativeSessionBytes(value)
		return nil, errors.New("native session file is invalid")
	}
	return value, nil
}

func zeroNativeSessionBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
