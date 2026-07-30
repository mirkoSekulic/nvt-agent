package nativeegress

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/url"
	"time"
)

const (
	connectTimeout   = 5 * time.Second
	handshakeTimeout = 5 * time.Second
)

type Connector interface {
	Connect(context.Context, string) (net.Conn, error)
}

type TLSConnector struct {
	roots *x509.CertPool
	Dial  func(context.Context, string, string) (net.Conn, error)
}

func NewTLSConnector(caPEM []byte) (*TLSConnector, error) {
	if len(caPEM) == 0 || len(caPEM) > 1<<20 {
		return nil, fail(ReasonConfiguration, false, false)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, fail(ReasonConfiguration, false, false)
	}
	return &TLSConnector{roots: roots}, nil
}

func NewTLSConnectorFromFile(path string) (*TLSConnector, error) {
	data, err := readProcessOwnedFile(path, 1<<20)
	if err != nil {
		return nil, fail(ReasonConfiguration, false, false)
	}
	defer zero(data)
	return NewTLSConnector(data)
}

func (connector *TLSConnector) Connect(ctx context.Context, endpoint string) (net.Conn, error) {
	if connector == nil || connector.roots == nil || ctx == nil || validateRelayEndpoint(endpoint) != nil {
		return nil, fail(ReasonConfiguration, false, false)
	}
	parsed, _ := url.Parse(endpoint)
	dial := (&net.Dialer{Timeout: connectTimeout, KeepAlive: 30 * time.Second}).DialContext
	if connector.Dial != nil {
		dial = connector.Dial
	}
	connection, err := dial(ctx, "tcp", parsed.Host)
	if err != nil {
		return nil, fail(ReasonRelayUnavailable, true, false)
	}
	tlsConnection := tls.Client(connection, &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    connector.roots,
		ServerName: parsed.Hostname(),
	})
	_ = tlsConnection.SetDeadline(time.Now().Add(handshakeTimeout))
	if err := tlsConnection.HandshakeContext(ctx); err != nil {
		_ = tlsConnection.Close()
		return nil, fail(ReasonRelayUnavailable, true, false)
	}
	_ = tlsConnection.SetDeadline(time.Time{})
	return tlsConnection, nil
}
