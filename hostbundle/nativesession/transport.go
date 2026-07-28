package nativesession

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/url"
	"time"

	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment"
)

const (
	connectTimeout   = 5 * time.Second
	handshakeTimeout = 5 * time.Second
	frameTimeout     = 5 * time.Second
	localTimeout     = 3 * time.Second
)

type Connector interface {
	Connect(context.Context, string) (net.Conn, error)
}

type TLSConnector struct {
	roots *x509.CertPool
	// Dial is an explicit transport seam used by hermetic conformance tests.
	// Production callers leave it nil and use the bounded direct TCP dialer.
	Dial func(context.Context, string, string) (net.Conn, error)
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
	data, err := readRootFile(path, 1<<20)
	if err != nil {
		return nil, fail(ReasonConfiguration, false, false)
	}
	defer zero(data)
	return NewTLSConnector(data)
}

func (connector *TLSConnector) Connect(ctx context.Context, endpoint string) (net.Conn, error) {
	if connector == nil || connector.roots == nil || ctx == nil || validateGatewayEndpoint(endpoint) != nil {
		return nil, fail(ReasonConfiguration, false, false)
	}
	parsed, _ := url.Parse(endpoint)
	dial := (&net.Dialer{Timeout: connectTimeout, KeepAlive: 30 * time.Second}).DialContext
	if connector.Dial != nil {
		dial = connector.Dial
	}
	connection, err := dial(ctx, "tcp", parsed.Host)
	if err != nil {
		return nil, fail(ReasonGatewayUnavailable, true, false)
	}
	tlsConnection := tls.Client(connection, &tls.Config{
		MinVersion: tls.VersionTLS12, RootCAs: connector.roots, ServerName: parsed.Hostname(),
	})
	_ = tlsConnection.SetDeadline(time.Now().Add(handshakeTimeout))
	if err := tlsConnection.HandshakeContext(ctx); err != nil {
		_ = tlsConnection.Close()
		return nil, fail(ReasonGatewayUnavailable, true, false)
	}
	_ = tlsConnection.SetDeadline(time.Time{})
	return tlsConnection, nil
}

func writeFrame(connection net.Conn, value guestenrollment.NativeSessionMessage, deadline time.Time) error {
	encoded, err := guestenrollment.EncodeNativeSessionMessage(value)
	if err != nil {
		return fail(ReasonProtocolInvalid, false, false)
	}
	defer zero(encoded)
	if err := connection.SetWriteDeadline(deadline); err != nil {
		return fail(ReasonGatewayUnavailable, true, false)
	}
	if _, err := io.Copy(connection, bytes.NewReader(encoded)); err != nil {
		return fail(ReasonGatewayUnavailable, true, false)
	}
	return nil
}

func readFrame(reader *bufio.Reader, connection net.Conn, deadline time.Time) (guestenrollment.NativeSessionMessage, error) {
	if err := connection.SetReadDeadline(deadline); err != nil {
		return guestenrollment.NativeSessionMessage{}, fail(ReasonGatewayUnavailable, true, false)
	}
	line, err := reader.ReadSlice('\n')
	if err != nil {
		zero(line)
		if errors.Is(err, bufio.ErrBufferFull) {
			return guestenrollment.NativeSessionMessage{}, fail(ReasonProtocolInvalid, false, false)
		}
		var networkError net.Error
		if errors.As(err, &networkError) && networkError.Timeout() {
			return guestenrollment.NativeSessionMessage{}, fail(ReasonGatewayUnavailable, true, false)
		}
		return guestenrollment.NativeSessionMessage{}, fail(ReasonGatewayUnavailable, true, false)
	}
	if len(line) == 0 || len(line) > guestenrollment.MaxNativeSessionFrameBytes {
		zero(line)
		return guestenrollment.NativeSessionMessage{}, fail(ReasonProtocolInvalid, false, false)
	}
	defer zero(line)
	value, err := guestenrollment.DecodeNativeSessionMessage(line)
	if err != nil {
		return guestenrollment.NativeSessionMessage{}, fail(ReasonProtocolInvalid, false, false)
	}
	return value, nil
}

func newFrameReader(connection io.Reader) *bufio.Reader {
	return bufio.NewReaderSize(connection, guestenrollment.MaxNativeSessionFrameBytes)
}

func relayAgentd(socketPath string, payload []byte) ([]byte, error) {
	if !validFile(socketPath) || len(payload) == 0 || len(payload) > guestenrollment.MaxNativeSessionAgentdPayloadBytes {
		return nil, fail(ReasonProtocolInvalid, false, false)
	}
	connection, err := net.DialTimeout("unix", socketPath, localTimeout)
	if err != nil {
		return nil, fail(ReasonAgentdUnavailable, true, false)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(localTimeout))
	request := append(append([]byte(nil), payload...), '\n')
	if _, err := io.Copy(connection, bytes.NewReader(request)); err != nil {
		zero(request)
		return nil, fail(ReasonAgentdUnavailable, true, false)
	}
	zero(request)
	reader := bufio.NewReader(io.LimitReader(connection, int64(guestenrollment.MaxNativeSessionAgentdPayloadBytes)+1))
	line, err := reader.ReadBytes('\n')
	if err != nil || len(line) == 0 || len(line) > guestenrollment.MaxNativeSessionAgentdPayloadBytes {
		zero(line)
		return nil, fail(ReasonAgentdUnavailable, true, false)
	}
	probe := guestenrollment.NativeSessionMessage{
		ContractVersion: guestenrollment.NativeSessionVersion,
		Type:            guestenrollment.NativeSessionAgentdResponse,
		RequestID:       "local-validation",
		Payload:         line[:len(line)-1],
	}
	if guestenrollment.ValidateNativeSessionMessage(probe) != nil {
		zero(line)
		return nil, fail(ReasonProtocolInvalid, false, false)
	}
	return line[:len(line)-1], nil
}
