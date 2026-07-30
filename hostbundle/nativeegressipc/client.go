package nativeegressipc

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"path/filepath"
	"time"

	protocol "github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment/nativeegress"
)

type Client struct {
	SocketPath string
	OwnerUID   uint32
	Shared     bool
	Dial       func(context.Context, string, string) (net.Conn, error)
}

type bufferedConnection struct {
	net.Conn
	reader *bufio.Reader
}

func (connection *bufferedConnection) Read(destination []byte) (int, error) {
	return connection.reader.Read(destination)
}

func (connection *bufferedConnection) CloseWrite() error {
	if closer, ok := connection.Conn.(interface{ CloseWrite() error }); ok {
		return closer.CloseWrite()
	}
	return connection.Conn.Close()
}

func (connection *bufferedConnection) CloseRead() error {
	if closer, ok := connection.Conn.(interface{ CloseRead() error }); ok {
		return closer.CloseRead()
	}
	return nil
}

func (client Client) OpenFlow(ctx context.Context, destination protocol.Destination) (net.Conn, uint64, error) {
	return client.open(ctx, Request{Version: Version, Type: Open, Destination: &destination}, OpenAck)
}

func (client Client) OpenHealth(ctx context.Context) (net.Conn, uint64, error) {
	return client.open(ctx, Request{Version: Version, Type: Health}, Ready)
}

func (client Client) open(ctx context.Context, request Request, want string) (net.Conn, uint64, error) {
	if ctx == nil || ctx.Err() != nil || !validSocketPath(client.SocketPath) || ValidateRequest(request) != nil {
		return nil, 0, protocol.ErrUnavailable
	}
	var socketErr error
	if client.Shared {
		socketErr = ValidateReadinessSocket(client.SocketPath, client.OwnerUID)
	} else {
		socketErr = validateSocket(client.SocketPath, client.OwnerUID)
	}
	if socketErr != nil {
		return nil, 0, protocol.ErrUnavailable
	}
	dial := client.Dial
	if dial == nil {
		dialer := &net.Dialer{}
		dial = dialer.DialContext
	}
	operation, cancel := context.WithTimeout(ctx, Deadline)
	defer cancel()
	connection, err := dial(operation, "unix", client.SocketPath)
	if err != nil {
		return nil, 0, protocol.ErrUnavailable
	}
	fail := func(err error) (net.Conn, uint64, error) {
		_ = connection.Close()
		return nil, 0, err
	}
	if err := validatePeer(connection, client.OwnerUID); err != nil {
		return fail(protocol.ErrUnavailable)
	}
	deadline, ok := operation.Deadline()
	if !ok {
		deadline = time.Now().Add(Deadline)
	}
	_ = connection.SetDeadline(deadline)
	encoded, err := EncodeRequest(request)
	if err != nil {
		return fail(protocol.ErrProtocol)
	}
	if _, err := connection.Write(encoded); err != nil {
		return fail(protocol.ErrUnavailable)
	}
	reader := bufio.NewReaderSize(connection, MaxMessageBytes)
	line, err := reader.ReadBytes('\n')
	if err != nil || len(line) > MaxMessageBytes {
		return fail(protocol.ErrUnavailable)
	}
	response, err := DecodeResponse(line)
	if err != nil {
		return fail(protocol.ErrProtocol)
	}
	if response.Type == OpenReject {
		return fail(protocol.ErrDenied)
	}
	if response.Type != want || (want == Ready && reader.Buffered() != 0) {
		return fail(protocol.ErrProtocol)
	}
	_ = connection.SetDeadline(time.Time{})
	if want == OpenAck {
		return &bufferedConnection{Conn: connection, reader: reader}, response.Epoch, nil
	}
	return connection, response.Epoch, nil
}

func validSocketPath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && filepath.Dir(path) != path
}

func WaitClosed(connection net.Conn) {
	if connection == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(connection, 1))
}

func validateSocket(path string, ownerUID uint32) error {
	return validateSocketPlatform(path, ownerUID)
}

func ValidateReadinessSocket(path string, ownerUID uint32) error {
	if !validSocketPath(path) {
		return errors.New("readiness socket is invalid")
	}
	return validateReadinessPlatform(path, ownerUID)
}
