// Package workspacetunnel defines the provider-neutral native workspace data
// plane. It is deliberately separate from nvt.native-session/v1 control and
// agentd relay traffic.
package workspacetunnel

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"time"

	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment"
)

const (
	Version       = "nvt.native-workspace/v1"
	YamuxVersion  = "github.com/hashicorp/yamux/v0.1.2"
	Hello         = "hello"
	HelloAck      = "hello_ack"
	HelloReject   = "hello_reject"
	MaxFrameBytes = 64 << 10

	MaxActiveStreams         = 32
	MaxPendingStreamOpens    = 8
	MaxGuestInitiatedStreams = 8
	AcceptBacklog            = 8
	StreamWindowBytes        = 256 << 10
	CopyBufferBytes          = 32 << 10

	HandshakeTimeout       = 5 * time.Second
	KeepAliveInterval      = 10 * time.Second
	ConnectionWriteTimeout = 5 * time.Second
	StreamOpenTimeout      = 5 * time.Second
	StreamCloseTimeout     = 5 * time.Second
	StreamIdleTimeout      = 2 * time.Minute
	LocalDialTimeout       = 3 * time.Second
)

var (
	ErrUnavailable             = errors.New("native workspace unavailable")
	ErrDenied                  = errors.New("native workspace denied")
	ErrProtocol                = errors.New("native workspace protocol failed")
	ErrCapacity                = errors.New("native workspace capacity exceeded")
	ErrAuthenticationDenied    = errors.New("native workspace authentication denied")
	ErrAuthenticationTemporary = errors.New("native workspace authentication temporarily unavailable")
)

// Message is the complete JSONL handshake vocabulary. No message exists after
// HelloAck: the connection switches directly to the pinned yamux wire format.
type Message struct {
	ContractVersion string                   `json:"contract_version"`
	Type            string                   `json:"type"`
	Binding         *guestenrollment.Binding `json:"binding,omitempty"`
	Audience        string                   `json:"audience,omitempty"`
	Credential      string                   `json:"credential,omitempty"`
	Reason          string                   `json:"reason,omitempty"`
}

// Authentication is non-secret authority output. LocalExpiresAt is a
// conservative monotonic deadline derived from the broker-owned window.
type Authentication struct {
	Binding        guestenrollment.Binding
	LocalExpiresAt time.Time
}

// Authenticator is implementation-neutral. A gateway implementation supplies
// the broker-backed authority; no yamux type crosses this boundary.
type Authenticator interface {
	AuthenticateWorkspace(context.Context, string, guestenrollment.Binding) (Authentication, error)
}

func ValidateMessage(value Message) error {
	if value.ContractVersion != Version {
		return ErrProtocol
	}
	switch value.Type {
	case Hello:
		if value.Binding == nil || guestenrollment.ValidateBinding(*value.Binding) != nil ||
			value.Audience != guestenrollment.NativeGuestControlAudience || value.Reason != "" {
			return ErrProtocol
		}
		if guestenrollment.ValidateGuestSessionCredential(value.Credential) != nil {
			return ErrProtocol
		}
	case HelloAck:
		if value.Binding == nil || guestenrollment.ValidateBinding(*value.Binding) != nil ||
			value.Audience != guestenrollment.NativeGuestControlAudience || value.Credential != "" || value.Reason != "" {
			return ErrProtocol
		}
	case HelloReject:
		if value.Binding != nil || value.Audience != "" || value.Credential != "" || value.Reason != "unauthorized" {
			return ErrProtocol
		}
	default:
		return ErrProtocol
	}
	return nil
}

func EncodeMessage(value Message) ([]byte, error) {
	if ValidateMessage(value) != nil {
		return nil, ErrProtocol
	}
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded)+1 > MaxFrameBytes {
		zero(encoded)
		return nil, ErrProtocol
	}
	return append(encoded, '\n'), nil
}

func DecodeMessage(data []byte) (Message, error) {
	var value Message
	if guestenrollment.DecodeStrictJSON(data, MaxFrameBytes, &value) != nil || ValidateMessage(value) != nil {
		value.Credential = ""
		return Message{}, ErrProtocol
	}
	return value, nil
}

// Accept authenticates the guest's first frame and writes HelloAck. Temporary
// authority failures close silently; only a definitive denial writes a reject.
func Accept(ctx context.Context, connection net.Conn, authenticator Authenticator) (Authentication, error) {
	if ctx == nil || connection == nil || authenticator == nil {
		return Authentication{}, ErrProtocol
	}
	deadline := operationDeadline(ctx)
	message, err := readMessage(connection, deadline)
	if err != nil || message.Type != Hello || message.Binding == nil {
		return Authentication{}, ErrProtocol
	}
	binding := *message.Binding
	credential := message.Credential
	message.Credential = ""
	authenticationContext, cancelAuthentication := context.WithDeadline(ctx, deadline)
	authenticated, err := authenticator.AuthenticateWorkspace(authenticationContext, credential, binding)
	cancelAuthentication()
	credential = ""
	if err != nil || authenticated.Binding != binding || !time.Now().Before(authenticated.LocalExpiresAt) {
		if errors.Is(err, ErrAuthenticationDenied) || (err == nil && authenticated.Binding != binding) {
			_ = writeMessage(connection, Message{ContractVersion: Version, Type: HelloReject, Reason: "unauthorized"}, deadline)
			return Authentication{}, ErrDenied
		}
		return Authentication{}, ErrUnavailable
	}
	if err := writeMessage(connection, Message{
		ContractVersion: Version,
		Type:            HelloAck,
		Binding:         &binding,
		Audience:        guestenrollment.NativeGuestControlAudience,
	}, deadline); err != nil {
		return Authentication{}, err
	}
	_ = connection.SetDeadline(time.Time{})
	return authenticated, nil
}

// Establish sends the sensitive hello and waits for the exact acknowledgement.
// Yamux bytes MUST NOT be sent before this function returns successfully.
func Establish(ctx context.Context, connection net.Conn, binding guestenrollment.Binding, credential string) error {
	if ctx == nil || connection == nil || guestenrollment.ValidateBinding(binding) != nil {
		return ErrProtocol
	}
	deadline := operationDeadline(ctx)
	message := Message{
		ContractVersion: Version,
		Type:            Hello,
		Binding:         &binding,
		Audience:        guestenrollment.NativeGuestControlAudience,
		Credential:      credential,
	}
	err := writeMessage(connection, message, deadline)
	message.Credential = ""
	credential = ""
	if err != nil {
		return err
	}
	response, err := readMessage(connection, deadline)
	if err != nil {
		return err
	}
	if response.Type == HelloReject {
		return ErrDenied
	}
	if response.Type != HelloAck || response.Binding == nil || *response.Binding != binding ||
		response.Audience != guestenrollment.NativeGuestControlAudience {
		return ErrProtocol
	}
	_ = connection.SetDeadline(time.Time{})
	return nil
}

func readMessage(connection net.Conn, deadline time.Time) (Message, error) {
	if deadline.IsZero() || !time.Now().Before(deadline) || connection.SetReadDeadline(deadline) != nil {
		return Message{}, ErrUnavailable
	}
	reader := bufio.NewReaderSize(connection, MaxFrameBytes)
	line, err := reader.ReadSlice('\n')
	if err != nil {
		zero(line)
		if len(line) == 0 {
			return Message{}, ErrUnavailable
		}
		return Message{}, ErrProtocol
	}
	if len(line) == 0 || len(line) > MaxFrameBytes || reader.Buffered() != 0 {
		zero(line)
		return Message{}, ErrProtocol
	}
	defer zero(line)
	return DecodeMessage(line)
}

func writeMessage(connection net.Conn, value Message, deadline time.Time) error {
	encoded, err := EncodeMessage(value)
	if err != nil {
		return err
	}
	defer zero(encoded)
	if deadline.IsZero() || !time.Now().Before(deadline) || connection.SetWriteDeadline(deadline) != nil {
		return ErrUnavailable
	}
	if _, err := io.Copy(connection, bytes.NewReader(encoded)); err != nil {
		return ErrUnavailable
	}
	return nil
}

func operationDeadline(ctx context.Context) time.Time {
	deadline := time.Now().Add(HandshakeTimeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	return deadline
}

func (Message) String() string   { return "[sensitive native workspace handshake]" }
func (Message) GoString() string { return "[sensitive native workspace handshake]" }

func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
