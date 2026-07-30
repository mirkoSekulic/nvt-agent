// Package nativeegress defines the provider-neutral authenticated session and
// flow-routing contract for mediated egress from independently managed guests.
// Its pinned transport remains behind NVT interfaces; it contains no provider,
// broker, target-adapter, or Kubernetes implementation.
package nativeegress

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment"
)

const (
	Version        = "nvt.native-egress/v1"
	YamuxVersion   = "github.com/hashicorp/yamux/v0.1.2"
	Hello          = "hello"
	HelloAck       = "hello_ack"
	HelloReject    = "hello_reject"
	FlowOpen       = "flow_open"
	FlowOpenAck    = "flow_open_ack"
	FlowOpenReject = "flow_open_reject"
	NetworkTCP     = "tcp"

	MaxFrameBytes           = 8 << 10
	MaxFlowIDBytes          = 128
	MaxDestinationHostBytes = 253
	MaxCapabilityHintBytes  = 128
	MaxActiveFlows          = 64
	MaxPendingFlowOpens     = 8
	MaxSessionBindings      = 128
	MaxFlowIDsPerSession    = 1024
	AcceptBacklog           = MaxPendingFlowOpens
	StreamWindowBytes       = 256 << 10
	CopyBufferBytes         = 32 << 10

	HandshakeTimeout       = 5 * time.Second
	RevalidationInterval   = 30 * time.Second
	FlowOpenTimeout        = 5 * time.Second
	FlowIdleTimeout        = 2 * time.Minute
	ShutdownTimeout        = 5 * time.Second
	KeepAliveInterval      = 10 * time.Second
	ConnectionWriteTimeout = 5 * time.Second
	StreamOpenTimeout      = FlowOpenTimeout
	StreamCloseTimeout     = ShutdownTimeout
)

var (
	ErrUnavailable             = errors.New("native egress unavailable")
	ErrDenied                  = errors.New("native egress denied")
	ErrProtocol                = errors.New("native egress protocol failed")
	ErrCapacity                = errors.New("native egress capacity exceeded")
	ErrAuthenticationDenied    = errors.New("native egress authentication denied")
	ErrAuthenticationTemporary = errors.New("native egress authentication temporarily unavailable")

	flowIDPattern         = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	hostnameLabelPattern  = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	numericHostPattern    = regexp.MustCompile(`^[0-9.]+$`)
	capabilityHintPattern = regexp.MustCompile(`^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$`)
)

// Destination is untrusted outbound intent, never routing authority. The
// exact binding chooses the trusted EgressTarget before this value is used.
// That target remains authoritative for DNS, private-address, grant, audit,
// quota, TLS mediation, and credential-injection decisions.
type Destination struct {
	Network        string `json:"network"`
	Host           string `json:"host"`
	Port           uint16 `json:"port"`
	CapabilityHint string `json:"capability_hint,omitempty"`
}

// Message is the bounded session and per-stream vocabulary. The transport
// maps one accepted flow_open to one backpressured byte stream without
// exposing its implementation types through NVT interfaces.
type Message struct {
	ContractVersion string                   `json:"contract_version"`
	Type            string                   `json:"type"`
	Binding         *guestenrollment.Binding `json:"binding,omitempty"`
	Audience        string                   `json:"audience,omitempty"`
	Credential      string                   `json:"credential,omitempty"`
	FlowID          string                   `json:"flow_id,omitempty"`
	Destination     *Destination             `json:"destination,omitempty"`
	Reason          string                   `json:"reason,omitempty"`
}

// Authentication is the non-secret result of authoritative broker
// authentication. LocalExpiresAt is derived by BeginAccept, never supplied by
// the authenticator.
type Authentication struct {
	Binding        guestenrollment.Binding
	Sequence       uint64
	IssuedAt       time.Time
	ExpiresAt      time.Time
	LocalExpiresAt time.Time
}

type Authenticator interface {
	AuthenticateNativeEgress(context.Context, string, guestenrollment.Binding) (Authentication, error)
}

// PendingAcceptance is an authenticated, credential-free hello awaiting
// caller-owned session admission. It deliberately keeps acknowledgement
// separate so a bounded registry can reserve the exact session first.
type PendingAcceptance struct {
	mu             sync.Mutex
	connection     net.Conn
	authentication Authentication
	deadline       time.Time
	acknowledged   bool
}

func ValidateDestination(value Destination) error {
	if value.Network != NetworkTCP || value.Port == 0 || len(value.Host) == 0 || len(value.Host) > MaxDestinationHostBytes || value.Host != strings.ToLower(value.Host) {
		return ErrProtocol
	}
	if address, err := netip.ParseAddr(value.Host); err == nil {
		if address.Zone() != "" || address.String() != value.Host {
			return ErrProtocol
		}
	} else if !canonicalHostname(value.Host) || numericHostPattern.MatchString(value.Host) {
		return ErrProtocol
	}
	if value.CapabilityHint != "" && (len(value.CapabilityHint) > MaxCapabilityHintBytes || !capabilityHintPattern.MatchString(value.CapabilityHint)) {
		return ErrProtocol
	}
	return nil
}

func canonicalHostname(value string) bool {
	labels := strings.Split(value, ".")
	if len(labels) == 0 {
		return false
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || !hostnameLabelPattern.MatchString(label) {
			return false
		}
	}
	return true
}

func ValidateMessage(value Message) error {
	if value.ContractVersion != Version {
		return ErrProtocol
	}
	switch value.Type {
	case Hello:
		if value.Binding == nil || guestenrollment.ValidateBinding(*value.Binding) != nil || value.Audience != guestenrollment.NativeEgressAudience ||
			guestenrollment.ValidateNativeEgressCredential(value.Credential) != nil || value.FlowID != "" || value.Destination != nil || value.Reason != "" {
			return ErrProtocol
		}
	case HelloAck:
		if value.Binding == nil || guestenrollment.ValidateBinding(*value.Binding) != nil || value.Audience != guestenrollment.NativeEgressAudience ||
			value.Credential != "" || value.FlowID != "" || value.Destination != nil || value.Reason != "" {
			return ErrProtocol
		}
	case HelloReject:
		if value.Binding != nil || value.Audience != "" || value.Credential != "" || value.FlowID != "" || value.Destination != nil || value.Reason != "unauthorized" {
			return ErrProtocol
		}
	case FlowOpen:
		if value.Binding != nil || value.Audience != "" || value.Credential != "" || !flowIDPattern.MatchString(value.FlowID) ||
			value.Destination == nil || ValidateDestination(*value.Destination) != nil || value.Reason != "" {
			return ErrProtocol
		}
	case FlowOpenAck:
		if value.Binding != nil || value.Audience != "" || value.Credential != "" || !flowIDPattern.MatchString(value.FlowID) || value.Destination != nil || value.Reason != "" {
			return ErrProtocol
		}
	case FlowOpenReject:
		if value.Binding != nil || value.Audience != "" || value.Credential != "" || !flowIDPattern.MatchString(value.FlowID) || value.Destination != nil || value.Reason != "denied" {
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

// BeginAccept reads and authenticates the exact hello without acknowledging
// it. Temporary authority failures close silently; only definitive
// credential/binding/purpose denial sends a reject. The returned value retains
// no credential and must be acknowledged only after caller-owned admission.
func BeginAccept(ctx context.Context, connection net.Conn, authenticator Authenticator) (*PendingAcceptance, error) {
	if ctx == nil || connection == nil || authenticator == nil {
		return nil, ErrProtocol
	}
	deadline := operationDeadline(ctx, HandshakeTimeout)
	message, err := readMessage(connection, deadline)
	if err != nil || message.Type != Hello || message.Binding == nil {
		return nil, ErrProtocol
	}
	binding := *message.Binding
	credential := message.Credential
	message.Credential = ""
	sequence, err := guestenrollment.NativeEgressCredentialSequence(credential)
	if err != nil {
		credential = ""
		return nil, ErrProtocol
	}
	authContext, cancel := context.WithDeadline(ctx, deadline)
	authentication, err := authenticator.AuthenticateNativeEgress(authContext, credential, binding)
	cancel()
	credential = ""
	if err == nil {
		authentication, err = deriveAuthentication(authentication, binding, sequence, time.Now())
	}
	if err != nil {
		if errors.Is(err, ErrAuthenticationDenied) {
			_ = writeMessage(connection, Message{ContractVersion: Version, Type: HelloReject, Reason: "unauthorized"}, deadline)
			return nil, ErrDenied
		}
		return nil, ErrUnavailable
	}
	return &PendingAcceptance{connection: connection, authentication: authentication, deadline: deadline}, nil
}

// Authentication returns the validated non-secret authority result.
func (pending *PendingAcceptance) Authentication() (Authentication, error) {
	if pending == nil {
		return Authentication{}, ErrProtocol
	}
	pending.mu.Lock()
	defer pending.mu.Unlock()
	return pending.authentication, nil
}

// Acknowledge completes the original absolute handshake only after the caller
// has reserved its bounded session. It is deliberately one-shot.
func (pending *PendingAcceptance) Acknowledge() error {
	if pending == nil {
		return ErrProtocol
	}
	pending.mu.Lock()
	defer pending.mu.Unlock()
	if pending.acknowledged || pending.connection == nil {
		return ErrProtocol
	}
	pending.acknowledged = true
	binding := pending.authentication.Binding
	if err := writeMessage(pending.connection, Message{ContractVersion: Version, Type: HelloAck, Binding: &binding, Audience: guestenrollment.NativeEgressAudience}, pending.deadline); err != nil {
		return err
	}
	_ = pending.connection.SetDeadline(time.Time{})
	return nil
}

// Accept is the compatibility wrapper for callers that do not own a separate
// admission registry. Relays with bounded admission use BeginAccept and send
// the acknowledgement only after reservation succeeds.
func Accept(ctx context.Context, connection net.Conn, authenticator Authenticator) (Authentication, error) {
	pending, err := BeginAccept(ctx, connection, authenticator)
	if err != nil {
		return Authentication{}, err
	}
	authentication, err := pending.Authentication()
	if err != nil {
		return Authentication{}, err
	}
	if err := pending.Acknowledge(); err != nil {
		return Authentication{}, err
	}
	return authentication, nil
}

func Establish(ctx context.Context, connection net.Conn, binding guestenrollment.Binding, credential string) error {
	if ctx == nil || connection == nil || guestenrollment.ValidateBinding(binding) != nil || guestenrollment.ValidateNativeEgressCredential(credential) != nil {
		return ErrProtocol
	}
	deadline := operationDeadline(ctx, HandshakeTimeout)
	message := Message{ContractVersion: Version, Type: Hello, Binding: &binding, Audience: guestenrollment.NativeEgressAudience, Credential: credential}
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
	if response.Type != HelloAck || response.Binding == nil || *response.Binding != binding || response.Audience != guestenrollment.NativeEgressAudience {
		return ErrProtocol
	}
	_ = connection.SetDeadline(time.Time{})
	return nil
}

func deriveAuthentication(value Authentication, binding guestenrollment.Binding, sequence uint64, now time.Time) (Authentication, error) {
	if value.Binding != binding || value.Sequence != sequence || sequence == 0 || sequence > guestenrollment.MaxGuestSessionIssuanceSequence {
		return Authentication{}, ErrAuthenticationTemporary
	}
	if !value.LocalExpiresAt.IsZero() || value.IssuedAt.IsZero() || value.ExpiresAt.IsZero() || !value.IssuedAt.Before(value.ExpiresAt) {
		return Authentication{}, ErrAuthenticationTemporary
	}
	if !now.Before(value.ExpiresAt) {
		return Authentication{}, ErrAuthenticationDenied
	}
	window := value.ExpiresAt.Sub(value.IssuedAt)
	if window <= 0 || window > guestenrollment.MaxNativeEgressCredentialLifetime {
		return Authentication{}, ErrAuthenticationTemporary
	}
	remaining := value.ExpiresAt.Sub(now)
	if remaining > window {
		remaining = window
	}
	if remaining > RevalidationInterval {
		remaining = RevalidationInterval
	}
	value.LocalExpiresAt = now.Add(remaining)
	return value, nil
}

func validateAuthentication(value Authentication, now time.Time) error {
	if guestenrollment.ValidateBinding(value.Binding) != nil || value.Sequence == 0 || value.Sequence > guestenrollment.MaxGuestSessionIssuanceSequence ||
		value.IssuedAt.IsZero() || value.ExpiresAt.IsZero() || value.LocalExpiresAt.IsZero() || !value.IssuedAt.Before(value.ExpiresAt) ||
		!now.Before(value.ExpiresAt) || !now.Before(value.LocalExpiresAt) {
		return ErrProtocol
	}
	window := value.ExpiresAt.Sub(value.IssuedAt)
	localRemaining := value.LocalExpiresAt.Sub(now)
	if window <= 0 || window > guestenrollment.MaxNativeEgressCredentialLifetime || localRemaining <= 0 || localRemaining > RevalidationInterval ||
		localRemaining > window || localRemaining > value.ExpiresAt.Sub(now) {
		return ErrProtocol
	}
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

func operationDeadline(ctx context.Context, limit time.Duration) time.Time {
	deadline := time.Now().Add(limit)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	return deadline
}

func (Message) String() string   { return "[sensitive native egress frame]" }
func (Message) GoString() string { return "[sensitive native egress frame]" }
func (Authentication) String() string {
	return "[native egress authentication]"
}
func (Authentication) GoString() string {
	return "[native egress authentication]"
}
func (*PendingAcceptance) String() string {
	return "[native egress pending acceptance]"
}
func (*PendingAcceptance) GoString() string {
	return "[native egress pending acceptance]"
}

func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
