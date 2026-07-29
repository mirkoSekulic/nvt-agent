package workspacetunnel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment"
)

type testAuthenticator struct {
	credential string
	binding    guestenrollment.Binding
	err        error
}

type blockingAuthenticator struct{}

func (blockingAuthenticator) AuthenticateWorkspace(ctx context.Context, _ string, _ guestenrollment.Binding) (Authentication, error) {
	<-ctx.Done()
	return Authentication{}, ErrAuthenticationTemporary
}

func (authenticator testAuthenticator) AuthenticateWorkspace(_ context.Context, credential string, binding guestenrollment.Binding) (Authentication, error) {
	if authenticator.err != nil {
		return Authentication{}, authenticator.err
	}
	if credential != authenticator.credential || binding != authenticator.binding {
		return Authentication{}, ErrAuthenticationDenied
	}
	return Authentication{Binding: binding, LocalExpiresAt: time.Now().Add(time.Minute)}, nil
}

func TestWorkspaceHandshakeStrictRoundTripAndRedaction(t *testing.T) {
	binding := testBinding()
	credential := testCredential(t, 1)
	message := Message{
		ContractVersion: Version,
		Type:            Hello,
		Binding:         &binding,
		Audience:        guestenrollment.NativeGuestControlAudience,
		Credential:      credential,
	}
	encoded, err := EncodeMessage(message)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeMessage(encoded)
	if err != nil || decoded.Binding == nil || *decoded.Binding != binding || decoded.Credential != credential {
		t.Fatalf("decoded handshake=%#v error=%v", decoded, err)
	}
	for _, rendered := range []string{fmt.Sprint(message), fmt.Sprintf("%#v", message)} {
		if strings.Contains(rendered, credential) {
			t.Fatal("handshake formatting disclosed credential")
		}
	}

	valid, _ := EncodeMessage(message)
	oversized := append(make([]byte, MaxFrameBytes), '\n')
	invalidUTF8 := append([]byte(nil), valid...)
	invalidUTF8[len(invalidUTF8)-2] = 0xff
	for name, value := range map[string][]byte{
		"unknown field":   []byte(`{"contract_version":"nvt.native-workspace/v1","type":"hello","binding":{},"audience":"nvt.native-guest-control/v1","credential":"x","extra":true}`),
		"duplicate key":   []byte(`{"contract_version":"nvt.native-workspace/v1","contract_version":"nvt.native-workspace/v1","type":"hello"}`),
		"invalid utf8":    invalidUTF8,
		"trailing object": append(valid, []byte(`{}`)...),
		"oversized":       oversized,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeMessage(value); !errors.Is(err, ErrProtocol) {
				t.Fatalf("DecodeMessage error=%v", err)
			}
		})
	}
}

func TestWorkspaceHandshakeAuthenticationOutcomes(t *testing.T) {
	binding := testBinding()
	credential := testCredential(t, 1)
	for _, test := range []struct {
		name      string
		authError error
		guestErr  error
		serverErr error
	}{
		{name: "success"},
		{name: "denied", authError: ErrAuthenticationDenied, guestErr: ErrDenied, serverErr: ErrDenied},
		{name: "temporary closes silently", authError: ErrAuthenticationTemporary, guestErr: ErrUnavailable, serverErr: ErrUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			gatewayConnection, guestConnection := net.Pipe()
			serverResult := make(chan error, 1)
			go func() {
				defer gatewayConnection.Close()
				_, err := Accept(t.Context(), gatewayConnection, testAuthenticator{
					credential: credential, binding: binding, err: test.authError,
				})
				serverResult <- err
			}()
			guestErr := Establish(t.Context(), guestConnection, binding, credential)
			_ = guestConnection.Close()
			serverErr := <-serverResult
			if test.guestErr == nil {
				if guestErr != nil || serverErr != nil {
					t.Fatalf("guest error=%v server error=%v", guestErr, serverErr)
				}
				return
			}
			if !errors.Is(guestErr, test.guestErr) || !errors.Is(serverErr, test.serverErr) {
				t.Fatalf("guest error=%v server error=%v", guestErr, serverErr)
			}
		})
	}
}

func TestWorkspaceHandshakeBoundsAuthenticationByCallerDeadline(t *testing.T) {
	binding := testBinding()
	credential := testCredential(t, 1)
	gatewayConnection, guestConnection := net.Pipe()
	serverResult := make(chan error, 1)
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	go func() {
		defer gatewayConnection.Close()
		_, err := Accept(ctx, gatewayConnection, blockingAuthenticator{})
		serverResult <- err
	}()

	started := time.Now()
	guestErr := Establish(t.Context(), guestConnection, binding, credential)
	_ = guestConnection.Close()
	serverErr := <-serverResult
	if !errors.Is(guestErr, ErrUnavailable) || !errors.Is(serverErr, ErrUnavailable) {
		t.Fatalf("guest error=%v server error=%v", guestErr, serverErr)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("authentication exceeded caller deadline: %v", elapsed)
	}
}

func TestWorkspaceHandshakeRejectsPipelinedYamuxBytes(t *testing.T) {
	binding := testBinding()
	credential := testCredential(t, 1)
	gatewayConnection, guestConnection := net.Pipe()
	done := make(chan error, 1)
	go func() {
		defer gatewayConnection.Close()
		_, err := Accept(t.Context(), gatewayConnection, testAuthenticator{credential: credential, binding: binding})
		done <- err
	}()
	hello, err := EncodeMessage(Message{
		ContractVersion: Version, Type: Hello, Binding: &binding,
		Audience: guestenrollment.NativeGuestControlAudience, Credential: credential,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := guestConnection.Write(append(hello, 0)); err != nil {
		t.Fatal(err)
	}
	_ = guestConnection.Close()
	if err := <-done; !errors.Is(err, ErrProtocol) {
		t.Fatalf("pipelined handshake error=%v", err)
	}
}

func testBinding() guestenrollment.Binding {
	return guestenrollment.Binding{
		AgentRunUID:        "11111111-1111-1111-1111-111111111111",
		ExecutionID:        "execution-workspace",
		DriverRegistration: "reference-driver",
		DesiredGeneration:  1,
		GuestInstanceID:    "guest-workspace-1",
	}
}

func testCredential(t *testing.T, sequence uint64) string {
	t.Helper()
	credential, err := guestenrollment.GenerateGuestSessionCredential(sequence)
	if err != nil {
		t.Fatal(err)
	}
	return credential
}
