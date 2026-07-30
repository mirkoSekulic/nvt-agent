package nativeegress

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment"
)

type testAuthenticator struct {
	credential string
	binding    guestenrollment.Binding
	err        error
	calls      atomic.Int32
}

type testAuthenticatorFunc func(context.Context, string, guestenrollment.Binding) (Authentication, error)

func (authenticate testAuthenticatorFunc) AuthenticateNativeEgress(ctx context.Context, credential string, binding guestenrollment.Binding) (Authentication, error) {
	return authenticate(ctx, credential, binding)
}

func (*testAuthenticator) String() string   { return "[native egress test authenticator]" }
func (*testAuthenticator) GoString() string { return "[native egress test authenticator]" }

func (authenticator *testAuthenticator) AuthenticateNativeEgress(_ context.Context, credential string, binding guestenrollment.Binding) (Authentication, error) {
	authenticator.calls.Add(1)
	if authenticator.err != nil {
		return Authentication{}, authenticator.err
	}
	if credential != authenticator.credential || binding != authenticator.binding {
		return Authentication{}, ErrAuthenticationDenied
	}
	sequence, err := guestenrollment.NativeEgressCredentialSequence(credential)
	if err != nil {
		return Authentication{}, ErrAuthenticationDenied
	}
	now := time.Now()
	return Authentication{Binding: binding, Sequence: sequence, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute)}, nil
}

func TestHandshakeExactBindingPurposeAndFailureClasses(t *testing.T) {
	binding := testBinding("run-a")
	credential := testCredential(t, 7)
	authenticator := &testAuthenticator{credential: credential, binding: binding}
	gateway, guest := net.Pipe()
	result := make(chan Authentication, 1)
	errs := make(chan error, 1)
	go func() {
		defer gateway.Close()
		authenticated, err := Accept(t.Context(), gateway, authenticator)
		result <- authenticated
		errs <- err
	}()
	if err := Establish(t.Context(), guest, binding, credential); err != nil {
		t.Fatal(err)
	}
	_ = guest.Close()
	authenticated := <-result
	if err := <-errs; err != nil || authenticated.Binding != binding || authenticated.Sequence != 7 || authenticated.LocalExpiresAt.IsZero() || time.Until(authenticated.LocalExpiresAt) > RevalidationInterval {
		t.Fatalf("authentication=%#v error=%v", authenticated, err)
	}

	for name, mutate := range map[string]func(*guestenrollment.Binding){
		"uid":        func(value *guestenrollment.Binding) { value.AgentRunUID = "other-uid" },
		"execution":  func(value *guestenrollment.Binding) { value.ExecutionID = "other-execution" },
		"driver":     func(value *guestenrollment.Binding) { value.DriverRegistration = "other-driver" },
		"generation": func(value *guestenrollment.Binding) { value.DesiredGeneration++ },
		"guest":      func(value *guestenrollment.Binding) { value.GuestInstanceID = "other-guest" },
	} {
		t.Run(name, func(t *testing.T) {
			wrong := binding
			mutate(&wrong)
			gateway, guest := net.Pipe()
			go func() {
				defer gateway.Close()
				_, _ = Accept(t.Context(), gateway, authenticator)
			}()
			if err := Establish(t.Context(), guest, wrong, credential); !errors.Is(err, ErrDenied) {
				t.Fatalf("mismatch error=%v", err)
			}
			_ = guest.Close()
		})
	}

	for name, authorityErr := range map[string]error{
		"revoked":            ErrAuthenticationDenied,
		"expired":            ErrAuthenticationDenied,
		"broker unavailable": ErrAuthenticationTemporary,
	} {
		t.Run(name, func(t *testing.T) {
			gateway, guest := net.Pipe()
			go func() {
				defer gateway.Close()
				_, _ = Accept(t.Context(), gateway, &testAuthenticator{credential: credential, binding: binding, err: authorityErr})
			}()
			err := Establish(t.Context(), guest, binding, credential)
			_ = guest.Close()
			if errors.Is(authorityErr, ErrAuthenticationDenied) && !errors.Is(err, ErrDenied) {
				t.Fatalf("definitive error=%v", err)
			}
			if errors.Is(authorityErr, ErrAuthenticationTemporary) && (!errors.Is(err, ErrUnavailable) || errors.Is(err, ErrDenied)) {
				t.Fatalf("temporary error=%v", err)
			}
		})
	}

	t.Run("contradictory success is temporary", func(t *testing.T) {
		gateway, guest := net.Pipe()
		go func() {
			defer gateway.Close()
			_, _ = Accept(t.Context(), gateway, testAuthenticatorFunc(func(_ context.Context, _ string, _ guestenrollment.Binding) (Authentication, error) {
				now := time.Now()
				wrong := binding
				wrong.GuestInstanceID = "other-guest"
				return Authentication{Binding: wrong, Sequence: 7, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute)}, nil
			}))
		}()
		err := Establish(t.Context(), guest, binding, credential)
		_ = guest.Close()
		if !errors.Is(err, ErrUnavailable) || errors.Is(err, ErrDenied) {
			t.Fatalf("contradictory authority result classification=%v", err)
		}
	})
}

func TestStagedHandshakeWithholdsAcknowledgementUntilAdmission(t *testing.T) {
	binding := testBinding("staged")
	credential := testCredential(t, 9)
	authenticator := &testAuthenticator{credential: credential, binding: binding}
	gateway, guest := net.Pipe()
	defer gateway.Close()
	defer guest.Close()

	guestResult := make(chan error, 1)
	go func() {
		guestResult <- Establish(t.Context(), guest, binding, credential)
	}()
	pending, err := BeginAccept(t.Context(), gateway, authenticator)
	if err != nil {
		t.Fatal(err)
	}
	authentication, err := pending.Authentication()
	if err != nil || authentication.Binding != binding || authentication.Sequence != 9 {
		t.Fatalf("pending authentication=%#v error=%v", authentication, err)
	}
	select {
	case err := <-guestResult:
		t.Fatalf("guest completed before admission acknowledgement: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	if err := pending.Acknowledge(); err != nil {
		t.Fatal(err)
	}
	if err := <-guestResult; err != nil {
		t.Fatal(err)
	}
	if err := pending.Acknowledge(); !errors.Is(err, ErrProtocol) {
		t.Fatalf("second acknowledgement error=%v", err)
	}
	for _, formatted := range []string{fmt.Sprint(pending), fmt.Sprintf("%#v", pending)} {
		if strings.Contains(formatted, credential) || strings.Contains(formatted, binding.GuestInstanceID) {
			t.Fatalf("pending acceptance formatting exposed state: %q", formatted)
		}
	}
}

func TestHandshakeRejectsWrongPurposeMalformedAndSensitiveFormatting(t *testing.T) {
	binding := testBinding("run-a")
	credential := testCredential(t, 1)
	authenticator := &testAuthenticator{credential: credential, binding: binding}

	wrongPurpose := fmt.Sprintf(`{"contract_version":"%s","type":"hello","binding":{"agent_run_uid":"%s","execution_id":"%s","driver_registration":"%s","desired_generation":%d,"guest_instance_id":"%s"},"audience":"%s","credential":"%s"}`+"\n",
		Version, binding.AgentRunUID, binding.ExecutionID, binding.DriverRegistration, binding.DesiredGeneration, binding.GuestInstanceID,
		guestenrollment.NativeGuestControlAudience, credential)
	for _, input := range [][]byte{
		[]byte(wrongPurpose),
		[]byte(`{"contract_version":"nvt.native-egress/v1","type":"flow_open","flow_id":"one","flow_id":"two","destination":{"network":"tcp","host":"example.com","port":443}}`),
		append(bytes.Repeat([]byte{'x'}, MaxFrameBytes), '\n'),
		{'{', '"', 'x', '"', ':', '"', 0xff, '"', '}', '\n'},
	} {
		gateway, guest := net.Pipe()
		result := make(chan error, 1)
		go func() {
			defer gateway.Close()
			_, err := Accept(t.Context(), gateway, authenticator)
			result <- err
		}()
		_, _ = guest.Write(input)
		_ = guest.Close()
		if err := <-result; err == nil || authenticator.calls.Load() != 0 {
			t.Fatalf("malformed input error=%v authority calls=%d", err, authenticator.calls.Load())
		}
	}

	message := Message{ContractVersion: Version, Type: Hello, Binding: &binding, Audience: guestenrollment.NativeEgressAudience, Credential: credential}
	for _, formatted := range []string{fmt.Sprint(message), fmt.Sprintf("%+v", message), fmt.Sprintf("%#v", message)} {
		if strings.Contains(formatted, credential) || !strings.Contains(formatted, "sensitive") {
			t.Fatalf("unsafe frame formatting %q", formatted)
		}
	}
	if formatted := fmt.Sprintf("%#v", authenticator); strings.Contains(formatted, credential) {
		t.Fatalf("test authority formatting exposed credential: %q", formatted)
	}
	authentication := Authentication{Binding: binding, Sequence: 1}
	if formatted := fmt.Sprintf("%#v", authentication); strings.Contains(formatted, binding.AgentRunUID) || strings.Contains(formatted, binding.GuestInstanceID) {
		t.Fatalf("ordinary authentication formatting exposed binding: %q", formatted)
	}
	if controlCredential, err := guestenrollment.GenerateGuestSessionCredential(1); err != nil || guestenrollment.ValidateNativeEgressCredential(controlCredential) == nil {
		t.Fatalf("native control credential crossed purpose: %v", err)
	}
}

func TestMessageAndDestinationBoundsFailClosed(t *testing.T) {
	binding := testBinding("run-a")
	credential := testCredential(t, 1)
	valid := Message{ContractVersion: Version, Type: Hello, Binding: &binding, Audience: guestenrollment.NativeEgressAudience, Credential: credential}
	if encoded, err := EncodeMessage(valid); err != nil || len(encoded) > MaxFrameBytes {
		t.Fatalf("valid hello error=%v size=%d", err, len(encoded))
	}
	flowOpen := Message{
		ContractVersion: Version, Type: FlowOpen, FlowID: "flow-1",
		Destination: &Destination{Network: NetworkTCP, Host: "api.example", Port: 443, CapabilityHint: "codex-main"},
	}
	encoded, err := EncodeMessage(flowOpen)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeMessage(encoded)
	if err != nil || decoded.FlowID != flowOpen.FlowID || decoded.Destination == nil || *decoded.Destination != *flowOpen.Destination {
		t.Fatalf("flow frame=%#v error=%v", decoded, err)
	}
	for _, destination := range []Destination{
		{},
		{Network: "udp", Host: "example.com", Port: 443},
		{Network: NetworkTCP, Host: "EXAMPLE.COM", Port: 443},
		{Network: NetworkTCP, Host: "example..com", Port: 443},
		{Network: NetworkTCP, Host: "-api.example", Port: 443},
		{Network: NetworkTCP, Host: "api-.example", Port: 443},
		{Network: NetworkTCP, Host: strings.Repeat("a", 64) + ".example", Port: 443},
		{Network: NetworkTCP, Host: "127.0.0.01", Port: 443},
		{Network: NetworkTCP, Host: "fe80::1%eth0", Port: 443},
		{Network: NetworkTCP, Host: "example.com", Port: 0},
		{Network: NetworkTCP, Host: "example.com", Port: 443, CapabilityHint: "Invalid Hint"},
	} {
		if ValidateDestination(destination) == nil {
			t.Fatalf("invalid destination accepted: %#v", destination)
		}
	}
	if ValidateDestination(Destination{Network: NetworkTCP, Host: "2001:db8::1", Port: 443, CapabilityHint: "codex-main"}) != nil {
		t.Fatal("canonical destination rejected")
	}
	for _, forbiddenType := range []string{"select_target", "open_internal_service", "delete", "enumerate"} {
		if ValidateMessage(Message{ContractVersion: Version, Type: forbiddenType}) == nil {
			t.Fatalf("forbidden guest operation %q accepted", forbiddenType)
		}
	}
}

func testBinding(name string) guestenrollment.Binding {
	return guestenrollment.Binding{
		AgentRunUID:        "11111111-2222-3333-4444-" + name,
		ExecutionID:        "execution-" + name,
		DriverRegistration: "driver-" + strings.TrimPrefix(name, "run-"),
		DesiredGeneration:  3,
		GuestInstanceID:    "guest-" + name,
	}
}

func testCredential(t *testing.T, sequence uint64) string {
	t.Helper()
	credential, err := guestenrollment.GenerateNativeEgressCredential(sequence)
	if err != nil {
		t.Fatal(err)
	}
	return credential
}
