package handoff

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment"
)

func TestPrivateUnixHandoffRoundTrip(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "handoff.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	binding := guestenrollment.Binding{AgentRunUID: "uid", ExecutionID: "execution", DriverRegistration: "fake", DesiredGeneration: 1, GuestInstanceID: "guest"}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/prepare", func(response http.ResponseWriter, request *http.Request) {
		if _, err := guestenrollment.DecodeHandoffPrepareRequest(readRequest(t, request)); err != nil {
			t.Error(err)
		}
		writeResponse(t, response, guestenrollment.HandoffPrepareResult{ContractVersion: guestenrollment.HandoffVersion, GuestInstanceID: binding.GuestInstanceID, State: guestenrollment.HandoffStatePrepared, NewlyPrepared: true})
	})
	mux.HandleFunc("/v1/replace", func(response http.ResponseWriter, request *http.Request) {
		if _, err := guestenrollment.DecodeHandoffReplaceRequest(readRequest(t, request)); err != nil {
			t.Error(err)
		}
		writeResponse(t, response, guestenrollment.HandoffPrepareResult{ContractVersion: guestenrollment.HandoffVersion, GuestInstanceID: "guest-new", State: guestenrollment.HandoffStatePrepared, NewlyPrepared: true})
	})
	mux.HandleFunc("/v1/deliver", func(response http.ResponseWriter, request *http.Request) {
		if _, err := guestenrollment.DecodeHandoffDeliverRequest(readRequest(t, request)); err != nil {
			t.Error(err)
		}
		writeResponse(t, response, guestenrollment.HandoffAcknowledgement{ContractVersion: guestenrollment.HandoffVersion})
	})
	server := &http.Server{Handler: mux, ReadHeaderTimeout: time.Second}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Shutdown(context.Background()) })
	client, err := NewLocalClient(socket, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := client.Prepare(context.Background(), guestenrollment.HandoffPrepareRequest{ContractVersion: guestenrollment.HandoffVersion, ExecutionScope: binding.ExecutionScope(), DesiredGeneration: 1})
	if err != nil || prepared.GuestInstanceID != binding.GuestInstanceID {
		t.Fatalf("prepare=%#v err=%v", prepared, err)
	}
	replaced, err := client.Replace(context.Background(), guestenrollment.HandoffReplaceRequest{ContractVersion: guestenrollment.HandoffVersion, Binding: binding})
	if err != nil || replaced.GuestInstanceID != "guest-new" {
		t.Fatalf("replace=%#v err=%v", replaced, err)
	}
	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	binding.GuestInstanceID = replaced.GuestInstanceID
	if err := client.Deliver(context.Background(), guestenrollment.HandoffDeliverRequest{ContractVersion: guestenrollment.HandoffVersion, Envelope: guestenrollment.BootstrapEnvelope{
		ContractVersion: guestenrollment.Version, Binding: binding, ExchangeURL: "https://broker.example/v1/guest-enrollment/exchange",
		Token: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", IssuedAt: guestenrollment.FormatTimestamp(now), ExpiresAt: guestenrollment.FormatTimestamp(now.Add(time.Minute)),
	}}); err != nil {
		t.Fatal(err)
	}
}

func TestPrivateUnixHandoffRejectsNonSocketAndMalformedResponse(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-a-socket")
	if err := os.WriteFile(path, []byte("not a socket"), 0o600); err != nil {
		t.Fatal(err)
	}
	client, err := NewLocalClient(path, 100*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Prepare(context.Background(), guestenrollment.HandoffPrepareRequest{ContractVersion: guestenrollment.HandoffVersion, ExecutionScope: guestenrollment.ExecutionScope{AgentRunUID: "uid", ExecutionID: "execution", DriverRegistration: "fake"}, DesiredGeneration: 1})
	if err != ErrUnavailable {
		t.Fatalf("non-socket error=%v", err)
	}
}

func readRequest(t *testing.T, request *http.Request) []byte {
	t.Helper()
	data, err := io.ReadAll(request.Body)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func writeResponse(t *testing.T, response http.ResponseWriter, value any) {
	t.Helper()
	response.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(response).Encode(value); err != nil {
		t.Fatal(err)
	}
}
