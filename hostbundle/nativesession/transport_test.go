package nativesession

import (
	"bytes"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment"
)

func TestGatewayFramingUsesAbsoluteBoundAndRejectsOverflow(t *testing.T) {
	for name, writer := range map[string]func(net.Conn){
		"overflow": func(connection net.Conn) {
			_, _ = connection.Write(bytes.Repeat([]byte{'x'}, guestenrollment.MaxNativeSessionFrameBytes+128))
		},
		"slow drip": func(connection net.Conn) {
			for index := 0; index < 20; index++ {
				if _, err := connection.Write([]byte{'x'}); err != nil {
					return
				}
				time.Sleep(10 * time.Millisecond)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			go writer(server)
			started := time.Now()
			_, err := readFrame(newFrameReader(client), client, time.Now().Add(50*time.Millisecond))
			reason, _, _ := FailureDetails(err)
			if err == nil || (name == "overflow" && reason != ReasonProtocolInvalid) || time.Since(started) > 300*time.Millisecond {
				t.Fatalf("bounded read = %v (%s) after %s", err, reason, time.Since(started))
			}
		})
	}
}

func TestConfigurationRejectsUnsafeEndpointAndFiles(t *testing.T) {
	root := t.TempDir()
	runtimeDirectory := filepath.Join(root, "run")
	configuration := Configuration{
		Version: ConfigurationVersion, RuntimeDirectory: runtimeDirectory,
		IdentitySocketPath: filepath.Join(root, "identity.sock"), AgentdSocketPath: filepath.Join(root, "agentd.sock"),
		GatewayEndpoint: "tls://gateway.example:7443", CAPEMPath: filepath.Join(root, "ca.pem"),
	}
	for _, endpoint := range []string{
		"http://gateway.example:7443", "tls://127.0.0.1:7443", "tls://gateway.example:0",
		"tls://gateway.example:99999", "tls://user@gateway.example:7443", "tls://gateway.example:7443/path",
	} {
		value := configuration
		value.GatewayEndpoint = endpoint
		if validateConfiguration(value) == nil {
			t.Fatalf("unsafe endpoint accepted: %s", endpoint)
		}
	}
	if err := os.Mkdir(runtimeDirectory, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := ensureRuntimeDirectory(runtimeDirectory); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(runtimeDirectory, 0o770); err != nil {
		t.Fatal(err)
	}
	if err := ensureRuntimeDirectory(runtimeDirectory); err == nil {
		t.Fatal("group-writable runtime directory was accepted")
	}
	if err := os.WriteFile(configuration.CAPEMPath, []byte("not-a-ca"), 0o622); err != nil {
		t.Fatal(err)
	}
	if _, err := NewTLSConnectorFromFile(configuration.CAPEMPath); err == nil {
		t.Fatal("writable trust file was accepted")
	}
	if _, err := os.Stat(configuration.CAPEMPath); errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
}
