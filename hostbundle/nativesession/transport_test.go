package nativesession

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
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
	if validateConfiguration(configuration) != nil {
		t.Fatal("legacy control-only configuration was rejected")
	}
	encoded, err := json.Marshal(configuration)
	if err != nil || bytes.Contains(encoded, []byte("workspace")) {
		t.Fatalf("omitted workspace changed control-only encoding: %s error=%v", encoded, err)
	}
	configurationPath := filepath.Join(root, "session.json")
	if err := os.WriteFile(configurationPath, append(encoded, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadConfiguration(configurationPath)
	if err != nil || loaded.Workspace != nil || !reflect.DeepEqual(loaded, configuration) {
		t.Fatalf("control-only round trip=%#v error=%v", loaded, err)
	}
	configuration.Workspace = &WorkspaceConfiguration{
		GatewayEndpoint: "tls://workspace.example:7444", LoopbackEndpoint: "127.0.0.1:4090",
	}
	if validateConfiguration(configuration) != nil {
		t.Fatal("valid workspace configuration was rejected")
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
	for _, target := range []string{"localhost:4090", "0.0.0.0:4090", "127.0.0.1:0", "127.0.0.1:99999", "/tmp/workspace.sock"} {
		value := configuration
		workspace := *configuration.Workspace
		workspace.LoopbackEndpoint = target
		value.Workspace = &workspace
		if validateConfiguration(value) == nil {
			t.Fatalf("unsafe workspace target accepted: %s", target)
		}
	}
	for _, endpoint := range []string{"http://workspace.example:7444", "tls://127.0.0.1:7444", "tls://workspace.example:0", "tls://workspace.example:7444/path"} {
		value := configuration
		workspace := *configuration.Workspace
		workspace.GatewayEndpoint = endpoint
		value.Workspace = &workspace
		if validateConfiguration(value) == nil {
			t.Fatalf("unsafe workspace gateway accepted: %s", endpoint)
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
