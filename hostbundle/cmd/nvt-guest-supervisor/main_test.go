package main

import (
	"bufio"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mirkoSekulic/nvt-agent/hostbundle/nativeegressipc"
)

func TestOptionalEgressReadinessSocketIsDistinctAndLive(t *testing.T) {
	config := configuration{
		SocketPath: "/run/nvt-agent/agentd.sock", SessionReadinessPath: "/run/nvt-agent-session/session-ready",
		EgressReadinessSocketPath: "/run/nvt-agent-capture/ready.sock",
	}
	if !validEgressReadinessPath(config) {
		t.Fatal("valid egress readiness socket was rejected")
	}
	for _, value := range []string{"relative", config.SocketPath, config.SessionReadinessPath} {
		config.EgressReadinessSocketPath = value
		if validEgressReadinessPath(config) {
			t.Fatalf("invalid egress readiness socket %q was accepted", value)
		}
	}

	directory := filepath.Join(t.TempDir(), "run")
	if err := os.Mkdir(directory, 0o750); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(directory, "ready.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := os.Chmod(socket, 0o660); err != nil {
		t.Fatal(err)
	}
	previous := readinessOwnerUID
	readinessOwnerUID = uint32(os.Geteuid())
	t.Cleanup(func() { readinessOwnerUID = previous })
	release := make(chan struct{})
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer connection.Close()
		_, _ = bufio.NewReader(connection).ReadBytes('\n')
		response, _ := nativeegressipc.EncodeResponse(nativeegressipc.Response{Version: nativeegressipc.Version, Type: nativeegressipc.Ready, Epoch: 1})
		_, _ = connection.Write(response)
		<-release
	}()
	done := make(chan struct{})
	lease, err := waitForEgressReadiness(socket, time.Now().Add(time.Second), done)
	if err != nil {
		t.Fatal(err)
	}
	closed := make(chan struct{})
	go func() { nativeegressipc.WaitClosed(lease); close(closed) }()
	select {
	case <-closed:
		t.Fatal("live readiness lease closed early")
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("readiness lease survived server loss")
	}
	_ = lease.Close()

	if err := os.Remove(socket); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if err := os.WriteFile(socket, []byte("ready\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := waitForEgressReadiness(socket, time.Now().Add(100*time.Millisecond), done); err == nil {
		t.Fatal("stale regular readiness marker was accepted")
	}
}
