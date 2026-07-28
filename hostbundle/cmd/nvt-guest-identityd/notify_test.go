package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNotifySystemdReadyUsesExactUnixDatagram(t *testing.T) {
	path := filepath.Join(t.TempDir(), "notify.sock")
	listener, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	t.Setenv("NOTIFY_SOCKET", path)
	if err := notifySystemdReady(); err != nil {
		t.Fatal(err)
	}
	if err := listener.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 32)
	count, _, err := listener.ReadFromUnix(buffer)
	if err != nil || string(buffer[:count]) != "READY=1" {
		t.Fatalf("notification = %q, %v", buffer[:count], err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
}

func TestNotifySystemdReadyRejectsInvalidEndpoint(t *testing.T) {
	t.Setenv("NOTIFY_SOCKET", "relative.sock")
	if err := notifySystemdReady(); err == nil {
		t.Fatal("relative notification endpoint was accepted")
	}
}
