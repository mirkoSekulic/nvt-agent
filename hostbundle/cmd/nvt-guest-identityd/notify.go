package main

import (
	"errors"
	"net"
	"os"
	"strings"
)

func notifySystemdReady() error {
	path := os.Getenv("NOTIFY_SOCKET")
	if path == "" {
		return nil
	}
	if len(path) > 100 || (path[0] != '/' && path[0] != '@') || strings.ContainsAny(path, "\r\n\x00") {
		return errors.New("systemd notification endpoint is invalid")
	}
	if path[0] == '@' {
		path = "\x00" + path[1:]
	}
	connection, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		return errors.New("systemd notification failed")
	}
	defer connection.Close()
	if _, err := connection.Write([]byte("READY=1")); err != nil {
		return errors.New("systemd notification failed")
	}
	return nil
}
