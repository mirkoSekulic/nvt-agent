//go:build !linux

package nativeegress

import (
	"errors"
	"net"
	"os"
)

func unixPeerUID(*net.UnixConn) (uint32, error) { return 0, errors.New("native egress requires Linux") }

func readProcessOwnedFile(_ string, _ int) ([]byte, error) {
	return nil, errors.New("native egress files require Linux")
}

func ownedByProcess(os.FileInfo) bool      { return false }
func groupOwnedByProcess(os.FileInfo) bool { return false }
