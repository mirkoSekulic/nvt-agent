//go:build !linux

package nativecapture

import (
	"errors"
	"net"
)

func unixPeerCredentials(*net.UnixConn) (uint32, uint32, error) {
	return 0, 0, errors.New("native capture requires Linux")
}
