//go:build !linux

package guestidentity

import (
	"errors"
	"net"
)

func unixPeerUID(_ *net.UnixConn) (uint32, error) {
	return 0, errors.New("peer credentials are unsupported")
}
