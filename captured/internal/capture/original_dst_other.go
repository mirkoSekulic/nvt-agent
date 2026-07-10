//go:build !linux

package capture

import (
	"errors"
	"net"
)

func originalDestination(*net.TCPConn) (string, error) {
	return "", errors.New("SO_ORIGINAL_DST is only supported on Linux")
}
