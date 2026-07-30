//go:build !linux

package capture

import (
	"net"

	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment/nativeegress/captureinspect"
)

func originalDestination(connection *net.TCPConn) (string, error) {
	return captureinspect.OriginalDestination(connection)
}
