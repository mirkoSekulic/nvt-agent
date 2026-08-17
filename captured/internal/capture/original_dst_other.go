//go:build !linux

package capture

import (
	"net"

	"github.com/mirkoSekulic/nvt-agent/captured/internal/captureinspect"
)

func originalDestination(connection *net.TCPConn) (string, error) {
	return captureinspect.OriginalDestination(connection)
}
