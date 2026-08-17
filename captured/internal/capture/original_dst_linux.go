//go:build linux

package capture

import (
	"net"

	"github.com/mirkoSekulic/nvt-agent/captured/internal/captureinspect"
)

func originalDestination(conn *net.TCPConn) (string, error) {
	return captureinspect.OriginalDestination(conn)
}
