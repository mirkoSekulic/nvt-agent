//go:build !linux

package captureinspect

import "net"

func OriginalDestination(*net.TCPConn) (string, error) {
	return "", invalidOriginalDestination()
}
