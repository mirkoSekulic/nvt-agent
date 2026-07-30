//go:build !linux

package nativeegressipc

import (
	"errors"
	"net"
)

func validateSocketPlatform(string, uint32) error {
	return errors.New("local native egress requires Linux")
}
func validateReadinessPlatform(string, uint32) error {
	return errors.New("local native egress requires Linux")
}
func validatePeer(net.Conn, uint32) error { return errors.New("local native egress requires Linux") }
