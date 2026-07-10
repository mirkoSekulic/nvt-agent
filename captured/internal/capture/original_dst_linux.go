//go:build linux

package capture

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

const soOriginalDst = 80

func originalDestination(conn *net.TCPConn) (string, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return "", err
	}
	var destination string
	var socketErr error
	err = raw.Control(func(fd uintptr) {
		var address [128]byte
		length := uint32(len(address))
		_, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd, syscall.SOL_IP, soOriginalDst,
			uintptr(unsafe.Pointer(&address[0])), uintptr(unsafe.Pointer(&length)), 0)
		if errno != 0 {
			length = uint32(len(address))
			_, _, errno = syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd, syscall.SOL_IPV6, soOriginalDst,
				uintptr(unsafe.Pointer(&address[0])), uintptr(unsafe.Pointer(&length)), 0)
			if errno != 0 {
				socketErr = errno
				return
			}
		}
		port := binary.BigEndian.Uint16(address[2:4])
		switch address[0] {
		case syscall.AF_INET:
			if length < 8 {
				socketErr = fmt.Errorf("short IPv4 original destination")
				return
			}
			ip := net.IPv4(address[4], address[5], address[6], address[7])
			destination = net.JoinHostPort(ip.String(), fmt.Sprint(port))
		case syscall.AF_INET6:
			if length < 24 {
				socketErr = fmt.Errorf("short IPv6 original destination")
				return
			}
			ip := net.IP(append([]byte(nil), address[8:24]...))
			destination = net.JoinHostPort(ip.String(), fmt.Sprint(port))
		default:
			socketErr = fmt.Errorf("unsupported original destination family")
		}
	})
	if err != nil {
		return "", err
	}
	if socketErr != nil {
		return "", socketErr
	}
	return destination, nil
}
