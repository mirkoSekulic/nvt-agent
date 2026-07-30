//go:build linux

package nativecapture

import (
	"errors"
	"net"
	"syscall"
)

func unixPeerCredentials(connection *net.UnixConn) (uint32, uint32, error) {
	raw, err := connection.SyscallConn()
	if err != nil {
		return 0, 0, err
	}
	var credential *syscall.Ucred
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		credential, socketErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil || socketErr != nil || credential == nil {
		return 0, 0, errors.New("native capture peer is unavailable")
	}
	return credential.Uid, credential.Gid, nil
}
