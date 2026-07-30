//go:build linux

package nativeegressipc

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"syscall"
)

func validateSocketPlatform(path string, ownerUID uint32) error {
	if err := validateSocketNode(path, ownerUID); err != nil {
		return err
	}
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil || !parent.IsDir() || parent.Mode()&os.ModeSymlink != 0 || parent.Mode().Perm() != 0o700 {
		return errors.New("local native egress directory is unsafe")
	}
	stat, ok := parent.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != ownerUID || stat.Nlink < 1 {
		return errors.New("local native egress directory is unsafe")
	}
	return nil
}

func validateSocketNode(path string, ownerUID uint32) error {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o007 != 0 {
		return errors.New("local native egress socket is unsafe")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != ownerUID || stat.Nlink != 1 {
		return errors.New("local native egress socket is unsafe")
	}
	return nil
}

func validateReadinessPlatform(path string, ownerUID uint32) error {
	if err := validateSocketNode(path, ownerUID); err != nil {
		return err
	}
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil || !parent.IsDir() || parent.Mode()&os.ModeSymlink != 0 || parent.Mode().Perm() != 0o750 {
		return errors.New("local native egress readiness directory is unsafe")
	}
	stat, ok := parent.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != ownerUID || stat.Nlink < 1 {
		return errors.New("local native egress readiness directory is unsafe")
	}
	return nil
}

func validatePeer(connection net.Conn, ownerUID uint32) error {
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok {
		return errors.New("local native egress peer is invalid")
	}
	raw, err := unixConnection.SyscallConn()
	if err != nil {
		return err
	}
	var credential *syscall.Ucred
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		credential, socketErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil || socketErr != nil || credential == nil || credential.Uid != ownerUID {
		return errors.New("local native egress peer is invalid")
	}
	return nil
}
