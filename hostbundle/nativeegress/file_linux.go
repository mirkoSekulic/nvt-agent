//go:build linux

package nativeegress

import (
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"syscall"
)

func unixPeerUID(connection *net.UnixConn) (uint32, error) {
	raw, err := connection.SyscallConn()
	if err != nil {
		return 0, err
	}
	var credential *syscall.Ucred
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		credential, socketErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil || socketErr != nil || credential == nil {
		return 0, errors.New("native egress peer is unavailable")
	}
	return credential.Uid, nil
}

func readProcessOwnedFile(path string, maximum int) ([]byte, error) {
	if !validFile(path) || maximum < 1 {
		return nil, errors.New("native egress file is invalid")
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	stat, ok := infoSys(info)
	if err != nil || info == nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 || info.Size() < 1 ||
		info.Size() > int64(maximum) || !ok || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 {
		return nil, errors.New("native egress file is unsafe")
	}
	data, err := io.ReadAll(io.LimitReader(file, int64(maximum)+1))
	if err != nil || len(data) == 0 || len(data) > maximum {
		zero(data)
		return nil, errors.New("native egress file is invalid")
	}
	if parent, err := filepath.EvalSymlinks(filepath.Dir(path)); err != nil || parent != filepath.Dir(path) {
		zero(data)
		return nil, errors.New("native egress file is unsafe")
	}
	return data, nil
}

func infoSys(info os.FileInfo) (*syscall.Stat_t, bool) {
	if info == nil {
		return nil, false
	}
	value, ok := info.Sys().(*syscall.Stat_t)
	return value, ok
}

func ownedByProcess(info os.FileInfo) bool {
	stat, ok := infoSys(info)
	return ok && stat.Uid == uint32(os.Geteuid())
}

func groupOwnedByProcess(info os.FileInfo) bool {
	stat, ok := infoSys(info)
	return ok && stat.Gid == uint32(os.Getegid())
}
