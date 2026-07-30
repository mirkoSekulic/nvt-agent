//go:build linux || darwin || freebsd

package relay

import (
	"errors"
	"io"
	"os"
	"syscall"
)

func readProcessOwnedFile(path string, maximum int, private bool) ([]byte, error) {
	if !validFilePath(path) || maximum < 1 {
		return nil, errors.New("native egress relay file is invalid")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	stat, ok := fileStat(info)
	permissions := os.FileMode(0)
	if info != nil {
		permissions = info.Mode().Perm()
	}
	if err != nil || info == nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > int64(maximum) || !ok ||
		stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 || permissions&0o022 != 0 || (private && permissions&0o077 != 0) {
		return nil, errors.New("native egress relay file is unsafe")
	}
	pathInfo, err := os.Lstat(path)
	if err != nil || pathInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(info, pathInfo) {
		return nil, errors.New("native egress relay file is unsafe")
	}
	data, err := io.ReadAll(io.LimitReader(file, int64(maximum)+1))
	if err != nil || len(data) == 0 || len(data) > maximum {
		zero(data)
		return nil, errors.New("native egress relay file is invalid")
	}
	return data, nil
}

func fileStat(info os.FileInfo) (*syscall.Stat_t, bool) {
	if info == nil {
		return nil, false
	}
	value, ok := info.Sys().(*syscall.Stat_t)
	return value, ok
}
