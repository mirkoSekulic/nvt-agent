// Package nativecapture owns the credential-less Linux guest capture process.
// It parses agent-controlled TCP/HTTP/TLS input, but it cannot represent or
// receive a runtime identity, egress bearer, or exact enrollment binding.
package nativecapture

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/mirkoSekulic/nvt-agent/hostbundle/contract"
)

const (
	ConfigurationVersion  = 1
	MaxConfigurationBytes = 64 << 10
	InspectBytes          = 16 << 10
	MaxConnections        = 64
)

type Configuration struct {
	Version                  int    `json:"version"`
	RuntimeDirectory         string `json:"runtime_directory"`
	TransparentListenAddress string `json:"transparent_listen_address"`
	ExplicitListenAddress    string `json:"explicit_listen_address"`
	FlowSocketPath           string `json:"flow_socket_path"`
	ReadinessSocketPath      string `json:"readiness_socket_path"`
}

func LoadConfiguration(path string) (Configuration, error) {
	data, err := readOwned(path, MaxConfigurationBytes)
	if err != nil {
		return Configuration{}, errors.New("native capture configuration is unavailable")
	}
	defer zero(data)
	var value Configuration
	if contract.DecodeStrict(data, MaxConfigurationBytes, &value) != nil || ValidateConfiguration(value) != nil {
		return Configuration{}, errors.New("native capture configuration is invalid")
	}
	return value, nil
}

func ValidateConfiguration(value Configuration) error {
	if value.Version != ConfigurationVersion || !validDirectory(value.RuntimeDirectory) ||
		!validFile(value.FlowSocketPath) || !validFile(value.ReadinessSocketPath) ||
		filepath.Dir(value.ReadinessSocketPath) != value.RuntimeDirectory ||
		value.FlowSocketPath == value.ReadinessSocketPath ||
		validateLoopback(value.TransparentListenAddress) != nil || validateLoopback(value.ExplicitListenAddress) != nil ||
		value.TransparentListenAddress == value.ExplicitListenAddress {
		return errors.New("native capture configuration is invalid")
	}
	return nil
}

func validateLoopback(value string) error {
	host, portText, err := net.SplitHostPort(value)
	if err != nil {
		return errors.New("native capture listener is invalid")
	}
	address, addressErr := netip.ParseAddr(host)
	port, portErr := strconv.Atoi(portText)
	if addressErr != nil || address.Zone() != "" || !address.IsLoopback() || address.String() != host ||
		portErr != nil || port < 1024 || port > 65535 || portText != strconv.Itoa(port) {
		return errors.New("native capture listener is invalid")
	}
	return nil
}

func (Configuration) String() string   { return "[non-secret native capture configuration]" }
func (Configuration) GoString() string { return "[non-secret native capture configuration]" }

func validDirectory(value string) bool {
	return filepath.IsAbs(value) && filepath.Clean(value) == value && value != "/" && !strings.ContainsRune(value, 0)
}

func validFile(value string) bool {
	return filepath.IsAbs(value) && filepath.Clean(value) == value && filepath.Dir(value) != value && !strings.ContainsRune(value, 0)
}

func readOwned(path string, maximum int) ([]byte, error) {
	if !validFile(path) || maximum < 1 {
		return nil, errors.New("native capture file is invalid")
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	var stat *syscall.Stat_t
	var ok bool
	if info != nil {
		stat, ok = info.Sys().(*syscall.Stat_t)
	}
	if err != nil || info == nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 || info.Size() < 1 ||
		info.Size() > int64(maximum) || !ok || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 {
		return nil, errors.New("native capture file is unsafe")
	}
	if parent, err := filepath.EvalSymlinks(filepath.Dir(path)); err != nil || parent != filepath.Dir(path) {
		return nil, errors.New("native capture file is unsafe")
	}
	return io.ReadAll(io.LimitReader(file, int64(maximum)+1))
}

func ensureRuntimeDirectory(path string) error {
	if !validDirectory(path) {
		return errors.New("native capture runtime directory is invalid")
	}
	if err := os.Mkdir(path, 0o750); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	info, err := os.Lstat(path)
	stat, ok := info.Sys().(*syscall.Stat_t)
	if err != nil || info == nil || !info.IsDir() || info.Mode().Perm() != 0o750 || info.Mode()&os.ModeSymlink != 0 ||
		!ok || stat.Uid != uint32(os.Geteuid()) || stat.Gid != uint32(os.Getegid()) {
		return errors.New("native capture runtime directory is unsafe")
	}
	return nil
}

func zero(data []byte) {
	for index := range data {
		data[index] = 0
	}
}
