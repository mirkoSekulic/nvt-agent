package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/mirkoSekulic/nvt-agent/executiondrivers/qemu/internal/config"
	"github.com/mirkoSekulic/nvt-agent/executiondrivers/qemu/internal/wire"
	"github.com/mirkoSekulic/nvt-agent/operator/executiondriver"
	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment"
)

const (
	controlDevice  = "/dev/virtio-ports/org.nvt.control"
	secretRoot     = "/var/lib/nvt-enrollment"
	enrollmentPath = secretRoot + "/enrollment.json"
)

type enrollmentRecord struct {
	ContractVersion string                          `json:"contract_version"`
	Binding         guestenrollment.Binding         `json:"binding"`
	RuntimeIdentity guestenrollment.RuntimeIdentity `json:"runtime_identity"`
}

type guest struct {
	mu            sync.Mutex
	configuration *wire.BootConfiguration
	enrolled      bool
	ready         bool
	failed        bool
	bootstrap     chan struct{}
}

var (
	controlDiscoveryPendingLog sync.Once
	controlDeviceReadyLog      sync.Once
)

func main() {
	if err := initializeOS(); err != nil {
		fatal("operating-system setup failed")
	}
	guestLog("control channel starting")
	guest := &guest{bootstrap: make(chan struct{}, 1)}
	binding, identity, err := loadEnrollment()
	if err != nil {
		fatal("sensitive enrollment state is invalid")
	}
	if binding != nil && identity != nil {
		guest.enrolled = true
	}
	go guest.bootstrapLoop()
	go guest.serveHealth()
	for {
		if err := guest.serveControl(); err != nil {
			time.Sleep(100 * time.Millisecond)
		}
	}
}

func initializeOS() error {
	guestLog("mounting native filesystems")
	// The Alpine initramfs hands the native root to PID 1 read-only even when
	// the kernel command line requests rw. The execution disk is deliberately
	// writable and owns enrollment plus the installed immutable host release,
	// so make that contract explicit before accepting sensitive configuration.
	if err := syscall.Mount("", "/", "", syscall.MS_REMOUNT, ""); err != nil {
		guestLog("native root activation failed (" + filesystemFailureClass(err) + ")")
		return err
	}
	for _, mount := range []struct{ source, target, kind string }{
		{"proc", "/proc", "proc"}, {"sysfs", "/sys", "sysfs"}, {"devtmpfs", "/dev", "devtmpfs"}, {"devpts", "/dev/pts", "devpts"},
	} {
		if err := os.MkdirAll(mount.target, 0o755); err != nil {
			return err
		}
		if err := syscall.Mount(mount.source, mount.target, mount.kind, 0, ""); err != nil && !errors.Is(err, syscall.EBUSY) {
			return err
		}
	}
	// Entropy is auto-probed. Load both devices explicitly because the pinned
	// kernel may package either driver as a module.
	for _, module := range []string{"virtio_net", "virtio_console"} {
		if err := exec.Command("/sbin/modprobe", module).Run(); err != nil {
			guestLog("required virtio device is unavailable")
			return err
		}
	}
	// The minimal guest has no udev daemon. Populate devtmpfs from the mounted
	// sysfs after loading the drivers so virtio character devices and
	// mdev-conf's stable named links exist before the control channel starts.
	if err := exec.Command("/sbin/mdev", "-s").Run(); err != nil {
		guestLog("native device discovery failed")
		return err
	}
	guestLog("configuring native network")
	_ = exec.Command("/bin/busybox", "ip", "link", "set", "lo", "up").Run()
	deviceDeadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat("/sys/class/net/eth0"); err == nil {
			break
		}
		if time.Now().After(deviceDeadline) {
			guestLog("required network device is unavailable")
			return errors.New("required network device is unavailable")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err := exec.Command("/bin/busybox", "ip", "link", "set", "eth0", "up").Run(); err != nil {
		guestLog("native network configuration failed")
		return err
	}
	networkContext, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := exec.CommandContext(networkContext, "/bin/busybox", "udhcpc", "-i", "eth0", "-q", "-n", "-t", "10", "-T", "1").Run(); err != nil {
		guestLog("native network configuration failed")
		return err
	}
	// QEMU user networking owns this stable DNS forwarder. Do not retain the
	// container-build resolver (commonly 127.0.0.11) inside the native guest.
	resolverTemporary := "/etc/.nvt-resolv.conf"
	if err := os.WriteFile(resolverTemporary, []byte("nameserver 10.0.2.3\noptions timeout:1 attempts:3\n"), 0o644); err != nil {
		_ = os.Remove(resolverTemporary)
		guestLog("native DNS temporary write failed (" + filesystemFailureClass(err) + ")")
		return err
	}
	if err := os.Rename(resolverTemporary, "/etc/resolv.conf"); err != nil {
		_ = os.Remove(resolverTemporary)
		guestLog("native DNS activation failed (" + filesystemFailureClass(err) + ")")
		return err
	}
	return nil
}

// filesystemFailureClass keeps native-guest diagnostics actionable without
// exposing paths, enrollment material, or arbitrary operating-system errors.
func filesystemFailureClass(err error) string {
	switch {
	case errors.Is(err, syscall.EROFS):
		return "read-only-filesystem"
	case errors.Is(err, syscall.EACCES), errors.Is(err, syscall.EPERM):
		return "permission-denied"
	case errors.Is(err, syscall.ENOSPC):
		return "capacity-exhausted"
	case errors.Is(err, syscall.ENOENT):
		return "path-unavailable"
	default:
		return "filesystem-error"
	}
}

func (guest *guest) serveControl() error {
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		devicePath, locateErr := locateControlDevice()
		if locateErr != nil {
			controlDiscoveryPendingLog.Do(func() { guestLog("control device discovery pending") })
			time.Sleep(50 * time.Millisecond)
			continue
		}
		device, err := os.OpenFile(devicePath, os.O_RDWR, 0)
		if err == nil {
			controlDeviceReadyLog.Do(func() { guestLog("control device ready") })
			// QEMU may accept a host-side chardev connection before this port is
			// open and discard bytes written during that window. Announce that the
			// guest endpoint is ready before the host sends configuration or the
			// one-time enrollment envelope.
			greeting, encodeErr := wire.Encode(wire.Response{ContractVersion: wire.Version, State: wire.StateConnected})
			if encodeErr != nil {
				_ = device.Close()
				return errors.New("control greeting failed")
			}
			defer device.Close()
			// QEMU retains this bounded greeting until an exact host connection
			// reads it, including when the first host attempt times out while the
			// guest is still booting. Sending it once avoids an output backlog.
			if _, writeErr := device.Write(greeting); writeErr != nil {
				zero(greeting)
				return errors.New("control greeting failed")
			}
			zero(greeting)
			line, readErr := bufio.NewReader(io.LimitReader(device, wire.MaxMessageBytes+1)).ReadBytes('\n')
			if readErr != nil || len(line) > wire.MaxMessageBytes {
				zero(line)
				return errors.New("control framing failed")
			}
			guestLog("control request received")
			response := guest.handle(bytes.TrimSuffix(line, []byte{'\n'}))
			zero(line)
			encoded, err := wire.Encode(response)
			if err != nil {
				return err
			}
			_, err = device.Write(encoded)
			zero(encoded)
			if err == nil {
				guestLog("control response sent")
			}
			return err
		}
		time.Sleep(50 * time.Millisecond)
	}
	return errors.New("control device unavailable")
}

func locateControlDevice() (string, error) {
	if info, err := os.Lstat(controlDevice); err == nil && info.Mode()&os.ModeCharDevice != 0 {
		return controlDevice, nil
	}
	return locateControlDeviceAt("/sys/class/virtio-ports", "/dev")
}

// Minimal native guests do not run udev, so the friendly
// /dev/virtio-ports/<name> link may not exist. The kernel still publishes the
// stable port name through sysfs and creates its vport character device in
// devtmpfs; resolve that relationship without guessing a device number.
func locateControlDeviceAt(sysfsRoot, deviceRoot string) (string, error) {
	entries, err := os.ReadDir(sysfsRoot)
	if err != nil {
		return "", errors.New("control device is unavailable")
	}
	for _, entry := range entries {
		name, readErr := os.ReadFile(filepath.Join(sysfsRoot, entry.Name(), "name"))
		if readErr != nil || strings.TrimSpace(string(name)) != "org.nvt.control" {
			continue
		}
		path := filepath.Join(deviceRoot, entry.Name())
		info, statErr := os.Lstat(path)
		if statErr != nil || info.Mode()&os.ModeCharDevice == 0 {
			return "", errors.New("control device is invalid")
		}
		return path, nil
	}
	return "", errors.New("control device is unavailable")
}

func (guest *guest) handle(data []byte) wire.Response {
	var request wire.Request
	if executiondriver.DecodeStrictJSON(data, &request) != nil || request.ContractVersion != wire.Version {
		return wire.Response{ContractVersion: wire.Version, State: wire.StateFailed, Error: "invalid-request"}
	}
	switch request.Type {
	case wire.RequestConfigure:
		if request.Configuration == nil || request.Envelope != nil || validateBootConfiguration(*request.Configuration) != nil {
			return wire.Response{ContractVersion: wire.Version, State: wire.StateFailed, Error: "invalid-configuration"}
		}
		guest.mu.Lock()
		if guest.configuration != nil && guest.configuration.Binding != request.Configuration.Binding {
			guest.mu.Unlock()
			return wire.Response{ContractVersion: wire.Version, State: wire.StateFailed, Error: "binding-mismatch"}
		}
		if persisted, _, err := loadEnrollment(); err == nil && persisted != nil && *persisted != request.Configuration.Binding {
			guest.mu.Unlock()
			return wire.Response{ContractVersion: wire.Version, State: wire.StateFailed, Error: "binding-mismatch"}
		}
		copy := *request.Configuration
		guest.configuration = &copy
		state := guest.responseLocked()
		enrolled := guest.enrolled
		guest.mu.Unlock()
		if enrolled {
			guest.triggerBootstrap()
		}
		guestLog("control configuration accepted")
		return state
	case wire.RequestStatus:
		if request.Configuration != nil || request.Envelope != nil {
			return wire.Response{ContractVersion: wire.Version, State: wire.StateFailed, Error: "invalid-request"}
		}
		guest.mu.Lock()
		defer guest.mu.Unlock()
		return guest.responseLocked()
	case wire.RequestDeliver:
		if request.Envelope == nil || request.Configuration != nil {
			return wire.Response{ContractVersion: wire.Version, State: wire.StateFailed, Error: "invalid-envelope"}
		}
		return guest.deliver(request.Envelope)
	default:
		return wire.Response{ContractVersion: wire.Version, State: wire.StateFailed, Error: "invalid-request"}
	}
}

func (guest *guest) deliver(envelope *guestenrollment.BootstrapEnvelope) wire.Response {
	guest.mu.Lock()
	configuration := guest.configuration
	alreadyEnrolled := guest.enrolled
	guest.mu.Unlock()
	if configuration == nil || guestenrollment.ValidateBootstrapEnvelope(*envelope) != nil || envelope.Binding != configuration.Binding {
		return wire.Response{ContractVersion: wire.Version, State: wire.StateFailed, Error: "binding-mismatch"}
	}
	if !alreadyEnrolled {
		guestLog("enrollment exchange starting")
		result, err := exchange(*envelope, configuration.EnrollmentCAPEM)
		envelope.Token = ""
		if err != nil {
			guestLog(enrollmentFailureLog(err))
			return wire.Response{ContractVersion: wire.Version, State: wire.StateFailed, Error: "enrollment-failed"}
		}
		if persistEnrollment(result) != nil {
			result.RuntimeIdentity.Opaque = ""
			guestLog("enrollment persistence failed")
			return wire.Response{ContractVersion: wire.Version, State: wire.StateFailed, Error: "enrollment-failed"}
		}
		result.RuntimeIdentity.Opaque = ""
		guest.mu.Lock()
		guest.enrolled = true
		guest.failed = false
		guest.mu.Unlock()
		guestLog("enrollment accepted")
		guest.triggerBootstrap()
	}
	guest.mu.Lock()
	defer guest.mu.Unlock()
	return guest.responseLocked()
}

func enrollmentFailureLog(err error) string {
	switch err.Error() {
	case "enrollment trust is invalid":
		return "enrollment exchange failed: trust invalid"
	case "enrollment request is invalid":
		return "enrollment exchange failed: request invalid"
	case "enrollment issuer is unavailable":
		return "enrollment exchange failed: issuer unavailable"
	case "enrollment exchange was rejected":
		return "enrollment exchange failed: issuer rejected"
	case "enrollment result is invalid":
		return "enrollment exchange failed: result invalid"
	default:
		return "enrollment exchange failed"
	}
}

func exchange(envelope guestenrollment.BootstrapEnvelope, caPEM string) (guestenrollment.ExchangeResult, error) {
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(caPEM)) {
		return guestenrollment.ExchangeResult{}, errors.New("enrollment trust is invalid")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}}
	client := &http.Client{Transport: transport, Timeout: guestenrollment.MaxOperationDuration, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	value := guestenrollment.ExchangeRequest{ContractVersion: guestenrollment.Version, Binding: envelope.Binding, Token: envelope.Token}
	payload, err := json.Marshal(value)
	if err != nil || len(payload) > guestenrollment.MaxExchangeRequestBytes {
		zero(payload)
		return guestenrollment.ExchangeResult{}, errors.New("enrollment request is invalid")
	}
	defer zero(payload)
	ctx, cancel := context.WithTimeout(context.Background(), guestenrollment.MaxOperationDuration)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, envelope.ExchangeURL, bytes.NewReader(payload))
	if err != nil {
		return guestenrollment.ExchangeResult{}, errors.New("enrollment request is invalid")
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return guestenrollment.ExchangeResult{}, errors.New("enrollment issuer is unavailable")
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, guestenrollment.MaxExchangeResultBytes+1))
	if err != nil || len(body) > guestenrollment.MaxExchangeResultBytes || response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "application/json" {
		zero(body)
		return guestenrollment.ExchangeResult{}, errors.New("enrollment exchange was rejected")
	}
	defer zero(body)
	result, err := guestenrollment.DecodeExchangeResult(body)
	if err != nil || result.Binding != envelope.Binding {
		return guestenrollment.ExchangeResult{}, errors.New("enrollment result is invalid")
	}
	return result, nil
}

func persistEnrollment(result guestenrollment.ExchangeResult) error {
	return persistEnrollmentAt(enrollmentPath, result, atomicWrite)
}

func persistEnrollmentAt(path string, result guestenrollment.ExchangeResult, write func(string, []byte, os.FileMode) error) error {
	if guestenrollment.ValidateExchangeResult(result) != nil || os.MkdirAll(filepath.Dir(path), 0o700) != nil {
		return errors.New("enrollment state is invalid")
	}
	record := enrollmentRecord{ContractVersion: guestenrollment.Version, Binding: result.Binding, RuntimeIdentity: result.RuntimeIdentity}
	encoded, err := json.Marshal(record)
	if err != nil || write(path, append(encoded, '\n'), 0o600) != nil {
		return errors.New("enrollment state is unavailable")
	}
	return nil
}

func loadEnrollment() (*guestenrollment.Binding, *guestenrollment.RuntimeIdentity, error) {
	return loadEnrollmentAt(enrollmentPath)
}

func loadEnrollmentAt(path string) (*guestenrollment.Binding, *guestenrollment.RuntimeIdentity, error) {
	encoded, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, errors.New("enrollment state is unavailable")
	}
	var record enrollmentRecord
	if executiondriver.DecodeStrictJSON(encoded, &record) != nil || record.ContractVersion != guestenrollment.Version ||
		guestenrollment.ValidateExchangeResult(guestenrollment.ExchangeResult{
			ContractVersion: record.ContractVersion, Binding: record.Binding, RuntimeIdentity: record.RuntimeIdentity,
		}) != nil {
		return nil, nil, errors.New("enrollment state is invalid")
	}
	return &record.Binding, &record.RuntimeIdentity, nil
}

func validateBootConfiguration(value wire.BootConfiguration) error {
	if value.ContractVersion != wire.Version || guestenrollment.ValidateBinding(value.Binding) != nil || config.ValidateArtifact(value.HostBundle) != nil ||
		(value.RegistryCAPEM != "" && config.ValidateCAPEM(value.RegistryCAPEM) != nil) || config.ValidateCAPEM(value.EnrollmentCAPEM) != nil {
		return errors.New("boot configuration is invalid")
	}
	return nil
}

func (guest *guest) responseLocked() wire.Response {
	state := wire.StateWaiting
	if guest.failed {
		state = wire.StateFailed
	} else if guest.ready {
		state = wire.StateReady
	} else if guest.enrolled {
		state = wire.StateEnrolled
	}
	response := wire.Response{ContractVersion: wire.Version, State: state}
	if guest.configuration != nil {
		binding := guest.configuration.Binding
		response.Binding = &binding
	}
	return response
}

func (guest *guest) triggerBootstrap() {
	select {
	case guest.bootstrap <- struct{}{}:
	default:
	}
}

func (guest *guest) bootstrapLoop() {
	for range guest.bootstrap {
		for {
			guest.mu.Lock()
			configuration := guest.configuration
			enrolled, ready := guest.enrolled, guest.ready
			guest.mu.Unlock()
			if configuration == nil || !enrolled || ready {
				break
			}
			if err := runNativeGuest(*configuration, guest); err == nil {
				break
			}
			guest.mu.Lock()
			guest.failed, guest.ready = true, false
			guest.mu.Unlock()
			time.Sleep(5 * time.Second)
		}
	}
}

func runNativeGuest(configuration wire.BootConfiguration, guest *guest) error {
	caFile := "/run/nvt-agent/registry-ca.pem"
	if err := os.MkdirAll(filepath.Dir(caFile), 0o755); err != nil {
		return err
	}
	ca := []byte(configuration.RegistryCAPEM)
	if len(ca) == 0 {
		ca, _ = os.ReadFile("/etc/ssl/certs/ca-certificates.crt")
	}
	if err := os.WriteFile(caFile, ca, 0o600); err != nil {
		return err
	}
	command := exec.Command("/usr/local/bin/nvt-host-bootstrap", "--repository", configuration.HostBundle.Repository, "--digest", configuration.HostBundle.Digest, "--root", "/opt/nvt", "--os", "linux", "--arch", "amd64", "--timeout", "5m")
	command.Env = []string{"PATH=/usr/bin:/bin:/usr/local/bin", "SSL_CERT_FILE=" + caFile}
	command.Stdout, command.Stderr = io.Discard, io.Discard
	if err := command.Run(); err != nil {
		return errors.New("host bundle installation failed")
	}
	for _, directory := range []string{"/workspace", "/run/nvt-agent", "/var/lib/nvt-agent"} {
		if err := os.MkdirAll(directory, 0o700); err != nil || os.Chown(directory, 65532, 65532) != nil {
			return errors.New("native runtime directory setup failed")
		}
	}
	if err := os.MkdirAll("/etc/nvt-agent", 0o755); err != nil {
		return err
	}
	guestConfig := map[string]any{
		"version": 1, "python_path": "/usr/bin/python3", "tmux_path": "/usr/bin/tmux", "state_dir": "/var/lib/nvt-agent",
		"socket_path": "/run/nvt-agent/agentd.sock", "workspace": "/workspace", "session_name": "agent", "session_startup_grace_seconds": 0,
		"session_command": []string{"@release/bin/nvt-guest-session-fixture", "--output", "/var/lib/nvt-agent/session-input.log"},
	}
	encoded, _ := json.Marshal(guestConfig)
	if err := atomicWrite("/etc/nvt-agent/guest.json", append(encoded, '\n'), 0o644); err != nil {
		return err
	}
	supervisor := exec.Command("/opt/nvt/current/bin/nvt-guest-supervisor", "--config", "/etc/nvt-agent/guest.json")
	supervisor.Env = []string{"PATH=/usr/bin:/bin", "HOME=/var/lib/nvt-agent"}
	supervisor.Stdout, supervisor.Stderr = io.Discard, io.Discard
	supervisor.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65532, Gid: 65532}, Setpgid: true}
	if err := supervisor.Start(); err != nil {
		return errors.New("native guest supervisor could not start")
	}
	done := make(chan error, 1)
	go func() { done <- supervisor.Wait() }()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-done:
			return errors.New("native guest supervisor exited")
		default:
		}
		if data, err := os.ReadFile("/var/lib/nvt-agent/guest-ready"); err == nil && bytes.Equal(data, []byte("ready\n")) {
			guest.mu.Lock()
			guest.failed, guest.ready = false, true
			guest.mu.Unlock()
			if err := <-done; err != nil {
				guest.mu.Lock()
				guest.failed, guest.ready = true, false
				guest.mu.Unlock()
				return errors.New("native guest supervisor exited")
			}
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	_ = syscall.Kill(-supervisor.Process.Pid, syscall.SIGKILL)
	return errors.New("native guest readiness timed out")
}

func (guest *guest) serveHealth() {
	mux := http.NewServeMux()
	mux.HandleFunc("/ready", func(response http.ResponseWriter, request *http.Request) {
		guest.mu.Lock()
		ready := guest.ready
		guest.mu.Unlock()
		if request.Method != http.MethodGet || !ready {
			response.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		response.WriteHeader(http.StatusOK)
	})
	server := &http.Server{Addr: ":8080", Handler: mux, ReadHeaderTimeout: 2 * time.Second}
	_ = server.ListenAndServe()
}

func atomicWrite(path string, content []byte, mode os.FileMode) error {
	return atomicWriteBeforeCommit(path, content, mode, nil)
}

func atomicWriteBeforeCommit(path string, content []byte, mode os.FileMode, beforeCommit func() error) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".nvt-*.tmp")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(mode); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(content); err != nil || temporary.Sync() != nil || temporary.Close() != nil {
		return errors.New("atomic write failed")
	}
	if beforeCommit != nil && beforeCommit() != nil {
		return errors.New("atomic write failed")
	}
	if os.Rename(name, path) != nil {
		return errors.New("atomic write failed")
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func fatal(message string) {
	guestLog(message)
	os.Exit(1)
}

func guestLog(message string) {
	console, err := os.OpenFile("/dev/console", os.O_WRONLY, 0)
	if err == nil {
		_, _ = fmt.Fprintln(console, "nvt-qemu-guest: "+message)
		_ = console.Close()
		return
	}
	_, _ = fmt.Fprintln(os.Stderr, "nvt-qemu-guest: "+message)
}
