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
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/mirkoSekulic/nvt-agent/executiondrivers/qemu/internal/config"
	"github.com/mirkoSekulic/nvt-agent/executiondrivers/qemu/internal/wire"
	"github.com/mirkoSekulic/nvt-agent/hostbundle/guestidentity"
	"github.com/mirkoSekulic/nvt-agent/operator/executiondriver"
	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment"
)

const (
	controlDevice          = "/dev/virtio-ports/org.nvt.control"
	identityStateRoot      = "/var/lib/nvt-agent-identity"
	identityRuntimeRoot    = "/run/nvt-agent-identity"
	identityEnrollmentPath = identityStateRoot + "/enrollment.json"
	identityConfigPath     = "/etc/nvt-agent/identity.json"
	identityCAPath         = "/etc/nvt-agent/runtime-identity-ca.pem"
	sessionConfigPath      = "/etc/nvt-agent/session.json"
	sessionCAPath          = "/etc/nvt-agent/native-session-ca.pem"
	sessionRuntimeRoot     = "/run/nvt-agent-session"
	sessionReadinessPath   = sessionRuntimeRoot + "/session-ready"
	egressConfigPath       = "/etc/nvt-agent/native-egress.json"
	egressCAPath           = "/etc/nvt-agent/native-egress-ca.pem"
	egressRuntimeRoot      = "/run/nvt-agent-egress"
	egressFlowSocketPath   = egressRuntimeRoot + "/flow.sock"
	captureConfigPath      = "/etc/nvt-agent/native-capture.json"
	captureRuntimeRoot     = "/run/nvt-agent-capture"
	captureReadinessPath   = captureRuntimeRoot + "/ready.sock"
	nativeEgressProofPath  = "/workspace/native-egress-proof.json"
)

type guest struct {
	mu            sync.Mutex
	configuration *wire.BootConfiguration
	enrolled      bool
	ready         bool
	failed        bool
	bypassDenied  bool
	bootstrap     chan struct{}
}

type boundedDiagnostic struct{ data []byte }

func (diagnostic *boundedDiagnostic) Write(value []byte) (int, error) {
	written := len(value)
	remaining := 512 - len(diagnostic.data)
	if remaining > 0 {
		if len(value) > remaining {
			value = value[:remaining]
		}
		diagnostic.data = append(diagnostic.data, value...)
	}
	return written, nil
}

func (diagnostic *boundedDiagnostic) String() string { return string(diagnostic.data) }

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
	binding, err := loadEnrollmentBinding()
	if err != nil {
		fatal("sensitive enrollment state is invalid")
	}
	if binding != nil {
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
	// restrict=on owns forwarding outside the guest, but the guest still needs
	// a route for arbitrary destinations so OUTPUT DNAT can capture them before
	// slirp applies that external default-deny boundary.
	if err := exec.Command("/bin/busybox", "ip", "route", "replace", "default", "via", "10.0.2.2", "dev", "eth0").Run(); err != nil {
		guestLog("native network route configuration failed")
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
		if guest.configuration != nil && !reflect.DeepEqual(*guest.configuration, *request.Configuration) {
			guest.mu.Unlock()
			return wire.Response{ContractVersion: wire.Version, State: wire.StateFailed, Error: "invalid-configuration"}
		}
		persisted, loadErr := loadEnrollmentBinding()
		if loadErr != nil {
			guest.mu.Unlock()
			return wire.Response{ContractVersion: wire.Version, State: wire.StateFailed, Error: "state-invalid"}
		}
		if persisted != nil && *persisted != request.Configuration.Binding {
			guest.mu.Unlock()
			return wire.Response{ContractVersion: wire.Version, State: wire.StateFailed, Error: "binding-mismatch"}
		}
		if guest.configuration != nil {
			state := guest.responseLocked()
			enrolled := guest.enrolled
			guest.mu.Unlock()
			if enrolled {
				guest.triggerBootstrap()
			}
			return state
		}
		guest.mu.Unlock()
		// Install only the attachment's public host aliases before the one-time
		// enrollment exchange. The restrict=on backend deliberately provides no
		// ambient DNS; this guest-local routing is required plumbing but is never
		// consumed as the infrastructure-confinement assertion. Identical later
		// Configure calls return above, so this direct-bypass probe can never be
		// confused with an already-active capture path.
		if request.Configuration.NativeEgressAttachment != nil {
			if configureNativeEgressHosts(*request.Configuration) != nil || !directEgressIsConfined(*request.Configuration) {
				return wire.Response{ContractVersion: wire.Version, State: wire.StateFailed, Error: "network-unavailable"}
			}
		}
		guest.mu.Lock()
		copy := *request.Configuration
		guest.configuration = &copy
		guest.bypassDenied = request.Configuration.NativeEgressAttachment != nil
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
		err := acceptEnrollment(*envelope, configuration.EnrollmentCAPEM)
		envelope.Token = ""
		if err != nil {
			guestLog("enrollment exchange failed")
			return wire.Response{ContractVersion: wire.Version, State: wire.StateFailed, Error: "enrollment-failed"}
		}
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

func loadEnrollmentBinding() (*guestenrollment.Binding, error) {
	store, err := guestidentity.OpenStore(identityConfiguration())
	if err != nil {
		return nil, errors.New("identity state is unavailable")
	}
	binding, err := store.LoadActiveBinding()
	if err != nil {
		return nil, errors.New("identity state is invalid")
	}
	return binding, nil
}

func acceptEnrollment(envelope guestenrollment.BootstrapEnvelope, caPEM string) error {
	client, err := guestidentity.NewClient([]byte(caPEM))
	if err != nil {
		return errors.New("identity trust is invalid")
	}
	store, err := guestidentity.OpenStore(identityConfiguration())
	if err != nil {
		return errors.New("identity state is unavailable")
	}
	runtime, err := guestidentity.NewRuntime(store, client)
	if err != nil {
		return errors.New("identity lifecycle is unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), guestenrollment.MaxOperationDuration)
	defer cancel()
	if err := runtime.AcceptEnvelope(ctx, envelope); err != nil {
		return errors.New("identity enrollment failed")
	}
	return nil
}

func identityConfiguration() guestidentity.Configuration {
	return guestidentity.Configuration{
		Version: guestidentity.ConfigurationVersion, StateDirectory: identityStateRoot, RuntimeDirectory: identityRuntimeRoot,
		EnrollmentPath: identityEnrollmentPath, CAPEMPath: identityCAPath,
	}
}

func validateBootConfiguration(value wire.BootConfiguration) error {
	if value.ContractVersion != wire.Version || guestenrollment.ValidateBinding(value.Binding) != nil || config.ValidateArtifact(value.HostBundle) != nil ||
		(value.RegistryCAPEM != "" && config.ValidateCAPEM(value.RegistryCAPEM) != nil) || config.ValidateCAPEM(value.EnrollmentCAPEM) != nil ||
		config.ValidateCAPEM(value.NativeSessionCAPEM) != nil || config.ValidateNativeSessionEndpoint(value.NativeSessionEndpoint) != nil {
		return errors.New("boot configuration is invalid")
	}
	if value.NativeEgressAttachment == nil {
		if value.NativeEgressProbe != nil {
			return errors.New("boot configuration is invalid")
		}
		return nil
	}
	if executiondriver.ValidateNativeEgressAttachment(*value.NativeEgressAttachment) != nil {
		return errors.New("boot configuration is invalid")
	}
	if _, err := wire.NativeEgressHostAliases(*value.NativeEgressAttachment); err != nil {
		return errors.New("boot configuration is invalid")
	}
	if value.NativeEgressProbe != nil && config.ValidateNativeEgressProbe(*value.NativeEgressProbe) != nil {
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
			} else {
				// This reference-only console records a bounded, sanitized stage
				// reason so the real-guest proof cannot turn an unavailable data
				// plane into an opaque readiness timeout. The errors below are
				// fixed diagnostics and never contain configuration or authority.
				guestLog("native runtime setup retrying: " + err.Error())
			}
			guest.mu.Lock()
			guest.failed, guest.ready = true, false
			guest.mu.Unlock()
			time.Sleep(5 * time.Second)
		}
	}
}

func runNativeGuest(configuration wire.BootConfiguration, guest *guest) error {
	if configuration.NativeEgressAttachment != nil {
		// Revalidate the guest-side plumbing after enrollment. This is a defense
		// against accidental local drift, not the confinement authority; the
		// driver reports only its independent live QEMU process read-back.
		if err := configureNativeEgressHosts(configuration); err != nil || !directEgressIsConfined(configuration) {
			return errors.New("native egress infrastructure confinement failed")
		}
		guest.mu.Lock()
		guest.bypassDenied = true
		guest.mu.Unlock()
	}
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
	if err := probeRegistryTLS(configuration.HostBundle.Repository, ca); err != nil {
		guestLog("native host bundle trust probe failed (" + err.Error() + ")")
		return errors.New("host bundle trust probe failed")
	}
	guestLog("native host bundle trust probe complete")
	command := exec.Command("/usr/local/bin/nvt-host-bootstrap", "--repository", configuration.HostBundle.Repository, "--digest", configuration.HostBundle.Digest, "--root", "/opt/nvt", "--os", "linux", "--arch", "amd64", "--timeout", "5m")
	command.Env = []string{"PATH=/usr/bin:/bin:/usr/local/bin", "SSL_CERT_FILE=" + caFile}
	var bootstrapDiagnostic boundedDiagnostic
	command.Stdout, command.Stderr = io.Discard, &bootstrapDiagnostic
	guestLog("native host bundle installation starting")
	if err := command.Run(); err != nil {
		guestLog("native host bundle installation failed (" + hostBundleFailureClass(bootstrapDiagnostic.String()) + ")")
		return errors.New("host bundle installation failed")
	}
	guestLog("native host bundle installation complete")
	for _, directory := range []string{"/workspace", "/run/nvt-agent", "/var/lib/nvt-agent"} {
		if err := os.MkdirAll(directory, 0o700); err != nil || os.Chown(directory, 65532, 65532) != nil {
			return errors.New("native runtime directory setup failed")
		}
	}
	if err := os.Chmod("/run/nvt-agent", 0o750); err != nil {
		return errors.New("native runtime directory permissions failed")
	}
	if err := os.MkdirAll("/etc/nvt-agent", 0o755); err != nil {
		return err
	}
	if err := atomicWrite(identityCAPath, []byte(configuration.EnrollmentCAPEM), 0o600); err != nil {
		return errors.New("native identity trust setup failed")
	}
	identityConfigBytes, _ := json.Marshal(identityConfiguration())
	if err := atomicWrite(identityConfigPath, append(identityConfigBytes, '\n'), 0o600); err != nil {
		return errors.New("native identity configuration failed")
	}
	identityDaemon := exec.Command("/opt/nvt/current/bin/nvt-guest-identityd", "--config", identityConfigPath)
	identityDaemon.Env = []string{"PATH=/usr/bin:/bin"}
	identityDaemon.Stdout, identityDaemon.Stderr = io.Discard, io.Discard
	identityDaemon.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	guestLog("native identity daemon starting")
	if err := identityDaemon.Start(); err != nil {
		return errors.New("native identity daemon could not start")
	}
	identityDone := make(chan struct{})
	go func() { _ = identityDaemon.Wait(); close(identityDone) }()
	defer stopNativeProcess(identityDaemon, identityDone)
	identityDeadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(identityDeadline) {
		select {
		case <-identityDone:
			return errors.New("native identity daemon exited")
		default:
		}
		if data, err := os.ReadFile(filepath.Join(identityRuntimeRoot, guestidentity.ReadinessFileName)); err == nil && bytes.Equal(data, []byte("ready\n")) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if data, err := os.ReadFile(filepath.Join(identityRuntimeRoot, guestidentity.ReadinessFileName)); err != nil || !bytes.Equal(data, []byte("ready\n")) {
		return errors.New("native identity readiness timed out")
	}
	guestLog("native identity daemon ready")
	identityStatePath := filepath.Join(identityStateRoot, guestidentity.StateFileName)
	identityStateInfo, identityStateErr := os.Lstat(identityStatePath)
	identityStateStat, identityStateStatOK := identityStateInfoSys(identityStateInfo)
	if identityStateErr != nil || !identityStateInfo.Mode().IsRegular() || identityStateInfo.Mode().Perm() != 0o600 ||
		!identityStateStatOK || identityStateStat.Uid != 0 {
		return errors.New("native identity state is not private")
	}
	identityAccessProbe := exec.Command("/bin/cat", identityStatePath)
	identityAccessProbe.Stdout, identityAccessProbe.Stderr = io.Discard, io.Discard
	identityAccessProbe.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65532, Gid: 65532}}
	if identityAccessProbe.Run() == nil {
		return errors.New("agent user can read native identity state")
	}
	var egressDaemon, captureDaemon *exec.Cmd
	var egressDone, captureDone <-chan struct{}
	if configuration.NativeEgressAttachment != nil {
		var startErr error
		guestLog("native egress transport and capture starting")
		egressDaemon, egressDone, captureDaemon, captureDone, startErr = startNativeEgress(configuration)
		if startErr != nil {
			return startErr
		}
		defer func() {
			// Stop routing new ordinary flows before withdrawing the local
			// capture/transport pair. QEMU's host-owned restrict=on boundary
			// remains active throughout and prevents a direct fallback.
			removeNativeEgressRedirect(configuration.NativeEgressAttachment.Redirect.TransparentTCPPort)
			stopNativeProcess(captureDaemon, captureDone)
			stopNativeProcess(egressDaemon, egressDone)
		}()
	}
	guestConfig := map[string]any{
		"version": 1, "python_path": "/usr/bin/python3", "tmux_path": "/usr/bin/tmux", "state_dir": "/var/lib/nvt-agent",
		"socket_path": "/run/nvt-agent/agentd.sock", "workspace": "/workspace", "session_name": "agent",
		"session_readiness_path": sessionReadinessPath, "session_startup_grace_seconds": 0,
		"session_command": []string{"@release/bin/nvt-guest-session-fixture", "--output", "/var/lib/nvt-agent/session-input.log"},
	}
	if configuration.NativeEgressAttachment != nil {
		guestConfig["egress_readiness_socket_path"] = captureReadinessPath
		if configuration.NativeEgressProbe != nil {
			guestConfig["session_command"] = []string{
				"/usr/local/bin/nvt-qemu-agent-fixture",
				"--host", configuration.NativeEgressProbe.Host,
				"--port", fmt.Sprintf("%d", configuration.NativeEgressProbe.Port),
				"--capability", configuration.NativeEgressProbe.Capability,
				"--explicit-proxy", net.JoinHostPort(configuration.NativeEgressAttachment.Redirect.LoopbackAddress, fmt.Sprintf("%d", configuration.NativeEgressAttachment.Redirect.ExplicitCONNECTPort)),
				"--output", nativeEgressProofPath,
			}
		}
	}
	encoded, _ := json.Marshal(guestConfig)
	if err := atomicWrite("/etc/nvt-agent/guest.json", append(encoded, '\n'), 0o644); err != nil {
		return err
	}
	supervisor := exec.Command("/opt/nvt/current/bin/nvt-guest-supervisor", "--config", "/etc/nvt-agent/guest.json")
	supervisor.Env = []string{"PATH=/usr/bin:/bin", "HOME=/var/lib/nvt-agent"}
	supervisor.Stdout, supervisor.Stderr = io.Discard, io.Discard
	supervisor.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65532, Gid: 65532}, Setpgid: true}
	guestLog("native guest supervisor starting")
	if err := supervisor.Start(); err != nil {
		return errors.New("native guest supervisor could not start")
	}
	done := make(chan struct{})
	go func() { _ = supervisor.Wait(); close(done) }()
	defer stopNativeProcess(supervisor, done)
	agentdSocketDeadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(agentdSocketDeadline) {
		info, statErr := os.Lstat("/run/nvt-agent/agentd.sock")
		stat, statOK := identityStateInfoSys(info)
		if statErr == nil && info.Mode()&os.ModeSocket != 0 && info.Mode().Perm() == 0o660 && statOK && stat.Uid == 65532 && stat.Gid == 65532 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	agentdSocketInfo, agentdSocketErr := os.Lstat("/run/nvt-agent/agentd.sock")
	agentdSocketStat, agentdSocketStatOK := identityStateInfoSys(agentdSocketInfo)
	if agentdSocketErr != nil || agentdSocketInfo.Mode()&os.ModeSocket == 0 || agentdSocketInfo.Mode().Perm() != 0o660 ||
		!agentdSocketStatOK || agentdSocketStat.Uid != 65532 || agentdSocketStat.Gid != 65532 {
		return errors.New("native agentd socket permission contract failed")
	}
	agentdGroupProbe := exec.Command("/usr/bin/python3", "-c", "import socket; s=socket.socket(socket.AF_UNIX); s.settimeout(2); s.connect('/run/nvt-agent/agentd.sock'); s.sendall(b'{\"type\":\"health\"}\\n'); data=s.recv(4096); raise SystemExit(0 if b'\"status\":\"ready\"' in data else 1)")
	agentdGroupProbe.Stdout, agentdGroupProbe.Stderr = io.Discard, io.Discard
	agentdGroupProbe.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65531, Gid: 65532}}
	if agentdGroupProbe.Run() != nil {
		return errors.New("native agentd group access contract failed")
	}
	if err := atomicWrite(sessionCAPath, []byte(configuration.NativeSessionCAPEM), 0o600); err != nil {
		return errors.New("native session trust setup failed")
	}
	sessionConfig := map[string]any{
		"version": 1, "runtime_directory": sessionRuntimeRoot,
		"identity_socket_path": filepath.Join(identityRuntimeRoot, guestidentity.SessionCredentialSocketName),
		"agentd_socket_path":   "/run/nvt-agent/agentd.sock", "gateway_endpoint": configuration.NativeSessionEndpoint,
		"ca_pem_path": sessionCAPath,
	}
	sessionEncoded, _ := json.Marshal(sessionConfig)
	if err := atomicWrite(sessionConfigPath, append(sessionEncoded, '\n'), 0o600); err != nil {
		return errors.New("native session configuration failed")
	}
	sessionDaemon := exec.Command("/opt/nvt/current/bin/nvt-guest-sessiond", "--config", sessionConfigPath)
	sessionDaemon.Env = []string{"PATH=/usr/bin:/bin"}
	sessionDaemon.Stdout, sessionDaemon.Stderr = io.Discard, io.Discard
	sessionDaemon.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: 0, Gid: 65532}, Setpgid: true,
	}
	guestLog("native control session starting")
	if err := sessionDaemon.Start(); err != nil {
		return errors.New("native session daemon could not start")
	}
	sessionDone := make(chan struct{})
	go func() { _ = sessionDaemon.Wait(); close(sessionDone) }()
	defer stopNativeProcess(sessionDaemon, sessionDone)
	guestLog("native guest readiness pending")
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-done:
			return errors.New("native guest supervisor exited")
		case <-identityDone:
			return errors.New("native identity daemon exited")
		case <-sessionDone:
			return errors.New("native session daemon exited")
		case <-egressDone:
			return errors.New("native egress daemon exited")
		case <-captureDone:
			return errors.New("native capture daemon exited")
		default:
		}
		if data, err := os.ReadFile("/var/lib/nvt-agent/guest-ready"); err == nil && bytes.Equal(data, []byte("ready\n")) {
			guest.mu.Lock()
			guest.failed, guest.ready = false, true
			guest.mu.Unlock()
			select {
			case <-identityDone:
				guest.mu.Lock()
				guest.failed, guest.ready = true, false
				guest.mu.Unlock()
				return errors.New("native identity daemon exited")
			case <-done:
				guest.mu.Lock()
				guest.failed, guest.ready = true, false
				guest.mu.Unlock()
				return errors.New("native guest supervisor exited")
			case <-sessionDone:
				guest.mu.Lock()
				guest.failed, guest.ready = true, false
				guest.mu.Unlock()
				return errors.New("native session daemon exited")
			case <-egressDone:
				guest.mu.Lock()
				guest.failed, guest.ready = true, false
				guest.mu.Unlock()
				return errors.New("native egress daemon exited")
			case <-captureDone:
				guest.mu.Lock()
				guest.failed, guest.ready = true, false
				guest.mu.Unlock()
				return errors.New("native capture daemon exited")
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	_ = syscall.Kill(-supervisor.Process.Pid, syscall.SIGKILL)
	return errors.New("native guest readiness timed out")
}

func probeRegistryTLS(repository string, caPEM []byte) error {
	endpoint, err := url.Parse(repository)
	if err != nil || endpoint.Scheme != "https" || endpoint.Hostname() == "" {
		return errors.New("endpoint-invalid")
	}
	pool := x509.NewCertPool()
	if len(caPEM) == 0 || !pool.AppendCertsFromPEM(caPEM) {
		return errors.New("trust-invalid")
	}
	port := endpoint.Port()
	if port == "" {
		port = "443"
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	connection, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(endpoint.Hostname(), port), &tls.Config{
		MinVersion: tls.VersionTLS12, RootCAs: pool, ServerName: endpoint.Hostname(),
	})
	if err != nil {
		var verificationError *tls.CertificateVerificationError
		if errors.As(err, &verificationError) {
			return errors.New("trust-invalid")
		}
		return errors.New("connection-unavailable")
	}
	return connection.Close()
}

func hostBundleFailureClass(diagnostic string) string {
	for _, class := range []string{
		"invalid bootstrap configuration",
		"host-bundle acquisition failed",
		"host-bundle archive platform does not match the selected OCI platform",
		"host-bundle manifest could not be read after extraction",
		"host-bundle install directory is unavailable",
		"host-bundle install directory is unsafe",
	} {
		if strings.Contains(diagnostic, class) {
			return strings.ReplaceAll(class, " ", "-")
		}
	}
	return "installation-error"
}

func identityStateInfoSys(info os.FileInfo) (*syscall.Stat_t, bool) {
	if info == nil {
		return nil, false
	}
	value, ok := info.Sys().(*syscall.Stat_t)
	return value, ok
}

func configureNativeEgressHosts(configuration wire.BootConfiguration) error {
	if configuration.NativeEgressAttachment == nil {
		return nil
	}
	aliases, err := wire.NativeEgressHostAliases(*configuration.NativeEgressAttachment)
	if err != nil {
		return err
	}
	var content strings.Builder
	content.WriteString("127.0.0.1 localhost\n::1 localhost\n")
	for _, alias := range aliases {
		fmt.Fprintf(&content, "%s %s\n", alias.Address, alias.Host)
	}
	if configuration.NativeEgressProbe != nil {
		fmt.Fprintf(&content, "192.0.2.200 %s\n", configuration.NativeEgressProbe.Host)
	}
	return atomicWrite("/etc/hosts", []byte(content.String()), 0o644)
}

func directEgressIsConfined(configuration wire.BootConfiguration) bool {
	targets := []string{"1.1.1.1:443"}
	if configuration.NativeEgressProbe != nil {
		targets = append(targets, net.JoinHostPort(configuration.NativeEgressProbe.Host, fmt.Sprintf("%d", configuration.NativeEgressProbe.Port)))
	}
	for _, target := range targets {
		connection, err := net.DialTimeout("tcp", target, 500*time.Millisecond)
		if err == nil {
			_ = connection.Close()
			return false
		}
	}
	return true
}

func startNativeEgress(configuration wire.BootConfiguration) (*exec.Cmd, <-chan struct{}, *exec.Cmd, <-chan struct{}, error) {
	attachment := configuration.NativeEgressAttachment
	if attachment == nil || attachment.Redirect.LoopbackAddress != "127.0.0.1" {
		return nil, nil, nil, nil, errors.New("native egress configuration is unavailable")
	}
	if err := atomicWrite(egressCAPath, []byte(attachment.Relay.CAPEM), 0o600); err != nil {
		return nil, nil, nil, nil, errors.New("native egress trust setup failed")
	}
	egressConfig := map[string]any{
		"version": 1, "runtime_directory": egressRuntimeRoot,
		"identity_socket_path": filepath.Join(identityRuntimeRoot, guestidentity.SessionCredentialSocketName),
		// Connect through the host-owned guestfwd alias while retaining the
		// attachment's exact DNS serving identity for TLS verification.
		"relay_endpoint": fmt.Sprintf("tls://%s:%d", attachment.Relay.ServerName, attachment.Relay.Port),
		"ca_pem_path":    egressCAPath, "flow_socket_path": egressFlowSocketPath,
	}
	encoded, _ := json.Marshal(egressConfig)
	if err := atomicWrite(egressConfigPath, append(encoded, '\n'), 0o600); err != nil {
		return nil, nil, nil, nil, errors.New("native egress configuration failed")
	}
	egress := exec.Command("/opt/nvt/current/bin/nvt-guest-egressd", "--config", egressConfigPath)
	egress.Env = []string{"PATH=/usr/bin:/bin"}
	egress.Stdout, egress.Stderr = io.Discard, io.Discard
	egress.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := egress.Start(); err != nil {
		return nil, nil, nil, nil, errors.New("native egress daemon could not start")
	}
	egressDone := make(chan struct{})
	go func() { _ = egress.Wait(); close(egressDone) }()
	fail := func(message string) (*exec.Cmd, <-chan struct{}, *exec.Cmd, <-chan struct{}, error) {
		stopNativeProcess(egress, egressDone)
		return nil, nil, nil, nil, errors.New(message)
	}
	if !waitForSocket(egressFlowSocketPath, 0o600, egressDone, 10*time.Second) {
		return fail("native egress flow socket is unavailable")
	}
	captureConfig := map[string]any{
		"version": 1, "runtime_directory": captureRuntimeRoot,
		"transparent_listen_address": net.JoinHostPort(attachment.Redirect.LoopbackAddress, fmt.Sprintf("%d", attachment.Redirect.TransparentTCPPort)),
		"explicit_listen_address":    net.JoinHostPort(attachment.Redirect.LoopbackAddress, fmt.Sprintf("%d", attachment.Redirect.ExplicitCONNECTPort)),
		"flow_socket_path":           egressFlowSocketPath, "readiness_socket_path": captureReadinessPath,
	}
	captureEncoded, _ := json.Marshal(captureConfig)
	if err := atomicWrite(captureConfigPath, append(captureEncoded, '\n'), 0o600); err != nil {
		return fail("native capture configuration failed")
	}
	capture := exec.Command("/opt/nvt/current/bin/nvt-guest-captured", "--config", captureConfigPath)
	capture.Env = []string{"PATH=/usr/bin:/bin"}
	capture.Stdout, capture.Stderr = io.Discard, io.Discard
	capture.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 0, Gid: 65532}, Setpgid: true}
	if err := capture.Start(); err != nil {
		return fail("native capture daemon could not start")
	}
	captureDone := make(chan struct{})
	go func() { _ = capture.Wait(); close(captureDone) }()
	failBoth := func(message string) (*exec.Cmd, <-chan struct{}, *exec.Cmd, <-chan struct{}, error) {
		stopNativeProcess(capture, captureDone)
		stopNativeProcess(egress, egressDone)
		return nil, nil, nil, nil, errors.New(message)
	}
	if !waitForSocket(captureReadinessPath, 0o660, captureDone, 10*time.Second) {
		return failBoth("native capture readiness socket is unavailable")
	}
	if err := installNativeEgressRedirect(attachment.Redirect.TransparentTCPPort); err != nil {
		removeNativeEgressRedirect(attachment.Redirect.TransparentTCPPort)
		return failBoth("native egress redirect setup failed")
	}
	return egress, egressDone, capture, captureDone, nil
}

func waitForSocket(path string, mode os.FileMode, done <-chan struct{}, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		select {
		case <-done:
			return false
		default:
		}
		if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSocket != 0 && info.Mode().Perm() == mode {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

func installNativeEgressRedirect(port uint16) error {
	for _, module := range []string{"nf_tables", "nft_chain_nat", "nft_compat", "xt_nat"} {
		if err := exec.Command("/sbin/modprobe", module).Run(); err != nil {
			guestLog("native egress redirect module unavailable")
			return err
		}
	}
	binary := "/usr/sbin/iptables"
	if _, err := os.Stat(binary); err != nil {
		guestLog("native egress redirect tool unavailable")
		return err
	}
	// This is guest routing plumbing, never the enforcement assertion. Keep the
	// QEMU-owned pseudo-network endpoints outside the redirect so the protected
	// identity/control/relay clients cannot recurse; every other guest TCP flow
	// enters the credential-less capture process. restrict=on remains the
	// independently read-back bypass-prevention boundary.
	rules := [][]string{
		{"-p", "tcp", "-d", "127.0.0.0/8", "-j", "RETURN"},
		{"-p", "tcp", "-d", "10.0.2.0/24", "-j", "RETURN"},
		{"-p", "tcp", "-j", "DNAT", "--to-destination", net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", port))},
	}
	for _, rule := range rules {
		check := append([]string{"-t", "nat", "-C", "OUTPUT"}, rule...)
		if exec.Command(binary, check...).Run() == nil {
			continue
		}
		add := append([]string{"-t", "nat", "-A", "OUTPUT"}, rule...)
		if err := exec.Command(binary, add...).Run(); err != nil {
			guestLog("native egress redirect rule rejected")
			return err
		}
	}
	return nil
}

func removeNativeEgressRedirect(port uint16) {
	binary := "/usr/sbin/iptables"
	if _, err := os.Stat(binary); err != nil {
		return
	}
	// Delete only the exact rules owned by installNativeEgressRedirect. Work in
	// reverse order so no new ordinary flow is redirected after the catch-all
	// rule is removed. Missing rules are already the desired fail-closed state.
	rules := [][]string{
		{"-p", "tcp", "-d", "127.0.0.0/8", "-j", "RETURN"},
		{"-p", "tcp", "-d", "10.0.2.0/24", "-j", "RETURN"},
		{"-p", "tcp", "-j", "DNAT", "--to-destination", net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", port))},
	}
	for index := len(rules) - 1; index >= 0; index-- {
		for {
			remove := append([]string{"-t", "nat", "-D", "OUTPUT"}, rules[index]...)
			if exec.Command(binary, remove...).Run() != nil {
				break
			}
		}
	}
}

func guestObservabilityIsClean() bool {
	for _, root := range []string{"/workspace", "/var/lib/nvt-agent"} {
		if filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
			if err != nil || entry.IsDir() || !entry.Type().IsRegular() {
				return err
			}
			data, readErr := os.ReadFile(path)
			if readErr != nil || containsAuthorityMaterial(data) {
				return errors.New("authority material is visible")
			}
			return nil
		}) != nil {
			return false
		}
	}
	processes, err := filepath.Glob("/proc/[0-9]*")
	if err != nil {
		return false
	}
	for _, process := range processes {
		for _, name := range []string{"cmdline", "environ"} {
			data, readErr := os.ReadFile(filepath.Join(process, name))
			if readErr == nil && containsAuthorityMaterial(data) {
				return false
			}
		}
	}
	return true
}

func containsAuthorityMaterial(data []byte) bool {
	lower := bytes.ToLower(data)
	for _, value := range [][]byte{[]byte("nvt_eg1_"), []byte("nvt_ri1_"), []byte("nvt_e1_"), []byte("nvt_egress_broker_token"), []byte("relay-control-canary")} {
		if bytes.Contains(lower, value) {
			return true
		}
	}
	return false
}

func stopNativeProcess(command *exec.Cmd, done <-chan struct{}) {
	if command == nil || command.Process == nil {
		return
	}
	_ = syscall.Kill(-command.Process.Pid, syscall.SIGTERM)
	select {
	case <-done:
		return
	case <-time.After(5 * time.Second):
		_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
	}
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
	mux.HandleFunc("/native-egress-proof", func(response http.ResponseWriter, request *http.Request) {
		guest.mu.Lock()
		ready, bypassDenied := guest.ready, guest.bypassDenied
		configured := guest.configuration != nil && guest.configuration.NativeEgressAttachment != nil
		guest.mu.Unlock()
		if request.Method != http.MethodGet || !ready || !configured || !bypassDenied {
			response.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		data, err := os.ReadFile(nativeEgressProofPath)
		var proof struct {
			TransparentCredentialMatch bool   `json:"transparent_credential_match"`
			ExplicitCredentialMatch    bool   `json:"explicit_credential_match"`
			AuthorityMaterialAbsent    bool   `json:"authority_material_absent"`
			Failure                    string `json:"failure,omitempty"`
		}
		if err != nil || len(data) > 4096 || executiondriver.DecodeStrictJSON(data, &proof) != nil ||
			!proof.TransparentCredentialMatch || !proof.ExplicitCredentialMatch || !proof.AuthorityMaterialAbsent || !guestObservabilityIsClean() {
			response.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(map[string]bool{
			"mediated": true, "credential_match": true, "infrastructure_bypass_denied": true, "authority_material_absent": true,
		})
	})
	mux.HandleFunc("/native-egress-diagnostic", func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			response.WriteHeader(http.StatusNotFound)
			return
		}
		data, err := os.ReadFile(nativeEgressProofPath)
		var proof struct {
			TransparentCredentialMatch bool   `json:"transparent_credential_match"`
			ExplicitCredentialMatch    bool   `json:"explicit_credential_match"`
			AuthorityMaterialAbsent    bool   `json:"authority_material_absent"`
			Failure                    string `json:"failure,omitempty"`
		}
		if err != nil || len(data) > 4096 || executiondriver.DecodeStrictJSON(data, &proof) != nil || !validProofFailure(proof.Failure) {
			response.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = io.WriteString(response, proof.Failure+"\n")
	})
	mux.HandleFunc("/native-egress-routing-diagnostic", func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			response.WriteHeader(http.StatusNotFound)
			return
		}
		output, err := exec.Command("/usr/sbin/iptables", "-t", "nat", "-L", "OUTPUT", "-v", "-n", "-x").Output()
		if err != nil || len(output) > 16<<10 {
			response.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		for _, line := range strings.Split(string(output), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 3 || fields[2] != "DNAT" || !strings.Contains(line, "to:127.0.0.1:") {
				continue
			}
			packets, parseErr := strconv.ParseUint(fields[0], 10, 64)
			if parseErr == nil && packets > 0 {
				_, _ = io.WriteString(response, "redirect-hit\n")
				return
			}
		}
		_, _ = io.WriteString(response, "redirect-miss\n")
	})
	server := &http.Server{Addr: ":8080", Handler: mux, ReadHeaderTimeout: 2 * time.Second}
	_ = server.ListenAndServe()
}

func validProofFailure(value string) bool {
	for _, phase := range []string{"transparent", "explicit"} {
		for _, class := range []string{"pending", "resolve-unavailable", "dial-unavailable", "request-unavailable", "connect-unavailable", "tls-unavailable", "response-unavailable", "response-invalid", "unavailable"} {
			if value == phase+"-"+class {
				return true
			}
		}
	}
	return false
}

func atomicWrite(path string, content []byte, mode os.FileMode) error {
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
