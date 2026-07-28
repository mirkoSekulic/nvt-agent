package driver

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/mirkoSekulic/nvt-agent/executiondrivers/qemu/internal/wire"
	"github.com/mirkoSekulic/nvt-agent/operator/executiondriver"
	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment"
)

type QEMUConfig struct {
	Binary       string
	Kernel       string
	Initramfs    string
	DiskTemplate string
	StateRoot    string
}

type QEMUManager struct {
	config      QEMUConfig
	imageDigest string
	mu          sync.Mutex
	active      map[string]*activeMachine
}

type activeMachine struct {
	command *exec.Cmd
	done    chan struct{}
}

func NewQEMUManager(value QEMUConfig) (*QEMUManager, error) {
	for _, path := range []string{value.Binary, value.Kernel, value.Initramfs, value.DiskTemplate} {
		if !regularFile(path) {
			return nil, errors.New("QEMU runtime artifact is unavailable")
		}
	}
	if value.StateRoot == "" {
		return nil, errors.New("QEMU state root is unavailable")
	}
	digest, err := aggregateDigest(value.Kernel, value.Initramfs, value.DiskTemplate)
	if err != nil {
		return nil, errors.New("QEMU guest image could not be verified")
	}
	return &QEMUManager{config: value, imageDigest: digest, active: map[string]*activeMachine{}}, nil
}

func (manager *QEMUManager) GuestImageDigest() (string, error) { return manager.imageDigest, nil }

func (manager *QEMUManager) Ensure(ctx context.Context, state *State) error {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if machine := manager.active[state.ExecutionID]; machine != nil {
		select {
		case <-machine.done:
			delete(manager.active, state.ExecutionID)
		default:
			return nil
		}
	}
	runDirectory := (Store{Root: manager.config.StateRoot}).RunDir(state.ExecutionID)
	if err := os.MkdirAll(runDirectory, 0o700); err != nil {
		return errors.New("QEMU execution directory is unavailable")
	}
	disk := filepath.Join(runDirectory, "guest.qcow2")
	if _, err := os.Stat(disk); errors.Is(err, os.ErrNotExist) {
		if err := copyAtomic(manager.config.DiskTemplate, disk); err != nil {
			return errors.New("QEMU guest disk could not be created")
		}
	} else if err != nil {
		return errors.New("QEMU guest disk is unavailable")
	}
	control := filepath.Join(runDirectory, "control.sock")
	_ = os.Remove(control)
	acceleration, err := resolveAcceleration(state.Configuration.Acceleration)
	if err != nil {
		return err
	}
	cpuModel := cpuModelForAcceleration(acceleration)
	args := []string{
		"-nodefaults", "-no-reboot", "-nographic", "-monitor", "none", "-serial", "null",
		"-machine", "q35,accel=" + acceleration, "-cpu", cpuModel, "-smp", strconv.Itoa(state.Configuration.CPUs),
		"-m", strconv.Itoa(state.Configuration.MemoryMiB),
		"-kernel", manager.config.Kernel, "-initrd", manager.config.Initramfs,
		"-append", "console=ttyS0 root=/dev/vda rw modules=virtio_pci,virtio_blk,virtio_net,virtio_console,ext4 quiet",
		"-drive", "file=" + disk + ",format=qcow2,if=virtio,cache=writeback",
		"-device", "virtio-rng-pci",
		"-device", "virtio-serial-pci",
		"-chardev", "socket,id=nvtcontrol,path=" + control + ",server=on,wait=off",
		"-device", "virtserialport,chardev=nvtcontrol,name=org.nvt.control",
		"-netdev", fmt.Sprintf("user,id=nvtnet,hostfwd=tcp:127.0.0.1:%d-:8080", state.HostPort),
		"-device", "virtio-net-pci,netdev=nvtnet",
	}
	command := exec.CommandContext(context.WithoutCancel(ctx), manager.config.Binary, args...)
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	command.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL, Setpgid: true}
	if err := command.Start(); err != nil {
		return errors.New("QEMU process could not be started")
	}
	done := make(chan struct{})
	go func() {
		_ = command.Wait()
		close(done)
	}()
	manager.active[state.ExecutionID] = &activeMachine{command: command, done: done}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(control); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			manager.stopLocked(state.ExecutionID)
			return errors.New("QEMU startup was cancelled")
		case <-done:
			delete(manager.active, state.ExecutionID)
			return errors.New("QEMU process exited during startup")
		case <-time.After(25 * time.Millisecond):
		}
	}
	manager.stopLocked(state.ExecutionID)
	return errors.New("QEMU control channel did not start")
}

func (manager *QEMUManager) Configure(ctx context.Context, state *State, configuration wire.BootConfiguration) error {
	response, err := manager.call(ctx, state, wire.Request{ContractVersion: wire.Version, Type: wire.RequestConfigure, Configuration: &configuration})
	if err != nil || (response.State != wire.StateWaiting && response.State != wire.StateEnrolled && response.State != wire.StateReady) {
		return errors.New("QEMU guest configuration is unavailable")
	}
	return nil
}

func (manager *QEMUManager) Observe(ctx context.Context, state *State) (MachineObservation, error) {
	manager.mu.Lock()
	machine := manager.active[state.ExecutionID]
	manager.mu.Unlock()
	if machine == nil {
		return MachineObservation{}, nil
	}
	select {
	case <-machine.done:
		return MachineObservation{}, nil
	default:
	}
	response, err := manager.call(ctx, state, wire.Request{ContractVersion: wire.Version, Type: wire.RequestStatus})
	if err != nil {
		return MachineObservation{Running: true}, err
	}
	observation := MachineObservation{Running: true, Enrolled: response.State == wire.StateEnrolled || response.State == wire.StateReady, Ready: response.State == wire.StateReady}
	if observation.Ready {
		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/ready", state.HostPort), nil)
		client := http.Client{Timeout: time.Second}
		result, healthErr := client.Do(request)
		if healthErr != nil {
			observation.Ready = false
		} else {
			_ = result.Body.Close()
			observation.Ready = result.StatusCode == http.StatusOK
		}
	}
	return observation, nil
}

func (manager *QEMUManager) Deliver(ctx context.Context, state *State, envelope guestenrollment.BootstrapEnvelope) (MachineObservation, error) {
	request := wire.Request{ContractVersion: wire.Version, Type: wire.RequestDeliver, Envelope: &envelope}
	response, err := manager.call(ctx, state, request)
	request.Envelope = nil
	envelope.Token = ""
	if err != nil || (response.State != wire.StateEnrolled && response.State != wire.StateReady) {
		return MachineObservation{}, errors.New("QEMU guest enrollment did not complete")
	}
	return MachineObservation{Running: true, Enrolled: true, Ready: response.State == wire.StateReady}, nil
}

func (manager *QEMUManager) Replace(ctx context.Context, state *State) error {
	manager.mu.Lock()
	manager.stopLocked(state.ExecutionID)
	manager.mu.Unlock()
	directory := (Store{Root: manager.config.StateRoot}).RunDir(state.ExecutionID)
	for _, name := range []string{"guest.qcow2", "control.sock"} {
		if err := os.Remove(filepath.Join(directory, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return errors.New("QEMU replacement cleanup failed")
		}
	}
	return nil
}

func (manager *QEMUManager) Delete(_ context.Context, state *State) error {
	manager.mu.Lock()
	manager.stopLocked(state.ExecutionID)
	manager.mu.Unlock()
	directory := (Store{Root: manager.config.StateRoot}).RunDir(state.ExecutionID)
	entries, err := os.ReadDir(directory)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return errors.New("QEMU execution directory is unavailable")
	}
	for _, entry := range entries {
		if entry.Name() == "state.json" {
			continue
		}
		if err := os.RemoveAll(filepath.Join(directory, entry.Name())); err != nil {
			return errors.New("QEMU resource cleanup failed")
		}
	}
	return syncDirectory(directory)
}

func (manager *QEMUManager) Shutdown(ctx context.Context) error {
	manager.mu.Lock()
	machines := make([]*activeMachine, 0, len(manager.active))
	for executionID, machine := range manager.active {
		machines = append(machines, machine)
		delete(manager.active, executionID)
		if machine.command.Process != nil {
			_ = syscall.Kill(-machine.command.Process.Pid, syscall.SIGTERM)
		}
	}
	manager.mu.Unlock()
	if waitForMachines(ctx, machines, 3*time.Second) {
		return nil
	}
	for _, machine := range machines {
		if machine.command.Process != nil {
			_ = syscall.Kill(-machine.command.Process.Pid, syscall.SIGKILL)
		}
	}
	if waitForMachines(context.Background(), machines, 2*time.Second) {
		return nil
	}
	return errors.New("QEMU shutdown did not reap every guest")
}

func (manager *QEMUManager) stopLocked(executionID string) {
	machine := manager.active[executionID]
	if machine == nil {
		return
	}
	delete(manager.active, executionID)
	if machine.command.Process != nil {
		_ = syscall.Kill(-machine.command.Process.Pid, syscall.SIGTERM)
	}
	select {
	case <-machine.done:
		return
	case <-time.After(3 * time.Second):
	}
	if machine.command.Process != nil {
		_ = syscall.Kill(-machine.command.Process.Pid, syscall.SIGKILL)
	}
	select {
	case <-machine.done:
	case <-time.After(2 * time.Second):
	}
}

func waitForMachines(ctx context.Context, machines []*activeMachine, maximum time.Duration) bool {
	deadline := time.NewTimer(maximum)
	defer deadline.Stop()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		complete := true
		for _, machine := range machines {
			select {
			case <-machine.done:
			default:
				complete = false
			}
		}
		if complete {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-deadline.C:
			return false
		case <-ticker.C:
		}
	}
}

func (manager *QEMUManager) call(ctx context.Context, state *State, request wire.Request) (wire.Response, error) {
	payload, err := wire.Encode(request)
	if err != nil {
		return wire.Response{}, errors.New("QEMU guest control request is invalid")
	}
	defer zero(payload)
	socket := filepath.Join((Store{Root: manager.config.StateRoot}).RunDir(state.ExecutionID), "control.sock")
	deadline := time.Now().Add(time.Duration(state.Configuration.BootTimeoutSec) * time.Second)
	for time.Now().Before(deadline) {
		connection, dialErr := (&net.Dialer{Timeout: 250 * time.Millisecond}).DialContext(ctx, "unix", socket)
		if dialErr == nil {
			defer connection.Close()
			operationDeadline := deadline
			if callerDeadline, ok := ctx.Deadline(); ok && callerDeadline.Before(operationDeadline) {
				operationDeadline = callerDeadline
			}
			_ = connection.SetDeadline(operationDeadline)
			if _, err := connection.Write(payload); err != nil {
				return wire.Response{}, errors.New("QEMU guest control request failed")
			}
			line, err := bufio.NewReader(io.LimitReader(connection, wire.MaxMessageBytes+1)).ReadBytes('\n')
			if err != nil || len(line) > wire.MaxMessageBytes {
				return wire.Response{}, errors.New("QEMU guest control response failed")
			}
			var response wire.Response
			if executiondriver.DecodeStrictJSON(bytes.TrimSuffix(line, []byte{'\n'}), &response) != nil || response.ContractVersion != wire.Version ||
				(response.State != wire.StateWaiting && response.State != wire.StateEnrolled && response.State != wire.StateReady && response.State != wire.StateFailed) || response.Error != "" {
				return wire.Response{}, errors.New("QEMU guest control response is invalid")
			}
			if state.ExecutionScope != nil {
				expected := guestenrollment.Binding{AgentRunUID: state.ExecutionScope.AgentRunUID, ExecutionID: state.ExecutionID, DriverRegistration: state.ExecutionScope.DriverRegistration, DesiredGeneration: state.Generation, GuestInstanceID: state.GuestInstanceID}
				if response.Binding == nil || *response.Binding != expected {
					return wire.Response{}, errors.New("QEMU guest control binding is invalid")
				}
			}
			return response, nil
		}
		select {
		case <-ctx.Done():
			return wire.Response{}, errors.New("QEMU guest control request was cancelled")
		case <-time.After(100 * time.Millisecond):
		}
	}
	return wire.Response{}, errors.New("QEMU guest control request timed out")
}

func resolveAcceleration(requested string) (string, error) {
	if requested == "tcg" {
		return "tcg", nil
	}
	file, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0)
	if err == nil {
		_ = file.Close()
		return "kvm", nil
	}
	if requested == "kvm" {
		return "", errors.New("QEMU KVM acceleration is unavailable")
	}
	return "tcg", nil
}

func cpuModelForAcceleration(acceleration string) string {
	if acceleration == "kvm" {
		return "host"
	}
	return "max"
}

func aggregateDigest(paths ...string) (string, error) {
	hash := sha256.New()
	for _, path := range paths {
		file, err := os.Open(path)
		if err != nil {
			return "", err
		}
		info, err := file.Stat()
		if err != nil {
			file.Close()
			return "", err
		}
		_, _ = fmt.Fprintf(hash, "%d:", info.Size())
		if _, err := io.Copy(hash, file); err != nil {
			file.Close()
			return "", err
		}
		if err := file.Close(); err != nil {
			return "", err
		}
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

func copyAtomic(source, destination string) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	temporary, err := os.CreateTemp(filepath.Dir(destination), ".guest-*.tmp")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := io.Copy(temporary, input); err != nil || temporary.Sync() != nil || temporary.Close() != nil {
		return errors.New("guest disk copy failed")
	}
	if err := os.Rename(name, destination); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(destination))
}

func regularFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
