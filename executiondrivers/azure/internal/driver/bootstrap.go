package driver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/mirkoSekulic/nvt-agent/executiondrivers/azure/internal/config"
	"github.com/mirkoSekulic/nvt-agent/operator/executiondriver"
	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment"
	"golang.org/x/crypto/ssh"
)

const (
	bootstrapVersion          = "nvt.azure-bootstrap/v1"
	bootstrapBinaryPath       = "/opt/nvt-azure/nvt-host-bootstrap"
	maxBootstrapBinaryBytes   = 32 << 20
	maxBootstrapMessageBytes  = 256 << 10
	maxBootstrapResponseBytes = 4 << 10
)

type GuestState string

const (
	GuestWaiting  GuestState = "waiting"
	GuestEnrolled GuestState = "enrolled"
	GuestReady    GuestState = "ready"
	GuestLocked   GuestState = "locked"
)

type Bootstrapper interface {
	Configure(context.Context, State) error
	Status(context.Context, State) (GuestState, error)
	Deliver(context.Context, State, guestenrollment.BootstrapEnvelope, string) error
	Lock(context.Context, State) error
}

type SSHBootstrapper struct {
	binary      []byte
	dialTimeout time.Duration
	stateRoot   string
}

type guestConfiguration struct {
	ContractVersion        string                                  `json:"contract_version"`
	Binding                guestenrollment.Binding                 `json:"binding"`
	HostBundle             config.Artifact                         `json:"host_bundle"`
	RegistryCAPEM          string                                  `json:"registry_ca_pem,omitempty"`
	EnrollmentEndpoint     string                                  `json:"enrollment_endpoint"`
	EnrollmentCAPEM        string                                  `json:"enrollment_ca_pem"`
	NativeSessionEndpoint  string                                  `json:"native_session_endpoint"`
	NativeSessionCAPEM     string                                  `json:"native_session_ca_pem"`
	NativeWorkspace        *config.NativeWorkspace                 `json:"native_workspace,omitempty"`
	NativeEgressAttachment *executiondriver.NativeEgressAttachment `json:"native_egress_attachment,omitempty"`
}

type installHeader struct {
	ContractVersion string `json:"contract_version"`
	Size            int    `json:"size"`
	SHA256          string `json:"sha256"`
}

type enrollmentDelivery struct {
	ContractVersion   string                            `json:"contract_version"`
	Envelope          guestenrollment.BootstrapEnvelope `json:"envelope"`
	NativeEgressCAPEM string                            `json:"native_egress_ca_pem,omitempty"`
}

func NewSSHBootstrapper(stateRoot string) (*SSHBootstrapper, error) {
	if stateRoot == "" {
		return nil, errors.New("Azure bootstrap state root is unavailable")
	}
	binary, err := os.ReadFile(bootstrapBinaryPath)
	if err != nil || len(binary) == 0 || len(binary) > maxBootstrapBinaryBytes {
		zero(binary)
		return nil, errors.New("Azure host bootstrap input is unavailable")
	}
	return &SSHBootstrapper{binary: binary, dialTimeout: 10 * time.Second, stateRoot: stateRoot}, nil
}

func NewSSHBootstrapperForTest(binary []byte, stateRoot string) (*SSHBootstrapper, error) {
	if len(binary) == 0 || len(binary) > maxBootstrapBinaryBytes {
		return nil, errors.New("bootstrap input is invalid")
	}
	return &SSHBootstrapper{binary: append([]byte(nil), binary...), dialTimeout: time.Second, stateRoot: stateRoot}, nil
}

func (bootstrapper *SSHBootstrapper) Configure(ctx context.Context, state State) error {
	digest := sha256.Sum256(bootstrapper.binary)
	header, _ := json.Marshal(installHeader{ContractVersion: bootstrapVersion, Size: len(bootstrapper.binary), SHA256: "sha256:" + hex.EncodeToString(digest[:])})
	payload := make([]byte, 0, len(header)+1+len(bootstrapper.binary))
	payload = append(payload, header...)
	payload = append(payload, '\n')
	payload = append(payload, bootstrapper.binary...)
	if response, err := bootstrapper.call(ctx, state, "/usr/local/libexec/nvt-azure-bootstrap-receiver install", payload); err != nil || response != "ok\n" {
		return errors.New("Azure protected bootstrap installation is unavailable")
	}
	configuration, err := json.Marshal(guestConfiguration{
		ContractVersion: bootstrapVersion, Binding: bindingFor(state), HostBundle: state.Configuration.HostBundle,
		RegistryCAPEM: state.Configuration.RegistryCAPEM, EnrollmentEndpoint: state.Configuration.EnrollmentEndpoint,
		EnrollmentCAPEM:       state.Configuration.EnrollmentCAPEM,
		NativeSessionEndpoint: state.Configuration.NativeSessionEndpoint, NativeSessionCAPEM: state.Configuration.NativeSessionCAPEM,
		NativeWorkspace: state.Configuration.NativeWorkspace, NativeEgressAttachment: cloneAttachment(state.NativeEgressAttachment),
	})
	if err != nil || len(configuration) > maxBootstrapMessageBytes {
		return errors.New("Azure guest configuration is invalid")
	}
	response, err := bootstrapper.call(ctx, state, "/usr/local/libexec/nvt-azure-bootstrap-receiver configure", append(configuration, '\n'))
	if err != nil || response != "ok\n" {
		return errors.New("Azure protected guest configuration is unavailable")
	}
	return nil
}

func (bootstrapper *SSHBootstrapper) Status(ctx context.Context, state State) (GuestState, error) {
	response, err := bootstrapper.call(ctx, state, "/usr/local/libexec/nvt-azure-bootstrap-receiver status", nil)
	if err != nil {
		return "", errors.New("Azure protected bootstrap status is unavailable")
	}
	value := GuestState(strings.TrimSuffix(response, "\n"))
	switch value {
	case GuestWaiting, GuestEnrolled, GuestReady, GuestLocked:
		return value, nil
	}
	return "", errors.New("Azure protected bootstrap status is invalid")
}

func (bootstrapper *SSHBootstrapper) Deliver(ctx context.Context, state State, envelope guestenrollment.BootstrapEnvelope, caPEM string) error {
	payload, err := json.Marshal(enrollmentDelivery{ContractVersion: bootstrapVersion, Envelope: envelope, NativeEgressCAPEM: caPEM})
	if err != nil || len(payload) > maxBootstrapMessageBytes {
		return errors.New("Azure enrollment delivery is invalid")
	}
	wire := append(payload, '\n')
	defer zero(payload)
	defer zero(wire)
	response, err := bootstrapper.call(ctx, state, "/usr/local/libexec/nvt-azure-bootstrap-receiver enroll", wire)
	if err != nil || response != "accepted\n" {
		return errors.New("Azure enrollment delivery is unavailable")
	}
	return nil
}

func (bootstrapper *SSHBootstrapper) Lock(ctx context.Context, state State) error {
	response, err := bootstrapper.call(ctx, state, "/usr/local/libexec/nvt-azure-bootstrap-receiver lock", nil)
	if err != nil || response != "locked\n" {
		return errors.New("Azure bootstrap account lock is unavailable")
	}
	return nil
}

func (bootstrapper *SSHBootstrapper) call(ctx context.Context, state State, command string, input []byte) (string, error) {
	if state.PrivateIPAddress == "" || !strings.HasPrefix(command, "/usr/local/libexec/nvt-azure-bootstrap-receiver ") {
		return "", errors.New("bootstrap channel is unavailable")
	}
	privateKey, err := readPrivateKey((Store{Root: bootstrapper.stateRoot}).KeyPath(state.ExecutionID))
	if err != nil {
		return "", err
	}
	defer zero(privateKey)
	signer, err := ssh.ParsePrivateKey(privateKey)
	if err != nil {
		return "", errors.New("bootstrap identity is unavailable")
	}
	hostKey, _, _, rest, err := ssh.ParseAuthorizedKey([]byte(state.Configuration.SSHHostPublicKey + "\n"))
	if err != nil || len(rest) != 0 {
		return "", errors.New("bootstrap host identity is invalid")
	}
	dialer := &net.Dialer{Timeout: bootstrapper.dialTimeout, KeepAlive: -1}
	connection, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(state.PrivateIPAddress, "22"))
	if err != nil {
		return "", errors.New("bootstrap channel is unavailable")
	}
	deadline := time.Now().Add(time.Duration(state.Configuration.BootstrapTimeoutSec) * time.Second)
	_ = connection.SetDeadline(deadline)
	clientConnection, channels, requests, err := ssh.NewClientConn(connection, net.JoinHostPort(state.PrivateIPAddress, "22"), &ssh.ClientConfig{
		User: "nvt-bootstrap", Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.FixedHostKey(hostKey), HostKeyAlgorithms: []string{ssh.KeyAlgoED25519}, Timeout: bootstrapper.dialTimeout,
	})
	if err != nil {
		connection.Close()
		return "", errors.New("bootstrap channel authentication failed")
	}
	client := ssh.NewClient(clientConnection, channels, requests)
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		return "", errors.New("bootstrap operation is unavailable")
	}
	defer session.Close()
	session.Stdin = bytes.NewReader(input)
	var output boundedWriter
	session.Stdout, session.Stderr = &output, io.Discard
	done := make(chan error, 1)
	go func() { done <- session.Run(command) }()
	select {
	case <-ctx.Done():
		_ = session.Close()
		<-done
		return "", errors.New("bootstrap operation was cancelled")
	case err := <-done:
		if err != nil || output.overflow {
			return "", errors.New("bootstrap operation failed")
		}
		return string(output.data), nil
	}
}

func readPrivateKey(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() < 1 || info.Size() > 64<<10 || filepath.Clean(path) != path {
		return nil, errors.New("bootstrap identity is unavailable")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || int(stat.Uid) != os.Geteuid() {
		return nil, errors.New("bootstrap identity ownership is invalid")
	}
	value, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("bootstrap identity is unavailable")
	}
	return value, nil
}

type boundedWriter struct {
	data     []byte
	overflow bool
}

func (writer *boundedWriter) Write(value []byte) (int, error) {
	if len(writer.data)+len(value) > maxBootstrapResponseBytes {
		writer.overflow = true
		return len(value), nil
	}
	writer.data = append(writer.data, value...)
	return len(value), nil
}

func bindingFor(state State) guestenrollment.Binding {
	if state.ExecutionScope == nil {
		return guestenrollment.Binding{}
	}
	return guestenrollment.Binding{AgentRunUID: state.ExecutionScope.AgentRunUID, ExecutionID: state.ExecutionID,
		DriverRegistration: state.ExecutionScope.DriverRegistration, DesiredGeneration: state.Generation, GuestInstanceID: state.GuestInstanceID}
}

func (bootstrapper *SSHBootstrapper) String() string {
	return fmt.Sprintf("Azure protected bootstrap (%d bytes)", len(bootstrapper.binary))
}
