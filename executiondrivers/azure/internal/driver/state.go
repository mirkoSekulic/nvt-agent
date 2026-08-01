package driver

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"

	"github.com/mirkoSekulic/nvt-agent/executiondrivers/azure/internal/config"
	"github.com/mirkoSekulic/nvt-agent/operator/executiondriver"
	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment"
	"golang.org/x/crypto/ssh"
)

const (
	stateVersion  = 1
	maxExecutions = 128
)

type ResourceIDs struct {
	VM         string `json:"vm"`
	NIC        string `json:"nic"`
	OSDisk     string `json:"os_disk"`
	NSG        string `json:"nsg"`
	Deployment string `json:"deployment"`
}

type PinnedDestination struct {
	Purpose string `json:"purpose"`
	Host    string `json:"host"`
	Port    uint16 `json:"port"`
	Address string `json:"address"`
}

type State struct {
	Version                 int                                     `json:"version"`
	ExecutionID             string                                  `json:"execution_id"`
	Generation              int64                                   `json:"generation"`
	DesiredFingerprint      string                                  `json:"desired_fingerprint"`
	ClassName               string                                  `json:"class_name"`
	Configuration           config.Configuration                    `json:"configuration"`
	Attempt                 int                                     `json:"attempt"`
	GuestInstanceID         string                                  `json:"guest_instance_id"`
	ExecutionScope          *guestenrollment.ExecutionScope         `json:"execution_scope,omitempty"`
	NativeEgressAttachment  *executiondriver.NativeEgressAttachment `json:"native_egress_attachment,omitempty"`
	Resources               ResourceIDs                             `json:"resources"`
	PinnedDestinations      []PinnedDestination                     `json:"pinned_destinations,omitempty"`
	BootstrapPublicKey      string                                  `json:"bootstrap_public_key"`
	BootstrapKeyFingerprint string                                  `json:"bootstrap_key_fingerprint"`
	PrivateIPAddress        string                                  `json:"private_ip_address,omitempty"`
	GuestConfigured         bool                                    `json:"guest_configured"`
	DeliveryPending         bool                                    `json:"delivery_pending"`
	GuestEnrolled           bool                                    `json:"guest_enrolled"`
	BootstrapLocked         bool                                    `json:"bootstrap_locked"`
	EnrollmentAccepted      bool                                    `json:"enrollment_accepted"`
}

func (state State) Validate() error {
	desired := executiondriver.DesiredExecution{
		ExecutionID: state.ExecutionID, Generation: state.Generation, DesiredFingerprint: state.DesiredFingerprint,
		WorkloadKind: executiondriver.WorkloadKindVM, ClassName: state.ClassName, Configuration: json.RawMessage(`{}`),
	}
	if state.Version != stateVersion || executiondriver.ValidateReconcileParams(executiondriver.ReconcileParams{Desired: desired}) != nil ||
		config.Validate(state.Configuration) != nil || state.Attempt < 1 || state.Attempt > 1_000_000 ||
		state.GuestInstanceID != guestInstanceID(state.ExecutionID, state.Generation, state.Attempt) {
		return errors.New("Azure durable state is invalid")
	}
	plan := planFor(state.Configuration, state.ExecutionID)
	if state.Resources != plan.Resources || state.Resources.Deployment == "" ||
		state.BootstrapPublicKey == "" || state.BootstrapKeyFingerprint == "" {
		return errors.New("Azure durable resource identity is invalid")
	}
	key, _, _, rest, err := ssh.ParseAuthorizedKey([]byte(state.BootstrapPublicKey + "\n"))
	if err != nil || len(rest) != 0 || key.Type() != ssh.KeyAlgoED25519 || ssh.FingerprintSHA256(key) != state.BootstrapKeyFingerprint {
		return errors.New("Azure durable bootstrap identity is invalid")
	}
	if state.NativeEgressAttachment != nil {
		if executiondriver.ValidateNativeEgressAttachment(*state.NativeEgressAttachment) != nil || validatePinnedDestinations(state) != nil {
			return errors.New("Azure durable native egress state is invalid")
		}
	} else if len(state.PinnedDestinations) != 0 {
		return errors.New("Azure durable native egress state is invalid")
	}
	for index, destination := range state.PinnedDestinations {
		address, err := netip.ParseAddr(destination.Address)
		if destination.Host == "" || destination.Port == 0 || destination.Address == "" || err != nil || address.String() != destination.Address || !validFenceAddress(address) ||
			(index > 0 && !pinnedDestinationLess(state.PinnedDestinations[index-1], destination)) {
			return errors.New("Azure durable destination state is invalid")
		}
	}
	if state.ExecutionScope != nil {
		if guestenrollment.ValidateExecutionScope(*state.ExecutionScope) != nil || state.ExecutionScope.ExecutionID != state.ExecutionID {
			return errors.New("Azure durable enrollment scope is invalid")
		}
	} else if state.GuestConfigured || state.DeliveryPending || state.GuestEnrolled || state.BootstrapLocked || state.EnrollmentAccepted {
		return errors.New("Azure durable enrollment state is invalid")
	}
	if state.DeliveryPending && (!state.GuestConfigured || state.EnrollmentAccepted) {
		return errors.New("Azure durable delivery state is invalid")
	}
	if state.EnrollmentAccepted && (!state.GuestEnrolled || !state.BootstrapLocked || state.DeliveryPending) {
		return errors.New("Azure durable enrollment state is invalid")
	}
	if state.PrivateIPAddress != "" {
		address, err := netip.ParseAddr(state.PrivateIPAddress)
		if err != nil || !address.Is4() || address.IsLoopback() || address.IsUnspecified() || address.String() != state.PrivateIPAddress {
			return errors.New("Azure durable private address is invalid")
		}
	}
	return nil
}

func validatePinnedDestinations(state State) error {
	if state.NativeEgressAttachment == nil {
		if len(state.PinnedDestinations) != 0 {
			return errors.New("unexpected destinations")
		}
		return nil
	}
	type endpoint struct {
		purpose string
		host    string
		port    uint16
	}
	allowed := map[endpoint]bool{{purpose: "relay", host: state.NativeEgressAttachment.Relay.Host, port: state.NativeEgressAttachment.Relay.Port}: true}
	for _, destination := range state.NativeEgressAttachment.RequiredDestinations {
		allowed[endpoint{purpose: string(destination.Purpose), host: destination.Host, port: destination.Port}] = true
	}
	if len(state.PinnedDestinations) == 0 || len(state.PinnedDestinations) > len(allowed)*maxAddressesPerDestination {
		return errors.New("destination count is invalid")
	}
	observed := map[endpoint]bool{}
	for _, destination := range state.PinnedDestinations {
		key := endpoint{purpose: destination.Purpose, host: destination.Host, port: destination.Port}
		if !allowed[key] {
			return errors.New("destination is outside attachment")
		}
		observed[key] = true
	}
	for key := range allowed {
		if !observed[key] {
			return errors.New("attachment destination is not pinned")
		}
	}
	return nil
}

type Store struct{ Root string }

func (store Store) RunDir(executionID string) string {
	sum := sha256.Sum256([]byte("nvt.azure-state/v1:" + executionID))
	return filepath.Join(store.Root, "executions", hex.EncodeToString(sum[:]))
}

func (store Store) KeyPath(executionID string) string {
	return filepath.Join(store.RunDir(executionID), "bootstrap-key.pem")
}

func (store Store) Load(executionID string) (State, error) {
	data, err := os.ReadFile(filepath.Join(store.RunDir(executionID), "state.json"))
	if err != nil {
		return State{}, err
	}
	var state State
	if executiondriver.DecodeStrictJSON(data, &state) != nil || state.ExecutionID != executionID || state.Validate() != nil {
		return State{}, errors.New("Azure durable state is invalid")
	}
	return state, nil
}

func (store Store) Save(state State) error {
	if state.Validate() != nil {
		return errors.New("Azure durable state is invalid")
	}
	directory := store.RunDir(state.ExecutionID)
	if err := os.MkdirAll(directory, 0o700); err != nil || os.Chmod(directory, 0o700) != nil {
		return errors.New("Azure durable state is unavailable")
	}
	data, err := json.Marshal(state)
	if err != nil {
		return errors.New("Azure durable state is invalid")
	}
	return writeAtomic(filepath.Join(directory, "state.json"), append(data, '\n'), 0o600)
}

func (store Store) Create(executionID string, state State) error {
	entries, err := os.ReadDir(filepath.Join(store.Root, "executions"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.New("Azure durable capacity is unavailable")
	}
	if len(entries) >= maxExecutions {
		return errors.New("Azure durable capacity is exhausted")
	}
	if err := os.MkdirAll(store.RunDir(executionID), 0o700); err != nil {
		return errors.New("Azure durable state is unavailable")
	}
	privatePEM, publicKey, fingerprint, err := generateBootstrapKey()
	if err != nil {
		return errors.New("Azure bootstrap key generation failed")
	}
	state.BootstrapPublicKey, state.BootstrapKeyFingerprint = publicKey, fingerprint
	if err := writeAtomic(store.KeyPath(executionID), privatePEM, 0o600); err != nil || store.Save(state) != nil {
		zero(privatePEM)
		_ = os.RemoveAll(store.RunDir(executionID))
		return errors.New("Azure durable bootstrap state is unavailable")
	}
	zero(privatePEM)
	return nil
}

func (store Store) RemoveKey(executionID string) error {
	path := store.KeyPath(executionID)
	file, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err == nil {
		if info, statErr := file.Stat(); statErr == nil && info.Mode().IsRegular() && info.Size() <= 64<<10 {
			zeros := make([]byte, info.Size())
			_, _ = file.WriteAt(zeros, 0)
			_ = file.Sync()
		}
		_ = file.Close()
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.New("Azure bootstrap key removal is pending")
	}
	return syncDirectory(filepath.Dir(path))
}

func (store Store) Remove(executionID string) error {
	if err := os.RemoveAll(store.RunDir(executionID)); err != nil {
		return errors.New("Azure durable state cleanup is pending")
	}
	return syncDirectory(filepath.Join(store.Root, "executions"))
}

func newState(configuration config.Configuration, desired executiondriver.DesiredExecution, attempt int, destinations []PinnedDestination) State {
	state := State{
		Version: stateVersion, ExecutionID: desired.ExecutionID, Generation: desired.Generation,
		DesiredFingerprint: desired.DesiredFingerprint, ClassName: desired.ClassName, Configuration: configuration,
		Attempt: attempt, GuestInstanceID: guestInstanceID(desired.ExecutionID, desired.Generation, attempt),
		NativeEgressAttachment: cloneAttachment(desired.NativeEgressAttachment), PinnedDestinations: destinations,
	}
	state.Resources = planFor(configuration, desired.ExecutionID).Resources
	return state
}

func guestInstanceID(executionID string, generation int64, attempt int) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("nvt.azure-guest/v1:%s:%d:%d", executionID, generation, attempt)))
	return "azure-guest-" + hex.EncodeToString(sum[:16])
}

func cloneAttachment(value *executiondriver.NativeEgressAttachment) *executiondriver.NativeEgressAttachment {
	if value == nil {
		return nil
	}
	copy := *value
	copy.RequiredDestinations = append([]executiondriver.NativeEgressRequiredDestination(nil), value.RequiredDestinations...)
	return &copy
}

func generateBootstrapKey() ([]byte, string, string, error) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", "", err
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return nil, "", "", err
	}
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded})
	sshPublic, err := ssh.NewPublicKey(public)
	if err != nil {
		zero(privatePEM)
		return nil, "", "", err
	}
	publicText := string(ssh.MarshalAuthorizedKey(sshPublic))
	publicText = publicText[:len(publicText)-1]
	return privatePEM, publicText, ssh.FingerprintSHA256(sshPublic), nil
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".nvt-azure-*.tmp")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if temporary.Chmod(mode) != nil || writeSyncClose(temporary, data) != nil || os.Rename(name, path) != nil || syncDirectory(directory) != nil {
		return errors.New("atomic write failed")
	}
	return nil
}

func writeSyncClose(file *os.File, data []byte) error {
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
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

func pinnedDestinationLess(left, right PinnedDestination) bool {
	if left.Purpose != right.Purpose {
		return left.Purpose < right.Purpose
	}
	if left.Host != right.Host {
		return left.Host < right.Host
	}
	if left.Port != right.Port {
		return left.Port < right.Port
	}
	return left.Address < right.Address
}

func canonicalPinned(values []PinnedDestination) []PinnedDestination {
	result := append([]PinnedDestination(nil), values...)
	sort.Slice(result, func(i, j int) bool { return pinnedDestinationLess(result[i], result[j]) })
	return result
}

func (State) String() string   { return "[Azure execution state]" }
func (State) GoString() string { return "[Azure execution state]" }
