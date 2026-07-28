package driver

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/mirkoSekulic/nvt-agent/executiondrivers/qemu/internal/config"
	"github.com/mirkoSekulic/nvt-agent/operator/executiondriver"
	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment"
)

const stateVersion = 1

type State struct {
	Version            int                             `json:"version"`
	ExecutionID        string                          `json:"execution_id"`
	Generation         int64                           `json:"generation"`
	DesiredFingerprint string                          `json:"desired_fingerprint"`
	ClassName          string                          `json:"class_name"`
	Configuration      config.Configuration            `json:"configuration"`
	Attempt            int                             `json:"attempt"`
	GuestInstanceID    string                          `json:"guest_instance_id"`
	ExecutionScope     *guestenrollment.ExecutionScope `json:"execution_scope,omitempty"`
	EnrollmentAccepted bool                            `json:"enrollment_accepted"`
	HostPort           int                             `json:"host_port"`
}

func (state State) Validate() error {
	desired := executiondriver.DesiredExecution{
		ExecutionID: state.ExecutionID, Generation: state.Generation, DesiredFingerprint: state.DesiredFingerprint,
		WorkloadKind: executiondriver.WorkloadKindVM, ClassName: state.ClassName, Configuration: json.RawMessage(`{}`),
	}
	if state.Version != stateVersion || executiondriver.ValidateReconcileParams(executiondriver.ReconcileParams{Desired: desired}) != nil ||
		config.Validate(state.Configuration) != nil || state.Attempt < 1 || state.Attempt > 1_000_000 ||
		state.GuestInstanceID != guestInstanceID(state.ExecutionID, state.Generation, state.Attempt) || state.HostPort < 20000 || state.HostPort > 49999 {
		return errors.New("QEMU durable state is invalid")
	}
	if state.ExecutionScope != nil {
		if guestenrollment.ValidateExecutionScope(*state.ExecutionScope) != nil || state.ExecutionScope.ExecutionID != state.ExecutionID {
			return errors.New("QEMU durable state is invalid")
		}
	} else if state.EnrollmentAccepted {
		return errors.New("QEMU durable state is invalid")
	}
	return nil
}

type Store struct{ Root string }

func (store Store) RunDir(executionID string) string {
	sum := sha256.Sum256([]byte(executionID))
	return filepath.Join(store.Root, "executions", hex.EncodeToString(sum[:]))
}

func (store Store) Load(executionID string) (State, error) {
	data, err := os.ReadFile(filepath.Join(store.RunDir(executionID), "state.json"))
	if err != nil {
		return State{}, err
	}
	var state State
	if executiondriver.DecodeStrictJSON(data, &state) != nil || state.ExecutionID != executionID || state.Validate() != nil {
		return State{}, errors.New("QEMU durable state is invalid")
	}
	return state, nil
}

func (store Store) Save(state State) error {
	if state.Validate() != nil {
		return errors.New("QEMU durable state is invalid")
	}
	directory := store.RunDir(state.ExecutionID)
	parent := filepath.Dir(directory)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return errors.New("QEMU durable state is unavailable")
	}
	data, err := json.Marshal(state)
	if err != nil {
		return errors.New("QEMU durable state is invalid")
	}
	temporary, err := os.CreateTemp(directory, ".state-*.tmp")
	if err != nil {
		return errors.New("QEMU durable state is unavailable")
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(0o600); err != nil || writeSyncClose(temporary, append(data, '\n')) != nil || os.Rename(name, filepath.Join(directory, "state.json")) != nil || syncDirectory(directory) != nil || syncDirectory(parent) != nil {
		return errors.New("QEMU durable state is unavailable")
	}
	return nil
}

func (store Store) Remove(executionID string) error {
	if err := os.RemoveAll(store.RunDir(executionID)); err != nil {
		return errors.New("QEMU durable resources could not be removed")
	}
	return syncDirectory(filepath.Join(store.Root, "executions"))
}

func guestInstanceID(executionID string, generation int64, attempt int) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("nvt.qemu-guest/v1:%s:%d:%d", executionID, generation, attempt)))
	return "qemu-guest-" + hex.EncodeToString(sum[:16])
}

func stableHostPort(executionID string) int {
	sum := sha256.Sum256([]byte("nvt.qemu-port/v1:" + executionID))
	return 20000 + int(binary.BigEndian.Uint16(sum[:2]))%30000
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
