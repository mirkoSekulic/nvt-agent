package guestidentity

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment"
)

type Store struct {
	directory      string
	statePath      string
	enrollmentPath string
	ownerUID       uint32
	beforeCommit   func() error
	syncFile       func(*os.File) error
	syncPath       func(string) error
}

func OpenStore(configuration Configuration) (*Store, error) {
	if validateConfiguration(configuration) != nil {
		return nil, failure(ReasonStateInvalid, false, false)
	}
	store := &Store{
		directory: configuration.StateDirectory, statePath: filepath.Join(configuration.StateDirectory, StateFileName),
		enrollmentPath: configuration.EnrollmentPath, ownerUID: uint32(os.Geteuid()),
	}
	if err := ensurePrivateDirectory(store.directory, store.ownerUID); err != nil {
		return nil, failure(ReasonStateUnavailable, false, false)
	}
	// A provider may pre-create the directory (systemd StateDirectory does),
	// but synchronizing its parent also makes a directory created here durable
	// before any bearer state is acknowledged.
	if err := store.synchronize(filepath.Dir(store.directory)); err != nil {
		return nil, failure(ReasonStateUnavailable, false, false)
	}
	return store, nil
}

func (store *Store) load() (durableState, bool, error) {
	data, err := readBoundedRegular(store.statePath, MaxStateBytes, store.ownerUID)
	if errors.Is(err, os.ErrNotExist) {
		return durableState{}, false, nil
	}
	if err != nil {
		return durableState{}, false, failure(ReasonStateInvalid, false, false)
	}
	defer zero(data)
	var state durableState
	if guestenrollment.DecodeStrictJSON(data, MaxStateBytes, &state) != nil || validateState(state) != nil {
		return durableState{}, false, failure(ReasonStateInvalid, false, false)
	}
	return state, true, nil
}

// LoadActiveBinding reports only the non-secret binding needed by a trusted
// bootstrap component to recognize an already enrolled guest. It deliberately
// does not let provider control code retain a second plaintext bearer copy.
func (store *Store) LoadActiveBinding() (*guestenrollment.Binding, error) {
	state, exists, err := store.load()
	if err != nil || !exists {
		return nil, err
	}
	if state.FailureReason != "" || state.RuntimeIdentity == nil {
		return nil, failure(ReasonStateInvalid, false, false)
	}
	state.RuntimeIdentity.Opaque = ""
	state.PendingSuccessor = ""
	binding := state.Binding
	return &binding, nil
}

func (store *Store) save(state durableState) error {
	if validateState(state) != nil {
		return failure(ReasonStateInvalid, false, false)
	}
	encoded, err := json.Marshal(state)
	if err != nil || len(encoded)+1 > MaxStateBytes {
		zero(encoded)
		return failure(ReasonStateInvalid, false, false)
	}
	encoded = append(encoded, '\n')
	defer zero(encoded)
	if err := store.atomicWrite(store.statePath, encoded, 0o600); err != nil {
		return failure(ReasonStateUnavailable, false, false)
	}
	return nil
}

func (store *Store) loadEnvelope() (guestenrollment.BootstrapEnvelope, error) {
	data, err := readBoundedRegular(store.enrollmentPath, guestenrollment.MaxBootstrapEnvelopeBytes, store.ownerUID)
	if errors.Is(err, os.ErrNotExist) {
		return guestenrollment.BootstrapEnvelope{}, failure(ReasonEnrollmentPending, true, false)
	}
	if err != nil {
		return guestenrollment.BootstrapEnvelope{}, failure(ReasonStateInvalid, false, false)
	}
	defer zero(data)
	value, err := guestenrollment.DecodeBootstrapEnvelope(data)
	if err != nil {
		return guestenrollment.BootstrapEnvelope{}, failure(ReasonStateInvalid, false, false)
	}
	return value, nil
}

// SaveEnvelope commits the provider-delivered one-time envelope into the
// protected state directory. It never replaces a different outstanding
// envelope; callers must revoke and replace that exact bootstrap attempt.
func (store *Store) saveEnvelope(value guestenrollment.BootstrapEnvelope) error {
	if guestenrollment.ValidateBootstrapEnvelope(value) != nil {
		return failure(ReasonProtocolInvalid, false, false)
	}
	if _, err := brokerURLFromExchange(value.ExchangeURL); err != nil {
		return failure(ReasonProtocolInvalid, false, false)
	}
	if existing, err := store.loadEnvelope(); err == nil {
		if existing != value {
			existing.Token = ""
			return failure(ReasonReplacementRequired, false, false)
		}
		existing.Token = ""
		return nil
	} else {
		reason, _, _ := FailureDetails(err)
		if reason != ReasonEnrollmentPending {
			return err
		}
	}
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded)+1 > guestenrollment.MaxBootstrapEnvelopeBytes {
		zero(encoded)
		return failure(ReasonProtocolInvalid, false, false)
	}
	encoded = append(encoded, '\n')
	defer zero(encoded)
	if err := store.atomicWrite(store.enrollmentPath, encoded, 0o600); err != nil {
		return failure(ReasonStateUnavailable, false, false)
	}
	return nil
}

func (store *Store) removeEnvelope() error {
	if err := os.Remove(store.enrollmentPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return failure(ReasonStateUnavailable, false, false)
	}
	if err := store.synchronize(store.directory); err != nil {
		return failure(ReasonStateUnavailable, false, false)
	}
	return nil
}

func (store *Store) saveFailure(binding guestenrollment.Binding, brokerURL string) error {
	return store.save(durableState{
		ContractVersion: StateVersion, Binding: binding, BrokerURL: brokerURL,
		FailureReason: ReasonReplacementRequired,
	})
}

func (store *Store) atomicWrite(path string, data []byte, mode os.FileMode) error {
	if err := ensurePrivateDirectory(store.directory, store.ownerUID); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(store.directory, ".identity-*.tmp")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(mode); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return err
	}
	if err := store.synchronizeFile(temporary); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if store.beforeCommit != nil {
		if err := store.beforeCommit(); err != nil {
			return err
		}
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	return store.synchronize(store.directory)
}

func (store *Store) synchronizeFile(file *os.File) error {
	if store.syncFile != nil {
		return store.syncFile(file)
	}
	return file.Sync()
}

func (store *Store) synchronize(path string) error {
	if store.syncPath != nil {
		return store.syncPath(path)
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Sync()
}

func ensurePrivateDirectory(path string, ownerUID uint32) error {
	if !validAbsoluteDirectory(path) {
		return errors.New("identity directory is invalid")
	}
	parent := filepath.Dir(path)
	resolvedParent, err := filepath.EvalSymlinks(parent)
	if err != nil || resolvedParent != parent || validateDirectoryAncestors(parent, ownerUID) != nil {
		return errors.New("identity directory is unsafe")
	}
	if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return errors.New("identity directory is unsafe")
	}
	if err := validateDirectoryAncestors(path, ownerUID); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return errors.New("identity directory is unsafe")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != ownerUID {
		return errors.New("identity directory is unsafe")
	}
	return nil
}

func validateDirectoryAncestors(path string, ownerUID uint32) error {
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("identity directory is unsafe")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || (stat.Uid != ownerUID && !(ownerUID != 0 && stat.Uid == 0)) {
			return errors.New("identity directory is unsafe")
		}
		if info.Mode().Perm()&0o022 != 0 && !(stat.Uid == 0 && info.Mode()&os.ModeSticky != 0) {
			return errors.New("identity directory is unsafe")
		}
		if current == "/" {
			return nil
		}
	}
}

func readBoundedRegular(path string, maximum int, ownerUID uint32) ([]byte, error) {
	if !validAbsoluteFile(path) || maximum < 1 {
		return nil, errors.New("identity file is invalid")
	}
	if err := validateDirectoryAncestors(filepath.Dir(path), ownerUID); err != nil {
		return nil, errors.New("identity file is unsafe")
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() < 1 || info.Size() > int64(maximum) {
		return nil, errors.New("identity file is unsafe")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != ownerUID || stat.Nlink != 1 {
		return nil, errors.New("identity file is unsafe")
	}
	data, err := io.ReadAll(io.LimitReader(file, int64(maximum)+1))
	if err != nil || len(data) == 0 || len(data) > maximum {
		zero(data)
		return nil, errors.New("identity file is invalid")
	}
	return data, nil
}

func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
