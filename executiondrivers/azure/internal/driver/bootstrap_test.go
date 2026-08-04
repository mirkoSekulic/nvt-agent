package driver

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBootstrapPrivateKeyIsOwnerOnlyAndSymlinkSafe(t *testing.T) {
	root := t.TempDir()
	desired := testDesired(t, false)
	state := newState(testConfiguration(t), desired, 1, nil)
	store := Store{Root: root}
	if err := store.Create(desired.ExecutionID, state); err != nil {
		t.Fatal(err)
	}
	keyPath := store.KeyPath(desired.ExecutionID)
	key, err := readPrivateKey(keyPath)
	if err != nil || !strings.Contains(string(key), "PRIVATE KEY") {
		t.Fatalf("owner-only key rejected: %v", err)
	}
	zero(key)
	link := filepath.Join(t.TempDir(), "bootstrap-key.pem")
	if err := os.Symlink(keyPath, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivateKey(link); err == nil {
		t.Fatal("bootstrap identity symlink was accepted")
	}
	if err := os.Chmod(keyPath, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivateKey(keyPath); err == nil {
		t.Fatal("group-readable bootstrap identity was accepted")
	}
}

func TestBootstrapKeyRemovalErasesDurableAuthority(t *testing.T) {
	root := t.TempDir()
	desired := testDesired(t, false)
	store := Store{Root: root}
	if err := store.Create(desired.ExecutionID, newState(testConfiguration(t), desired, 1, nil)); err != nil {
		t.Fatal(err)
	}
	if err := store.RemoveKey(desired.ExecutionID); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(store.KeyPath(desired.ExecutionID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("bootstrap identity remains after removal: %v", err)
	}
}
