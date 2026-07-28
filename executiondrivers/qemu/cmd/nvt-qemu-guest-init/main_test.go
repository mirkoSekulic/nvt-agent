package main

import (
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment"
)

func TestAtomicEnrollmentRecordSurvivesPreCommitFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "enrollment.json")
	old := []byte("old-complete-record\n")
	if err := os.WriteFile(path, old, 0o600); err != nil {
		t.Fatal(err)
	}
	err := atomicWriteBeforeCommit(path, []byte("new-record\n"), 0o600, func() error {
		return errors.New("injected pre-commit failure")
	})
	if err == nil || strings.Contains(err.Error(), "injected") {
		t.Fatalf("pre-commit failure was not sanitized: %v", err)
	}
	got, readErr := os.ReadFile(path)
	if readErr != nil || string(got) != string(old) {
		t.Fatalf("pre-commit failure changed the prior complete record: %q %v", got, readErr)
	}
	matches, globErr := filepath.Glob(filepath.Join(filepath.Dir(path), ".nvt-*.tmp"))
	if globErr != nil || len(matches) != 0 {
		t.Fatalf("pre-commit failure retained temporary state: %v %v", matches, globErr)
	}
}

func TestEnrollmentRecordIsOneStrictAtomicDocument(t *testing.T) {
	now := time.Date(2026, 7, 28, 9, 0, 0, 0, time.UTC)
	result := guestenrollment.ExchangeResult{
		ContractVersion: guestenrollment.Version,
		Binding: guestenrollment.Binding{
			AgentRunUID: "11111111-1111-1111-1111-111111111111", ExecutionID: "nvt-agentrun-" + strings.Repeat("a", 64),
			DriverRegistration: "qemu-reference", DesiredGeneration: 1, GuestInstanceID: "qemu-guest-" + strings.Repeat("b", 32),
		},
		RuntimeIdentity: guestenrollment.RuntimeIdentity{
			Type: guestenrollment.RuntimeIdentityType, Opaque: base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("A", guestenrollment.TokenBytes))),
			IssuedAt: guestenrollment.FormatTimestamp(now), ExpiresAt: guestenrollment.FormatTimestamp(now.Add(time.Hour)),
		},
	}
	if guestenrollment.ValidateExchangeResult(result) != nil {
		t.Fatal("test exchange result is invalid")
	}
	path := filepath.Join(t.TempDir(), "enrollment.json")
	if err := persistEnrollmentAt(path, result, atomicWrite); err != nil {
		t.Fatalf("persist atomic enrollment: %v", err)
	}
	binding, identity, err := loadEnrollmentAt(path)
	if err != nil || binding == nil || identity == nil || *binding != result.Binding || *identity != result.RuntimeIdentity {
		t.Fatalf("atomic enrollment record lost exact identity state: %#v %#v %v", binding, identity, err)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(entries) != 1 || entries[0].Name() != "enrollment.json" {
		t.Fatalf("enrollment persistence was not one committed file: %#v %v", entries, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("enrollment record mode = %v, want 0600", info.Mode())
	}
}

func TestLocateNamedVirtioControlDeviceWithoutUdevSymlink(t *testing.T) {
	sysfs := t.TempDir()
	entry := filepath.Join(sysfs, "null")
	if err := os.Mkdir(entry, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(entry, "name"), []byte("org.nvt.control\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	path, err := locateControlDeviceAt(sysfs, "/dev")
	if err != nil || path != "/dev/null" {
		t.Fatalf("kernel-named control device = %q, %v", path, err)
	}
}
