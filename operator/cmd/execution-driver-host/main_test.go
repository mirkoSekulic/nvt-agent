package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInstallAtomicallyReplacesInterruptedTemporaryFile(t *testing.T) {
	destination := filepath.Join(t.TempDir(), "host", "nvt-execution-driver-host")
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination+".tmp", []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := install([]string{"--destination=" + destination}); err != nil {
		t.Fatalf("install: %v", err)
	}
	info, err := os.Stat(destination)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o555 || info.Size() <= int64(len("partial")) {
		t.Fatalf("installed info=%#v error=%v", info, err)
	}
	if _, err := os.Stat(destination + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("temporary path remains: %v", err)
	}
}
