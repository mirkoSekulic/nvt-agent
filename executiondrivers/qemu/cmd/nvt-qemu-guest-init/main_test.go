package main

import (
	"os"
	"path/filepath"
	"testing"
)

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
