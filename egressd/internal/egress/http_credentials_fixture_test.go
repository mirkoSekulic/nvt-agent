package egress

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Keep the fixture isolated from ambient credentials and Python overrides, but
// retain the selected interpreter's installation and shared-library search path.
func httpCredentialFixturePython(t *testing.T, ctx context.Context, args ...string) *exec.Cmd {
	t.Helper()
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal(err)
	}
	python, err = filepath.Abs(python)
	if err != nil {
		t.Fatal(err)
	}
	// Do not resolve symlinks: a venv's executable path identifies its environment.
	// An absolute argv[0] also prevents CPython from rediscovering a different
	// installation via PATH, even though Go already resolved Cmd.Path correctly.
	cmd := exec.CommandContext(ctx, python, args...)
	cmd.Env = []string{"PATH=" + filepath.Dir(python) + ":/usr/bin:/bin"}
	if libraryPath, ok := os.LookupEnv("LD_LIBRARY_PATH"); ok {
		cmd.Env = append(cmd.Env, "LD_LIBRARY_PATH="+libraryPath)
	}
	return cmd
}

func TestHTTPFixturePythonPreservesSelectedInstallation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	venv := filepath.Join(t.TempDir(), "python-env")
	create := httpCredentialFixturePython(t, ctx, "-m", "venv", "--without-pip", venv)
	if out, err := create.CombinedOutput(); err != nil {
		t.Fatalf("create isolated Python fixture: %v: %s", err, out)
	}
	python := filepath.Join(venv, "bin", "python3")
	locate := exec.CommandContext(ctx, python, "-c", "import sysconfig; print(sysconfig.get_path('purelib'))")
	locate.Env = create.Env
	out, err := locate.Output()
	if err != nil {
		t.Fatal(err)
	}
	module := filepath.Join(strings.TrimSpace(string(out)), "nvt_fixture_installation.py")
	if err := os.WriteFile(module, []byte("VALUE = 'selected-installation'\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", filepath.Dir(python)+":"+os.Getenv("PATH"))
	t.Setenv("PYTHONHOME", "/nonexistent-ambient-python-home")
	t.Setenv("PYTHONPATH", "/nonexistent-ambient-python-path")
	t.Setenv("NVT_FIXTURE_AMBIENT_SECRET", "fake-ambient-canary")
	t.Setenv("HTTPS_PROXY", "http://ambient.invalid:1234")
	probe := "import os, sys, nvt_fixture_installation as m; " +
		"assert sys.prefix == sys.argv[1]; " +
		"assert all(k not in os.environ for k in ('PYTHONHOME', 'PYTHONPATH', 'NVT_FIXTURE_AMBIENT_SECRET', 'HTTPS_PROXY')); " +
		"print(m.VALUE)"
	command := httpCredentialFixturePython(t, ctx, "-c", probe, venv)
	if command.Path != python || command.Args[0] != python {
		t.Fatalf("interpreter must remain absolute and retain venv identity: %q / %q", command.Path, command.Args[0])
	}
	// Reproduce the old startup bug: Cmd.Path is correct, but bare argv[0] and
	// the overwritten PATH cause Python to use system packages instead.
	broken := exec.CommandContext(ctx, python, "-c", "import nvt_fixture_installation")
	broken.Args[0] = "python3"
	broken.Env = []string{"PATH=/usr/bin:/bin"}
	for _, entry := range command.Env {
		if strings.HasPrefix(entry, "LD_LIBRARY_PATH=") {
			broken.Env = append(broken.Env, entry)
		}
	}
	if output, err := broken.CombinedOutput(); err == nil || !strings.Contains(string(output), "ModuleNotFoundError") {
		t.Fatalf("old fixture must lose its interpreter-specific package: %v: %s", err, output)
	}
	if output, err := command.CombinedOutput(); err != nil || strings.TrimSpace(string(output)) != "selected-installation" {
		t.Fatalf("selected Python installation was not preserved: %v: %s", err, output)
	}
}
