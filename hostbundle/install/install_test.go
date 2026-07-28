package install

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/mirkoSekulic/nvt-agent/hostbundle/bundle"
	"github.com/mirkoSekulic/nvt-agent/hostbundle/contract"
	"github.com/mirkoSekulic/nvt-agent/hostbundle/oci"
)

type staticPuller struct {
	data []byte
	err  error
}

func (puller staticPuller) Pull(context.Context, oci.Source) ([]byte, error) {
	return append([]byte(nil), puller.data...), puller.err
}

func TestInstallIsAtomicIdempotentAndPreservesPreviousActivation(t *testing.T) {
	root := filepath.Join(t.TempDir(), "opt", "nvt")
	firstArchive := makeArchive(t, "0.8.33-a", "first")
	firstSource := oci.Source{Repository: "https://registry.example.test/nvt/host", Digest: "sha256:" + strings.Repeat("1", 64), OS: "linux", Architecture: "amd64"}
	installer := Installer{Puller: staticPuller{data: firstArchive}, Root: root}
	first, err := installer.Install(context.Background(), firstSource)
	if err != nil {
		t.Fatal(err)
	}
	if first.Reused {
		t.Fatal("first install was reported as reused")
	}
	currentBefore, err := os.Readlink(filepath.Join(root, "current"))
	if err != nil {
		t.Fatal(err)
	}
	repeated, err := installer.Install(context.Background(), firstSource)
	if err != nil || !repeated.Reused || repeated.ReleasePath != first.ReleasePath {
		t.Fatalf("repeat install was not idempotent: %#v %v", repeated, err)
	}

	secondArchive := makeArchive(t, "0.8.33-b", "second")
	secondSource := oci.Source{Repository: firstSource.Repository, Digest: "sha256:" + strings.Repeat("2", 64), OS: "linux", Architecture: "amd64"}
	failed := Installer{
		Puller: staticPuller{data: secondArchive}, Root: root,
		BeforeActivate: func() error { return errors.New("injected activation failure") },
	}
	if _, err := failed.Install(context.Background(), secondSource); err == nil {
		t.Fatal("activation failure was accepted")
	}
	currentAfter, _ := os.Readlink(filepath.Join(root, "current"))
	if currentAfter != currentBefore {
		t.Fatalf("failed update changed current from %q to %q", currentBefore, currentAfter)
	}
	content, _ := os.ReadFile(filepath.Join(root, currentAfter, "bin", "nvt-guest-supervisor"))
	if string(content) != "first" {
		t.Fatalf("previous release was not usable: %q", content)
	}

	corrupt := append([]byte(nil), secondArchive...)
	corrupt[len(corrupt)/2] ^= 0xff
	if _, err := (Installer{Puller: staticPuller{data: corrupt}, Root: root}).Install(context.Background(), secondSource); err == nil {
		t.Fatal("corrupt update was accepted")
	}
	currentAfterCorruption, _ := os.Readlink(filepath.Join(root, "current"))
	if currentAfterCorruption != currentBefore {
		t.Fatal("corrupt update changed current")
	}
	entries, _ := filepath.Glob(filepath.Join(root, "releases", ".install-*"))
	if len(entries) != 0 {
		t.Fatalf("temporary installs remain: %v", entries)
	}
}

func TestInstallRejectsIncompleteFinalPathAndCleansTemporaryState(t *testing.T) {
	root := filepath.Join(t.TempDir(), "opt", "nvt")
	archive := makeArchive(t, "0.8.33-test", "content")
	source := oci.Source{Repository: "https://registry.example.test/nvt/host", Digest: "sha256:" + strings.Repeat("3", 64), OS: "linux", Architecture: "amd64"}
	incomplete := filepath.Join(root, "releases", "0.8.33-test", strings.Repeat("3", 64))
	if err := os.MkdirAll(incomplete, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(incomplete, "partial"), []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (Installer{Puller: staticPuller{data: archive}, Root: root}).Install(context.Background(), source); err == nil {
		t.Fatal("incomplete final path was accepted")
	}
	if content, _ := os.ReadFile(filepath.Join(incomplete, "partial")); string(content) != "partial" {
		t.Fatal("existing partial path was destroyed")
	}
	entries, _ := filepath.Glob(filepath.Join(root, "releases", ".install-*"))
	if len(entries) != 0 {
		t.Fatalf("temporary install was not cleaned: %v", entries)
	}
}

func TestInstallRejectsUnsafeExistingRootWithoutMutatingIt(t *testing.T) {
	archive := makeArchive(t, "0.8.33-root", "content")
	source := oci.Source{Repository: "https://registry.example.test/nvt/host", Digest: "sha256:" + strings.Repeat("5", 64), OS: "linux", Architecture: "amd64"}

	insecure := filepath.Join(t.TempDir(), "nvt")
	if err := os.Mkdir(insecure, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(insecure, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := (Installer{Puller: staticPuller{data: archive}, Root: insecure}).Install(context.Background(), source); err == nil {
		t.Fatal("insecure existing install root was accepted")
	}
	if info, err := os.Stat(insecure); err != nil || info.Mode().Perm() != 0o777 {
		t.Fatalf("unsafe root was mutated: %v %v", info, err)
	}

	target := filepath.Join(t.TempDir(), "target")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(t.TempDir(), "nvt")
	if err := os.Symlink(target, linked); err != nil {
		t.Fatal(err)
	}
	if _, err := (Installer{Puller: staticPuller{data: archive}, Root: linked}).Install(context.Background(), source); err == nil {
		t.Fatal("symlinked install root was accepted")
	}
	if info, err := os.Stat(target); err != nil || info.Mode().Perm() != 0o755 {
		t.Fatalf("symlink target was mutated: %v %v", info, err)
	}
}

func TestInstallSynchronizesReleaseAndActivationDurably(t *testing.T) {
	root := filepath.Join(t.TempDir(), "opt", "nvt")
	archive := makeArchive(t, "0.8.33-durable", "content")
	source := oci.Source{Repository: "https://registry.example.test/nvt/host", Digest: "sha256:" + strings.Repeat("6", 64), OS: "linux", Architecture: "amd64"}
	var synchronized []string
	installer := Installer{
		Puller: staticPuller{data: archive}, Root: root,
		syncPath: func(path string) error {
			synchronized = append(synchronized, path)
			return nil
		},
	}
	if _, err := installer.Install(context.Background(), source); err != nil {
		t.Fatal(err)
	}
	if len(synchronized) == 0 || synchronized[0] != filepath.Dir(root) {
		t.Fatalf("install-root parent was not synchronized after creation: %v", synchronized)
	}
	requiredSuffixes := []string{
		filepath.Join("bin", "nvt-guest-supervisor"),
		contract.ManifestPath,
		completionFile,
		filepath.Join("releases", "0.8.33-durable"),
		"releases",
	}
	for _, suffix := range requiredSuffixes {
		if !containsPathSuffix(synchronized, suffix) {
			t.Fatalf("durability sync omitted %q: %v", suffix, synchronized)
		}
	}
	if synchronized[len(synchronized)-1] != root {
		t.Fatalf("install root was not synchronized after current commit: %v", synchronized)
	}
}

func TestDurabilityFailuresBeforeActivationPreserveCurrent(t *testing.T) {
	root := filepath.Join(t.TempDir(), "opt", "nvt")
	firstSource := oci.Source{Repository: "https://registry.example.test/nvt/host", Digest: "sha256:" + strings.Repeat("7", 64), OS: "linux", Architecture: "amd64"}
	if _, err := (Installer{Puller: staticPuller{data: makeArchive(t, "0.8.33-durable-a", "first")}, Root: root}).Install(context.Background(), firstSource); err != nil {
		t.Fatal(err)
	}
	currentBefore, err := os.Readlink(filepath.Join(root, "current"))
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		version    string
		digestByte string
		fail       func(string) bool
	}{
		{name: "file before publication", version: "0.8.33-durable-file", digestByte: "8", fail: func(path string) bool { return filepath.Base(path) == completionFile }},
		{name: "parent after publication", version: "0.8.33-durable-parent", digestByte: "9", fail: func(path string) bool { return path == filepath.Join(root, "releases", "0.8.33-durable-parent") }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			canary := "NVT_TEST_SYNC_CANARY"
			source := oci.Source{Repository: firstSource.Repository, Digest: "sha256:" + strings.Repeat(test.digestByte, 64), OS: "linux", Architecture: "amd64"}
			installer := Installer{
				Puller: staticPuller{data: makeArchive(t, test.version, "next")}, Root: root,
				syncPath: func(path string) error {
					if test.fail(path) {
						return errors.New(canary)
					}
					return syncFilesystemPath(path)
				},
			}
			_, err := installer.Install(context.Background(), source)
			if err == nil || strings.Contains(err.Error(), canary) {
				t.Fatalf("durability failure was not sanitized: %v", err)
			}
			currentAfter, readErr := os.Readlink(filepath.Join(root, "current"))
			if readErr != nil || currentAfter != currentBefore {
				t.Fatalf("pre-activation sync failure changed current: %q %v", currentAfter, readErr)
			}
		})
	}
}

func containsPathSuffix(paths []string, suffix string) bool {
	for _, path := range paths {
		if path == suffix || strings.HasSuffix(path, string(filepath.Separator)+suffix) {
			return true
		}
	}
	return false
}

func TestConcurrentIdenticalInstallsConvergeOnOneCompleteRelease(t *testing.T) {
	root := filepath.Join(t.TempDir(), "opt", "nvt")
	archive := makeArchive(t, "0.8.33-concurrent", "content")
	source := oci.Source{Repository: "https://registry.example.test/nvt/host", Digest: "sha256:" + strings.Repeat("4", 64), OS: "linux", Architecture: "amd64"}
	installer := Installer{Puller: staticPuller{data: archive}, Root: root}
	results := make([]Result, 2)
	errorsFound := make([]error, 2)
	var wait sync.WaitGroup
	for index := range results {
		wait.Add(1)
		go func() {
			defer wait.Done()
			results[index], errorsFound[index] = installer.Install(context.Background(), source)
		}()
	}
	wait.Wait()
	for index, err := range errorsFound {
		if err != nil {
			t.Fatalf("installer %d failed: %v", index, err)
		}
	}
	if results[0].ReleasePath != results[1].ReleasePath {
		t.Fatalf("installers diverged: %#v", results)
	}
	current, err := os.Readlink(filepath.Join(root, "current"))
	if err != nil || filepath.Clean(filepath.Join(root, current)) != results[0].ReleasePath {
		t.Fatalf("unexpected activation: %q %v", current, err)
	}
}

func TestInstallErrorsDoNotExposePullerMaterial(t *testing.T) {
	canary := "NVT_TEST_SECRET_CANARY"
	root := filepath.Join(t.TempDir(), "nvt")
	_, err := (Installer{Puller: staticPuller{err: errors.New(canary)}, Root: root}).Install(context.Background(), oci.Source{})
	if err == nil {
		t.Fatal("pull failure was accepted")
	}
	if strings.Contains(err.Error(), canary) {
		t.Fatal("puller diagnostic escaped the installer boundary")
	}
	if paths, _ := filepath.Glob(filepath.Join(root, "releases", ".install-*")); len(paths) != 0 {
		t.Fatal("unexpected residue")
	}
}

func makeArchive(t *testing.T, version, content string) []byte {
	t.Helper()
	directory := t.TempDir()
	source := filepath.Join(directory, "supervisor")
	if err := os.WriteFile(source, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(directory, "bundle.tar.gz")
	manifest := contract.Manifest{
		ContractVersion: contract.Version, OS: "linux", Architecture: "amd64",
		BundleVersion: version, BuildID: strings.Repeat("a", 40),
		NativeEntrypoint: "bin/nvt-guest-supervisor", ServiceIdentity: "nvt-agent-guest.service",
		Compatibility: contract.Compatibility{AgentdProtocol: contract.AgentdProtocolVersion, NativeSessionProtocol: contract.NativeSessionProtocolVersion},
	}
	if _, err := bundle.BuildArchive(archive, manifest, []bundle.InputFile{{Path: "bin/nvt-guest-supervisor", Source: source, Mode: 0o755}}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.Clone(data)
}
