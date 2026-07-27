package install

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/mirkoSekulic/nvt-agent/hostbundle/bundle"
	"github.com/mirkoSekulic/nvt-agent/hostbundle/contract"
	"github.com/mirkoSekulic/nvt-agent/hostbundle/oci"
)

const completionFile = ".nvt-complete.json"

type Puller interface {
	Pull(context.Context, oci.Source) ([]byte, error)
}

type Installer struct {
	Puller         Puller
	Root           string
	BeforeActivate func() error
}

type Result struct {
	ReleasePath string
	Digest      string
	Version     string
	Reused      bool
}

type completion struct {
	Version        int    `json:"version"`
	IndexDigest    string `json:"index_digest"`
	ManifestDigest string `json:"manifest_digest"`
}

func (installer Installer) Install(ctx context.Context, source oci.Source) (Result, error) {
	if installer.Puller == nil || !filepath.IsAbs(installer.Root) || filepath.Clean(installer.Root) != installer.Root {
		return Result{}, errors.New("host-bundle installer configuration is invalid")
	}
	if source.OS == "" {
		source.OS = runtime.GOOS
	}
	if source.Architecture == "" {
		source.Architecture = runtime.GOARCH
	}
	if err := ensurePrivateRoot(installer.Root); err != nil {
		return Result{}, err
	}
	layer, err := installer.Puller.Pull(ctx, source)
	if err != nil {
		return Result{}, errors.New("host-bundle acquisition failed")
	}
	temporary, err := os.MkdirTemp(filepath.Join(installer.Root, "releases"), ".install-*")
	if err != nil {
		return Result{}, errors.New("host-bundle temporary release could not be created")
	}
	published := false
	defer func() {
		if !published {
			_ = os.RemoveAll(temporary)
		}
	}()
	if err := os.Chmod(temporary, 0o700); err != nil {
		return Result{}, errors.New("host-bundle temporary release could not be secured")
	}
	manifest, err := bundle.ExtractArchive(bytes.NewReader(layer), temporary)
	if err != nil {
		return Result{}, err
	}
	if manifest.OS != source.OS || manifest.Architecture != source.Architecture {
		return Result{}, errors.New("host-bundle archive platform does not match the selected OCI platform")
	}
	manifestBytes, err := os.ReadFile(filepath.Join(temporary, contract.ManifestPath))
	if err != nil {
		return Result{}, errors.New("host-bundle manifest could not be read after extraction")
	}
	metadata := completion{Version: 1, IndexDigest: source.Digest, ManifestDigest: contract.Digest(manifestBytes)}
	completionBytes, err := encodeCompletion(metadata)
	if err != nil {
		return Result{}, err
	}
	if err := os.WriteFile(filepath.Join(temporary, completionFile), completionBytes, 0o600); err != nil {
		return Result{}, errors.New("host-bundle completion metadata could not be written")
	}
	if err := os.Chmod(temporary, 0o755); err != nil {
		return Result{}, errors.New("host-bundle release permissions could not be finalized")
	}
	if err := validateInstalledTree(temporary, manifest, metadata); err != nil {
		return Result{}, err
	}
	digestComponent := strings.TrimPrefix(source.Digest, "sha256:")
	versionDirectory := filepath.Join(installer.Root, "releases", manifest.BundleVersion)
	if err := secureDirectory(versionDirectory, 0o755); err != nil {
		return Result{}, err
	}
	releasePath := filepath.Join(versionDirectory, digestComponent)
	reused := false
	if _, statErr := os.Lstat(releasePath); statErr == nil {
		if err := validateInstalledTree(releasePath, manifest, metadata); err != nil {
			return Result{}, errors.New("host-bundle release path exists but is incomplete or invalid")
		}
		reused = true
		if err := os.RemoveAll(temporary); err != nil {
			return Result{}, errors.New("host-bundle temporary release cleanup failed")
		}
		published = true
	} else if !os.IsNotExist(statErr) {
		return Result{}, errors.New("host-bundle release path could not be inspected")
	} else {
		if err := os.Rename(temporary, releasePath); err != nil {
			// Another idempotent installer may have won the same content-addressed
			// publication race. Reuse only a complete, byte-validated winner.
			if validateErr := validateInstalledTree(releasePath, manifest, metadata); validateErr != nil {
				return Result{}, errors.New("host-bundle release could not be published")
			}
			if removeErr := os.RemoveAll(temporary); removeErr != nil {
				return Result{}, errors.New("host-bundle temporary release cleanup failed")
			}
			reused = true
		}
		published = true
	}
	if installer.BeforeActivate != nil {
		if err := installer.BeforeActivate(); err != nil {
			return Result{}, errors.New("host-bundle activation precondition failed")
		}
	}
	if err := activate(installer.Root, releasePath); err != nil {
		return Result{}, err
	}
	return Result{ReleasePath: releasePath, Digest: source.Digest, Version: manifest.BundleVersion, Reused: reused}, nil
}

func ensurePrivateRoot(root string) error {
	if err := secureDirectory(root, 0o755); err != nil {
		return err
	}
	if err := secureDirectory(filepath.Join(root, "releases"), 0o755); err != nil {
		return err
	}
	return nil
}

func secureDirectory(directory string, mode os.FileMode) error {
	created := false
	if _, err := os.Lstat(directory); os.IsNotExist(err) {
		if err := os.MkdirAll(directory, mode); err != nil {
			return errors.New("host-bundle install directory is unavailable")
		}
		created = true
	} else if err != nil {
		return errors.New("host-bundle install directory is unavailable")
	}
	if created {
		if err := os.Chmod(directory, mode); err != nil {
			return errors.New("host-bundle install directory could not be secured")
		}
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode().Perm() != mode || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("host-bundle install directory is unsafe")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() {
		return errors.New("host-bundle install directory ownership is unsafe")
	}
	return nil
}

func activate(root, releasePath string) error {
	current := filepath.Join(root, "current")
	if info, err := os.Lstat(current); err == nil {
		if info.Mode()&os.ModeSymlink == 0 {
			return errors.New("host-bundle current path is not a symlink")
		}
		target, readErr := os.Readlink(current)
		if readErr != nil {
			return errors.New("host-bundle current link could not be read")
		}
		absolute := target
		if !filepath.IsAbs(target) {
			absolute = filepath.Join(root, target)
		}
		if filepath.Clean(absolute) == releasePath {
			return nil
		}
	} else if !os.IsNotExist(err) {
		return errors.New("host-bundle current path could not be inspected")
	}
	relative, err := filepath.Rel(root, releasePath)
	if err != nil || strings.HasPrefix(relative, "..") {
		return errors.New("host-bundle activation target is invalid")
	}
	temporary := filepath.Join(root, fmt.Sprintf(".current-%d", time.Now().UnixNano()))
	if err := os.Symlink(relative, temporary); err != nil {
		return errors.New("host-bundle activation link could not be created")
	}
	defer os.Remove(temporary)
	if err := os.Rename(temporary, current); err != nil {
		return errors.New("host-bundle activation could not be committed")
	}
	return nil
}

func validateInstalledTree(root string, manifest contract.Manifest, expected completion) error {
	rootInfo, err := os.Lstat(root)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode().Perm() != 0o755 || !ownedByCurrentIdentity(rootInfo) {
		return errors.New("installed host-bundle release root is unsafe")
	}
	manifestBytes, err := os.ReadFile(filepath.Join(root, contract.ManifestPath))
	if err != nil || contract.Digest(manifestBytes) != expected.ManifestDigest {
		return errors.New("installed host-bundle manifest is invalid")
	}
	decoded, err := contract.DecodeManifest(manifestBytes)
	if err != nil || decoded.BundleVersion != manifest.BundleVersion || decoded.BuildID != manifest.BuildID {
		return errors.New("installed host-bundle manifest is incompatible")
	}
	completionBytes, err := os.ReadFile(filepath.Join(root, completionFile))
	if err != nil {
		return errors.New("installed host-bundle completion metadata is missing")
	}
	var found completion
	if contract.DecodeStrict(completionBytes, 4096, &found) != nil || found != expected {
		return errors.New("installed host-bundle completion metadata is invalid")
	}
	expectedPaths := map[string]contract.File{}
	for _, file := range manifest.Files {
		expectedPaths[filepath.FromSlash(file.Path)] = file
	}
	seen := map[string]struct{}{}
	err = filepath.WalkDir(root, func(fullPath string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return errors.New("installed host-bundle tree could not be inspected")
		}
		relative, err := filepath.Rel(root, fullPath)
		if err != nil || strings.HasPrefix(relative, "..") {
			return errors.New("installed host-bundle path is invalid")
		}
		if relative == "." {
			return nil
		}
		info, err := entry.Info()
		if err != nil || !ownedByCurrentIdentity(info) {
			return errors.New("installed host-bundle ownership is invalid")
		}
		if entry.IsDir() {
			if entry.Type()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o755 {
				return errors.New("installed host-bundle contains an unsafe directory")
			}
			return nil
		}
		if relative == contract.ManifestPath {
			if !info.Mode().IsRegular() || info.Mode().Perm() != 0o644 {
				return errors.New("installed host-bundle manifest metadata is unsafe")
			}
			return nil
		}
		if relative == completionFile {
			if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
				return errors.New("installed host-bundle completion metadata is unsafe")
			}
			return nil
		}
		metadata, exists := expectedPaths[relative]
		if !exists {
			return errors.New("installed host-bundle contains an unexpected file")
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != os.FileMode(metadata.Mode) || info.Size() != metadata.Size {
			return errors.New("installed host-bundle file metadata is invalid")
		}
		file, err := os.Open(fullPath)
		if err != nil {
			return errors.New("installed host-bundle file could not be read")
		}
		digest, hashErr := hashFile(file, metadata.Size)
		file.Close()
		if hashErr != nil || digest != metadata.SHA256 {
			return errors.New("installed host-bundle file digest is invalid")
		}
		seen[relative] = struct{}{}
		return nil
	})
	if err != nil {
		return err
	}
	if len(seen) != len(expectedPaths) {
		return errors.New("installed host-bundle is missing a required file")
	}
	return nil
}

func ownedByCurrentIdentity(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(stat.Uid) == os.Geteuid()
}

func encodeCompletion(value completion) ([]byte, error) {
	data := []byte(fmt.Sprintf("{\"version\":%d,\"index_digest\":%q,\"manifest_digest\":%q}\n", value.Version, value.IndexDigest, value.ManifestDigest))
	if contract.ValidateDigest(value.IndexDigest) != nil || contract.ValidateDigest(value.ManifestDigest) != nil {
		return nil, errors.New("host-bundle completion metadata is invalid")
	}
	return data, nil
}

func hashFile(reader io.Reader, size int64) (string, error) {
	data, err := io.ReadAll(io.LimitReader(reader, size+1))
	if err != nil || int64(len(data)) != size {
		return "", errors.New("file size changed")
	}
	return contract.Digest(data), nil
}
