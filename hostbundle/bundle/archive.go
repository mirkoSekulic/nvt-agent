package bundle

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/mirkoSekulic/nvt-agent/hostbundle/contract"
)

type InputFile struct {
	Path   string
	Source string
	Mode   os.FileMode
}

func BuildArchive(output string, manifest contract.Manifest, inputs []InputFile) (contract.Manifest, error) {
	if len(inputs) == 0 || len(inputs) > contract.MaxFiles {
		return contract.Manifest{}, errors.New("host-bundle input count is invalid")
	}
	files := make([]contract.File, 0, len(inputs))
	seen := map[string]struct{}{}
	for _, input := range inputs {
		if input.Mode != 0o644 && input.Mode != 0o755 {
			return contract.Manifest{}, errors.New("host-bundle input mode is invalid")
		}
		if input.Path == "" || path.Clean(input.Path) != input.Path || path.IsAbs(input.Path) || strings.HasPrefix(input.Path, "../") || strings.Contains(input.Path, "\\") || input.Path == contract.ManifestPath {
			return contract.Manifest{}, errors.New("host-bundle input path is invalid")
		}
		if _, duplicate := seen[input.Path]; duplicate {
			return contract.Manifest{}, errors.New("host-bundle input path is duplicated")
		}
		seen[input.Path] = struct{}{}
		info, err := os.Lstat(input.Source)
		if err != nil || !info.Mode().IsRegular() {
			return contract.Manifest{}, errors.New("host-bundle input is unavailable")
		}
		file, err := os.Open(input.Source)
		if err != nil {
			return contract.Manifest{}, errors.New("host-bundle input is unavailable")
		}
		digest, size, copyErr := hashReader(file, contract.MaxExtractedBytes)
		closeErr := file.Close()
		if copyErr != nil || closeErr != nil {
			return contract.Manifest{}, errors.New("host-bundle input could not be read")
		}
		files = append(files, contract.File{Path: input.Path, SHA256: digest, Size: size, Mode: uint32(input.Mode.Perm())})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	manifest.Files = files
	manifestBytes, err := contract.EncodeManifest(manifest)
	if err != nil {
		return contract.Manifest{}, err
	}

	temporary, err := os.CreateTemp(filepath.Dir(output), ".host-bundle-*.tmp")
	if err != nil {
		return contract.Manifest{}, fmt.Errorf("create host-bundle archive: %w", err)
	}
	temporaryName := temporary.Name()
	committed := false
	defer func() {
		_ = temporary.Close()
		if !committed {
			_ = os.Remove(temporaryName)
		}
	}()

	gzipWriter, err := gzip.NewWriterLevel(temporary, gzip.BestCompression)
	if err != nil {
		return contract.Manifest{}, fmt.Errorf("create host-bundle compressor: %w", err)
	}
	gzipWriter.Header.ModTime = time.Unix(0, 0).UTC()
	gzipWriter.Header.OS = 255
	tarWriter := tar.NewWriter(gzipWriter)
	if err := writeBytes(tarWriter, contract.ManifestPath, manifestBytes, 0o644); err != nil {
		return contract.Manifest{}, err
	}

	directories := requiredDirectories(files)
	for _, directory := range directories {
		if err := tarWriter.WriteHeader(&tar.Header{
			Name: directory + "/", Mode: 0o755, Typeflag: tar.TypeDir,
			Uid: 0, Gid: 0, Uname: "root", Gname: "root", ModTime: time.Unix(0, 0).UTC(),
		}); err != nil {
			return contract.Manifest{}, errors.New("write host-bundle directory")
		}
	}
	inputByPath := make(map[string]InputFile, len(inputs))
	for _, input := range inputs {
		inputByPath[input.Path] = input
	}
	for _, metadata := range files {
		input := inputByPath[metadata.Path]
		if err := writeFile(tarWriter, input.Source, metadata); err != nil {
			return contract.Manifest{}, err
		}
	}
	if err := tarWriter.Close(); err != nil {
		return contract.Manifest{}, errors.New("finalize host-bundle tar")
	}
	if err := gzipWriter.Close(); err != nil {
		return contract.Manifest{}, errors.New("finalize host-bundle compression")
	}
	if err := temporary.Sync(); err != nil {
		return contract.Manifest{}, errors.New("sync host-bundle archive")
	}
	if err := temporary.Close(); err != nil {
		return contract.Manifest{}, errors.New("close host-bundle archive")
	}
	if err := os.Rename(temporaryName, output); err != nil {
		return contract.Manifest{}, fmt.Errorf("publish host-bundle archive: %w", err)
	}
	committed = true
	return manifest, nil
}

func ExtractArchive(reader io.Reader, destination string) (contract.Manifest, error) {
	limited := &io.LimitedReader{R: reader, N: contract.MaxBundleBytes + 1}
	buffered := bufio.NewReader(limited)
	gzipReader, err := gzip.NewReader(buffered)
	if err != nil {
		return contract.Manifest{}, errors.New("host-bundle layer is not valid gzip")
	}
	defer gzipReader.Close()
	gzipReader.Multistream(false)
	tarReader := tar.NewReader(&io.LimitedReader{R: gzipReader, N: contract.MaxExtractedBytes + contract.MaxManifestBytes + 1})
	header, err := tarReader.Next()
	if err != nil || header.Name != contract.ManifestPath || header.Typeflag != tar.TypeReg || header.Size <= 0 || header.Size > contract.MaxManifestBytes {
		return contract.Manifest{}, errors.New("host-bundle manifest entry is invalid")
	}
	if err := validateHeader(header, 0o644); err != nil {
		return contract.Manifest{}, err
	}
	manifestBytes, err := io.ReadAll(io.LimitReader(tarReader, contract.MaxManifestBytes+1))
	if err != nil || int64(len(manifestBytes)) != header.Size {
		return contract.Manifest{}, errors.New("host-bundle manifest could not be read")
	}
	manifest, err := contract.DecodeManifest(manifestBytes)
	if err != nil {
		return contract.Manifest{}, err
	}
	expected := make(map[string]contract.File, len(manifest.Files))
	allowedDirs := map[string]struct{}{}
	for _, file := range manifest.Files {
		expected[file.Path] = file
		for directory := path.Dir(file.Path); directory != "."; directory = path.Dir(directory) {
			allowedDirs[directory] = struct{}{}
		}
	}
	if err := os.MkdirAll(destination, 0o700); err != nil {
		return contract.Manifest{}, errors.New("host-bundle destination is unavailable")
	}
	if err := os.WriteFile(filepath.Join(destination, contract.ManifestPath), manifestBytes, 0o600); err != nil {
		return contract.Manifest{}, errors.New("host-bundle manifest could not be installed")
	}
	seen := map[string]struct{}{contract.ManifestPath: {}}
	seenFiles := map[string]struct{}{}
	var total int64
	entries := 1
	for {
		header, nextErr := tarReader.Next()
		if nextErr == io.EOF {
			break
		}
		if nextErr != nil {
			return contract.Manifest{}, errors.New("host-bundle tar is malformed")
		}
		entries++
		if entries > contract.MaxFiles*2+1 {
			return contract.Manifest{}, errors.New("host-bundle entry count exceeds the bound")
		}
		name := strings.TrimSuffix(header.Name, "/")
		if name == "" || path.Clean(name) != name || path.IsAbs(name) || strings.HasPrefix(name, "../") || strings.Contains(name, "\\") {
			return contract.Manifest{}, errors.New("host-bundle entry path is unsafe")
		}
		if _, duplicate := seen[name]; duplicate {
			return contract.Manifest{}, errors.New("host-bundle contains a duplicate path")
		}
		seen[name] = struct{}{}
		switch header.Typeflag {
		case tar.TypeDir:
			if _, allowed := allowedDirs[name]; !allowed || header.Size != 0 {
				return contract.Manifest{}, errors.New("host-bundle contains an unexpected directory")
			}
			if err := validateHeader(header, 0o755); err != nil {
				return contract.Manifest{}, err
			}
			if err := secureMkdirAll(destination, name); err != nil {
				return contract.Manifest{}, err
			}
		case tar.TypeReg:
			metadata, allowed := expected[name]
			if !allowed || header.Size != metadata.Size || uint32(header.Mode) != metadata.Mode {
				return contract.Manifest{}, errors.New("host-bundle file metadata does not match the manifest")
			}
			if err := validateHeader(header, os.FileMode(metadata.Mode)); err != nil {
				return contract.Manifest{}, err
			}
			if total > contract.MaxExtractedBytes-header.Size {
				return contract.Manifest{}, errors.New("host-bundle extracted content exceeds the bound")
			}
			total += header.Size
			if err := extractFile(tarReader, destination, metadata); err != nil {
				return contract.Manifest{}, err
			}
			seenFiles[name] = struct{}{}
		default:
			return contract.Manifest{}, errors.New("host-bundle contains an unsupported file type")
		}
	}
	if limited.N <= 0 {
		return contract.Manifest{}, errors.New("host-bundle layer exceeds the compressed-size bound")
	}
	if len(seenFiles) != len(expected) {
		return contract.Manifest{}, errors.New("host-bundle is missing a required file")
	}
	if _, err := io.Copy(io.Discard, gzipReader); err != nil {
		return contract.Manifest{}, errors.New("host-bundle gzip trailer is invalid")
	}
	if _, err := buffered.Peek(1); err != io.EOF {
		return contract.Manifest{}, errors.New("host-bundle contains trailing compressed data")
	}
	if err := os.Chmod(filepath.Join(destination, contract.ManifestPath), 0o644); err != nil {
		return contract.Manifest{}, errors.New("host-bundle manifest mode could not be finalized")
	}
	return manifest, nil
}

func writeBytes(writer *tar.Writer, name string, data []byte, mode int64) error {
	header := &tar.Header{Name: name, Mode: mode, Size: int64(len(data)), Typeflag: tar.TypeReg, Uid: 0, Gid: 0, Uname: "root", Gname: "root", ModTime: time.Unix(0, 0).UTC()}
	if err := writer.WriteHeader(header); err != nil {
		return errors.New("write host-bundle header")
	}
	if _, err := writer.Write(data); err != nil {
		return errors.New("write host-bundle content")
	}
	return nil
}

func writeFile(writer *tar.Writer, source string, metadata contract.File) error {
	header := &tar.Header{Name: metadata.Path, Mode: int64(metadata.Mode), Size: metadata.Size, Typeflag: tar.TypeReg, Uid: 0, Gid: 0, Uname: "root", Gname: "root", ModTime: time.Unix(0, 0).UTC()}
	if err := writer.WriteHeader(header); err != nil {
		return errors.New("write host-bundle file header")
	}
	file, err := os.Open(source)
	if err != nil {
		return errors.New("open host-bundle input")
	}
	defer file.Close()
	hasher := sha256.New()
	written, err := io.Copy(io.MultiWriter(writer, hasher), io.LimitReader(file, metadata.Size+1))
	if err != nil || written != metadata.Size || hashDigest(hasher) != metadata.SHA256 {
		return errors.New("write host-bundle file")
	}
	return nil
}

func requiredDirectories(files []contract.File) []string {
	directories := map[string]struct{}{}
	for _, file := range files {
		for directory := path.Dir(file.Path); directory != "."; directory = path.Dir(directory) {
			directories[directory] = struct{}{}
		}
	}
	result := make([]string, 0, len(directories))
	for directory := range directories {
		result = append(result, directory)
	}
	sort.Strings(result)
	return result
}

func validateHeader(header *tar.Header, expected os.FileMode) error {
	if header.Uid != 0 || header.Gid != 0 || (header.Uname != "" && header.Uname != "root") || (header.Gname != "" && header.Gname != "root") {
		return errors.New("host-bundle archive ownership is invalid")
	}
	if header.Mode != int64(expected.Perm()) || header.Mode&0o7000 != 0 {
		return errors.New("host-bundle archive mode is invalid")
	}
	if !header.ModTime.Equal(time.Unix(0, 0).UTC()) || len(header.PAXRecords) != 0 || len(header.Xattrs) != 0 {
		return errors.New("host-bundle archive metadata is not deterministic")
	}
	return nil
}

func secureMkdirAll(root, relative string) error {
	current := root
	for _, component := range strings.Split(relative, "/") {
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if os.IsNotExist(err) {
			if err := os.Mkdir(current, 0o755); err != nil {
				return errors.New("host-bundle directory could not be created")
			}
			continue
		}
		if err != nil || !info.IsDir() || info.Mode().Perm() != 0o755 {
			return errors.New("host-bundle directory is unsafe")
		}
	}
	return nil
}

func extractFile(reader io.Reader, root string, metadata contract.File) error {
	directory := path.Dir(metadata.Path)
	if directory != "." {
		if err := secureMkdirAll(root, directory); err != nil {
			return err
		}
	}
	destination := filepath.Join(root, filepath.FromSlash(metadata.Path))
	file, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return errors.New("host-bundle file could not be created")
	}
	hasher := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(file, hasher), io.LimitReader(reader, metadata.Size+1))
	closeErr := file.Close()
	if copyErr != nil || closeErr != nil || written != metadata.Size || "sha256:"+hex.EncodeToString(hasher.Sum(nil)) != metadata.SHA256 {
		return errors.New("host-bundle file content is invalid")
	}
	if err := os.Chmod(destination, os.FileMode(metadata.Mode)); err != nil {
		return errors.New("host-bundle file mode could not be set")
	}
	return nil
}

func hashReader(reader io.Reader, maximum int64) (string, int64, error) {
	hasher := sha256.New()
	written, err := io.Copy(hasher, io.LimitReader(reader, maximum+1))
	if err != nil || written > maximum {
		return "", 0, errors.New("content exceeds the bound")
	}
	return hashDigest(hasher), written, nil
}

func hashDigest(hasher hash.Hash) string {
	return "sha256:" + hex.EncodeToString(hasher.Sum(nil))
}
