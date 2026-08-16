// Package state resolves private local-manifest inputs and prepares the
// Docker-volume state used only by trusted local-platform services.
package state

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"unicode/utf8"

	"github.com/mirkoSekulic/nvt-agent/localplatform/manifest"
)

const (
	MaxInstructionBytes = 256 << 10
	MaxSecretBytes      = 64 << 10
)

// Instruction is resolved, non-secret profile guidance. Content is allowed in
// generated configuration; secret input content is deliberately never exposed
// by this package's public model.
type Instruction struct {
	Owner   string `json:"owner"`
	Name    string `json:"name"`
	Content []byte `json:"content"`
}

// Inputs owns resolved sensitive bytes until Close is called. Callers can
// inspect instructions and the redacted plan, but cannot retrieve secret
// material. Only Manager may hand it to a Store through an io.Reader.
type Inputs struct {
	Instructions []Instruction
	private      map[inputKey][]byte
}

type inputKey struct {
	owner string
	name  string
}

type stableInputReader func(*os.Root, string, int64, bool, bool) ([]byte, error)

// Resolve opens all referenced files relative to the directory containing the
// manifest. It reads each file through an os.Root, rechecks stable file
// identity, and returns no partial result on failure.
func Resolve(manifestPath string, compiled manifest.Compiled) (*Inputs, error) {
	return resolveWithReader(manifestPath, compiled, readStable)
}

func resolveWithReader(manifestPath string, compiled manifest.Compiled, readInput stableInputReader) (*Inputs, error) {
	absolute, err := filepath.Abs(manifestPath)
	if err != nil || filepath.Base(absolute) == "." || filepath.Base(absolute) == string(filepath.Separator) {
		return nil, errors.New("local manifest path is invalid")
	}
	rootPath, err := filepath.EvalSymlinks(filepath.Dir(absolute))
	if err != nil {
		return nil, errors.New("local manifest root is unavailable")
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return nil, errors.New("local manifest root is unavailable")
	}
	defer root.Close()

	result := &Inputs{private: map[inputKey][]byte{}}
	fail := func(message string) (*Inputs, error) {
		result.Close()
		return nil, errors.New(message)
	}
	seenInstructions := map[inputKey]struct{}{}
	seenSecrets := map[inputKey]string{}
	secretSnapshots := map[string][]byte{}
	for _, input := range compiled.PrivateInputs {
		key := inputKey{owner: input.Owner, name: input.Name}
		if input.Purpose == "instructions" {
			if input.Owner != "local-controller" || input.Name == "" {
				return fail("instruction input ownership is unsafe")
			}
			if _, exists := seenInstructions[key]; exists {
				return fail("duplicate instruction input")
			}
			seenInstructions[key] = struct{}{}
			if !safeInputPath(input.File, false) {
				return fail("instruction input path is unsafe")
			}
			content, readErr := readStable(root, input.File, MaxInstructionBytes, false, false)
			if readErr != nil || !utf8.Valid(content) {
				clear(content)
				return fail("instruction input is missing, unsafe, or oversized")
			}
			result.Instructions = append(result.Instructions, Instruction{Owner: input.Owner, Name: input.Name, Content: content})
			continue
		}
		if !trustedPrivateOwner(input.Owner) || !safeInputPath(input.File, true) {
			return fail("secret input ownership or path is unsafe")
		}
		source := filepath.Clean(strings.TrimPrefix(input.File, "./"))
		if previous, exists := seenSecrets[key]; exists {
			if previous != source {
				return fail("secret input has conflicting paths")
			}
			continue
		}
		content, exists := secretSnapshots[source]
		if !exists {
			var readErr error
			content, readErr = readInput(root, source, MaxSecretBytes, true, true)
			if readErr != nil || len(content) == 0 {
				clear(content)
				return fail("secret input is missing, unsafe, or oversized")
			}
			secretSnapshots[source] = content
		}
		seenSecrets[key] = source
		result.private[key] = content
	}
	sort.Slice(result.Instructions, func(i, j int) bool {
		if result.Instructions[i].Owner != result.Instructions[j].Owner {
			return result.Instructions[i].Owner < result.Instructions[j].Owner
		}
		return result.Instructions[i].Name < result.Instructions[j].Name
	})
	return result, nil
}

func safeInputPath(value string, secret bool) bool {
	if value == "" || filepath.IsAbs(value) || strings.Contains(value, "\\") || strings.ContainsRune(value, 0) {
		return false
	}
	cleaned := filepath.Clean(strings.TrimPrefix(value, "./"))
	if cleaned == "." || cleaned != strings.TrimPrefix(value, "./") {
		return false
	}
	for _, component := range strings.Split(filepath.ToSlash(cleaned), "/") {
		if component == "" || component == "." || component == ".." {
			return false
		}
	}
	return !secret || cleaned == ".nvt-local/secrets" || strings.HasPrefix(cleaned, ".nvt-local/secrets/")
}

func trustedPrivateOwner(owner string) bool {
	return owner == "broker" || producerServicePattern.MatchString(owner)
}

func readStable(root *os.Root, name string, maximum int64, rejectSymlinks, privateMode bool) ([]byte, error) {
	return readStableAfterFirst(root, name, maximum, rejectSymlinks, privateMode, nil)
}

func readStableAfterFirst(root *os.Root, name string, maximum int64, rejectSymlinks, privateMode bool, afterRead func()) ([]byte, error) {
	cleaned := filepath.Clean(strings.TrimPrefix(name, "./"))
	components := map[string]os.FileInfo{}
	if rejectSymlinks {
		current := ""
		for _, component := range strings.Split(filepath.ToSlash(cleaned), "/") {
			current = filepath.Join(current, component)
			info, err := root.Lstat(current)
			if err != nil || info.Mode()&os.ModeSymlink != 0 {
				return nil, errors.New("symlinked input")
			}
			components[current] = info
		}
	}
	file, err := root.Open(cleaned)
	if err != nil {
		return nil, errors.New("input unavailable")
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Size() < 0 || before.Size() > maximum {
		return nil, errors.New("input is not a bounded regular file")
	}
	if privateMode {
		if !safePrivateMetadata(before) {
			return nil, errors.New("private input ownership or mode is unsafe")
		}
	}
	read := func() ([]byte, error) {
		content, err := io.ReadAll(io.LimitReader(file, maximum+1))
		if err != nil || int64(len(content)) > maximum {
			clear(content)
			return nil, errors.New("input read failed")
		}
		return content, nil
	}
	first, err := read()
	if err != nil {
		return nil, err
	}
	if afterRead != nil {
		afterRead()
	}
	afterFirst, err := file.Stat()
	if err != nil || !os.SameFile(before, afterFirst) || before.Size() != afterFirst.Size() || !before.ModTime().Equal(afterFirst.ModTime()) || privateMode && !safePrivateMetadata(afterFirst) {
		clear(first)
		return nil, errors.New("input changed while being read")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		clear(first)
		return nil, errors.New("input cannot be rechecked")
	}
	second, err := read()
	if err != nil {
		clear(first)
		return nil, err
	}
	afterSecond, err := file.Stat()
	stable := err == nil && os.SameFile(before, afterSecond) && before.Size() == afterSecond.Size() && before.ModTime().Equal(afterSecond.ModTime()) && (!privateMode || safePrivateMetadata(afterSecond)) && bytes.Equal(first, second)
	clear(second)
	if !stable {
		clear(first)
		return nil, errors.New("input changed while being read")
	}
	if rejectSymlinks {
		for component, original := range components {
			final, err := root.Lstat(component)
			if err != nil || final.Mode()&os.ModeSymlink != 0 || !os.SameFile(original, final) {
				clear(first)
				return nil, errors.New("input path changed while being read")
			}
		}
		final := components[cleaned]
		if final == nil || !os.SameFile(before, final) {
			clear(first)
			return nil, errors.New("input path changed while being read")
		}
	}
	return first, nil
}

func safePrivateMetadata(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && info.Mode().IsRegular() && stat.Uid == uint32(os.Geteuid()) && info.Mode().Perm()&0o077 == 0
}

// Close clears all resolved content. Inputs must not be reused afterward.
func (inputs *Inputs) Close() {
	if inputs == nil {
		return
	}
	for index := range inputs.Instructions {
		clear(inputs.Instructions[index].Content)
	}
	inputs.Instructions = nil
	for key, content := range inputs.private {
		clear(content)
		delete(inputs.private, key)
	}
}

func (inputs *Inputs) privateReader(owner, name string) (io.Reader, error) {
	if inputs == nil {
		return nil, errors.New("private inputs are unavailable")
	}
	value, ok := inputs.private[inputKey{owner: owner, name: name}]
	if !ok {
		return nil, fmt.Errorf("private input %s/%s is unavailable", owner, name)
	}
	return bytes.NewReader(value), nil
}
