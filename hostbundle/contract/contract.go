package contract

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

const (
	Version                        = "nvt.host-bundle/v1"
	AgentdProtocolVersion          = "nvt.agentd/v1"
	NativeSessionProtocolVersion   = "nvt.native-session/v1"
	NativeWorkspaceProtocolVersion = "nvt.native-workspace/v1"
	ArtifactType                   = "application/vnd.nvt.host-bundle.v1"
	LayerMediaType                 = "application/vnd.nvt.host-bundle.layer.v1.tar+gzip"
	OCIManifestMediaType           = "application/vnd.oci.image.manifest.v1+json"
	OCIIndexMediaType              = "application/vnd.oci.image.index.v1+json"
	OCIEmptyConfigMediaType        = "application/vnd.oci.empty.v1+json"
	ManifestPath                   = "manifest.json"
	MaxManifestBytes               = 256 * 1024
	MaxBundleBytes                 = 128 * 1024 * 1024
	MaxExtractedBytes              = 256 * 1024 * 1024
	MaxFiles                       = 1024
)

var (
	versionPattern  = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z._-]{0,127}$`)
	revisionPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
	digestPattern   = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

type Manifest struct {
	ContractVersion  string        `json:"contract_version"`
	OS               string        `json:"os"`
	Architecture     string        `json:"architecture"`
	BundleVersion    string        `json:"bundle_version"`
	BuildID          string        `json:"build_id"`
	NativeEntrypoint string        `json:"native_entrypoint"`
	ServiceIdentity  string        `json:"service_identity"`
	Compatibility    Compatibility `json:"compatibility"`
	Files            []File        `json:"files"`
}

type Compatibility struct {
	AgentdProtocol          string `json:"agentd_protocol"`
	NativeSessionProtocol   string `json:"native_session_protocol,omitempty"`
	NativeWorkspaceProtocol string `json:"native_workspace_protocol,omitempty"`
}

type File struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
	Mode   uint32 `json:"mode"`
}

func Digest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func ValidateDigest(value string) error {
	if !digestPattern.MatchString(value) {
		return errors.New("digest must be a lowercase sha256 digest")
	}
	return nil
}

func ValidateManifest(manifest Manifest) error {
	if manifest.ContractVersion != Version {
		return errors.New("unsupported host-bundle contract version")
	}
	if manifest.OS != "linux" {
		return errors.New("host bundle OS must be linux")
	}
	if !validArchitecture(manifest.Architecture) {
		return errors.New("host bundle architecture is invalid")
	}
	if !versionPattern.MatchString(manifest.BundleVersion) {
		return errors.New("host bundle version is invalid")
	}
	if !revisionPattern.MatchString(manifest.BuildID) {
		return errors.New("host bundle build identity is invalid")
	}
	if validateContainedPath(manifest.NativeEntrypoint) != nil {
		return errors.New("host bundle native entrypoint is invalid")
	}
	if manifest.ServiceIdentity != "nvt-agent-guest.service" {
		return errors.New("host bundle service identity is invalid")
	}
	if manifest.Compatibility.AgentdProtocol != AgentdProtocolVersion ||
		(manifest.Compatibility.NativeSessionProtocol != "" && manifest.Compatibility.NativeSessionProtocol != NativeSessionProtocolVersion) ||
		(manifest.Compatibility.NativeWorkspaceProtocol != "" && manifest.Compatibility.NativeWorkspaceProtocol != NativeWorkspaceProtocolVersion) {
		return errors.New("host bundle protocol compatibility is invalid")
	}
	if len(manifest.Files) == 0 || len(manifest.Files) > MaxFiles {
		return errors.New("host bundle file count is invalid")
	}
	seen := make(map[string]struct{}, len(manifest.Files))
	var total int64
	entrypoint := false
	previous := ""
	for _, file := range manifest.Files {
		if err := validateContainedPath(file.Path); err != nil || file.Path == ManifestPath {
			return errors.New("host bundle contains an invalid file path")
		}
		if _, duplicate := seen[file.Path]; duplicate {
			return errors.New("host bundle contains duplicate file metadata")
		}
		seen[file.Path] = struct{}{}
		if previous != "" && file.Path <= previous {
			return errors.New("host bundle file metadata is not canonically ordered")
		}
		previous = file.Path
		if err := ValidateDigest(file.SHA256); err != nil {
			return errors.New("host bundle file digest is invalid")
		}
		if file.Size < 0 || file.Size > MaxExtractedBytes || total > MaxExtractedBytes-file.Size {
			return errors.New("host bundle file sizes exceed the bound")
		}
		total += file.Size
		if file.Mode != 0o644 && file.Mode != 0o755 {
			return errors.New("host bundle file mode is invalid")
		}
		if file.Path == manifest.NativeEntrypoint {
			entrypoint = file.Mode == 0o755
		}
	}
	if !entrypoint {
		return errors.New("host bundle native entrypoint is missing or not executable")
	}
	return nil
}

func DecodeManifest(data []byte) (Manifest, error) {
	var manifest Manifest
	if err := DecodeStrict(data, MaxManifestBytes, &manifest); err != nil {
		return Manifest{}, errors.New("host-bundle manifest is invalid")
	}
	if err := ValidateManifest(manifest); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func DecodeStrict(data []byte, maximum int, destination any) error {
	if len(data) == 0 || len(data) > maximum || !utf8.Valid(data) {
		return errors.New("JSON input is invalid")
	}
	if err := rejectDuplicateKeys(data); err != nil {
		return errors.New("JSON input is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return errors.New("JSON input is invalid")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("JSON input is invalid")
	}
	return nil
}

func EncodeManifest(manifest Manifest) ([]byte, error) {
	files := append([]File(nil), manifest.Files...)
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	manifest.Files = files
	if err := ValidateManifest(manifest); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		return nil, fmt.Errorf("encode host-bundle manifest: %w", err)
	}
	return append(encoded, '\n'), nil
}

func validateContainedPath(value string) error {
	if value == "" || strings.Contains(value, "\\") || strings.ContainsRune(value, 0) || path.IsAbs(value) || path.Clean(value) != value || value == "." || strings.HasPrefix(value, "../") {
		return errors.New("path is not contained")
	}
	return nil
}

func validArchitecture(value string) bool {
	switch value {
	case "amd64", "arm64":
		return true
	default:
		return false
	}
}

func rejectDuplicateKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	return scanJSONValue(decoder)
}

func scanJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}
	switch delimiter {
	case '{':
		keys := map[string]struct{}{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("object key is invalid")
			}
			if _, duplicate := keys[key]; duplicate {
				return errors.New("duplicate object key")
			}
			keys[key] = struct{}{}
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	case '[':
		for decoder.More() {
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	default:
		return errors.New("invalid JSON delimiter")
	}
}
