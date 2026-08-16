package state

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/distribution/reference"
	"github.com/mirkoSekulic/nvt-agent/localplatform/manifest"
)

// CommandBoundary is the only Docker-specific authority. Implementations must
// treat stdin as sensitive and must never include it in output or diagnostics.
type CommandBoundary interface {
	Run(context.Context, io.Reader, ...string) ([]byte, error)
}

type DockerStore struct {
	Docker      CommandBoundary
	HelperImage string
}

func (store DockerStore) EnsureVolumes(ctx context.Context, volumes []Volume) (map[string]bool, error) {
	if store.Docker == nil || !validHelperImage(store.HelperImage) {
		return nil, errors.New("docker state store configuration invalid")
	}
	ordered := append([]Volume(nil), volumes...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Name < ordered[j].Name })
	missing := []Volume{}
	for _, volume := range ordered {
		if !validVolume(volume) {
			return nil, errors.New("invalid managed volume")
		}
		output, err := store.Docker.Run(ctx, nil, "volume", "ls", "--filter", "name=^"+volume.Name+"$", "--format", "{{.Name}}")
		if err != nil {
			return nil, errors.New("cannot list managed volumes")
		}
		found := false
		for _, line := range strings.Fields(string(output)) {
			if line == volume.Name {
				found = true
			} else {
				return nil, errors.New("ambiguous managed volume lookup")
			}
		}
		if !found {
			missing = append(missing, volume)
			continue
		}
		if err := store.verifyVolume(ctx, volume); err != nil {
			return nil, err
		}
	}
	created := map[string]bool{}
	for _, volume := range missing {
		arguments := []string{"volume", "create"}
		keys := make([]string, 0, len(volume.Labels))
		for key := range volume.Labels {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			arguments = append(arguments, "--label", key+"="+volume.Labels[key])
		}
		arguments = append(arguments, volume.Name)
		if _, err := store.Docker.Run(ctx, nil, arguments...); err != nil {
			return nil, errors.New("cannot create managed volume")
		}
		if err := store.verifyVolume(ctx, volume); err != nil {
			return nil, err
		}
		created[volume.Name] = true
	}
	return created, nil
}

func (store DockerStore) verifyVolume(ctx context.Context, volume Volume) error {
	output, err := store.Docker.Run(ctx, nil, "volume", "inspect", "--format", "{{json .Labels}}", volume.Name)
	if err != nil {
		return errors.New("cannot inspect managed volume")
	}
	labels := map[string]string{}
	if json.Unmarshal(bytes.TrimSpace(output), &labels) != nil || !equalLabels(labels, volume.Labels) {
		return errors.New("managed volume ownership conflict")
	}
	return nil
}

func (store DockerStore) ReplaceFiles(ctx context.Context, volume Volume, files []StateFile) error {
	return store.writeFiles(ctx, volume, files, 0)
}

func (store DockerStore) InitializePrivateSource(ctx context.Context, volume Volume, expectedSize int, files []StateFile) error {
	if !validGeneratedValueSize(expectedSize) {
		return errors.New("invalid private source size")
	}
	return store.writeFiles(ctx, volume, files, expectedSize)
}

func (store DockerStore) writeFiles(ctx context.Context, volume Volume, files []StateFile, expectedSize int) error {
	if !validVolume(volume) || len(files) == 0 || len(files) > maxStateFiles {
		return errors.New("invalid state update")
	}
	var archive bytes.Buffer
	written := map[string]struct{}{}
	writer := tar.NewWriter(&archive)
	for _, file := range files {
		if !safeArchiveName(file.Name) || file.Data == nil || file.Mode&^0o777 != 0 || file.UID < 0 || file.GID < 0 {
			_ = writer.Close()
			clear(archive.Bytes())
			return errors.New("invalid state file")
		}
		if _, exists := written[file.Name]; exists {
			_ = writer.Close()
			clear(archive.Bytes())
			return errors.New("duplicate state file")
		}
		written[file.Name] = struct{}{}
		content, err := io.ReadAll(io.LimitReader(file.Data, maxStateFileBytes+1))
		if err != nil || len(content) > maxStateFileBytes {
			clear(content)
			_ = writer.Close()
			clear(archive.Bytes())
			return errors.New("state file unavailable")
		}
		header := &tar.Header{Name: file.Name, Mode: file.Mode, Size: int64(len(content)), Uid: file.UID, Gid: file.GID, Typeflag: tar.TypeReg}
		if writer.WriteHeader(header) != nil {
			clear(content)
			_ = writer.Close()
			clear(archive.Bytes())
			return errors.New("state archive failed")
		}
		_, err = writer.Write(content)
		clear(content)
		if err != nil {
			_ = writer.Close()
			clear(archive.Bytes())
			return errors.New("state archive failed")
		}
	}
	if writer.Close() != nil {
		clear(archive.Bytes())
		return errors.New("state archive failed")
	}
	payload := archive.Bytes()
	defer clear(payload)
	script := `set -eu
umask 077
rm -rf /state/.next /state/current.old
mkdir /state/.next
tar -xpf - -C /state/.next
sync
if [ -e /state/current ]; then mv /state/current /state/current.old; fi
mv /state/.next /state/current
sync
rm -rf /state/current.old
sync`
	if expectedSize != 0 {
		script = `set -eu
umask 077
test ! -e /state/.initialized
test ! -L /state/.initialized
test ! -e /state/current
test ! -L /state/current
rm -rf /state/.next /state/current.old
mkdir /state/.next
tar -xpf - -C /state/.next
test_private_source /state/.next/.initialized /state/.next/value "$1"
sync
mv /state/.next /state/current
sync
ln /state/current/.initialized /state/.initialized
sync
rm /state/current/.initialized
sync`
	}
	values := []string{}
	if expectedSize != 0 {
		values = append(values, strconv.Itoa(expectedSize))
	}
	_, err := store.runHelper(ctx, bytes.NewReader(payload), []helperMount{{volume: volume, target: "/state"}}, script, values...)
	if err != nil {
		return errors.New("state volume update failed")
	}
	return nil
}

func (store DockerStore) EnsureDirectory(ctx context.Context, volume Volume, uid, gid int, mode int64) error {
	if !validVolume(volume) || uid < 0 || gid < 0 || mode < 0 || mode > 0o777 {
		return errors.New("invalid state directory")
	}
	script := `set -eu
test -d /state
chown "$1:$2" /state
chmod "$3" /state
sync`
	_, err := store.runHelper(ctx, nil, []helperMount{{volume: volume, target: "/state"}}, script, strconv.Itoa(uid), strconv.Itoa(gid), strconv.FormatInt(mode, 8))
	if err != nil {
		return errors.New("state directory initialization failed")
	}
	return nil
}

func (store DockerStore) InspectPrivateSource(ctx context.Context, volume Volume, expectedSize int) (PrivateSourceState, error) {
	if !validVolume(volume) || !validGeneratedValueSize(expectedSize) {
		return PrivateSourceInvalid, errors.New("invalid private source")
	}
	script := `set -eu
if [ ! -e /source/.initialized ] && [ ! -L /source/.initialized ] && [ ! -e /source/current ] && [ ! -L /source/current ]; then
  printf 'empty'
elif test_ready_private_source /source "$1"; then
  sync
  if test_ready_private_source /source "$1"; then printf 'ready'; else printf 'corrupt'; fi
elif test_publishing_private_source /source "$1"; then
  sync
  if test_publishing_private_source /source "$1"; then printf 'publishing'; else printf 'corrupt'; fi
else
  printf 'corrupt'
fi`
	output, err := store.runHelper(ctx, nil, []helperMount{{volume: volume, target: "/source", readOnly: true}}, script, strconv.Itoa(expectedSize))
	if err != nil {
		return PrivateSourceInvalid, errors.New("private source inspection failed")
	}
	switch string(bytes.TrimSpace(output)) {
	case "empty":
		return PrivateSourceEmpty, nil
	case "ready":
		return PrivateSourceReady, nil
	case "publishing":
		return PrivateSourcePublishing, nil
	case "corrupt":
		return PrivateSourceCorrupt, nil
	default:
		return PrivateSourceInvalid, errors.New("private source inspection returned invalid state")
	}
}

func (store DockerStore) FinalizePrivateSource(ctx context.Context, volume Volume, expectedSize int) error {
	if !validVolume(volume) || !validGeneratedValueSize(expectedSize) {
		return errors.New("invalid private source")
	}
	script := `set -eu
test_publishing_private_source /source "$1"
if [ ! -e /source/.initialized ] && [ ! -L /source/.initialized ]; then
  ln /source/current/.initialized /source/.initialized
fi
sync
test_publishing_private_source /source "$1"
rm /source/current/.initialized
sync
test_ready_private_source /source "$1"`
	_, err := store.runHelper(ctx, nil, []helperMount{{volume: volume, target: "/source"}}, script, strconv.Itoa(expectedSize))
	if err != nil {
		return errors.New("private source publication recovery failed")
	}
	return nil
}

func (store DockerStore) CopyPrivateFile(ctx context.Context, source, destination Volume, uid, gid, expectedSize int) error {
	if !validVolume(source) || !validVolume(destination) || uid < 0 || gid < 0 || !validGeneratedValueSize(expectedSize) {
		return errors.New("invalid private copy")
	}
	script := `set -eu
umask 077
test_ready_private_source /source "$3"
rm -rf /state/.next /state/current.old
mkdir /state/.next
cp /source/.initialized /state/.next/.initialized
cp /source/current/value /state/.next/value
test "$(stat -c '%u:%g:%a' /state/.next/.initialized)" = '0:0:400'
test "$(stat -c '%u:%g:%a' /state/.next/value)" = '0:0:400'
test_private_source /state/.next/.initialized /state/.next/value "$3"
test_ready_private_source /source "$3"
source_marker_digest=$(sha256sum /source/.initialized)
source_marker_digest=${source_marker_digest%% *}
staged_marker_digest=$(sha256sum /state/.next/.initialized)
staged_marker_digest=${staged_marker_digest%% *}
test "$staged_marker_digest" = "$source_marker_digest"
test_private_source /state/.next/.initialized /state/.next/value "$3"
test "$(stat -c '%u:%g:%a' /state/.next/.initialized)" = '0:0:400'
test "$(stat -c '%u:%g:%a' /state/.next/value)" = '0:0:400'
chown "$1:$2" /state/.next/value
chmod 0400 /state/.next/value
test "$(stat -c '%u:%g:%a' /state/.next/value)" = "$1:$2:400"
sync
if [ -e /state/current ]; then mv /state/current /state/current.old; fi
mv /state/.next /state/current
sync
rm -rf /state/current.old
sync`
	_, err := store.runHelper(ctx, nil, []helperMount{{volume: source, target: "/source", readOnly: true}, {volume: destination, target: "/state"}}, script, strconv.Itoa(uid), strconv.Itoa(gid), strconv.Itoa(expectedSize))
	if err != nil {
		return errors.New("private state copy failed")
	}
	return nil
}

const (
	maxStateFileBytes = (1 << 20) + MaxInstructionBytes
	// One legal manifest may project MaxItems instruction files and MaxItems
	// producer configurations plus the fixed owner documents.
	maxStateFiles = 2*manifest.MaxItems + 16
)

type helperMount struct {
	volume   Volume
	target   string
	readOnly bool
}

const privateSourceValidation = `snapshot_counter=0
snapshot_bounded() {
  source_path=$1
  maximum_bytes=$2
  snapshot_counter=$((snapshot_counter + 1))
  bounded_snapshot="/tmp/nvt-bounded-$snapshot_counter"
  read_bytes=$((maximum_bytes + 1))
  timeout 2 head -c "$read_bytes" "$source_path" > "$bounded_snapshot" || return 1
  snapshot_bytes=$(stat -c '%s' "$bounded_snapshot") || return 1
  [ "$snapshot_bytes" -le "$maximum_bytes" ] || return 1
}
test_private_source() {
  marker=$1
  value=$2
  expected_bytes=$3
  case "$expected_bytes" in
    32|43) ;;
    *) return 1 ;;
  esac
  journal_bytes=$(stat -c '%s' "$marker") || return 1
  [ "$journal_bytes" -ge 1 ] || return 1
  [ "$journal_bytes" -le 192 ] || return 1
  value_bytes=$(stat -c '%s' "$value") || return 1
  [ "$value_bytes" = "$expected_bytes" ] || return 1
  snapshot_bounded "$marker" 192 || return 1
  marker=$bounded_snapshot
  snapshot_bounded "$value" "$expected_bytes" || return 1
  value=$bounded_snapshot
  [ "$(stat -c '%s' "$value")" = "$expected_bytes" ] || return 1
  marker_version=
  marker_digest=
  marker_size=
  marker_extra=
  IFS=' ' read -r marker_version marker_digest marker_size marker_extra < "$marker" || return 1
  [ -z "$marker_extra" ] || return 1
  [ "$marker_version" = '` + privateSourceMarkerVersion + `' ] || return 1
  actual_digest=$(sha256sum "$value") || return 1
  actual_digest=${actual_digest%% *}
  [ "$marker_digest" = "sha256:$actual_digest" ] || return 1
  actual_size=$(stat -c '%s' "$value") || return 1
  [ "$marker_size" = "$actual_size" ] || return 1
  canonical_digest=$(printf '%s sha256:%s %s\n' '` + privateSourceMarkerVersion + `' "$actual_digest" "$actual_size" | sha256sum) || return 1
  canonical_digest=${canonical_digest%% *}
  stored_digest=$(sha256sum "$marker") || return 1
  stored_digest=${stored_digest%% *}
  [ "$stored_digest" = "$canonical_digest" ] || return 1
}
test_ready_private_source() {
  root=$1
  expected_bytes=$2
  [ ! -L "$root/.initialized" ] || return 1
  [ -f "$root/.initialized" ] || return 1
  [ ! -L "$root/current" ] || return 1
  [ -d "$root/current" ] || return 1
  [ ! -e "$root/current/.initialized" ] || return 1
  [ ! -L "$root/current/.initialized" ] || return 1
  [ ! -L "$root/current/value" ] || return 1
  [ -f "$root/current/value" ] || return 1
  [ -s "$root/current/value" ] || return 1
  [ "$(stat -c '%u:%g:%a' "$root/.initialized")" = '0:0:400' ] || return 1
  [ "$(stat -c '%u:%g:%a' "$root/current")" = '0:0:700' ] || return 1
  [ "$(stat -c '%u:%g:%a' "$root/current/value")" = '0:0:400' ] || return 1
  test_private_source "$root/.initialized" "$root/current/value" "$expected_bytes" || return 1
}
test_publishing_private_source() {
  root=$1
  expected_bytes=$2
  [ ! -L "$root/current" ] || return 1
  [ -d "$root/current" ] || return 1
  [ ! -L "$root/current/.initialized" ] || return 1
  [ -f "$root/current/.initialized" ] || return 1
  [ ! -L "$root/current/value" ] || return 1
  [ -f "$root/current/value" ] || return 1
  [ -s "$root/current/value" ] || return 1
  [ "$(stat -c '%u:%g:%a' "$root/current")" = '0:0:700' ] || return 1
  [ "$(stat -c '%u:%g:%a' "$root/current/.initialized")" = '0:0:400' ] || return 1
  [ "$(stat -c '%u:%g:%a' "$root/current/value")" = '0:0:400' ] || return 1
  test_private_source "$root/current/.initialized" "$root/current/value" "$expected_bytes" || return 1
  if [ ! -e "$root/.initialized" ] && [ ! -L "$root/.initialized" ]; then
    return 0
  fi
  [ ! -L "$root/.initialized" ] || return 1
  [ -f "$root/.initialized" ] || return 1
  [ "$(stat -c '%u:%g:%a' "$root/.initialized")" = '0:0:400' ] || return 1
  test_private_source "$root/.initialized" "$root/current/value" "$expected_bytes" || return 1
}
`

func (store DockerStore) runHelper(ctx context.Context, stdin io.Reader, mounts []helperMount, script string, values ...string) ([]byte, error) {
	if len(mounts) == 0 {
		return nil, errors.New("state helper has no managed volumes")
	}
	if err := store.ensureHelperImage(ctx); err != nil {
		return nil, err
	}
	container, err := newHelperContainerName()
	if err != nil {
		return nil, err
	}
	arguments := []string{"create", "--name", container, "--pull", "never", "-i", "--network", "none", "--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=65536,mode=0700", "--cap-drop", "ALL", "--cap-add", "CHOWN", "--cap-add", "FOWNER", "--security-opt", "no-new-privileges"}
	seenTargets := map[string]struct{}{}
	for _, mount := range mounts {
		if !validVolume(mount.volume) || !safeContainerPath(mount.target) {
			return nil, errors.New("invalid state helper mount")
		}
		if _, duplicate := seenTargets[mount.target]; duplicate {
			return nil, errors.New("duplicate state helper mount")
		}
		seenTargets[mount.target] = struct{}{}
		option := "type=volume,src=" + mount.volume.Name + ",dst=" + mount.target
		if mount.readOnly {
			option += ",readonly"
		}
		arguments = append(arguments, "--mount", option)
	}
	arguments = append(arguments, "--entrypoint", "/bin/sh", store.HelperImage, "-euc", privateSourceValidation+script, "state-helper")
	arguments = append(arguments, values...)
	_, err = store.Docker.Run(ctx, nil, arguments...)
	if err != nil {
		return nil, err
	}
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	defer func() { _, _ = store.Docker.Run(cleanupCtx, nil, "rm", "--force", container) }()
	for _, mount := range mounts {
		if err := store.verifyVolume(ctx, mount.volume); err != nil {
			return nil, err
		}
	}
	return store.Docker.Run(ctx, stdin, "start", "--attach", "--interactive", container)
}

func (store DockerStore) ensureHelperImage(ctx context.Context) error {
	inspect := []string{"image", "inspect", "--format", "{{.Id}}", store.HelperImage}
	if _, err := store.Docker.Run(ctx, nil, inspect...); err == nil {
		return nil
	}
	if _, err := store.Docker.Run(ctx, nil, "pull", "--quiet", store.HelperImage); err != nil {
		return errors.New("state helper image unavailable")
	}
	if _, err := store.Docker.Run(ctx, nil, inspect...); err != nil {
		return errors.New("state helper image unavailable")
	}
	return nil
}

func newHelperContainerName() (string, error) {
	random := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, random); err != nil {
		return "", errors.New("state helper identity unavailable")
	}
	return "nvt-state-helper-" + hex.EncodeToString(random), nil
}

func validVolume(volume Volume) bool {
	return safeVolumeName(volume.Name) && volume.Role != "" && volume.Owner != "" && equalLabels(volume.Labels, map[string]string{ownerLabel: volume.Labels[ownerLabel], custodianLabel: volume.Owner, roleLabel: volume.Role, volumeLabel: volume.Name, versionLabel: stateVersion}) && volume.Labels[ownerLabel] != ""
}

func safeVolumeName(value string) bool {
	if len(value) == 0 || len(value) > 255 || !((value[0] >= 'a' && value[0] <= 'z') || (value[0] >= '0' && value[0] <= '9')) {
		return false
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-' || character == '_' || character == '.') {
			return false
		}
	}
	return true
}

func safeContainerPath(value string) bool {
	return strings.HasPrefix(value, "/") && value == path.Clean(value) && !strings.ContainsAny(value, "\x00\r\n,=")
}

func validGeneratedValueSize(value int) bool { return value == 32 || value == 43 }

func validHelperImage(value string) bool {
	parsed, err := reference.ParseNamed(value)
	if err != nil || parsed.String() != value {
		return false
	}
	digested, ok := parsed.(reference.Digested)
	return ok && digested.Digest().Algorithm() == "sha256" && len(digested.Digest().Encoded()) == 64
}
func safeArchiveName(value string) bool {
	return value != "" && value == path.Clean(value) && !strings.HasPrefix(value, "/") && !strings.HasPrefix(value, "../") && !strings.Contains(value, "\\") && !strings.ContainsRune(value, 0)
}
func equalLabels(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		if right[key] != value {
			return false
		}
	}
	return true
}

var _ Store = DockerStore{}
