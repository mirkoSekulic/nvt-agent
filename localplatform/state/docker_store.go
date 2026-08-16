package state

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/distribution/reference"
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
	return store.writeFiles(ctx, volume, files, false)
}

func (store DockerStore) InitializePrivateSource(ctx context.Context, volume Volume, files []StateFile) error {
	return store.writeFiles(ctx, volume, files, true)
}

func (store DockerStore) writeFiles(ctx context.Context, volume Volume, files []StateFile, initialize bool) error {
	if !validVolume(volume) || len(files) == 0 || len(files) > 512 {
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
if [ -e /state/current ]; then mv /state/current /state/current.old; fi
mv /state/.next /state/current
rm -rf /state/current.old`
	if initialize {
		script = `set -eu
umask 077
test ! -e /state/.initialized
test ! -e /state/current
rm -rf /state/.next /state/current.old
mkdir /state/.next
tar -xpf - -C /state/.next
test_private_source /state/.next/.initialized /state/.next/value
mv /state/.next /state/current
mv /state/current/.initialized /state/.initialized`
	}
	_, err := store.runHelper(ctx, bytes.NewReader(payload), []helperMount{{volume: volume, target: "/state"}}, script)
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
chmod "$3" /state`
	_, err := store.runHelper(ctx, nil, []helperMount{{volume: volume, target: "/state"}}, script, strconv.Itoa(uid), strconv.Itoa(gid), strconv.FormatInt(mode, 8))
	if err != nil {
		return errors.New("state directory initialization failed")
	}
	return nil
}

func (store DockerStore) InspectPrivateSource(ctx context.Context, volume Volume) (PrivateSourceState, error) {
	if !validVolume(volume) {
		return PrivateSourceInvalid, errors.New("invalid private source")
	}
	script := `set -eu
if [ ! -e /source/.initialized ] && [ ! -e /source/current ]; then
  printf 'empty'
elif [ ! -L /source/.initialized ] && [ -f /source/.initialized ] && [ ! -L /source/current ] && [ -d /source/current ] && [ ! -L /source/current/value ] && [ -s /source/current/value ] && [ "$(stat -c '%u:%g:%a' /source/.initialized)" = '0:0:400' ] && [ "$(stat -c '%u:%g:%a' /source/current)" = '0:0:700' ] && [ "$(stat -c '%u:%g:%a' /source/current/value)" = '0:0:400' ] && test_private_source /source/.initialized /source/current/value; then
  printf 'ready'
else
  printf 'corrupt'
fi`
	output, err := store.runHelper(ctx, nil, []helperMount{{volume: volume, target: "/source", readOnly: true}}, script)
	if err != nil {
		return PrivateSourceInvalid, errors.New("private source inspection failed")
	}
	switch string(bytes.TrimSpace(output)) {
	case "empty":
		return PrivateSourceEmpty, nil
	case "ready":
		return PrivateSourceReady, nil
	case "corrupt":
		return PrivateSourceCorrupt, nil
	default:
		return PrivateSourceInvalid, errors.New("private source inspection returned invalid state")
	}
}

func (store DockerStore) CopyPrivateFile(ctx context.Context, source, destination Volume, uid, gid int) error {
	if !validVolume(source) || !validVolume(destination) || uid < 0 || gid < 0 {
		return errors.New("invalid private copy")
	}
	script := `set -eu
umask 077
test -d /source/current
test ! -L /source/.initialized
test ! -L /source/current
test ! -L /source/current/value
test -f /source/.initialized
test -s /source/current/value
test "$(stat -c '%u:%g:%a' /source/.initialized)" = '0:0:400'
test "$(stat -c '%u:%g:%a' /source/current)" = '0:0:700'
test "$(stat -c '%u:%g:%a' /source/current/value)" = '0:0:400'
test_private_source /source/.initialized /source/current/value
rm -rf /state/.next /state/current.old
mkdir /state/.next
cp /source/current/value /state/.next/value
chown "$1:$2" /state/.next/value
chmod 0400 /state/.next/value
if [ -e /state/current ]; then mv /state/current /state/current.old; fi
mv /state/.next /state/current
rm -rf /state/current.old`
	_, err := store.runHelper(ctx, nil, []helperMount{{volume: source, target: "/source", readOnly: true}, {volume: destination, target: "/state"}}, script, strconv.Itoa(uid), strconv.Itoa(gid))
	if err != nil {
		return errors.New("private state copy failed")
	}
	return nil
}

const maxStateFileBytes = (1 << 20) + MaxInstructionBytes

type helperMount struct {
	volume   Volume
	target   string
	readOnly bool
}

const privateSourceValidation = `test_private_source() {
  marker=$1
  value=$2
  marker_version=
  marker_digest=
  marker_size=
  marker_extra=
  IFS=' ' read -r marker_version marker_digest marker_size marker_extra < "$marker"
  [ -z "$marker_extra" ]
  [ "$(wc -l < "$marker")" -eq 1 ]
  [ "$marker_version" = '` + privateSourceMarkerVersion + `' ]
  actual_digest=$(sha256sum "$value")
  actual_digest=${actual_digest%% *}
  [ "$marker_digest" = "sha256:$actual_digest" ]
  [ "$marker_size" = "$(stat -c '%s' "$value")" ]
}
`

func (store DockerStore) runHelper(ctx context.Context, stdin io.Reader, mounts []helperMount, script string, values ...string) ([]byte, error) {
	if len(mounts) == 0 {
		return nil, errors.New("state helper has no managed volumes")
	}
	arguments := []string{"create", "-i", "--network", "none", "--read-only", "--cap-drop", "ALL", "--cap-add", "CHOWN", "--cap-add", "FOWNER", "--security-opt", "no-new-privileges"}
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
	created, err := store.Docker.Run(ctx, nil, arguments...)
	if err != nil {
		return nil, err
	}
	container := string(bytes.TrimSpace(created))
	if !safeContainerID(container) {
		return nil, errors.New("state helper returned invalid container ID")
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

func safeContainerID(value string) bool {
	if len(value) < 12 || len(value) > 64 {
		return false
	}
	for _, character := range value {
		if !(character >= '0' && character <= '9' || character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}

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
