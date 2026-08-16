package state

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type dockerCommand struct {
	arguments []string
	stdin     []byte
}
type fakeDocker struct {
	volumes                map[string]map[string]string
	commands               []dockerCommand
	runOutput              []byte
	runErr                 error
	deleteBeforeAttachment bool
	imagePresent           bool
	pullOutput             []byte
	createOutput           []byte
}

func (docker *fakeDocker) Run(_ context.Context, input io.Reader, arguments ...string) ([]byte, error) {
	command := dockerCommand{arguments: append([]string(nil), arguments...)}
	if input != nil {
		command.stdin, _ = io.ReadAll(input)
	}
	docker.commands = append(docker.commands, command)
	if len(arguments) >= 2 && arguments[0] == "volume" {
		switch arguments[1] {
		case "ls":
			filter := arguments[3]
			name := strings.TrimSuffix(strings.TrimPrefix(filter, "name=^"), "$")
			if _, ok := docker.volumes[name]; ok {
				return []byte(name + "\n"), nil
			}
			return nil, nil
		case "inspect":
			name := arguments[len(arguments)-1]
			labels, ok := docker.volumes[name]
			if !ok {
				return nil, errors.New("missing")
			}
			return json.Marshal(labels)
		case "create":
			name := arguments[len(arguments)-1]
			labels := map[string]string{}
			for index := 2; index < len(arguments)-1; index += 2 {
				pair := strings.SplitN(arguments[index+1], "=", 2)
				labels[pair[0]] = pair[1]
			}
			docker.volumes[name] = labels
			return []byte(name), nil
		}
	}
	if len(arguments) >= 2 && arguments[0] == "image" && arguments[1] == "inspect" {
		if docker.imagePresent {
			return []byte("[]"), nil
		}
		return nil, errors.New("missing image")
	}
	if len(arguments) > 0 && arguments[0] == "pull" {
		docker.imagePresent = true
		return docker.pullOutput, nil
	}
	if len(arguments) > 0 && arguments[0] == "create" {
		for index, argument := range arguments {
			if argument != "--mount" || index+1 >= len(arguments) {
				continue
			}
			var source string
			for _, option := range strings.Split(arguments[index+1], ",") {
				if strings.HasPrefix(option, "src=") {
					source = strings.TrimPrefix(option, "src=")
				}
			}
			if docker.deleteBeforeAttachment {
				delete(docker.volumes, source)
			}
			if _, exists := docker.volumes[source]; !exists {
				docker.volumes[source] = map[string]string{}
			}
		}
		docker.deleteBeforeAttachment = false
		if docker.createOutput != nil {
			return docker.createOutput, nil
		}
		return []byte(strings.Repeat("d", 64) + "\n"), nil
	}
	if len(arguments) > 0 && arguments[0] == "start" {
		return docker.runOutput, docker.runErr
	}
	if len(arguments) > 0 && arguments[0] == "rm" {
		return nil, nil
	}
	return nil, errors.New("unexpected command")
}

func dockerTestVolume(name, role string) Volume {
	return Volume{Name: name, Role: role, Owner: "local-platform-state", Labels: map[string]string{
		ownerLabel: "local-test", custodianLabel: "local-platform-state", roleLabel: role, volumeLabel: name, versionLabel: stateVersion,
	}}
}

func TestDockerStoreInitializesDirectoryAndClassifiesSources(t *testing.T) {
	docker := &fakeDocker{volumes: map[string]map[string]string{}, pullOutput: []byte("pull progress\nmore diagnostics\n"), createOutput: []byte("diagnostic\n" + strings.Repeat("d", 64) + "\n")}
	store := DockerStore{Docker: docker, HelperImage: "ghcr.io/nvt/state-helper@sha256:" + strings.Repeat("c", 64)}
	seeds := dockerTestVolume("local-test-seeds", "credential-seeds")
	docker.volumes[seeds.Name] = maps.Clone(seeds.Labels)
	if err := store.EnsureDirectory(context.Background(), seeds, 1000, 1000, 0o700); err != nil {
		t.Fatal(err)
	}
	directoryCommand := lastDockerCommand(t, docker.commands, "create")
	for _, expected := range []string{"1000", "700"} {
		if !containsArgument(directoryCommand.arguments, expected) {
			t.Fatalf("directory init omitted %q: %v", expected, directoryCommand.arguments)
		}
	}
	for _, expected := range []string{"--pull", "never", "--name", "--tmpfs"} {
		if !containsArgument(directoryCommand.arguments, expected) {
			t.Fatalf("helper create omitted %q: %v", expected, directoryCommand.arguments)
		}
	}
	if lastDockerCommand(t, docker.commands, "pull").arguments[1] != "--quiet" {
		t.Fatal("missing helper image was not pulled quietly before create")
	}
	source := dockerTestVolume("local-test-source", "generated-private-source")
	docker.volumes[source.Name] = maps.Clone(source.Labels)
	for output, expected := range map[string]PrivateSourceState{"empty": PrivateSourceEmpty, "publishing": PrivateSourcePublishing, "ready": PrivateSourceReady, "corrupt": PrivateSourceCorrupt} {
		docker.runOutput = []byte(output)
		state, err := store.InspectPrivateSource(context.Background(), source, 32)
		if err != nil || state != expected {
			t.Fatalf("inspect %q = %v, %v", output, state, err)
		}
	}
	secret := bytes.Repeat([]byte{'s'}, 32)
	docker.runOutput = nil
	if err := store.InitializePrivateSource(context.Background(), source, 32, []StateFile{{Name: ".initialized", Mode: 0o400, Data: bytes.NewReader(privateSourceMarker(secret))}, {Name: "value", Mode: 0o400, Data: bytes.NewReader(secret)}}); err != nil {
		t.Fatal(err)
	}
	createCommand := lastDockerCommand(t, docker.commands, "create")
	startCommand := lastDockerCommand(t, docker.commands, "start")
	if bytes.Contains([]byte(strings.Join(createCommand.arguments, "\x00")), secret) || !bytes.Contains(startCommand.stdin, secret) {
		t.Fatal("source initialization did not keep private bytes on stdin")
	}
	if script := strings.Join(createCommand.arguments, "\n"); !strings.Contains(script, "test ! -e /state/current") || !strings.Contains(script, "test ! -e /state/.initialized") || !strings.Contains(script, "test ! -L /state/current") || !strings.Contains(script, "test ! -L /state/.initialized") {
		t.Fatal("source initialization is not create-only")
	} else if strings.Count(script, "\nsync\n") < 4 {
		t.Fatal("source publication does not durably flush each transition")
	}
	if err := store.FinalizePrivateSource(context.Background(), source, 32); err != nil {
		t.Fatal(err)
	}
	finalizeScript := strings.Join(lastDockerCommand(t, docker.commands, "create").arguments, "\n")
	for _, expected := range []string{"test_publishing_private_source /source", "ln /source/current/.initialized /source/.initialized", "rm /source/current/.initialized", "test_ready_private_source /source"} {
		if !strings.Contains(finalizeScript, expected) {
			t.Fatalf("publication recovery omitted %q", expected)
		}
	}
}

func TestDockerStoreCreatesAndAdoptsOnlyExactlyLabeledVolumes(t *testing.T) {
	docker := &fakeDocker{volumes: map[string]map[string]string{}}
	store := DockerStore{Docker: docker, HelperImage: "ghcr.io/nvt/state-helper@sha256:" + strings.Repeat("a", 64)}
	volume := Volume{Name: "local-test-state", Role: "test-state", Owner: "broker", Consumers: []string{"broker"}, Labels: map[string]string{ownerLabel: "local-test", custodianLabel: "broker", roleLabel: "test-state", volumeLabel: "local-test-state", versionLabel: stateVersion}}
	created, err := store.EnsureVolumes(context.Background(), []Volume{volume})
	if err != nil || !created[volume.Name] {
		t.Fatalf("create = %v, %v", created, err)
	}
	created, err = store.EnsureVolumes(context.Background(), []Volume{volume})
	if err != nil || created[volume.Name] {
		t.Fatalf("restart = %v, %v", created, err)
	}

	docker.volumes[volume.Name]["unmanaged"] = "collision"
	before := len(docker.commands)
	if _, err := store.EnsureVolumes(context.Background(), []Volume{volume}); err == nil {
		t.Fatal("extra ownership label accepted")
	}
	for _, command := range docker.commands[before:] {
		if len(command.arguments) > 1 && command.arguments[1] == "create" {
			t.Fatal("ownership conflict triggered a create")
		}
	}
}

func TestDockerStoreReadsBoundedInventoryThroughReadOnlyHelper(t *testing.T) {
	docker := &fakeDocker{volumes: map[string]map[string]string{}, imagePresent: true, runOutput: []byte(`{"version":"1"}`)}
	store := DockerStore{Docker: docker, HelperImage: "ghcr.io/nvt/state-helper@sha256:" + strings.Repeat("a", 64)}
	volume := dockerTestVolume("local-test-generated-config", "generated-config")
	docker.volumes[volume.Name] = maps.Clone(volume.Labels)
	output, err := store.ReadVolumeInventory(context.Background(), volume)
	if err != nil || !bytes.Equal(output, docker.runOutput) {
		t.Fatalf("inventory read = %q, %v", output, err)
	}
	command := lastDockerCommand(t, docker.commands, "create")
	joined := strings.Join(command.arguments, "\n")
	if !strings.Contains(joined, "readonly") || !strings.Contains(joined, "test ! -L") || !strings.Contains(joined, "stat -c '%s'") {
		t.Fatalf("inventory reader is not bounded and read-only: %v", command.arguments)
	}
}

func TestDockerStoreKeepsPrivateBytesOnlyOnStdin(t *testing.T) {
	docker := &fakeDocker{volumes: map[string]map[string]string{}}
	store := DockerStore{Docker: docker, HelperImage: "ghcr.io/nvt/state-helper@sha256:" + strings.Repeat("b", 64)}
	secret := []byte("NEVER-IN-DOCKER-INSPECT")
	secretVolume := dockerTestVolume("local-test-secret", "static-private-input")
	sourceVolume := dockerTestVolume("local-test-source", "generated-private-source")
	destinationVolume := dockerTestVolume("local-test-destination", "generated-private-input")
	for _, volume := range []Volume{secretVolume, sourceVolume, destinationVolume} {
		docker.volumes[volume.Name] = maps.Clone(volume.Labels)
	}
	if err := store.ReplaceFiles(context.Background(), secretVolume, []StateFile{{Name: "value", Mode: 0o400, UID: 65532, GID: 65532, Data: bytes.NewReader(secret)}}); err != nil {
		t.Fatal(err)
	}
	createCommand := lastDockerCommand(t, docker.commands, "create")
	startCommand := lastDockerCommand(t, docker.commands, "start")
	for _, command := range docker.commands {
		if bytes.Contains([]byte(strings.Join(command.arguments, "\x00")), secret) {
			t.Fatal("secret entered Docker arguments")
		}
	}
	if !bytes.Contains(startCommand.stdin, secret) {
		t.Fatal("secret was not transported through stdin")
	}
	for _, expected := range []string{"--network", "none", "--read-only", "--cap-drop", "ALL", "no-new-privileges"} {
		if !containsArgument(createCommand.arguments, expected) {
			t.Fatalf("helper omitted %q: %v", expected, createCommand.arguments)
		}
	}
	if err := store.CopyPrivateFile(context.Background(), sourceVolume, destinationVolume, 65532, 65532, 32); err != nil {
		t.Fatal(err)
	}
	copyCommand := lastDockerCommand(t, docker.commands, "start")
	if len(copyCommand.stdin) != 0 || bytes.Contains([]byte(strings.Join(copyCommand.arguments, "\x00")), secret) {
		t.Fatal("copy exposed private bytes")
	}
	copyScript := strings.Join(lastDockerCommand(t, docker.commands, "create").arguments, "\n")
	for _, expected := range []string{"cp /source/.initialized /state/.next/.initialized", "test_private_source /state/.next/.initialized /state/.next/value", "test_ready_private_source /source", `test "$staged_marker_digest" = "$source_marker_digest"`} {
		if !strings.Contains(copyScript, expected) {
			t.Fatalf("private copy omitted %q", expected)
		}
	}
}

func TestDockerStoreRejectsVolumeRecreatedDuringHelperAttachment(t *testing.T) {
	volume := dockerTestVolume("local-test-raced", "generated-config")
	docker := &fakeDocker{volumes: map[string]map[string]string{volume.Name: maps.Clone(volume.Labels)}, deleteBeforeAttachment: true}
	store := DockerStore{Docker: docker, HelperImage: "ghcr.io/nvt/state-helper@sha256:" + strings.Repeat("e", 64)}
	if err := store.ReplaceFiles(context.Background(), volume, []StateFile{{Name: "config", Mode: 0o444, Data: bytes.NewReader([]byte("safe"))}}); err == nil {
		t.Fatal("implicitly recreated unlabeled volume accepted")
	}
	for _, command := range docker.commands {
		if len(command.arguments) > 0 && command.arguments[0] == "start" {
			t.Fatal("helper started before attached volume labels were verified")
		}
	}
}

func TestPrivateSourceValidationRejectsTrailingJournalBytes(t *testing.T) {
	directory := t.TempDir()
	markerPath := filepath.Join(directory, "marker")
	valuePath := filepath.Join(directory, "value")
	value := bytes.Repeat([]byte{'v'}, 32)
	if err := os.WriteFile(valuePath, value, 0o600); err != nil {
		t.Fatal(err)
	}
	runValidation := func(marker []byte, expectedSize string) error {
		if err := os.WriteFile(markerPath, marker, 0o600); err != nil {
			t.Fatal(err)
		}
		command := exec.Command("/bin/sh", "-euc", privateSourceValidation+`test_private_source "$1" "$2" "$3"`, "state-helper", markerPath, valuePath, expectedSize)
		return command.Run()
	}
	marker := privateSourceMarker(value)
	if err := runValidation(marker, "32"); err != nil {
		t.Fatalf("canonical journal rejected: %v", err)
	}
	if err := runValidation(marker, "43"); err == nil {
		t.Fatal("source value with the wrong expected encoding length was accepted")
	}
	malformed := append(append([]byte(nil), marker...), []byte("trailing-corruption")...)
	if err := runValidation(malformed, "32"); err == nil {
		t.Fatal("unterminated bytes after canonical journal were accepted")
	}
	oversizedJournal := append(append([]byte(nil), marker...), bytes.Repeat([]byte{'x'}, 193)...)
	if err := runValidation(oversizedJournal, "32"); err == nil {
		t.Fatal("oversized journal was accepted")
	}
	if err := os.Truncate(valuePath, 1<<30); err != nil {
		t.Fatal(err)
	}
	if err := runValidation(marker, "32"); err == nil {
		t.Fatal("oversized sparse value was accepted")
	}
	valueBound := strings.Index(privateSourceValidation, `value_bytes=$(stat -c '%s' "$value")`)
	valueHash := strings.Index(privateSourceValidation, `actual_digest=$(sha256sum "$value")`)
	journalBound := strings.Index(privateSourceValidation, `[ "$journal_bytes" -le 192 ]`)
	journalHash := strings.Index(privateSourceValidation, `stored_digest=$(sha256sum "$marker")`)
	valueSnapshot := strings.Index(privateSourceValidation, `snapshot_bounded "$value" "$expected_bytes"`)
	journalSnapshot := strings.Index(privateSourceValidation, `snapshot_bounded "$marker" 192`)
	if valueBound < 0 || valueSnapshot < valueBound || valueHash < valueSnapshot || journalBound < 0 || journalSnapshot < journalBound || journalHash < journalSnapshot {
		t.Fatal("managed source bounds are not checked before hashing")
	}
}

func lastDockerCommand(t *testing.T, commands []dockerCommand, operation string) dockerCommand {
	t.Helper()
	for index := len(commands) - 1; index >= 0; index-- {
		if len(commands[index].arguments) > 0 && commands[index].arguments[0] == operation {
			return commands[index]
		}
	}
	t.Fatalf("missing docker %s command", operation)
	return dockerCommand{}
}

func containsArgument(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
