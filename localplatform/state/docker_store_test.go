package state

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

type dockerCommand struct {
	arguments []string
	stdin     []byte
}
type fakeDocker struct {
	volumes   map[string]map[string]string
	commands  []dockerCommand
	runOutput []byte
	runErr    error
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
	if len(arguments) > 0 && arguments[0] == "run" {
		return docker.runOutput, docker.runErr
	}
	return nil, errors.New("unexpected command")
}

func TestDockerStoreInitializesDirectoryAndClassifiesSources(t *testing.T) {
	docker := &fakeDocker{volumes: map[string]map[string]string{}}
	store := DockerStore{Docker: docker, HelperImage: "ghcr.io/nvt/state-helper@sha256:" + strings.Repeat("c", 64)}
	if err := store.EnsureDirectory(context.Background(), "local-test-seeds", 1000, 1000, 0o700); err != nil {
		t.Fatal(err)
	}
	directoryCommand := docker.commands[0]
	for _, expected := range []string{"1000", "700"} {
		if !containsArgument(directoryCommand.arguments, expected) {
			t.Fatalf("directory init omitted %q: %v", expected, directoryCommand.arguments)
		}
	}
	for output, expected := range map[string]PrivateSourceState{"empty": PrivateSourceEmpty, "ready": PrivateSourceReady, "corrupt": PrivateSourceCorrupt} {
		docker.runOutput = []byte(output)
		state, err := store.InspectPrivateSource(context.Background(), "local-test-source")
		if err != nil || state != expected {
			t.Fatalf("inspect %q = %v, %v", output, state, err)
		}
	}
	secret := []byte("INITIAL-GENERATED-PRIVATE")
	docker.runOutput = nil
	if err := store.InitializePrivateSource(context.Background(), "local-test-source", []StateFile{{Name: ".initialized", Mode: 0o400, Data: bytes.NewBufferString(privateSourceMarker)}, {Name: "value", Mode: 0o400, Data: bytes.NewReader(secret)}}); err != nil {
		t.Fatal(err)
	}
	command := docker.commands[len(docker.commands)-1]
	if bytes.Contains([]byte(strings.Join(command.arguments, "\x00")), secret) || !bytes.Contains(command.stdin, secret) {
		t.Fatal("source initialization did not keep private bytes on stdin")
	}
	if !strings.Contains(strings.Join(command.arguments, "\n"), "test ! -e /state/current") {
		t.Fatal("source initialization is not create-only")
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

func TestDockerStoreKeepsPrivateBytesOnlyOnStdin(t *testing.T) {
	docker := &fakeDocker{volumes: map[string]map[string]string{}}
	store := DockerStore{Docker: docker, HelperImage: "ghcr.io/nvt/state-helper@sha256:" + strings.Repeat("b", 64)}
	secret := []byte("NEVER-IN-DOCKER-INSPECT")
	if err := store.ReplaceFiles(context.Background(), "local-test-secret", []StateFile{{Name: "value", Mode: 0o400, UID: 65532, GID: 65532, Data: bytes.NewReader(secret)}}); err != nil {
		t.Fatal(err)
	}
	if len(docker.commands) != 1 {
		t.Fatalf("commands = %d", len(docker.commands))
	}
	command := docker.commands[0]
	if bytes.Contains([]byte(strings.Join(command.arguments, "\x00")), secret) {
		t.Fatal("secret entered Docker arguments")
	}
	if !bytes.Contains(command.stdin, secret) {
		t.Fatal("secret was not transported through stdin")
	}
	for _, expected := range []string{"--network", "none", "--read-only", "--cap-drop", "ALL", "no-new-privileges"} {
		if !containsArgument(command.arguments, expected) {
			t.Fatalf("helper omitted %q: %v", expected, command.arguments)
		}
	}
	if err := store.CopyPrivateFile(context.Background(), "local-test-source", "local-test-destination", 65532, 65532); err != nil {
		t.Fatal(err)
	}
	copyCommand := docker.commands[1]
	if len(copyCommand.stdin) != 0 || bytes.Contains([]byte(strings.Join(copyCommand.arguments, "\x00")), secret) {
		t.Fatal("copy exposed private bytes")
	}
}

func containsArgument(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
