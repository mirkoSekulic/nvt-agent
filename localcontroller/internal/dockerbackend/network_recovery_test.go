package dockerbackend

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/mirkoSekulic/nvt-agent/localcontroller/internal/controller"
)

func TestParseInitNetworkNamespace(t *testing.T) {
	for _, test := range []struct {
		name, output string
		want         uint64
	}{
		{"normal", "PID NETNS\n123 4026534083\n", 4026534083},
		{"children", " PID   NETNS\n456 99\n123 42\n789 99\n", 42},
		{"empty", "", 0},
		{"missing init", "PID NETNS\n456 42\n", 0},
		{"duplicate", "PID NETNS\n123 42\n123 42\n", 0},
		{"unsupported", "PID COMMAND\n123 readlink\n", 0},
		{"unavailable", "PID NETNS\n123 -\n", 0},
		{"zero", "PID NETNS\n123 0\n", 0},
		{"truncated", "PID NETNS\n123\n", 0},
		{"overflow", "PID NETNS\n123 18446744073709551616\n", 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := parseInitNetworkNamespace([]byte(test.output), 123)
			if got != test.want || (err != nil) != (test.want == 0) {
				t.Fatalf("namespace=%d, err=%v", got, err)
			}
		})
	}
}

func TestNetworkRecoveryReplacesOnlyStaleDependants(t *testing.T) {
	for _, staleServices := range [][]string{{"agent"}, {"captured"}, {"agent", "captured"}, {"net-init"}} {
		t.Run(strings.Join(staleServices, "+"), func(t *testing.T) {
			backend, docker, run, _ := testBackend(t)
			desired := controller.BackendRun{Resolved: run, SnapshotDigest: strings.Repeat("a", 64)}
			if _, err := backend.Ensure(context.Background(), desired); err != nil {
				t.Fatal(err)
			}
			for _, service := range staleServices {
				docker.networkNamespaces["fake-"+service+"-id"] = 7
			}
			docker.agentStatus = "healthy" // Loopback health cannot establish readiness.
			before := len(docker.commands)
			observation, err := backend.Inspect(context.Background(), desired)
			if err != nil || observation.Ready || !observation.RecoveryRequired || observation.TerminalTarget != "" {
				t.Fatalf("stale network inspection = %#v %v", observation, err)
			}
			for _, command := range docker.commands[before:] {
				if command[0] == "rm" || command[0] == "stop" || command[0] == "restart" {
					t.Fatal("inspection mutated the runtime")
				}
			}
			objectsBefore := len(docker.objects)
			before = len(docker.commands)
			observation, err = backend.Ensure(context.Background(), desired)
			if err != nil || !observation.Ready || observation.RecoveryRequired {
				t.Fatalf("network recovery = %#v %v", observation, err)
			}
			removed := map[string]bool{}
			for _, command := range docker.commands[before:] {
				if command[0] == "rm" {
					removed[command[len(command)-1]] = true
				}
			}
			// The confinement guard is already replaced on every preparation.
			for _, service := range []string{"agent", "captured", "docker", "egressd"} {
				if removed["fake-"+service+"-id"] != contains(staleServices, service) {
					t.Fatalf("unexpected replacement set: %v", removed)
				}
			}
			if len(docker.objects) != objectsBefore {
				t.Fatal("network recovery changed named volumes/networks")
			}
			before = len(docker.commands)
			observation, err = backend.Inspect(context.Background(), desired)
			if err != nil || !observation.Ready {
				t.Fatalf("post-repair inspection = %#v %v", observation, err)
			}
			for _, command := range docker.commands[before:] {
				if command[0] == "rm" {
					t.Fatal("healthy inspection replaced a container")
				}
			}
		})
	}
}

func TestNetworkRecoveryRetriesPartialReplacement(t *testing.T) {
	backend, docker, run, _ := testBackend(t)
	desired := controller.BackendRun{Resolved: run, SnapshotDigest: strings.Repeat("a", 64)}
	if _, err := backend.Ensure(context.Background(), desired); err != nil {
		t.Fatal(err)
	}
	docker.networkNamespaces["fake-agent-id"] = 7
	docker.networkNamespaces["fake-captured-id"] = 7
	docker.failRemove = "fake-captured-id"
	if _, err := backend.Ensure(context.Background(), desired); !errors.Is(err, controller.ErrBackendRetryable) {
		t.Fatalf("partial repair = %v", err)
	}
	if _, exists := docker.containers["fake-agent-id"]; exists {
		t.Fatal("fixture did not interrupt between dependant replacements")
	}
	observation, err := backend.Ensure(context.Background(), desired)
	if err != nil || !observation.Ready {
		t.Fatalf("retry = %#v %v", observation, err)
	}
}

func TestNetworkObservationFailsClosedWithoutMutation(t *testing.T) {
	for _, mode := range []string{"foreign", "duplicate", "unavailable"} {
		t.Run(mode, func(t *testing.T) {
			backend, docker, run, _ := testBackend(t)
			desired := controller.BackendRun{Resolved: run, SnapshotDigest: strings.Repeat("a", 64)}
			if _, err := backend.Ensure(context.Background(), desired); err != nil {
				t.Fatal(err)
			}
			docker.networkNamespaces["fake-agent-id"] = 7
			switch mode {
			case "foreign":
				docker.containers["fake-captured-id"][ownerLabel] = "someone-else"
			case "duplicate":
				docker.containers["duplicate-proxy"] = cloneLabels(docker.containers["fake-captured-id"])
			case "unavailable":
				docker.networkTopErrors["fake-captured-id"] = true
			}
			before := len(docker.commands)
			observation, err := backend.Inspect(context.Background(), desired)
			if err == nil || observation.Ready || observation.RecoveryRequired {
				t.Fatalf("uncertain inspection = %#v %v", observation, err)
			}
			names := namesFor(backend.config, run.RunID, desired.SnapshotDigest)
			labels := ownedLabels{Owner: backend.config.Owner, RunID: run.RunID, Digest: desired.SnapshotDigest}
			if err := backend.repairSharedNetwork(context.Background(), run, names, labels); err == nil {
				t.Fatal("uncertain inventory permitted mutation")
			}
			for _, command := range docker.commands[before:] {
				if command[0] == "rm" {
					t.Fatal("partially validated inventory allowed deletion")
				}
			}
		})
	}
}

func TestNetworkRecoveryWithoutDinD(t *testing.T) {
	backend, docker, run, _ := testBackend(t)
	run.Runtime.Docker = nil
	run.Persistence.DockerData = false
	desired := controller.BackendRun{Resolved: run, SnapshotDigest: strings.Repeat("a", 64)}
	if _, err := backend.Ensure(context.Background(), desired); err != nil {
		t.Fatal(err)
	}
	docker.networkNamespaces["fake-agent-id"] = 7
	observation, err := backend.Ensure(context.Background(), desired)
	if err != nil || !observation.Ready {
		t.Fatalf("network-only recovery = %#v %v", observation, err)
	}
	if docker.networkNamespaces["fake-agent-id"] != docker.networkNamespaces["fake-network-id"] {
		t.Fatal("agent did not rejoin network owner")
	}
}

func TestNetworkObservationSupportsMinimalDockerHosts(t *testing.T) {
	backend, docker, run, _ := testBackend(t)
	desired := controller.BackendRun{Resolved: run, SnapshotDigest: strings.Repeat("a", 64)}
	if _, err := backend.Ensure(context.Background(), desired); err != nil {
		t.Fatal(err)
	}
	docker.networkTopErrors["fake-agent-id"] = true
	docker.networkProbe = true
	namespace, err := backend.containerNetworkNamespace(context.Background(), "fake-agent-id")
	if err != nil || namespace != 42 {
		t.Fatalf("minimal-host namespace = %d, %v", namespace, err)
	}
	found := false
	for _, command := range docker.commands {
		if argumentAfter(command, "--entrypoint") != "readlink" {
			continue
		}
		found = true
		for key, want := range map[string]string{"--network": "none", "--pid": "container:fake-agent-id", "--cap-drop": "ALL", "--cap-add": "SYS_PTRACE", "--security-opt": "no-new-privileges"} {
			if argumentAfter(command, key) != want {
				t.Fatalf("probe omitted %s=%s", key, want)
			}
		}
		if !contains(command, "--read-only") || contains(command, "--privileged") || contains(command, "--volume") || contains(command, "--env") {
			t.Fatalf("unsafe probe: %v", command)
		}
	}
	if !found {
		t.Fatal("fallback was not exercised")
	}
}

func TestNetworkObservationRejectsIncompleteProcessState(t *testing.T) {
	backend, docker, run, _ := testBackend(t)
	desired := controller.BackendRun{Resolved: run, SnapshotDigest: strings.Repeat("a", 64)}
	if _, err := backend.Ensure(context.Background(), desired); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{`{}`, `null`, `{"Running":true}`, `{"Running":true,"Pid":-1}`, `{"Running":false,"Pid":100}`, `{"Pid":100}`} {
		docker.networkStateOverride["fake-captured-id"] = raw
		if _, err := backend.containerNetworkNamespace(context.Background(), "fake-captured-id"); err == nil {
			t.Fatalf("ambiguous process state accepted: %s", raw)
		}
	}
}
