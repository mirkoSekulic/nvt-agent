package dockerbackend

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"

	"github.com/mirkoSekulic/nvt-agent/localcontroller/internal/controller"
	"github.com/mirkoSekulic/nvt-agent/protocol/resolvedrun"
)

func TestHostCredentialRolloutRetainsDurableState(t *testing.T) {
	backend, docker, run, _ := testBackend(t)
	run.Repositories = nil
	run.CredentialProviders = nil
	run.Persistence = resolvedrun.Persistence{Workspace: true, RuntimeState: true, DockerData: true}
	run.Retention = "persistent"
	run.TTL = resolvedrun.TTL{}
	run.Egress.ProxyProvider = "forge-api"
	run.Broker.Grants = []resolvedrun.BrokerGrant{{Provider: "forge-api", Materialization: "header-inject", EgressHosts: []string{"forge.example.test:443"}}}
	ownership := strings.Repeat("d", 64)
	initial := controller.BackendRun{Resolved: run, SnapshotDigest: ownership, DesiredDigest: ownership}
	if _, err := backend.Ensure(context.Background(), initial); err != nil {
		t.Fatal(err)
	}
	names := namesFor(backend.config, run.RunID, ownership)
	desired := run
	desired.Broker.Grants = append(append([]resolvedrun.BrokerGrant(nil), run.Broker.Grants...), resolvedrun.BrokerGrant{Provider: "forge-git", Materialization: "header-inject", EgressHosts: []string{"forge.example.test:443"}})
	if egressCANameSetFor(run).digest() != egressCANameSetFor(desired).digest() {
		t.Fatal("same-host binding changed CA names")
	}
	before := len(docker.commands)
	rollout := controller.BackendRun{Resolved: desired, PreviousResolved: &run, SnapshotDigest: ownership, DesiredDigest: strings.Repeat("e", 64), ConfigurationRollout: true}
	if _, err := backend.Ensure(context.Background(), rollout); err != nil {
		t.Fatal(err)
	}
	for _, volume := range []string{names.workspace, names.home, names.dockerData, names.egressPrivate} {
		labels, ok := docker.objects["volume:"+volume]
		if !ok || labels[digestLabel] != ownership {
			t.Fatal("durable volume ownership lost")
		}
	}
	for _, command := range docker.commands[before:] {
		if len(command) > 1 && command[0] == "volume" && command[1] == "rm" {
			t.Fatal("rollout deleted volume")
		}
	}
	policy, err := os.ReadFile(backend.config.BrokerAgentsPath)
	if err != nil || !bytes.Contains(policy, []byte("forge-git")) {
		t.Fatal("new grant not committed")
	}
	removal := controller.BackendRun{Resolved: run, PreviousResolved: &desired, SnapshotDigest: ownership, DesiredDigest: strings.Repeat("f", 64), ConfigurationRollout: true}
	if _, err := backend.Ensure(context.Background(), removal); err != nil {
		t.Fatal(err)
	}
	policy, err = os.ReadFile(backend.config.BrokerAgentsPath)
	if err != nil || bytes.Contains(policy, []byte("forge-git")) {
		t.Fatal("removed grant retained")
	}
}
