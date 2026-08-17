package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	plancontract "github.com/mirkoSekulic/nvt-agent/localplatform/plan"
)

func TestExactOwnedContainerLabels(t *testing.T) {
	application := app{project: "nvt-local"}
	platform := map[string]string{
		"nvt.dev/local-platform-owner":   "nvt-local",
		"nvt.dev/local-platform-version": "1",
		"com.docker.compose.project":     "nvt-local",
		"com.docker.compose.service":     "local-controller",
	}
	if !application.validPlatformContainer(platform) {
		t.Fatal("exact platform service labels were rejected")
	}
	helper := map[string]string{
		"nvt.dev/local-platform-owner":        "nvt-local",
		"nvt.dev/local-platform-version":      "1",
		"nvt.dev/local-platform-state-helper": "1",
	}
	if !application.validPlatformContainer(helper) {
		t.Fatal("exact state helper labels were rejected")
	}
	platform["com.docker.compose.service"] = "unrelated"
	if application.validPlatformContainer(platform) {
		t.Fatal("unknown platform service was accepted")
	}
	run := map[string]string{
		"nvt.dev/local-controller-owner": "nvt-local",
		"nvt.dev/local-run-id":           "studio",
		"nvt.dev/local-run-digest":       "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"com.docker.compose.project":     "nvt-local-da0daaba4b156961c049ab4b",
		"com.docker.compose.service":     "agent",
	}
	if !application.validRunContainer(run) {
		t.Fatal("exact runtime service labels were rejected")
	}
	seedHelper := map[string]string{
		"nvt.dev/local-controller-owner":  "nvt-local",
		"nvt.dev/local-run-id":            "studio",
		"nvt.dev/local-run-digest":        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"nvt.dev/local-controller-helper": "volume-seed-v1",
	}
	if !application.validRunContainer(seedHelper) {
		t.Fatal("exact-owned seed helper was rejected")
	}
	seedHelper["com.docker.compose.service"] = "agent"
	if application.validRunContainer(seedHelper) {
		t.Fatal("ambiguous seed helper was accepted")
	}
	run["nvt.dev/local-run-digest"] = "short"
	if application.validRunContainer(run) {
		t.Fatal("ambiguous runtime service was accepted")
	}
}

func TestOwnedVolumesRequireCompletePersistedLabelMap(t *testing.T) {
	project := "nvt-local"
	configName := plancontract.VolumeName(project, plancontract.GeneratedConfigSuffix)
	brokerName := plancontract.VolumeName(project, "broker-data")
	retiredName := plancontract.VolumeName(project, "credential-seeds")
	configLabels := platformVolumeLabels(project, configName, "local-platform-state", "generated-config")
	brokerLabels := platformVolumeLabels(project, brokerName, "broker", "broker-database-audit")
	retiredLabels := platformVolumeLabels(project, retiredName, "credential-portal", "credential-portal-seed")
	plan := plancontract.VolumeInventory{Version: "1", Project: project, Volumes: []plancontract.Volume{
		{Name: configName, Owner: "local-platform-state", Role: "generated-config", Labels: configLabels},
		{Name: brokerName, Owner: "broker", Role: "broker-database-audit", Labels: brokerLabels},
		{Name: retiredName, Owner: "credential-portal", Role: "credential-portal-seed", Labels: retiredLabels},
	}}
	encoded, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	docker := &resetDocker{project: project, plan: encoded, platformVolumes: []string{configName, brokerName, retiredName}, labels: map[string]map[string]string{configName: configLabels, brokerName: brokerLabels, retiredName: retiredLabels}}
	application := app{project: project, docker: docker}
	if names, err := application.ownedObjects(context.Background(), "volume"); err != nil || len(names) != 3 || names[len(names)-1] != configName {
		t.Fatalf("exact volume inventory = %#v, %v", names, err)
	}
	if docker.outputLimit <= 64<<10 {
		t.Fatalf("reset inventory retained the generic Docker output limit: %d", docker.outputLimit)
	}
	if docker.volumeListLimit != docker.outputLimit {
		t.Fatalf("reset volume enumeration limit = %d, inventory limit = %d", docker.volumeListLimit, docker.outputLimit)
	}
	if !strings.Contains(docker.helperScript, "root=/state/current.old") {
		t.Fatal("reset did not use the interrupted-publication inventory fallback")
	}
	docker.labels[brokerName] = cloneTestLabels(brokerLabels)
	docker.labels[brokerName]["unexpected"] = "label"
	if _, err := application.ownedObjects(context.Background(), "volume"); err == nil || !strings.Contains(err.Error(), "mislabeled") {
		t.Fatalf("volume with an extra label was not rejected: %v", err)
	}
	docker.labels[brokerName] = cloneTestLabels(brokerLabels)
	docker.labels[brokerName]["nvt.dev/local-platform-custodian"] = "local-controller"
	if _, err := application.ownedObjects(context.Background(), "volume"); err == nil || !strings.Contains(err.Error(), "mislabeled") {
		t.Fatalf("volume with a changed custodian was not rejected: %v", err)
	}
}

func TestOwnedVolumesAcceptOnlyEmptyFirstInitializationAnchor(t *testing.T) {
	project := "nvt-local"
	configName := plancontract.VolumeName(project, plancontract.GeneratedConfigSuffix)
	configLabels := platformVolumeLabels(project, configName, "local-platform-state", "generated-config")
	docker := &resetDocker{project: project, platformVolumes: []string{configName}, labels: map[string]map[string]string{configName: configLabels}}
	application := app{project: project, docker: docker}
	names, err := application.ownedObjects(context.Background(), "volume")
	if err != nil || len(names) != 1 || names[0] != configName {
		t.Fatalf("interrupted first initialization inventory = %#v, %v", names, err)
	}
	brokerName := plancontract.VolumeName(project, "broker-data")
	docker.platformVolumes = append(docker.platformVolumes, brokerName)
	docker.labels[brokerName] = platformVolumeLabels(project, brokerName, "broker", "broker-database-audit")
	if _, err := application.ownedObjects(context.Background(), "volume"); err == nil {
		t.Fatal("empty inventory with additional platform volumes was accepted")
	}
}

func TestResetRemovesAnonymousVolumesFromExactOwnedContainers(t *testing.T) {
	project := "nvt-local"
	containerID := strings.Repeat("a", 64)
	docker := &resetContainerDocker{id: containerID, labels: map[string]string{
		"nvt.dev/local-platform-owner":   project,
		"nvt.dev/local-platform-version": "1",
		"com.docker.compose.project":     project,
		"com.docker.compose.service":     "local-controller",
	}}
	if err := (app{project: project, docker: docker}).reset(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, command := range docker.commands {
		if len(command) > 0 && command[0] == "rm" {
			if !containsTestArgument(command, "--force") || !containsTestArgument(command, "--volumes") || command[len(command)-1] != containerID {
				t.Fatalf("container removal did not include anonymous volumes: %v", command)
			}
			return
		}
	}
	t.Fatal("reset did not remove the exact-owned container")
}

type resetContainerDocker struct {
	id       string
	labels   map[string]string
	commands [][]string
}

func (docker *resetContainerDocker) Run(_ context.Context, _ io.Reader, arguments ...string) ([]byte, error) {
	docker.commands = append(docker.commands, append([]string(nil), arguments...))
	if len(arguments) == 0 {
		return nil, errors.New("missing command")
	}
	switch arguments[0] {
	case "ps":
		if strings.Contains(strings.Join(arguments, " "), "local-platform-owner") {
			return []byte(docker.id + "\n"), nil
		}
		return nil, nil
	case "container":
		return json.Marshal(docker.labels)
	case "rm":
		return nil, nil
	case "network", "volume":
		if len(arguments) > 1 && arguments[1] == "ls" {
			return nil, nil
		}
	}
	return nil, errors.New("unexpected Docker command")
}

func containsTestArgument(arguments []string, expected string) bool {
	for _, argument := range arguments {
		if argument == expected {
			return true
		}
	}
	return false
}

type resetDocker struct {
	project         string
	plan            []byte
	platformVolumes []string
	labels          map[string]map[string]string
	outputLimit     int
	volumeListLimit int
	helperScript    string
}

func (docker *resetDocker) RunWithOutputLimit(ctx context.Context, input io.Reader, maximum int, arguments ...string) ([]byte, error) {
	docker.outputLimit = maximum
	if len(arguments) >= 2 && arguments[0] == "volume" && arguments[1] == "ls" {
		docker.volumeListLimit = maximum
	}
	return docker.Run(ctx, input, arguments...)
}

func (docker *resetDocker) Run(_ context.Context, _ io.Reader, arguments ...string) ([]byte, error) {
	if len(arguments) >= 2 && arguments[0] == "volume" && arguments[1] == "ls" {
		if strings.Contains(strings.Join(arguments, " "), "local-platform-owner") {
			return []byte(strings.Join(docker.platformVolumes, "\n") + "\n"), nil
		}
		for _, argument := range arguments {
			if !strings.HasPrefix(argument, "name=^") {
				continue
			}
			name := strings.TrimSuffix(strings.TrimPrefix(argument, "name=^"), "$")
			if _, exists := docker.labels[name]; exists {
				return []byte(name + "\n"), nil
			}
		}
		return nil, nil
	}
	if len(arguments) >= 2 && arguments[0] == "volume" && arguments[1] == "inspect" {
		labels, exists := docker.labels[arguments[len(arguments)-1]]
		if !exists {
			return nil, errors.New("missing")
		}
		return json.Marshal(labels)
	}
	if len(arguments) >= 2 && arguments[0] == "image" && arguments[1] == "inspect" {
		return []byte("sha256:" + strings.Repeat("a", 64) + "\n"), nil
	}
	if len(arguments) > 0 && arguments[0] == "create" {
		docker.helperScript = strings.Join(arguments, "\n")
		return nil, nil
	}
	if len(arguments) > 0 && arguments[0] == "start" {
		return append([]byte(nil), docker.plan...), nil
	}
	if len(arguments) > 0 && arguments[0] == "rm" {
		return nil, nil
	}
	return nil, errors.New("unexpected Docker command")
}

func cloneTestLabels(labels map[string]string) map[string]string {
	result := map[string]string{}
	for key, value := range labels {
		result[key] = value
	}
	return result
}
