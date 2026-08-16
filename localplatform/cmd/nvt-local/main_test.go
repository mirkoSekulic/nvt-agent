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
	configLabels := platformVolumeLabels(project, configName, "local-platform-state", "generated-config")
	brokerLabels := platformVolumeLabels(project, brokerName, "broker", "broker-database-audit")
	plan := plancontract.Plan{Version: "1", Project: project, Volumes: []plancontract.Volume{
		{Name: configName, Owner: "local-platform-state", Role: "generated-config", Labels: configLabels},
		{Name: brokerName, Owner: "broker", Role: "broker-database-audit", Labels: brokerLabels},
	}}
	encoded, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	docker := &resetDocker{project: project, plan: encoded, labels: map[string]map[string]string{configName: configLabels, brokerName: brokerLabels}}
	application := app{project: project, docker: docker}
	if names, err := application.ownedObjects(context.Background(), "volume"); err != nil || len(names) != 2 {
		t.Fatalf("exact volume inventory = %#v, %v", names, err)
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

type resetDocker struct {
	project string
	plan    []byte
	labels  map[string]map[string]string
}

func (docker *resetDocker) Run(_ context.Context, _ io.Reader, arguments ...string) ([]byte, error) {
	if len(arguments) >= 2 && arguments[0] == "volume" && arguments[1] == "ls" {
		if strings.Contains(strings.Join(arguments, " "), "local-platform-owner") {
			return []byte(strings.Join([]string{plancontract.VolumeName(docker.project, plancontract.GeneratedConfigSuffix), plancontract.VolumeName(docker.project, "broker-data")}, "\n") + "\n"), nil
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
	if len(arguments) > 0 && arguments[0] == "run" {
		return append([]byte(nil), docker.plan...), nil
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
