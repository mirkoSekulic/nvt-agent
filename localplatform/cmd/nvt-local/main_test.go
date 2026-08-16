package main

import "testing"

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
	run["nvt.dev/local-run-digest"] = "short"
	if application.validRunContainer(run) {
		t.Fatal("ambiguous runtime service was accepted")
	}
}
