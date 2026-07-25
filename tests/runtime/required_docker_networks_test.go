package runtime_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestRequiredDockerNetworksSurvivePruneAtCLIBoundary(t *testing.T) {
	root := repoRoot(t)
	temp := t.TempDir()
	state := filepath.Join(temp, "state.json")
	log := filepath.Join(temp, "docker.log")
	fake := filepath.Join(temp, "docker-real")
	mustWriteExecutable(t, fake, `#!/usr/bin/env python3
import json, os, sys
state_file = os.environ["FAKE_DOCKER_STATE"]
log_file = os.environ["FAKE_DOCKER_LOG"]
try:
    state = json.load(open(state_file))
except (FileNotFoundError, json.JSONDecodeError):
    state = {}
args = sys.argv[1:]
with open(log_file, "a") as out:
    out.write(" ".join(args) + "\n")
command = args
if command[:2] == ["--log-level", "debug"]:
    command = command[2:]
if args[:2] == ["network", "inspect"]:
    name = args[2]
    if name not in state:
        print("Error: No such network", file=sys.stderr)
        sys.exit(1)
    print(json.dumps([state[name]]))
elif args[:2] == ["network", "create"]:
    name = args[-1]
    subnet = next(value.split("=", 1)[1] for value in args if value.startswith("--subnet="))
    state[name] = {"Name": name, "Driver": "bridge", "EnableIPv6": False, "Internal": False,
                   "IPAM": {"Config": [{"Subnet": subnet}]},
                   "Options": {"com.docker.network.bridge.enable_ip_masquerade": "true"}}
    json.dump(state, open(state_file, "w"))
    print(name)
elif command[:2] == ["system", "prune"]:
    json.dump({}, open(state_file, "w"))
elif args == ["version"]:
    print("fake Docker")
else:
    print("unexpected fake Docker command", file=sys.stderr)
    sys.exit(2)
`)

	env := append(os.Environ(),
		`NVT_DOCKER_REQUIRED_NETWORKS=[{"name":"kind","subnet":"172.31.250.0/24"}]`,
		"NVT_DOCKER_REAL_BIN="+fake,
		"NVT_DOCKER_ENSURE_BIN="+filepath.Join(root, "runtime/core/ensure-docker-networks.py"),
		"FAKE_DOCKER_STATE="+state,
		"FAKE_DOCKER_LOG="+log,
	)
	wrapper := filepath.Join(root, "runtime/core/docker-wrapper.sh")
	for _, args := range [][]string{{"version"}, {"--log-level", "debug", "system", "prune"}} {
		command := exec.Command(wrapper, args...)
		command.Env = env
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("docker wrapper %v failed: %v\n%s", args, err, output)
		}
		assertRequiredDockerNetwork(t, root, fake, state, log)
	}
	contents, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(contents), "network create") != 2 {
		t.Fatalf("required network was not created initially and restored after prune:\n%s", contents)
	}

	mustWriteFile(t, state, `{"kind":{"Name":"kind","Driver":"bridge","EnableIPv6":true,"Internal":false,"IPAM":{"Config":[{"Subnet":"172.31.250.0/24"}]},"Options":{"com.docker.network.bridge.enable_ip_masquerade":"true"}}}`)
	mustWriteFile(t, log, "")
	command := exec.Command(wrapper, "version")
	command.Env = env
	if output, err := command.CombinedOutput(); err == nil || strings.Contains(string(output), "172.31.250.0/24") {
		t.Fatalf("incompatible existing network did not fail closed safely: err=%v output=%q", err, output)
	}
	contents, err = os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(contents), "\nversion\n") || strings.HasPrefix(string(contents), "version\n") {
		t.Fatalf("Docker command ran after incompatible network validation:\n%s", contents)
	}
}

func TestDockerWrapperRejectsPerCommandDaemonOverrides(t *testing.T) {
	root := repoRoot(t)
	temp := t.TempDir()
	log := filepath.Join(temp, "docker.log")
	fake := filepath.Join(temp, "docker-real")
	ensure := filepath.Join(temp, "ensure")
	mustWriteExecutable(t, fake, "#!/bin/sh\nprintf 'docker:%s\\n' \"$*\" >>\"$FAKE_DOCKER_LOG\"\n")
	mustWriteExecutable(t, ensure, "#!/bin/sh\nprintf 'ensure\\n' >>\"$FAKE_DOCKER_LOG\"\n")
	env := append(os.Environ(),
		`NVT_DOCKER_REQUIRED_NETWORKS=[{"name":"kind","subnet":"172.31.250.0/24"}]`,
		"NVT_DOCKER_REAL_BIN="+fake,
		"NVT_DOCKER_ENSURE_BIN="+ensure,
		"FAKE_DOCKER_LOG="+log,
	)
	wrapper := filepath.Join(root, "runtime/core/docker-wrapper.sh")
	for _, args := range [][]string{
		{"--context", "default", "version"},
		{"--context=default", "version"},
		{"-H", "tcp://127.0.0.1:2375", "version"},
		{"-Htcp://127.0.0.1:2375", "version"},
		{"--host=tcp://127.0.0.1:2375", "version"},
	} {
		command := exec.Command(wrapper, args...)
		command.Env = env
		output, err := command.CombinedOutput()
		if err == nil || !strings.Contains(string(output), "daemon-selection overrides are not supported") {
			t.Fatalf("configured wrapper did not reject daemon override %v safely: err=%v output=%q", args, err, output)
		}
	}
	if contents, err := os.ReadFile(log); err == nil && len(contents) != 0 {
		t.Fatalf("daemon override ran preflight or Docker command:\n%s", contents)
	} else if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
}

func TestDockerWrapperWithoutRequiredNetworksIsPassThrough(t *testing.T) {
	root := repoRoot(t)
	temp := t.TempDir()
	fake := filepath.Join(temp, "docker-real")
	mustWriteExecutable(t, fake, "#!/bin/sh\nprintf 'real:%s\\n' \"$*\"\n")
	command := exec.Command(filepath.Join(root, "runtime/core/docker-wrapper.sh"), "--context", "default", "version")
	command.Env = []string{"PATH=" + os.Getenv("PATH"), "NVT_DOCKER_REAL_BIN=" + fake}
	output, err := command.CombinedOutput()
	if err != nil || string(output) != "real:--context default version\n" {
		t.Fatalf("unconfigured wrapper changed Docker behavior: err=%v output=%q", err, output)
	}
}

func TestRequiredDockerNetworksFailClosed(t *testing.T) {
	root := repoRoot(t)
	helper := filepath.Join(root, "runtime/core/ensure-docker-networks.py")
	for _, config := range []string{
		`[{"name":"Kind","subnet":"172.31.250.0/24"}]`,
		`[{"name":"kind","subnet":"172.30.250.0/24"}]`,
		`[{"name":"kind","subnet":"fd00::/64"}]`,
		`[{"name":"kind","subnet":"172.31.250.1/24"}]`,
		`[{"name":"kind","subnet":"172.31.250.0/24","ipv6":false}]`,
	} {
		command := exec.Command(helper)
		command.Env = append(os.Environ(), "NVT_DOCKER_REQUIRED_NETWORKS="+config, "NVT_DOCKER_REAL_BIN=/bin/false")
		if output, err := command.CombinedOutput(); err == nil || strings.Contains(string(output), config) {
			t.Fatalf("invalid contract was not rejected safely: err=%v output=%q", err, output)
		}
	}
}

func assertRequiredDockerNetwork(t *testing.T, root, fake, state, log string) {
	t.Helper()
	command := exec.Command(filepath.Join(root, "runtime/core/ensure-docker-networks.py"))
	command.Env = append(os.Environ(),
		`NVT_DOCKER_REQUIRED_NETWORKS=[{"name":"kind","subnet":"172.31.250.0/24"}]`,
		"NVT_DOCKER_REAL_BIN="+fake,
		"FAKE_DOCKER_STATE="+state,
		"FAKE_DOCKER_LOG="+log,
	)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("required network validation failed: %v\n%s", err, output)
	}
}
