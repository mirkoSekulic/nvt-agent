package runtime_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestWorkControlPublishesOnlyFixedEvents(t *testing.T) {
	root := repoRoot(t)
	script := filepath.Join(root, "runtime", "plugins", "work-control", "nvt-work.py")
	manifest, err := os.ReadFile(filepath.Join(root, "runtime", "plugins", "work-control", "plugin.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(manifest), "name: nvt-work") || !strings.Contains(string(manifest), "nvt-work.py") {
		t.Fatalf("work-control does not export nvt-work:\n%s", manifest)
	}
	bin := t.TempDir()
	capture := filepath.Join(t.TempDir(), "args.json")
	stub := filepath.Join(bin, "agentdctl")
	if err := os.WriteFile(stub, []byte("#!/usr/bin/env python3\nimport json,os,sys\njson.dump(sys.argv[1:],open(os.environ['CAPTURE'],'w'))\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	for command, event := range map[string]string{"complete": "plugin.work.completed", "fail": "plugin.work.failed"} {
		cmd := exec.Command("python3", script, command)
		cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "CAPTURE="+capture)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s: %v: %s", command, err, output)
		}
		data, err := os.ReadFile(capture)
		if err != nil {
			t.Fatal(err)
		}
		var args []string
		if err := json.Unmarshal(data, &args); err != nil {
			t.Fatal(err)
		}
		want := []string{"publish", event, "--source", "plugin:work-control"}
		if strings.Join(args, "\x00") != strings.Join(want, "\x00") {
			t.Fatalf("args = %#v, want %#v", args, want)
		}
	}
	cmd := exec.Command("python3", script, "plugin.evil", "--payload", "secret")
	cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "CAPTURE="+capture)
	if err := cmd.Run(); err == nil {
		t.Fatal("arbitrary event and payload were accepted")
	}
}
