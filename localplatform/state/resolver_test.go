package state

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mirkoSekulic/nvt-agent/localplatform/manifest"
)

func TestResolveSeparatesInstructionsFromPrivateMaterial(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "guidance", "development.md"), 0o644, []byte("trusted guidance\n"))
	mustWrite(t, filepath.Join(root, ".nvt-local", "secrets", "github", "app.pem"), 0o600, []byte("PRIVATE-STATIC-VALUE"))
	compiled := manifest.Compiled{PrivateInputs: []manifest.PrivateInputIntent{
		{Owner: "local-controller", Name: "development", File: "guidance/development.md", Purpose: "instructions"},
		{Owner: "broker", Name: "github-key", File: "./.nvt-local/secrets/github/app.pem", Purpose: "secret"},
	}}
	inputs, err := Resolve(filepath.Join(root, "nvt.local.yaml"), compiled)
	if err != nil {
		t.Fatal(err)
	}
	if len(inputs.Instructions) != 1 || string(inputs.Instructions[0].Content) != "trusted guidance\n" {
		t.Fatalf("instructions = %#v", inputs.Instructions)
	}
	plan, err := BuildPlan("test-local", compiled, inputs)
	if err != nil {
		t.Fatal(err)
	}
	redacted, err := plan.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"PRIVATE-STATIC-VALUE", root, ".nvt-local", "app.pem"} {
		if bytes.Contains(redacted, []byte(forbidden)) {
			t.Fatalf("redacted plan contains %q: %s", forbidden, redacted)
		}
	}
	privateMounts := 0
	for _, mount := range plan.Mounts {
		if mount.Service == "agent" || strings.HasPrefix(mount.Service, "agent:") {
			t.Fatalf("agent received mount: %#v", mount)
		}
		if mount.Service == "broker" && strings.HasPrefix(mount.Target, "/run/nvt-private/") {
			privateMounts++
			if !mount.ReadOnly || mount.Subpath != "current/value" {
				t.Fatalf("private mount is not exact read-only: %#v", mount)
			}
		}
	}
	if privateMounts != 1 {
		t.Fatalf("private mounts = %d", privateMounts)
	}
	content := inputs.Instructions[0].Content
	inputs.Close()
	if !bytes.Equal(content, make([]byte, len(content))) {
		t.Fatal("Close did not clear instruction content")
	}
}

func TestResolveRejectsUnsafeInputs(t *testing.T) {
	cases := map[string]func(*testing.T, string) manifest.PrivateInputIntent{
		"missing instruction": func(t *testing.T, root string) manifest.PrivateInputIntent {
			return manifest.PrivateInputIntent{Owner: "local-controller", Name: "p", File: "missing", Purpose: "instructions"}
		},
		"absolute instruction": func(t *testing.T, root string) manifest.PrivateInputIntent {
			return manifest.PrivateInputIntent{Owner: "local-controller", Name: "p", File: filepath.Join(root, "file"), Purpose: "instructions"}
		},
		"parent instruction": func(t *testing.T, root string) manifest.PrivateInputIntent {
			return manifest.PrivateInputIntent{Owner: "local-controller", Name: "p", File: "../file", Purpose: "instructions"}
		},
		"escaping instruction symlink": func(t *testing.T, root string) manifest.PrivateInputIntent {
			outside := filepath.Join(t.TempDir(), "outside")
			mustWrite(t, outside, 0o600, []byte("outside"))
			mustSymlink(t, outside, filepath.Join(root, "guidance"))
			return manifest.PrivateInputIntent{Owner: "local-controller", Name: "p", File: "guidance", Purpose: "instructions"}
		},
		"oversized instruction": func(t *testing.T, root string) manifest.PrivateInputIntent {
			path := filepath.Join(root, "large")
			mustWrite(t, path, 0o600, bytes.Repeat([]byte{'i'}, MaxInstructionBytes+1))
			return manifest.PrivateInputIntent{Owner: "local-controller", Name: "p", File: "large", Purpose: "instructions"}
		},
		"secret outside directory": func(t *testing.T, root string) manifest.PrivateInputIntent {
			path := filepath.Join(root, "secret")
			mustWrite(t, path, 0o600, []byte("secret"))
			return manifest.PrivateInputIntent{Owner: "broker", Name: "s", File: "secret", Purpose: "secret"}
		},
		"secret final symlink": func(t *testing.T, root string) manifest.PrivateInputIntent {
			target := filepath.Join(root, ".nvt-local", "secrets", "target")
			mustWrite(t, target, 0o600, []byte("secret"))
			mustSymlink(t, "target", filepath.Join(root, ".nvt-local", "secrets", "link"))
			return manifest.PrivateInputIntent{Owner: "broker", Name: "s", File: ".nvt-local/secrets/link", Purpose: "secret"}
		},
		"secret directory symlink": func(t *testing.T, root string) manifest.PrivateInputIntent {
			target := filepath.Join(root, "target")
			mustWrite(t, filepath.Join(target, "value"), 0o600, []byte("secret"))
			mustSymlink(t, target, filepath.Join(root, ".nvt-local", "secrets", "linked"))
			return manifest.PrivateInputIntent{Owner: "broker", Name: "s", File: ".nvt-local/secrets/linked/value", Purpose: "secret"}
		},
		"permissive secret": func(t *testing.T, root string) manifest.PrivateInputIntent {
			path := filepath.Join(root, ".nvt-local", "secrets", "value")
			mustWrite(t, path, 0o640, []byte("secret"))
			return manifest.PrivateInputIntent{Owner: "broker", Name: "s", File: ".nvt-local/secrets/value", Purpose: "secret"}
		},
		"wrong owner secret": func(t *testing.T, root string) manifest.PrivateInputIntent {
			path := filepath.Join(root, ".nvt-local", "secrets", "value")
			mustWrite(t, path, 0o600, []byte("secret"))
			if err := os.Chown(path, 12345, 12345); err != nil {
				t.Skip(err)
			}
			return manifest.PrivateInputIntent{Owner: "broker", Name: "s", File: ".nvt-local/secrets/value", Purpose: "secret"}
		},
		"empty secret": func(t *testing.T, root string) manifest.PrivateInputIntent {
			path := filepath.Join(root, ".nvt-local", "secrets", "value")
			mustWrite(t, path, 0o600, nil)
			return manifest.PrivateInputIntent{Owner: "broker", Name: "s", File: ".nvt-local/secrets/value", Purpose: "secret"}
		},
		"non-regular secret": func(t *testing.T, root string) manifest.PrivateInputIntent {
			if err := os.MkdirAll(filepath.Join(root, ".nvt-local", "secrets", "directory"), 0o700); err != nil {
				t.Fatal(err)
			}
			return manifest.PrivateInputIntent{Owner: "broker", Name: "s", File: ".nvt-local/secrets/directory", Purpose: "secret"}
		},
		"oversized secret": func(t *testing.T, root string) manifest.PrivateInputIntent {
			path := filepath.Join(root, ".nvt-local", "secrets", "value")
			mustWrite(t, path, 0o600, bytes.Repeat([]byte{'s'}, MaxSecretBytes+1))
			return manifest.PrivateInputIntent{Owner: "broker", Name: "s", File: ".nvt-local/secrets/value", Purpose: "secret"}
		},
		"untrusted secret owner": func(t *testing.T, root string) manifest.PrivateInputIntent {
			path := filepath.Join(root, ".nvt-local", "secrets", "value")
			mustWrite(t, path, 0o600, []byte("secret"))
			return manifest.PrivateInputIntent{Owner: "agent", Name: "s", File: ".nvt-local/secrets/value", Purpose: "secret"}
		},
	}
	for name, prepare := range cases {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			input := prepare(t, root)
			if _, err := Resolve(filepath.Join(root, "nvt.local.yaml"), manifest.Compiled{PrivateInputs: []manifest.PrivateInputIntent{input}}); err == nil {
				t.Fatal("unsafe input accepted")
			}
		})
	}
}

func TestResolveAllowsConfinedInstructionSymlink(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "guidance", "real.md"), 0o644, []byte("inside"))
	mustSymlink(t, "real.md", filepath.Join(root, "guidance", "linked.md"))
	compiled := manifest.Compiled{PrivateInputs: []manifest.PrivateInputIntent{{Owner: "local-controller", Name: "p", File: "guidance/linked.md", Purpose: "instructions"}}}
	inputs, err := Resolve(filepath.Join(root, "nvt.local.yaml"), compiled)
	if err != nil {
		t.Fatal(err)
	}
	defer inputs.Close()
	if string(inputs.Instructions[0].Content) != "inside" {
		t.Fatal("wrong instruction content")
	}
}

func TestStableReadRejectsPathAndContentRaces(t *testing.T) {
	rootPath := t.TempDir()
	name := ".nvt-local/secrets/value"
	full := filepath.Join(rootPath, name)
	mustWrite(t, full, 0o600, []byte("first-value"))
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	_, err = readStableAfterFirst(root, name, MaxSecretBytes, true, true, func() {
		replacement := filepath.Join(rootPath, ".nvt-local", "secrets", "replacement")
		mustWrite(t, replacement, 0o600, []byte("second-valu"))
		if err := os.Rename(replacement, full); err != nil {
			t.Fatal(err)
		}
	})
	if err == nil {
		t.Fatal("path replacement race accepted")
	}

	mustWrite(t, full, 0o600, []byte("first-value"))
	_, err = readStableAfterFirst(root, name, MaxSecretBytes, true, true, func() {
		if err := os.WriteFile(full, []byte("third-value"), 0o600); err != nil {
			t.Fatal(err)
		}
	})
	if err == nil {
		t.Fatal("in-place content race accepted")
	}

	directoryName := ".nvt-local/secrets/directory/value"
	directoryPath := filepath.Join(rootPath, filepath.FromSlash(directoryName))
	mustWrite(t, directoryPath, 0o600, []byte("directory-value"))
	_, err = readStableAfterFirst(root, directoryName, MaxSecretBytes, true, true, func() {
		directory := filepath.Dir(directoryPath)
		moved := directory + "-moved"
		if err := os.Rename(directory, moved); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Base(moved), directory); err != nil {
			t.Fatal(err)
		}
	})
	if err == nil {
		t.Fatal("intermediate symlink race accepted")
	}
}

func mustWrite(t *testing.T, name string, mode os.FileMode, content []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(name), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, content, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(name, mode); err != nil {
		t.Fatal(err)
	}
}

func mustSymlink(t *testing.T, target, name string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(name), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, name); err != nil {
		t.Fatal(err)
	}
}
