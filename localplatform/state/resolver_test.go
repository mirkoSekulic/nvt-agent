package state

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	serviceconfig "github.com/mirkoSekulic/nvt-agent/localplatform/config"
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

func TestResolveSnapshotsSharedSecretOnceAcrossOwners(t *testing.T) {
	rootPath := t.TempDir()
	name := ".nvt-local/secrets/shared"
	full := filepath.Join(rootPath, filepath.FromSlash(name))
	oldValue := []byte("old-shared-value")
	newValue := []byte("new-shared-value")
	mustWrite(t, full, 0o600, oldValue)
	compiled := manifest.Compiled{PrivateInputs: []manifest.PrivateInputIntent{
		{Owner: "broker", Name: "shared", File: "./" + name, Purpose: "secret"},
		{Owner: "producer:external", Name: "shared", File: name, Purpose: "secret:shared"},
	}}
	reads := 0
	inputs, err := resolveWithReader(filepath.Join(rootPath, "nvt.local.yaml"), compiled, func(root *os.Root, source string, maximum int64, rejectSymlinks, privateMode bool) ([]byte, error) {
		reads++
		content, readErr := readStable(root, source, maximum, rejectSymlinks, privateMode)
		if readErr == nil && reads == 1 {
			replacement := filepath.Join(rootPath, ".nvt-local", "secrets", "replacement")
			mustWrite(t, replacement, 0o600, newValue)
			if renameErr := os.Rename(replacement, full); renameErr != nil {
				t.Fatal(renameErr)
			}
		}
		return content, readErr
	})
	if err != nil {
		t.Fatal(err)
	}
	defer inputs.Close()
	if reads != 1 {
		t.Fatalf("shared logical source reads = %d", reads)
	}
	broker := inputs.private[inputKey{owner: "broker", name: "shared"}]
	producer := inputs.private[inputKey{owner: "producer:external", name: "shared"}]
	if !bytes.Equal(broker, oldValue) || !bytes.Equal(producer, oldValue) || !bytes.Equal(broker, producer) {
		t.Fatalf("shared secret projections diverged: broker=%q producer=%q", broker, producer)
	}
	if current, readErr := os.ReadFile(full); readErr != nil || !bytes.Equal(current, newValue) {
		t.Fatalf("test rotation did not occur: value=%q err=%v", current, readErr)
	}
}

func TestResolveUsesBoundedKubeconfigSecretSizeClass(t *testing.T) {
	for _, size := range []int{MaxSecretBytes + 1, MaxKubeconfigSecretBytes} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, ".nvt-local", "secrets", "config")
			mustWrite(t, path, 0o600, paddedKubeconfig(size, "dev"))
			compiled := kubeconfigBoundCompiled("clusters", ".nvt-local/secrets/config")
			inputs, err := Resolve(filepath.Join(root, "nvt.local.yaml"), compiled)
			if err != nil {
				t.Fatalf("bounded kubeconfig of %d bytes rejected: %v", size, err)
			}
			inputs.Close()
		})
	}
	root := t.TempDir()
	path := filepath.Join(root, ".nvt-local", "secrets", "config")
	mustWrite(t, path, 0o600, paddedKubeconfig(MaxKubeconfigSecretBytes+1, "dev"))
	compiled := kubeconfigBoundCompiled("clusters", ".nvt-local/secrets/config")
	if _, err := Resolve(filepath.Join(root, "nvt.local.yaml"), compiled); err == nil {
		t.Fatal("oversized kubeconfig secret accepted")
	}
}

func TestResolveKeepsCrossPurposeSecretReuseAtGenericLimit(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, ".nvt-local", "secrets", "shared")
	mustWrite(t, path, 0o600, paddedKubeconfig(MaxSecretBytes+1, "dev"))
	compiled := manifest.Compiled{PrivateInputs: []manifest.PrivateInputIntent{
		{Owner: "broker", Name: "clusters", File: ".nvt-local/secrets/shared", Purpose: "kubeconfig"},
		{Owner: "producer:external", Name: "shared", File: "./.nvt-local/secrets/shared", Purpose: "secret:shared"},
	}}
	if _, err := Resolve(filepath.Join(root, "nvt.local.yaml"), compiled); err == nil {
		t.Fatal("cross-purpose secret reuse escalated beyond the generic 64 KiB limit")
	}
}

func TestResolvePreparesLargeAllContextKubeconfigAsConcreteObserveGrants(t *testing.T) {
	root := t.TempDir()
	raw, err := os.ReadFile(filepath.Join("..", "manifest", "testdata", "valid.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := manifest.Decode(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	decoded.Secrets["cluster-config"] = manifest.Secret{File: "./.nvt-local/secrets/kubernetes/config"}
	decoded.BrokerProviders["clusters"] = manifest.BrokerProvider{Plugin: "kubeconfig", Secrets: map[string]string{"private-kubeconfig": "cluster-config"}}
	all := true
	profile := decoded.Profiles["development"]
	profile.Egress = nil
	profile.Kubernetes = []manifest.KubernetesAccess{{Provider: "clusters", AllContexts: &all, Authorization: &manifest.KubernetesAuthorization{Preset: "observe"}}}
	decoded.Profiles["development"] = profile
	compiled, err := manifest.Compile(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := serviceconfig.Broker(compiled); err == nil {
		t.Fatal("unresolved all-context selection reached broker configuration")
	}
	if _, err := serviceconfig.Controller(compiled, serviceconfig.Instructions{"development": "instructions"}); err == nil {
		t.Fatal("unresolved all-context selection reached controller configuration")
	}
	for _, input := range compiled.PrivateInputs {
		if input.Owner == "broker" && input.Name == "cluster-config" {
			compiled.PrivateInputs = []manifest.PrivateInputIntent{input}
			break
		}
	}
	if len(compiled.PrivateInputs) != 1 || compiled.PrivateInputs[0].Purpose != "kubeconfig" {
		t.Fatalf("compiled kubeconfig input = %#v", compiled.PrivateInputs)
	}
	path := filepath.Join(root, ".nvt-local", "secrets", "kubernetes", "config")
	mustWrite(t, path, 0o600, paddedKubeconfig(MaxSecretBytes+1, "prod", "dev", "staging"))
	inputs, err := Resolve(filepath.Join(root, "nvt.local.yaml"), compiled)
	if err != nil {
		t.Fatalf("resolve large all-context kubeconfig: %v", err)
	}
	defer inputs.Close()
	prepared, err := inputs.PreparedCompiled()
	if err != nil {
		t.Fatal(err)
	}
	var grant *manifest.BrokerGrantIntent
	for index := range prepared.Controller.Profiles[0].BrokerGrants {
		candidate := &prepared.Controller.Profiles[0].BrokerGrants[index]
		if candidate.Provider == "clusters" {
			grant = candidate
		}
	}
	if grant == nil || !grant.AllContexts || strings.Join(grant.Resources, ",") != "dev,prod,staging" || grant.Authorization == nil || len(grant.Authorization.Rules) != 3 {
		t.Fatalf("prepared all-context grant = %#v", grant)
	}
	for index, contextName := range grant.Resources {
		want := manifest.BrokerGrantAuthorizationRule{Operation: "observe", Resource: "context/" + contextName}
		if grant.Authorization.Rules[index] != want {
			t.Fatalf("context %q observe authorization = %#v", contextName, grant.Authorization.Rules[index])
		}
	}
	brokerConfig, err := serviceconfig.Broker(prepared)
	if err != nil {
		t.Fatalf("render prepared broker configuration: %v", err)
	}
	controllerConfig, err := serviceconfig.Controller(prepared, serviceconfig.Instructions{"development": "instructions"})
	if err != nil {
		t.Fatalf("render prepared controller configuration: %v", err)
	}
	for name, rendered := range map[string][]byte{"broker": brokerConfig, "controller": controllerConfig} {
		if bytes.Contains(rendered, []byte("allContexts")) || bytes.Contains(rendered, []byte(`"preset":"observe"`)) || bytes.Contains(rendered, []byte(`"resources":["*"]`)) {
			t.Fatalf("%s configuration contains an unresolved selection or policy: %s", name, rendered)
		}
	}
	for _, contextName := range []string{"dev", "prod", "staging"} {
		if !bytes.Contains(brokerConfig, []byte(`"`+contextName+`"`)) {
			t.Fatalf("broker configuration omitted concrete resource %q", contextName)
		}
		if !bytes.Contains(controllerConfig, []byte("context/"+contextName)) {
			t.Fatalf("controller configuration omitted concrete observe rule for %q", contextName)
		}
	}
	canonical, err := prepared.CanonicalJSON()
	if err != nil || bytes.Contains(canonical, []byte("real-private-token")) {
		t.Fatalf("prepared metadata leaked private kubeconfig: err=%v", err)
	}
}

func paddedKubeconfig(size int, contexts ...string) []byte {
	var value strings.Builder
	value.WriteString("apiVersion: v1\nkind: Config\nclusters: []\nusers:\n- name: private\n  user:\n    token: real-private-token\ncontexts:\n")
	for _, contextName := range contexts {
		fmt.Fprintf(&value, "- name: %s\n  context: {}\n", contextName)
	}
	if value.Len() < size {
		value.WriteByte('#')
		value.WriteString(strings.Repeat("x", size-value.Len()))
	}
	return []byte(value.String())
}

func kubeconfigBoundCompiled(secretName, file string) manifest.Compiled {
	return manifest.Compiled{
		Broker: manifest.BrokerIntent{Providers: []manifest.NamedBrokerProvider{{Name: "clusters", Provider: manifest.BrokerProvider{
			Plugin: "kubeconfig", Secrets: map[string]string{"private-kubeconfig": secretName},
		}}}},
		PrivateInputs: []manifest.PrivateInputIntent{{Owner: "broker", Name: secretName, File: file, Purpose: "kubeconfig"}},
	}
}

func TestKubeconfigSecretLimitFitsBoundedStateTransport(t *testing.T) {
	if MaxKubeconfigSecretBytes > maxStateFileBytes {
		t.Fatalf("kubeconfig limit %d exceeds state transport limit %d", MaxKubeconfigSecretBytes, maxStateFileBytes)
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

func TestStableReadRejectsPrivateMetadataRaces(t *testing.T) {
	for name, change := range map[string]func(*testing.T, string){
		"mode becomes permissive": func(t *testing.T, path string) {
			if err := os.Chmod(path, 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"owner changes": func(t *testing.T, path string) {
			wrongOwner := os.Geteuid() + 1
			if err := os.Chown(path, wrongOwner, wrongOwner); err != nil {
				t.Skip(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			rootPath := t.TempDir()
			name := ".nvt-local/secrets/value"
			full := filepath.Join(rootPath, filepath.FromSlash(name))
			mustWrite(t, full, 0o600, []byte("stable-private-value"))
			root, err := os.OpenRoot(rootPath)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			if _, err := readStableAfterFirst(root, name, MaxSecretBytes, true, true, func() { change(t, full) }); err == nil {
				t.Fatal("private metadata race accepted")
			}
		})
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
