package state

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"strings"
	"testing"

	"github.com/mirkoSekulic/nvt-agent/localplatform/manifest"
	plancontract "github.com/mirkoSekulic/nvt-agent/localplatform/plan"
	producerrender "github.com/mirkoSekulic/nvt-agent/localplatform/producer"
	"github.com/mirkoSekulic/nvt-agent/protocol/resolvedrun"
)

var _ producerrender.ImageInspectRunner = DockerCLI{}

type memoryStore struct {
	volumes     map[string]Volume
	files       map[string]map[string][]byte
	oldFiles    map[string]map[string][]byte
	directories map[string]directoryPlan
	publishing  map[string]bool
	conflict    bool
	writes      int
	failVolume  string
}

func newMemoryStore() *memoryStore {
	return &memoryStore{volumes: map[string]Volume{}, files: map[string]map[string][]byte{}, oldFiles: map[string]map[string][]byte{}, directories: map[string]directoryPlan{}, publishing: map[string]bool{}}
}

func validStateCompiled() manifest.Compiled {
	return manifest.Compiled{
		Version: manifest.APIVersion,
		Broker:  manifest.BrokerIntent{Owner: "broker"},
		Controller: manifest.ControllerIntent{
			Owner:        "local-controller",
			Profiles:     []manifest.ControllerProfileIntent{{Name: "profile", Profile: manifest.Profile{Runtime: manifest.Runtime{Preset: "shell", Autonomy: "read-only"}}}},
			Repositories: []manifest.ControllerRepositoryIntent{{Name: "repository", URL: "https://github.com/example/repository.git", CheckoutTarget: "github.com/example/repository"}},
			Workflows:    []manifest.NamedWorkflow{{Name: "workflow", Workflow: manifest.Workflow{Profile: "profile", Repository: "repository", Retention: "disposable"}}},
			Workstations: []manifest.Workstation{{Name: "workstation", Profile: "profile"}},
		},
		Gateway: manifest.GatewayIntent{Owner: "gateway"},
	}
}
func (store *memoryStore) EnsureVolumes(_ context.Context, volumes []Volume) (map[string]bool, error) {
	if store.conflict {
		return nil, errors.New("conflict")
	}
	created := map[string]bool{}
	for _, volume := range volumes {
		if existing, ok := store.volumes[volume.Name]; ok {
			if !maps.Equal(existing.Labels, volume.Labels) {
				return nil, errors.New("conflict")
			}
			continue
		}
		store.volumes[volume.Name] = volume
		created[volume.Name] = true
	}
	return created, nil
}
func (store *memoryStore) ReplaceFiles(_ context.Context, volume Volume, files []StateFile) error {
	if store.failVolume == volume.Name {
		store.failVolume = ""
		return errors.New("injected write failure")
	}
	if _, ok := store.volumes[volume.Name]; !ok {
		return errors.New("missing volume")
	}
	next := map[string][]byte{}
	for _, file := range files {
		value, err := io.ReadAll(file.Data)
		if err != nil {
			return err
		}
		next[file.Name] = value
	}
	store.files[volume.Name] = next
	delete(store.oldFiles, volume.Name)
	store.writes++
	return nil
}

func (store *memoryStore) ReadVolumeInventory(_ context.Context, volume Volume) ([]byte, error) {
	existing, ok := store.volumes[volume.Name]
	if !ok {
		return nil, nil
	}
	if !maps.Equal(existing.Labels, volume.Labels) {
		return nil, errors.New("ownership conflict")
	}
	if current := store.files[volume.Name]["volume-inventory.json"]; len(current) != 0 {
		return append([]byte(nil), current...), nil
	}
	return append([]byte(nil), store.oldFiles[volume.Name]["volume-inventory.json"]...), nil
}

func (store *memoryStore) EnsureDirectory(_ context.Context, volume Volume, uid, gid int, mode int64) error {
	if _, ok := store.volumes[volume.Name]; !ok {
		return errors.New("missing volume")
	}
	store.directories[volume.Name] = directoryPlan{volume: volume.Name, uid: uid, gid: gid, mode: mode}
	return nil
}

func (store *memoryStore) InspectPrivateSource(_ context.Context, volume Volume, expectedSize int) (PrivateSourceState, error) {
	files := store.files[volume.Name]
	if len(files) == 0 {
		return PrivateSourceEmpty, nil
	}
	if bytes.Equal(files[".initialized"], privateSourceMarker(files["value"])) && len(files["value"]) == expectedSize {
		if store.publishing[volume.Name] {
			return PrivateSourcePublishing, nil
		}
		return PrivateSourceReady, nil
	}
	return PrivateSourceCorrupt, nil
}

func (store *memoryStore) FinalizePrivateSource(_ context.Context, volume Volume, expectedSize int) error {
	if state, _ := store.InspectPrivateSource(context.Background(), volume, expectedSize); state != PrivateSourcePublishing {
		return errors.New("source is not publishing")
	}
	store.publishing[volume.Name] = false
	return nil
}

func (store *memoryStore) InitializePrivateSource(ctx context.Context, volume Volume, _ int, files []StateFile) error {
	if len(store.files[volume.Name]) != 0 {
		return errors.New("source already initialized")
	}
	return store.ReplaceFiles(ctx, volume, files)
}
func (store *memoryStore) CopyPrivateFile(_ context.Context, source, destination Volume, _, _, expectedSize int) error {
	if state, _ := store.InspectPrivateSource(context.Background(), source, expectedSize); state != PrivateSourceReady {
		return errors.New("corrupt source")
	}
	value := store.files[source.Name]["value"]
	if len(value) == 0 {
		return errors.New("missing source")
	}
	store.files[destination.Name] = map[string][]byte{"value": append([]byte(nil), value...)}
	store.writes++
	return nil
}

func TestManagerPreservesGeneratedStateAndRefreshesExactCopies(t *testing.T) {
	secret := []byte("STATIC-PRIVATE-VALUE")
	inputs := &Inputs{private: map[inputKey][]byte{{owner: "broker", name: "github-key"}: append([]byte(nil), secret...)}, Instructions: []Instruction{{Owner: "local-controller", Name: "development", Content: []byte("instructions")}}}
	defer inputs.Close()
	compiled := validStateCompiled()
	compiled.Gateway.CredentialPortalAccounts = []manifest.PortalAccountIntent{{Name: "codex", Preset: "codex-oauth"}}
	compiled.Producers = []manifest.ProducerIntent{{
		Owner: "producer:test", Name: "test", Kind: "oci",
		Image:           "ghcr.io/example/test@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		RuntimeIdentity: manifest.RuntimeIdentityIntent{UID: 1000, GID: 1000}, Workflow: "workflow", AdmissionCredential: "producer-admission:test",
	}}
	compiled.PrivateInputs = []manifest.PrivateInputIntent{
		{Owner: "local-controller", Name: "development", File: "instructions.md", Purpose: "instructions"},
		{Owner: "broker", Name: "github-key", File: ".nvt-local/secrets/key", Purpose: "secret"},
	}
	compiled.GeneratedPrivateInputs = []manifest.GeneratedPrivateInputIntent{{Owner: "local-platform-state", Name: "producer-admission:test", Purpose: "schedule-admission-token", Consumers: []string{"local-controller", "producer:test"}}}
	store := newMemoryStore()
	manager := Manager{Store: store, Random: bytes.NewReader(bytes.Repeat([]byte{0x11}, 4096))}
	plan, err := manager.Ensure(context.Background(), "local-test", compiled, inputs)
	if err != nil {
		t.Fatal(err)
	}
	producerCompose, err := producerrender.RenderCompose(context.Background(), compiled, plan, producerrender.Options{
		ImageInspector: producerrender.ImageInspectorFunc(func(context.Context, string) (producerrender.ResolvedImage, error) {
			return producerrender.ResolvedImage{ID: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}, nil
		}),
	})
	if err != nil || !bytes.Contains(producerCompose, []byte("producer-test")) {
		t.Fatalf("managed plan did not render producer Compose: %v %s", err, producerCompose)
	}
	for volume, files := range store.files {
		if value := files["compiled.json"]; bytes.Contains(value, secret) {
			t.Fatalf("secret entered compiled config volume %s", volume)
		}
		if value := files["state-plan.json"]; bytes.Contains(value, secret) {
			t.Fatalf("secret entered plan config volume %s", volume)
		}
		if value := files["volume-inventory.json"]; bytes.Contains(value, secret) {
			t.Fatalf("secret entered volume inventory %s", volume)
		}
	}
	for _, mount := range plan.Mounts {
		if mount.Service == "agent" {
			t.Fatal("agent received state")
		}
		if stringsContainsSecret(mount.Service+mount.Volume+mount.Subpath+mount.Target, secret) {
			t.Fatal("secret entered mount metadata")
		}
	}
	assertMount := func(service, target string, readOnly bool) Mount {
		t.Helper()
		for _, mount := range plan.Mounts {
			if mount.Service == service && mount.Target == target {
				if mount.ReadOnly != readOnly {
					t.Fatalf("mount %s/%s readOnly=%v", service, target, mount.ReadOnly)
				}
				return mount
			}
		}
		t.Fatalf("missing mount %s/%s", service, target)
		return Mount{}
	}
	seed := assertMount("credential-portal", "/seed", false)
	brokerSeed := assertMount("broker", "/portal-seed", true)
	if seed.Volume != brokerSeed.Volume {
		t.Fatal("portal seed and broker import storage diverged")
	}
	if initialized := store.directories[seed.Volume]; initialized.uid != 1000 || initialized.gid != 1000 || initialized.mode != 0o700 {
		t.Fatalf("portal seed directory ownership = %#v", initialized)
	}
	assertMount("broker", "/private", false)
	assertMount("credential-portal", "/etc/nvt-local/credential-portal.json", true)
	assertMount("producer:test", "/etc/nvt-producer/config.json", true)
	sources := map[string][]byte{}
	for name, volume := range store.volumes {
		if volume.Role == "generated-private-source" {
			sources[name] = append([]byte(nil), store.files[name]["value"]...)
		}
	}
	if len(sources) != 6 {
		t.Fatalf("generated source count = %d", len(sources))
	}
	var staticVolume string
	for _, mount := range plan.Mounts {
		if mount.Service == "broker" && mount.Target == privateTarget("github-key") {
			staticVolume = mount.Volume
		}
	}
	if staticVolume == "" || !bytes.Equal(store.files[staticVolume]["value"], secret) {
		t.Fatal("static private input was not stored exactly")
	}
	replacementSecret := []byte("REPLACED-PRIVATE-VALUE")
	clear(inputs.private[inputKey{owner: "broker", name: "github-key"}])
	inputs.private[inputKey{owner: "broker", name: "github-key"}] = append([]byte(nil), replacementSecret...)

	manager.Random = bytes.NewReader(bytes.Repeat([]byte{0x22}, 4096))
	if _, err := manager.Ensure(context.Background(), "local-test", compiled, inputs); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(store.files[staticVolume]["value"], replacementSecret) {
		t.Fatal("static input replacement was not applied")
	}
	for _, files := range store.files {
		for name, value := range files {
			if name != "value" && bytes.Contains(value, replacementSecret) {
				t.Fatal("replacement secret entered generated configuration")
			}
		}
	}
	for name, value := range sources {
		if !bytes.Equal(store.files[name]["value"], value) {
			t.Fatalf("restart rotated %s", name)
		}
	}

	var replacedCopy string
	for name, volume := range store.volumes {
		if volume.Role == "generated-private-input" {
			replacedCopy = name
			break
		}
	}
	delete(store.volumes, replacedCopy)
	delete(store.files, replacedCopy)
	if _, err := manager.Ensure(context.Background(), "local-test", compiled, inputs); err != nil {
		t.Fatal(err)
	}
	if len(store.files[replacedCopy]["value"]) == 0 {
		t.Fatal("replacement consumer volume was not restored")
	}
}

func TestManagerPreservesRetiredVolumeLabelInventory(t *testing.T) {
	withPortal := validStateCompiled()
	withPortal.Gateway.CredentialPortalAccounts = []manifest.PortalAccountIntent{{Name: "codex", Preset: "codex-oauth"}}
	store := newMemoryStore()
	manager := Manager{Store: store, Random: bytes.NewReader(bytes.Repeat([]byte{0x31}, 4096))}
	inputs := &Inputs{private: map[inputKey][]byte{}}
	if _, err := manager.Ensure(context.Background(), "local-test", withPortal, inputs); err != nil {
		t.Fatal(err)
	}
	retiredName := "local-test-credential-seeds"
	retired := store.volumes[retiredName]
	if retired.Name == "" {
		t.Fatal("portal volume was not created")
	}
	withoutPortal := withPortal
	withoutPortal.Gateway.CredentialPortalAccounts = nil
	if _, err := manager.Ensure(context.Background(), "local-test", withoutPortal, inputs); err != nil {
		t.Fatal(err)
	}
	configName := "local-test-generated-config"
	store.oldFiles[configName] = store.files[configName]
	delete(store.files, configName)
	if _, err := manager.Ensure(context.Background(), "local-test", withoutPortal, inputs); err != nil {
		t.Fatalf("interrupted config publication recovery failed: %v", err)
	}
	configFiles := store.files[configName]
	var current Plan
	if json.Unmarshal(configFiles["state-plan.json"], &current) != nil {
		t.Fatal("current state plan is invalid")
	}
	for _, volume := range current.Volumes {
		if volume.Name == retiredName {
			t.Fatal("retired volume remained in the current state plan")
		}
	}
	var inventory plancontract.VolumeInventory
	if json.Unmarshal(configFiles["volume-inventory.json"], &inventory) != nil {
		t.Fatal("historical volume inventory is invalid")
	}
	found := false
	for _, volume := range inventory.Volumes {
		if volume.Name == retiredName {
			found = maps.Equal(volume.Labels, retired.Labels)
		}
	}
	if !found {
		t.Fatal("retired exact-owned volume labels were not preserved")
	}
	inventory.Volumes[0].Labels["unexpected"] = "label"
	tampered, err := json.Marshal(inventory)
	if err != nil {
		t.Fatal(err)
	}
	configFiles["volume-inventory.json"] = tampered
	writes := store.writes
	if _, err := manager.Ensure(context.Background(), "local-test", withoutPortal, inputs); err == nil {
		t.Fatal("tampered historical ownership inventory was accepted")
	}
	if store.writes != writes {
		t.Fatal("tampered historical ownership inventory changed state")
	}
}

func TestManagerFailsBeforeWritesOnOwnershipConflict(t *testing.T) {
	store := newMemoryStore()
	store.conflict = true
	compiled := validStateCompiled()
	inputs := &Inputs{private: map[inputKey][]byte{}}
	if _, err := (Manager{Store: store}).Ensure(context.Background(), "local-test", compiled, inputs); err == nil {
		t.Fatal("ownership conflict accepted")
	}
	if store.writes != 0 {
		t.Fatal("state changed before ownership validation")
	}
}

func TestManagerRejectsInvalidNativeProjectionBeforeVolumeCreation(t *testing.T) {
	compiled := validStateCompiled()
	compiled.PrivateInputs = []manifest.PrivateInputIntent{{Owner: "local-controller", Name: "profile", File: "instructions.md", Purpose: "instructions"}}
	inputs := &Inputs{private: map[inputKey][]byte{}, Instructions: []Instruction{{Owner: "local-controller", Name: "profile", Content: bytes.Repeat([]byte{'x'}, resolvedrun.MaxWorkspaceInstructionsBytes+1)}}}
	defer inputs.Close()
	store := newMemoryStore()
	if _, err := (Manager{Store: store}).Ensure(context.Background(), "local-test", compiled, inputs); err == nil {
		t.Fatal("invalid native controller projection was published")
	}
	if len(store.volumes) != 0 || store.writes != 0 {
		t.Fatal("invalid native controller projection changed managed state")
	}
}

func TestManagerRejectsOversizedCurrentVolumeInventoryBeforeCreation(t *testing.T) {
	compiled := validStateCompiled()
	inputs := &Inputs{private: map[inputKey][]byte{}}
	for index := 0; index < MaxVolumeInventoryRecords; index++ {
		name := fmt.Sprintf("secret-%04d", index)
		compiled.PrivateInputs = append(compiled.PrivateInputs, manifest.PrivateInputIntent{Owner: "broker", Name: name, File: ".nvt-local/secrets/" + name, Purpose: "secret"})
		inputs.private[inputKey{owner: "broker", name: name}] = []byte("secret")
	}
	defer inputs.Close()
	plan, err := BuildPlan("local-test", compiled, inputs)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Volumes) <= MaxVolumeInventoryRecords {
		t.Fatalf("test plan did not exceed the inventory bound: %d", len(plan.Volumes))
	}
	store := newMemoryStore()
	if _, err := (Manager{Store: store}).Ensure(context.Background(), "local-test", compiled, inputs); err == nil {
		t.Fatal("oversized current volume inventory was accepted")
	}
	if len(store.volumes) != 0 || store.writes != 0 {
		t.Fatal("oversized current volume inventory changed managed state")
	}
}

func TestManagerRejectsExpandedGeneratedFileBeforeVolumeCreation(t *testing.T) {
	document := manifest.Manifest{
		APIVersion:   manifest.APIVersion,
		Profiles:     map[string]manifest.Profile{},
		Repositories: map[string]manifest.Repository{"repo": {GitHub: "owner/repo"}},
		Workflows:    map[string]manifest.Workflow{"work": {Profile: "profile-000", Repository: "repo", Retention: "disposable"}},
	}
	instructionPath := "instructions/" + strings.Repeat("a", 3000)
	for index := 0; index < manifest.MaxItems; index++ {
		name := fmt.Sprintf("profile-%03d", index)
		document.Profiles[name] = manifest.Profile{
			Runtime:      manifest.Runtime{Preset: "shell", Autonomy: "read-only"},
			Instructions: &manifest.FileRef{File: instructionPath},
		}
	}
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) > manifest.MaxDocumentBytes {
		t.Fatalf("test manifest exceeds accepted document size: %d", len(raw))
	}
	decoded, err := manifest.Decode(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("valid expanded manifest was rejected: %v", err)
	}
	compiled, err := manifest.Compile(decoded)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := compiled.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if len(canonical) <= maxStateFileBytes {
		t.Fatalf("test compiled.json did not exceed state-file limit: %d", len(canonical))
	}
	inputs := &Inputs{private: map[inputKey][]byte{}}
	for _, input := range compiled.PrivateInputs {
		inputs.Instructions = append(inputs.Instructions, Instruction{Owner: input.Owner, Name: input.Name, Content: []byte("instruction")})
	}
	defer inputs.Close()
	store := newMemoryStore()
	if _, err := (Manager{Store: store}).Ensure(context.Background(), "local-test", compiled, inputs); err == nil {
		t.Fatal("oversized compiled.json was accepted")
	}
	if len(store.volumes) != 0 || len(store.directories) != 0 || store.writes != 0 {
		t.Fatal("oversized generated state changed managed volumes")
	}
}

func TestManagerRecoversEmptySourceAfterPartialWriteFailure(t *testing.T) {
	compiled := validStateCompiled()
	inputs := &Inputs{private: map[inputKey][]byte{}}
	store := newMemoryStore()
	store.failVolume = "local-test-generated-config"
	manager := Manager{Store: store, Random: bytes.NewReader(bytes.Repeat([]byte{0x51}, 1024))}
	if _, err := manager.Ensure(context.Background(), "local-test", compiled, inputs); err == nil {
		t.Fatal("injected partial failure succeeded")
	}
	for name, volume := range store.volumes {
		if volume.Role == "generated-private-source" && len(store.files[name]) != 0 {
			t.Fatalf("source initialized before config failure: %s", name)
		}
	}
	if _, err := manager.Ensure(context.Background(), "local-test", compiled, inputs); err != nil {
		t.Fatalf("retry did not recover empty sources: %v", err)
	}
	for name, volume := range store.volumes {
		if volume.Role == "generated-private-source" {
			if state, _ := store.InspectPrivateSource(context.Background(), volume, len(store.files[name]["value"])); state != PrivateSourceReady {
				t.Fatalf("source %s state=%v", name, state)
			}
		}
	}
}

func TestManagerFinalizesInterruptedGeneratedSourcePublication(t *testing.T) {
	compiled := validStateCompiled()
	inputs := &Inputs{private: map[inputKey][]byte{}}
	store := newMemoryStore()
	plan, err := preparePlan("local-test", compiled, inputs)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.EnsureVolumes(context.Background(), plan.Volumes); err != nil {
		t.Fatal(err)
	}
	source := plan.generated[0].sourceVolume
	value := bytes.Repeat([]byte{'p'}, generatedValueSize(plan.generated[0].encoding))
	store.files[source] = map[string][]byte{
		".initialized": privateSourceMarker(value),
		"value":        append([]byte(nil), value...),
	}
	store.publishing[source] = true
	manager := Manager{Store: store, Random: bytes.NewReader(bytes.Repeat([]byte{0x59}, 4096))}
	if _, err := manager.Ensure(context.Background(), "local-test", compiled, inputs); err != nil {
		t.Fatalf("interrupted publication was not recovered: %v", err)
	}
	if store.publishing[source] {
		t.Fatal("source publication remained unfinished")
	}
	if !bytes.Equal(store.files[source]["value"], value) {
		t.Fatal("publication recovery rotated the generated value")
	}
}

func TestManagerRejectsMarkedSourceWithoutValue(t *testing.T) {
	compiled := validStateCompiled()
	inputs := &Inputs{private: map[inputKey][]byte{}}
	store := newMemoryStore()
	plan, err := preparePlan("local-test", compiled, inputs)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.EnsureVolumes(context.Background(), plan.Volumes); err != nil {
		t.Fatal(err)
	}
	source := plan.generated[0].sourceVolume
	store.files[source] = map[string][]byte{".initialized": privateSourceMarker([]byte("missing-value"))}
	if _, err := (Manager{Store: store, Random: bytes.NewReader(bytes.Repeat([]byte{0x61}, 1024))}).Ensure(context.Background(), "local-test", compiled, inputs); err == nil {
		t.Fatal("corrupt initialized source was rotated")
	}
	if _, exists := store.files[source]["value"]; exists {
		t.Fatal("corrupt source was silently regenerated")
	}
}

func TestManagerRejectsGeneratedSourceValueThatDoesNotMatchJournal(t *testing.T) {
	compiled := validStateCompiled()
	inputs := &Inputs{private: map[inputKey][]byte{}}
	for name, replacement := range map[string][]byte{
		"same-sized replacement": bytes.Repeat([]byte{'b'}, 43),
		"truncated replacement":  []byte("A"),
	} {
		t.Run(name, func(t *testing.T) {
			store := newMemoryStore()
			plan, err := preparePlan("local-test", compiled, inputs)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.EnsureVolumes(context.Background(), plan.Volumes); err != nil {
				t.Fatal(err)
			}
			sourceName := plan.generated[0].sourceVolume
			original := bytes.Repeat([]byte{'a'}, 43)
			store.files[sourceName] = map[string][]byte{
				".initialized": privateSourceMarker(original),
				"value":        append([]byte(nil), replacement...),
			}
			manager := Manager{Store: store, Random: bytes.NewReader(bytes.Repeat([]byte{0x71}, 1024))}
			if _, err := manager.Ensure(context.Background(), "local-test", compiled, inputs); err == nil {
				t.Fatal("generated source with mismatched journal was accepted")
			}
			if !bytes.Equal(store.files[sourceName]["value"], replacement) {
				t.Fatal("corrupt generated source was silently rotated")
			}
			if store.writes != 0 {
				t.Fatal("state was written before generated source validation completed")
			}
		})
	}
}

func TestPlanOmitsCredentialPortalStateWithoutOAuthAccounts(t *testing.T) {
	compiled := validStateCompiled()
	inputs := &Inputs{private: map[inputKey][]byte{}}
	plan, err := BuildPlan("local-test", compiled, inputs)
	if err != nil {
		t.Fatal(err)
	}
	for _, volume := range plan.Volumes {
		if stringsContains(volume.Name, "credential-seeds") || volume.Owner == "credential-portal" || containsString(volume.Consumers, "credential-portal") || containsString(volume.Consumers, "credential-runner") {
			t.Fatalf("disabled portal received volume: %#v", volume)
		}
	}
	for _, mount := range plan.Mounts {
		if mount.Service == "credential-portal" || mount.Service == "credential-runner" || stringsContains(mount.Volume+mount.Target, "credential") {
			t.Fatalf("disabled portal received mount: %#v", mount)
		}
	}
	files, err := configurationFiles(compiled, inputs, plan, plan.Volumes)
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		if file.Name == "credential-portal.json" {
			t.Fatal("disabled portal received configuration")
		}
	}
}

func TestPlanUsesDeclaredExternalProducerRuntimeIdentity(t *testing.T) {
	compiled := validStateCompiled()
	compiled.Producers = []manifest.ProducerIntent{{Owner: "producer:external", Name: "external", Kind: "oci", RuntimeIdentity: manifest.RuntimeIdentityIntent{UID: 1001, GID: 1002}}}
	compiled.PrivateInputs = []manifest.PrivateInputIntent{{Owner: "producer:external", Name: "api-key", File: ".nvt-local/secrets/api-key", Purpose: "secret"}}
	compiled.GeneratedPrivateInputs = []manifest.GeneratedPrivateInputIntent{{Owner: "local-platform-state", Name: "producer-admission:external", Purpose: "schedule-admission-token", Consumers: []string{"local-controller", "producer:external"}}}
	inputs := &Inputs{private: map[inputKey][]byte{{owner: "producer:external", name: "api-key"}: []byte("private")}}
	defer inputs.Close()
	plan, err := preparePlan("local-test", compiled, inputs)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.static) != 1 || plan.static[0].uid != 1001 || plan.static[0].gid != 1002 {
		t.Fatalf("static producer identity = %#v", plan.static)
	}
	foundGenerated := false
	for _, generated := range plan.generated {
		for _, consumer := range generated.consumer {
			if consumer.service == "producer:external" {
				foundGenerated = true
				if consumer.uid != 1001 || consumer.gid != 1002 {
					t.Fatalf("generated producer identity = %#v", consumer)
				}
			}
		}
	}
	if !foundGenerated {
		t.Fatal("generated producer consumer was not planned")
	}
	compiled.Producers = nil
	if _, err := preparePlan("local-test", compiled, inputs); err == nil {
		t.Fatal("producer inputs without a compiled runtime identity were accepted")
	}
}

func TestPortalConfigurationUsesUniqueCanonicalLocalDestinations(t *testing.T) {
	raw, err := portalConfiguration([]manifest.PortalAccountIntent{{Name: "a.b", Preset: "codex-oauth"}, {Name: "a-b-2e7336dc", Preset: "codex-oauth"}, {Name: "claude", Preset: "claude-oauth"}})
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Slots []struct {
			Name           string `json:"name"`
			DataKey        string `json:"dataKey"`
			BrokerProvider string `json:"brokerProvider"`
		} `json:"slots"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	seenNames, seenKeys := map[string]bool{}, map[string]bool{}
	for _, slot := range document.Slots {
		if slot.Name == "" || stringsContains(slot.Name, ".") || slot.DataKey != slot.Name+".json" || seenNames[slot.Name] || seenKeys[slot.DataKey] || slot.BrokerProvider == "" {
			t.Fatalf("invalid portal slot: %#v", slot)
		}
		seenNames[slot.Name], seenKeys[slot.DataKey] = true, true
	}
	if len(seenNames) != 3 {
		t.Fatalf("slots = %#v", document.Slots)
	}
}

func TestPortalAccountLimitFailsBeforeVolumeWrites(t *testing.T) {
	accounts := make([]manifest.PortalAccountIntent, 129)
	for index := range accounts {
		accounts[index] = manifest.PortalAccountIntent{Name: fmt.Sprintf("account-%03d", index), Preset: "codex-oauth"}
	}
	if _, err := portalConfiguration(accounts[:128]); err != nil {
		t.Fatalf("portal rejected its exact slot limit: %v", err)
	}
	compiled := validStateCompiled()
	compiled.Gateway.CredentialPortalAccounts = accounts
	store := newMemoryStore()
	if _, err := (Manager{Store: store}).Ensure(context.Background(), "local-test", compiled, &Inputs{private: map[inputKey][]byte{}}); err == nil {
		t.Fatal("oversized portal slot set accepted")
	}
	if len(store.volumes) != 0 || store.writes != 0 {
		t.Fatal("invalid portal config changed Docker state")
	}
}

func TestGeneratedSourceReplacementRotatesAllConsumersTogether(t *testing.T) {
	compiled := validStateCompiled()
	compiled.GeneratedPrivateInputs = []manifest.GeneratedPrivateInputIntent{{Owner: "local-platform-state", Name: "shared", Purpose: "test", Consumers: []string{"gateway", "local-controller"}}}
	inputs := &Inputs{private: map[inputKey][]byte{}}
	store := newMemoryStore()
	manager := Manager{Store: store, Random: bytes.NewReader(bytes.Repeat([]byte{0x31}, 4096))}
	plan, err := manager.Ensure(context.Background(), "local-test", compiled, inputs)
	if err != nil {
		t.Fatal(err)
	}
	source := "local-test-generated-" + shortID("shared")
	copies := []string{}
	for _, mount := range plan.Mounts {
		if mount.Target == privateTarget("shared") {
			copies = append(copies, mount.Volume)
		}
	}
	if source == "" || len(copies) != 2 {
		t.Fatalf("source=%q copies=%v", source, copies)
	}
	old := append([]byte(nil), store.files[source]["value"]...)
	delete(store.volumes, source)
	delete(store.files, source)
	manager.Random = bytes.NewReader(bytes.Repeat([]byte{0x42}, 4096))
	if _, err := manager.Ensure(context.Background(), "local-test", compiled, inputs); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(store.files[source]["value"], old) {
		t.Fatal("replaced source did not rotate")
	}
	for _, copyName := range copies {
		if !bytes.Equal(store.files[copyName]["value"], store.files[source]["value"]) {
			t.Fatal("consumer copies diverged after replacement")
		}
	}
}

func stringsContainsSecret(value string, secret []byte) bool {
	return bytes.Contains([]byte(value), secret)
}

func stringsContains(value, target string) bool {
	return bytes.Contains([]byte(value), []byte(target))
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
