package producer

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/mirkoSekulic/nvt-agent/localplatform/manifest"
	plancontract "github.com/mirkoSekulic/nvt-agent/localplatform/plan"
	"gopkg.in/yaml.v3"
)

func TestConfigurationsRenderBuiltInAndBoundedExternalContracts(t *testing.T) {
	compiled, _ := producerFixture()
	files, err := Configurations(compiled)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 || files[0].Name != "producers/chat.json" || files[1].Name != "producers/github.json" {
		t.Fatalf("configuration files = %#v", files)
	}
	var external map[string]any
	if err := json.Unmarshal(files[0].Data, &external); err != nil {
		t.Fatal(err)
	}
	if external["apiVersion"] != "nvt.dev/local-producer/v1" || external["name"] != "chat" || external["workflow"] != "development" {
		t.Fatalf("external configuration = %#v", external)
	}
	for _, forbidden := range []string{"profile", "backend", "image", "credential", "repository", "admissionToken", "admissionURL"} {
		if _, exists := external[forbidden]; exists {
			t.Fatalf("external configuration exposed %q selection", forbidden)
		}
	}
	secrets, ok := external["secretFiles"].(map[string]any)
	if !ok || secrets["hook"] != plancontract.PrivateTarget("chat-hook") || strings.Contains(string(files[0].Data), "PRIVATE") {
		t.Fatalf("external secret projection = %#v", secrets)
	}

	var builtIn map[string]any
	if err := json.Unmarshal(files[1].Data, &builtIn); err != nil {
		t.Fatal(err)
	}
	submission := builtIn["submission"].(map[string]any)
	workflows := submission["commandWorkflows"].(map[string]any)
	for _, command := range []string{"pr-create", "review", "run"} {
		if workflows[command] != "development" {
			t.Fatalf("command %q workflow = %#v", command, workflows[command])
		}
	}
	if submission["backend"] != "local" || submission["admissionMode"] != "profiled" ||
		submission["admissionTokenFile"] != plancontract.PrivateTarget("producer-admission:github") ||
		submission["scheduleNamespace"] != "unused" ||
		builtIn["state"].(map[string]any)["sqlitePath"] != StatePath+"/state.db" || builtIn["pollInterval"] != "30s" ||
		builtIn["idempotency"].(map[string]any)["scope"] != "issue" || builtIn["schedulingReactions"].(map[string]any)["enabled"] != true {
		t.Fatalf("built-in configuration = %#v", builtIn)
	}
}

func TestRenderComposeConfinesEveryProducer(t *testing.T) {
	compiled, statePlan := producerFixture()
	raw, err := RenderCompose(compiled, statePlan, Options{})
	if err != nil {
		t.Fatal(err)
	}
	var document composeDocument
	if err := yaml.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	if len(document.Services) != 2 || len(document.Networks) != 2 {
		t.Fatalf("compose document = %#v", document)
	}
	for name, service := range document.Services {
		if !service.ReadOnly || service.User == "0:0" || strings.Join(service.CapDrop, ",") != "ALL" ||
			strings.Join(service.SecurityOpt, ",") != "no-new-privileges:true" || service.PidsLimit != 128 ||
			service.CPUs == "" || service.MemLimit == "" || service.Restart != "unless-stopped" || !service.Init {
			t.Fatalf("service %s is not confined: %#v", name, service)
		}
		for _, mount := range service.Volumes {
			if mount.Type != "volume" || strings.Contains(mount.Source+mount.Target, "docker.sock") || strings.HasPrefix(mount.Source, "/") {
				t.Fatalf("service %s received unsafe mount: %#v", name, mount)
			}
		}
	}
	external := document.Services["producer-chat"]
	if len(external.Environment) != 3 || external.Environment["NVT_SCHEDULE_ADMISSION_URL"] != "http://local-controller:7480/v1/schedules/chat/admissions" ||
		external.Environment["NVT_SCHEDULE_ADMISSION_TOKEN_FILE"] != plancontract.PrivateTarget("producer-admission:chat") {
		t.Fatalf("external environment = %#v", external.Environment)
	}
	for _, mount := range external.Volumes {
		if !mount.ReadOnly || mount.Target == StatePath {
			t.Fatalf("external producer received writable or state mount: %#v", mount)
		}
	}
	builtIn := document.Services["producer-github"]
	writable := 0
	for _, mount := range builtIn.Volumes {
		if !mount.ReadOnly {
			writable++
			if mount.Target != StatePath {
				t.Fatalf("unexpected built-in writable mount: %#v", mount)
			}
		}
	}
	if writable != 1 || len(builtIn.Environment) != 1 || builtIn.Environment["NVT_GITHUB_COMMENTS_CONFIG"] != ConfigPath {
		t.Fatalf("built-in service = %#v", builtIn)
	}
}

func TestRenderComposeRejectsExpandedAuthority(t *testing.T) {
	compiled, statePlan := producerFixture()
	statePlan.Mounts = append(statePlan.Mounts, plancontract.Mount{
		Service: "producer:chat", Volume: "local-broker-private", Target: "/broker", ReadOnly: true,
	})
	statePlan.Volumes = append(statePlan.Volumes, plancontract.Volume{Name: "local-broker-private"})
	if _, err := RenderCompose(compiled, statePlan, Options{}); err == nil {
		t.Fatal("arbitrary broker mount was accepted")
	}
	compiled, statePlan = producerFixture()
	compiled.Producers[0].Image = "ghcr.io/example/chat:latest"
	if _, err := RenderCompose(compiled, statePlan, Options{}); err == nil {
		t.Fatal("mutable external image was accepted")
	}
	compiled, statePlan = producerFixture()
	for index := range statePlan.Mounts {
		if statePlan.Mounts[index].Service == "producer:chat" && statePlan.Mounts[index].Target == plancontract.PrivateTarget("producer-admission:chat") {
			statePlan.Mounts[index].ReadOnly = false
		}
	}
	if _, err := RenderCompose(compiled, statePlan, Options{}); err == nil {
		t.Fatal("writable admission credential was accepted")
	}
	compiled, statePlan = producerFixture()
	var configVolume string
	for _, mount := range statePlan.Mounts {
		if mount.Service == "producer:chat" && mount.Target == ConfigPath {
			configVolume = mount.Volume
		}
	}
	for index := range statePlan.Mounts {
		if statePlan.Mounts[index].Service == "producer:chat" && statePlan.Mounts[index].Target == plancontract.PrivateTarget("producer-admission:chat") {
			statePlan.Mounts[index].Volume = configVolume
		}
	}
	if _, err := RenderCompose(compiled, statePlan, Options{}); err == nil {
		t.Fatal("non-credential volume was substituted for the admission credential")
	}
	compiled, statePlan = producerFixture()
	firstTarget := plancontract.PrivateTarget("chat-hook")
	secondTarget := plancontract.PrivateTarget("chat-secondary")
	firstIndex, secondIndex := -1, -1
	for index := range statePlan.Mounts {
		if statePlan.Mounts[index].Service != "producer:chat" {
			continue
		}
		switch statePlan.Mounts[index].Target {
		case firstTarget:
			firstIndex = index
		case secondTarget:
			secondIndex = index
		}
	}
	if firstIndex < 0 || secondIndex < 0 {
		t.Fatal("two-secret fixture is incomplete")
	}
	statePlan.Mounts[firstIndex].Volume, statePlan.Mounts[secondIndex].Volume = statePlan.Mounts[secondIndex].Volume, statePlan.Mounts[firstIndex].Volume
	if _, err := RenderCompose(compiled, statePlan, Options{}); err == nil {
		t.Fatal("same-role producer secret volume swap was accepted")
	}
}

func producerFixture() (manifest.Compiled, plancontract.Plan) {
	github := manifest.ProducerIntent{
		Owner: "producer:github", Name: "github", Kind: "github-comments", RuntimeIdentity: manifest.RuntimeIdentityIntent{UID: 65532, GID: 65532},
		Workflow: "development", AdmissionCredential: "producer-admission:github",
		GitHub: &manifest.GitHubProducerIntent{
			AppID: 1, InstallationID: 2, PrivateKeySecret: "github-key", RepositoryOwner: "example", RepositoryName: "repo",
			Prefix: "/nvtagent", AllowedAuthors: []string{"owner"},
		},
	}
	external := manifest.ProducerIntent{
		Owner: "producer:chat", Name: "chat", Kind: "oci",
		Image:           "ghcr.io/example/chat@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		RuntimeIdentity: manifest.RuntimeIdentityIntent{UID: 1000, GID: 1000}, Workflow: "development",
		PublicConfig: map[string]any{"prefix": "/agent"}, Secrets: map[string]string{"hook": "chat-hook", "secondary": "chat-secondary"},
		AdmissionCredential: "producer-admission:chat",
	}
	compiled := manifest.Compiled{Version: manifest.APIVersion, Producers: []manifest.ProducerIntent{external, github}}
	statePlan := plancontract.Plan{Version: "1", Project: "local", Volumes: []plancontract.Volume{}, Mounts: []plancontract.Mount{}}
	addVolume := func(volume, role, owner string, consumers ...string) {
		statePlan.Volumes = append(statePlan.Volumes, plancontract.Volume{
			Name: volume, Role: role, Owner: owner, Consumers: consumers,
			Labels: map[string]string{
				"nvt.dev/local-platform-owner": "local", "nvt.dev/local-platform-custodian": owner,
				"nvt.dev/local-platform-role": role, "nvt.dev/local-platform-volume": volume, "nvt.dev/local-platform-version": "1",
			},
		})
	}
	addMount := func(service, volume, subpath, target string, readOnly bool) {
		statePlan.Mounts = append(statePlan.Mounts, plancontract.Mount{Service: service, Volume: volume, Subpath: subpath, Target: target, ReadOnly: readOnly})
	}
	configVolume := plancontract.VolumeName("local", plancontract.GeneratedConfigSuffix)
	addVolume(configVolume, "generated-config", "local-platform-state", "producer:chat", "producer:github")
	addMount("producer:chat", configVolume, "current/producers/chat.json", ConfigPath, true)
	addMount("producer:github", configVolume, "current/producers/github.json", ConfigPath, true)
	for service, logicalName := range map[string]string{"producer:chat": "producer-admission:chat", "producer:github": "producer-admission:github"} {
		volume := plancontract.VolumeName("local", plancontract.GeneratedInputSuffix(logicalName, service))
		addVolume(volume, "generated-private-input", "local-platform-state", service)
		addMount(service, volume, "current/value", plancontract.PrivateTarget(logicalName), true)
	}
	for service, logicalNames := range map[string][]string{"producer:chat": {"chat-hook", "chat-secondary"}, "producer:github": {"github-key"}} {
		for _, logicalName := range logicalNames {
			volume := plancontract.VolumeName("local", plancontract.StaticInputSuffix(service, logicalName))
			addVolume(volume, "static-private-input", service, service)
			addMount(service, volume, "current/value", plancontract.PrivateTarget(logicalName), true)
		}
	}
	stateVolume := plancontract.VolumeName("local", plancontract.ProducerStateSuffix("github"))
	addVolume(stateVolume, "producer-state", "producer:github", "producer:github")
	addMount("producer:github", stateVolume, "", StatePath, false)
	return compiled, statePlan
}
