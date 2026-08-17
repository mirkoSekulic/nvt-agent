package config_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	serviceconfig "github.com/mirkoSekulic/nvt-agent/localplatform/config"
	"github.com/mirkoSekulic/nvt-agent/localplatform/manifest"
	plancontract "github.com/mirkoSekulic/nvt-agent/localplatform/plan"
	"github.com/mirkoSekulic/nvt-agent/protocol/resolvedrun"
)

func TestRenderValidManifestUsesContainerPrivateFilesAndNativePolicy(t *testing.T) {
	path := filepath.Join("..", "manifest", "testdata", "valid.yaml")
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := manifest.Decode(file)
	_ = file.Close()
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := manifest.Compile(decoded)
	if err != nil {
		t.Fatal(err)
	}

	broker, err := serviceconfig.Broker(compiled)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range [][]byte{
		[]byte(`"private-key-file":"` + plancontract.PrivateTarget("github-key") + `"`),
		[]byte(`"injection-hosts":["github.com","api.github.com"]`),
		[]byte(`"token-file":"` + plancontract.PrivateTarget("azure-token") + `"`),
		[]byte(`"app-id":3912708`),
		[]byte(`"installation-id":123`),
		[]byte(`"auth-file":"/private/portal/` + plancontract.CredentialSlotName("codex") + `"`),
		[]byte(`"repositories":["dev.azure.com/example/platform/_git/infrastructure"]`),
	} {
		if !bytes.Contains(broker, expected) {
			t.Fatalf("broker configuration omitted private file reference %s: %s", expected, broker)
		}
	}
	if bytes.Contains(broker, []byte(".nvt-local")) || bytes.Contains(broker, []byte("PRIVATE KEY")) {
		t.Fatalf("host path or credential entered broker configuration: %s", broker)
	}
	if bytes.Contains(broker, []byte(plancontract.CredentialSlotName("codex")+".json")) {
		t.Fatalf("broker OAuth path does not match the portal-persisted slot name: %s", broker)
	}
	claudeCompiled := compiled
	claudeCompiled.Broker.Accounts = append(append([]manifest.NamedAccount(nil), compiled.Broker.Accounts...), manifest.NamedAccount{Name: "claude", Account: manifest.Account{Preset: "claude-oauth"}})
	claudeBroker, err := serviceconfig.Broker(claudeCompiled)
	if err != nil || !bytes.Contains(claudeBroker, []byte(`"credentials-file":"/private/portal/`+plancontract.CredentialSlotName("claude")+`"`)) || bytes.Contains(claudeBroker, []byte(plancontract.CredentialSlotName("claude")+".json")) {
		t.Fatalf("Claude broker path does not match the portal-persisted slot name: %v %s", err, claudeBroker)
	}

	controller, err := serviceconfig.Controller(compiled, serviceconfig.Instructions{"development": "bounded instructions"})
	if err != nil {
		t.Fatal(err)
	}
	var trusted resolvedrun.TrustedConfiguration
	if err := json.Unmarshal(controller, &trusted); err != nil {
		t.Fatal(err)
	}
	if _, err := resolvedrun.NewResolver(trusted); err != nil {
		t.Fatalf("native controller policy is invalid: %v\n%s", err, controller)
	}
	if len(trusted.Profiles) != 1 || trusted.Profiles[0].Runtime == nil || trusted.Profiles[0].Runtime.Docker == nil ||
		trusted.Profiles[0].Egress.Transport != "transparent" || !trusted.Profiles[0].Egress.AllowInsecureBroker || trusted.Profiles[0].DefaultCredentialProvider != "github" {
		t.Fatalf("local Docker or mediated transport policy missing: %#v", trusted.Profiles)
	}
	githubGrantFound := false
	for _, grant := range trusted.Profiles[0].Broker.Grants {
		if grant.Provider == "github" {
			githubGrantFound = true
			if strings.Join(grant.EgressHosts, ",") != "github.com:443,api.github.com:443" {
				t.Fatalf("GitHub grant omitted the API injection route: %#v", grant)
			}
		}
	}
	if !githubGrantFound {
		t.Fatalf("GitHub repository grant is missing: %#v", trusted.Profiles[0].Broker.Grants)
	}
	var agentConfig struct {
		Runtime struct {
			Args   []string `json:"args"`
			Resume struct {
				Args []string `json:"args"`
			} `json:"resume"`
		} `json:"runtime"`
	}
	if err := json.Unmarshal(trusted.Profiles[0].AgentConfig, &agentConfig); err != nil {
		t.Fatal(err)
	}
	if got := agentConfig.Runtime.Resume.Args; len(got) != 3 || got[0] != "resume" || got[1] != "--last" || got[2] != "--dangerously-bypass-approvals-and-sandbox" {
		t.Fatalf("Codex resume command is incomplete: %#v", got)
	}
	claudeRuntimeCompiled := compiled
	claudeRuntimeCompiled.Controller.Profiles = append([]manifest.ControllerProfileIntent(nil), compiled.Controller.Profiles...)
	claudeRuntimeCompiled.Controller.Profiles[0].Profile.Runtime.Preset = "claude"
	claudeController, err := serviceconfig.Controller(claudeRuntimeCompiled, serviceconfig.Instructions{"development": "bounded instructions"})
	if err != nil {
		t.Fatal(err)
	}
	var claudeTrusted resolvedrun.TrustedConfiguration
	if err := json.Unmarshal(claudeController, &claudeTrusted); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(claudeTrusted.Profiles[0].AgentConfig, &agentConfig); err != nil {
		t.Fatal(err)
	}
	if got := agentConfig.Runtime.Resume.Args; len(got) != 2 || got[0] != "--continue" || got[1] != "--dangerously-skip-permissions" {
		t.Fatalf("Claude resume command is incomplete: %#v", got)
	}
	if _, err := serviceconfig.Controller(compiled, serviceconfig.Instructions{"development": strings.Repeat("x", resolvedrun.MaxWorkspaceInstructionsBytes+1)}); err == nil {
		t.Fatal("controller projection accepted oversized native workspace instructions")
	}
	overpopulated := compiled
	overpopulated.Controller.Workstations = make([]manifest.Workstation, 129)
	for index := range overpopulated.Controller.Workstations {
		overpopulated.Controller.Workstations[index] = manifest.Workstation{Name: fmt.Sprintf("workstation-%03d", index), Profile: "development"}
	}
	if _, err := serviceconfig.Controller(overpopulated, serviceconfig.Instructions{"development": "bounded instructions"}); err == nil {
		t.Fatal("controller projection accepted too many native workstations")
	}
	readOnly := compiled
	readOnly.Controller.Profiles = append([]manifest.ControllerProfileIntent(nil), compiled.Controller.Profiles...)
	readOnly.Controller.Profiles[0].Profile.Runtime.Autonomy = "read-only"
	if _, err := serviceconfig.Controller(readOnly, serviceconfig.Instructions{"development": "bounded instructions"}); err == nil || !strings.Contains(err.Error(), "compiled runtime autonomy is unsupported") {
		t.Fatalf("unsupported compiled read-only autonomy did not fail closed: %v", err)
	}
	github := decoded.Accounts["github"]
	github.Installations["other"] = "456"
	decoded.Accounts["github"] = github
	decoded.Repositories["other"] = manifest.Repository{GitHub: "other/repository", Account: "github"}
	decoded.Workstations[0].Repositories = append(decoded.Workstations[0].Repositories, "other")
	ambiguous, err := manifest.Compile(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := serviceconfig.Controller(ambiguous, serviceconfig.Instructions{"development": "bounded instructions"}); err == nil || !bytes.Contains([]byte(err.Error()), []byte("default credential provider is ambiguous")) {
		t.Fatalf("multi-installation default policy did not fail closed: %v", err)
	}
}

func TestBrokerRejectsDerivedProviderNameCollision(t *testing.T) {
	file, err := os.Open(filepath.Join("..", "manifest", "testdata", "valid.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := manifest.Decode(file)
	_ = file.Close()
	if err != nil {
		t.Fatal(err)
	}
	github := decoded.Accounts["github"]
	github.Installations = map[string]string{"mirkoSekulic": "123", "owner-one": "456", "owner-two": "789"}
	decoded.Accounts["github"] = github
	decoded.Secrets["collision-token"] = manifest.Secret{File: "./.nvt-local/secrets/collision-token"}
	decoded.Accounts["github-70864727"] = manifest.Account{Preset: "github-pat", TokenSecret: "collision-token"}
	compiled, err := manifest.Compile(decoded)
	if err != nil {
		t.Fatalf("collision fixture is not schema-valid: %v", err)
	}
	if _, err := serviceconfig.Broker(compiled); err == nil || !strings.Contains(err.Error(), `provider name "github-70864727" is not unique`) {
		t.Fatalf("derived provider collision did not fail closed: %v", err)
	}
}
