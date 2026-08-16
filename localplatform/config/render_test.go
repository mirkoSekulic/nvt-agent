package config_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
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
		[]byte(`"token-file":"` + plancontract.PrivateTarget("azure-token") + `"`),
		[]byte(`"app-id":3912708`),
		[]byte(`"installation-id":123`),
		[]byte(`"auth-file":"/private/portal/` + plancontract.CredentialSlotName("codex") + `.json"`),
	} {
		if !bytes.Contains(broker, expected) {
			t.Fatalf("broker configuration omitted private file reference %s: %s", expected, broker)
		}
	}
	if bytes.Contains(broker, []byte(".nvt-local")) || bytes.Contains(broker, []byte("PRIVATE KEY")) {
		t.Fatalf("host path or credential entered broker configuration: %s", broker)
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
		trusted.Profiles[0].Egress.Transport != "transparent" || !trusted.Profiles[0].Egress.AllowInsecureBroker {
		t.Fatalf("local Docker or mediated transport policy missing: %#v", trusted.Profiles)
	}
}
