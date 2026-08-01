package template

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestCompiledTemplateIsBoundedCredentialFreeGraph(t *testing.T) {
	value, err := Compiled()
	if err != nil {
		t.Fatal(err)
	}
	resources, ok := value["resources"].([]any)
	if !ok || len(resources) != 4 {
		t.Fatalf("unexpected Azure graph: %#v", value["resources"])
	}
	var vm, disk map[string]any
	for _, raw := range resources {
		resource, _ := raw.(map[string]any)
		switch resource["type"] {
		case "Microsoft.Compute/virtualMachines":
			vm = resource
		case "Microsoft.Compute/disks":
			disk = resource
		}
	}
	vmJSON, _ := json.Marshal(vm)
	diskJSON, _ := json.Marshal(disk)
	if vm == nil || disk == nil || !bytes.Contains(vmJSON, []byte(`"osProfile"`)) ||
		!bytes.Contains(vmJSON, []byte(`"imageReference"`)) || !bytes.Contains(vmJSON, []byte(`"createOption":"FromImage"`)) ||
		bytes.Contains(vmJSON, []byte(`"createOption":"Attach"`)) || !bytes.Contains(diskJSON, []byte(`"dependsOn"`)) {
		t.Fatal("compiled template does not use generalized-image VM provisioning followed by owned disk lockdown")
	}
	encoded := strings.ToLower(string(Bytes()))
	for _, forbidden := range []string{"publicipaddresses", "customdata", "userdata", "clientsecret", "enrollment_token", "private_key"} {
		if strings.Contains(encoded, forbidden) {
			t.Fatalf("compiled template contains %q", forbidden)
		}
	}
	if !strings.Contains(encoded, `"mode":"incremental"`) && strings.Contains(encoded, `"mode"`) {
		t.Fatal("deployment mode belongs to the SDK request, not the embedded template")
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, Bytes()); err != nil {
		t.Fatal(err)
	}
	source, err := os.ReadFile("deployment.bicep")
	if err != nil || !bytes.Contains(source, []byte("deny-all-outbound")) || !bytes.Contains(source, []byte("deny-all-inbound")) || !bytes.Contains(source, []byte("publicNetworkAccess: 'Disabled'")) {
		t.Fatal("reviewed Bicep source does not contain the required network boundary")
	}
}
