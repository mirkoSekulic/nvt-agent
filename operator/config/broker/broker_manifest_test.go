package broker_test

import (
	"bytes"
	"os"
	"reflect"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/util/yaml"
)

func TestBrokerManifestYAMLAndNoCommittedSecrets(t *testing.T) {
	data, err := os.ReadFile("broker.yaml")
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, forbidden := range []string{
		"kind: Secret",
		"GITHUB_APP_ID:",
		"GITHUB_APP_INSTALLATION_ID:",
		"GITHUB_APP_PRIVATE_KEY_BASE64:",
		"private_key",
		"BEGIN PRIVATE KEY",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("broker manifest must not commit secret material or Secret values; found %q", forbidden)
		}
	}

	decoder := yaml.NewYAMLOrJSONDecoder(bytes.NewReader(data), 4096)
	objects := map[string]map[string]any{}
	for {
		var object map[string]any
		if err := decoder.Decode(&object); err != nil {
			if err.Error() == "EOF" {
				break
			}
			t.Fatalf("decode broker manifest document: %v", err)
		}
		if len(object) == 0 {
			continue
		}
		key := stringValue(object, "kind") + "/" + nestedString(object, "metadata", "name")
		objects[key] = object
	}

	for _, expected := range []string{
		"ConfigMap/nvt-broker-config",
		"ConfigMap/nvt-broker-agents",
		"Deployment/nvt-broker",
		"Service/nvt-broker",
	} {
		if _, ok := objects[expected]; !ok {
			t.Fatalf("expected manifest object %s, got %#v", expected, reflect.ValueOf(objects).MapKeys())
		}
	}

	deployment := objects["Deployment/nvt-broker"]
	containers := nestedSlice(deployment, "spec", "template", "spec", "containers")
	if len(containers) != 1 {
		t.Fatalf("expected one broker container, got %#v", containers)
	}
	container := containers[0].(map[string]any)
	if stringValue(container, "image") != "nvt-broker:latest" {
		t.Fatalf("expected nvt-broker:latest image, got %#v", container["image"])
	}
	if !envValuePresent(container, "NVT_BROKER_BIND", "0.0.0.0:7347") ||
		!envValuePresent(container, "NVT_BROKER_CONFIG", "/config/broker.yaml") ||
		!envValuePresent(container, "NVT_BROKER_AGENTS_CONFIG", "/config/agents.yaml") ||
		!envValuePresent(container, "NVT_BROKER_AUDIT_LOG", "/state/audit.jsonl") {
		t.Fatalf("broker container env is incomplete: %#v", container["env"])
	}
	envFrom := sliceValue(container, "envFrom")
	if len(envFrom) != 1 || nestedString(envFrom[0].(map[string]any), "secretRef", "name") != "nvt-broker-env" {
		t.Fatalf("expected envFrom secretRef nvt-broker-env, got %#v", envFrom)
	}
}

func envValuePresent(container map[string]any, name, value string) bool {
	for _, env := range sliceValue(container, "env") {
		envMap := env.(map[string]any)
		if stringValue(envMap, "name") == name && stringValue(envMap, "value") == value {
			return true
		}
	}
	return false
}

func nestedSlice(object map[string]any, keys ...string) []any {
	current := any(object)
	for _, key := range keys {
		current = current.(map[string]any)[key]
	}
	return current.([]any)
}

func nestedString(object map[string]any, keys ...string) string {
	current := any(object)
	for _, key := range keys {
		current = current.(map[string]any)[key]
	}
	return current.(string)
}

func sliceValue(object map[string]any, key string) []any {
	return object[key].([]any)
}

func stringValue(object map[string]any, key string) string {
	return object[key].(string)
}
