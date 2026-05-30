package broker_test

import (
	"bytes"
	"os"
	"sort"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/util/yaml"
)

func TestBrokerManifestYAMLAndNoCommittedSecrets(t *testing.T) {
	objects := readManifestObjects(t)

	for key, object := range objects {
		if stringValue(t, object, "kind") == "Secret" {
			t.Fatalf("broker manifest must not commit Secret objects; found %s", key)
		}
	}
	for _, expected := range []string{
		"ConfigMap/nvt-broker-config",
		"ConfigMap/nvt-broker-agents",
		"Deployment/nvt-broker",
		"Service/nvt-broker",
	} {
		if _, ok := objects[expected]; !ok {
			t.Fatalf("expected manifest object %s, got %v", expected, sortedKeys(objects))
		}
	}

	configData := requireMap(t, objects["ConfigMap/nvt-broker-config"], "data")
	brokerConfig := stringValue(t, configData, "broker.yaml")
	for _, forbidden := range []string{
		"GITHUB_APP_ID:",
		"GITHUB_APP_INSTALLATION_ID:",
		"GITHUB_APP_PRIVATE_KEY_BASE64:",
		"private_key",
		"BEGIN PRIVATE KEY",
	} {
		if strings.Contains(brokerConfig, forbidden) {
			t.Fatalf("broker config must not commit secret material or Secret values; found %q", forbidden)
		}
	}

	agentsData := requireMap(t, objects["ConfigMap/nvt-broker-agents"], "data")
	if got := strings.TrimSpace(stringValue(t, agentsData, "agents.yaml")); got != "agents: []" {
		t.Fatalf("expected initial empty agents policy, got %q", got)
	}
}

func TestBrokerDeploymentAndServiceWiring(t *testing.T) {
	objects := readManifestObjects(t)
	deployment := objects["Deployment/nvt-broker"]
	template := requireMap(t, requireMap(t, deployment, "spec"), "template")
	podSpec := requireMap(t, template, "spec")
	containers := requireSlice(t, podSpec, "containers")
	if len(containers) != 1 {
		t.Fatalf("expected one broker container, got %#v", containers)
	}

	container := requireMapFromValue(t, containers[0], "container")
	if got := stringValue(t, container, "image"); got != "nvt-broker:latest" {
		t.Fatalf("expected nvt-broker:latest image, got %q", got)
	}
	ports := requireSlice(t, container, "ports")
	if len(ports) != 1 || numberValue(t, requireMapFromValue(t, ports[0], "port"), "containerPort") != 7347 {
		t.Fatalf("expected container port 7347, got %#v", ports)
	}
	if !envValuePresent(t, container, "NVT_BROKER_BIND", "0.0.0.0:7347") ||
		!envValuePresent(t, container, "NVT_BROKER_CONFIG", "/config/broker.yaml") ||
		!envValuePresent(t, container, "NVT_BROKER_AGENTS_CONFIG", "/config/agents.yaml") ||
		!envValuePresent(t, container, "NVT_BROKER_AUDIT_LOG", "/state/audit.jsonl") {
		t.Fatalf("broker container env is incomplete: %#v", container["env"])
	}

	envFrom := requireSlice(t, container, "envFrom")
	if len(envFrom) != 1 || nestedString(t, requireMapFromValue(t, envFrom[0], "envFrom"), "secretRef", "name") != "nvt-broker-env" {
		t.Fatalf("expected envFrom secretRef nvt-broker-env, got %#v", envFrom)
	}
	assertVolumeMount(t, container, "broker-config", "/config", "", true)
	assertVolumeMount(t, container, "broker-state", "/state", "", false)

	volumes := requireSlice(t, podSpec, "volumes")
	projectedVolume := requireNamedMap(t, volumes, "broker-config")
	sources := requireSlice(t, requireMap(t, projectedVolume, "projected"), "sources")
	assertProjectedConfigMapItem(t, sources, "nvt-broker-config", "broker.yaml", "broker.yaml")
	assertProjectedConfigMapItem(t, sources, "nvt-broker-agents", "agents.yaml", "agents.yaml")
	stateVolume := requireNamedMap(t, volumes, "broker-state")
	if _, ok := stateVolume["emptyDir"]; !ok {
		t.Fatalf("expected broker-state emptyDir volume, got %#v", stateVolume)
	}

	service := objects["Service/nvt-broker"]
	selector := requireMap(t, requireMap(t, service, "spec"), "selector")
	if stringValue(t, selector, "app.kubernetes.io/name") != "nvt-broker" ||
		stringValue(t, selector, "app.kubernetes.io/component") != "broker" {
		t.Fatalf("unexpected service selector: %#v", selector)
	}
	servicePorts := requireSlice(t, requireMap(t, service, "spec"), "ports")
	if len(servicePorts) != 1 {
		t.Fatalf("expected one service port, got %#v", servicePorts)
	}
	servicePort := requireMapFromValue(t, servicePorts[0], "service port")
	if numberValue(t, servicePort, "port") != 7347 || numberValue(t, servicePort, "targetPort") != 7347 {
		t.Fatalf("expected service port 7347 -> 7347, got %#v", servicePort)
	}
}

func readManifestObjects(t *testing.T) map[string]map[string]any {
	t.Helper()

	data, err := os.ReadFile("broker.yaml")
	if err != nil {
		t.Fatal(err)
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
		key := stringValue(t, object, "kind") + "/" + nestedString(t, object, "metadata", "name")
		objects[key] = object
	}
	return objects
}

func envValuePresent(t *testing.T, container map[string]any, name, value string) bool {
	t.Helper()

	for _, env := range requireSlice(t, container, "env") {
		envMap := requireMapFromValue(t, env, "env")
		if stringValue(t, envMap, "name") == name && stringValue(t, envMap, "value") == value {
			return true
		}
	}
	return false
}

func assertVolumeMount(t *testing.T, container map[string]any, name, mountPath, subPath string, readOnly bool) {
	t.Helper()

	mount := requireNamedMap(t, requireSlice(t, container, "volumeMounts"), name)
	if stringValue(t, mount, "mountPath") != mountPath {
		t.Fatalf("expected mount %s path %s, got %#v", name, mountPath, mount)
	}
	if got, ok := mount["subPath"].(string); ok && got != subPath {
		t.Fatalf("expected mount %s subPath %q, got %#v", name, subPath, mount)
	}
	if readOnly && mount["readOnly"] != true {
		t.Fatalf("expected mount %s to be readOnly, got %#v", name, mount)
	}
}

func assertProjectedConfigMapItem(t *testing.T, sources []any, configMapName, key, path string) {
	t.Helper()

	for _, source := range sources {
		configMap, ok := requireMapFromValue(t, source, "projected source")["configMap"].(map[string]any)
		if !ok || stringValue(t, configMap, "name") != configMapName {
			continue
		}
		items := requireSlice(t, configMap, "items")
		if len(items) != 1 {
			t.Fatalf("expected one item for %s, got %#v", configMapName, items)
		}
		item := requireMapFromValue(t, items[0], "projected item")
		if stringValue(t, item, "key") != key || stringValue(t, item, "path") != path {
			t.Fatalf("expected %s item %s -> %s, got %#v", configMapName, key, path, item)
		}
		return
	}
	t.Fatalf("projected ConfigMap %s not found in %#v", configMapName, sources)
}

func requireNamedMap(t *testing.T, values []any, name string) map[string]any {
	t.Helper()

	for _, value := range values {
		object := requireMapFromValue(t, value, name)
		if stringValue(t, object, "name") == name {
			return object
		}
	}
	t.Fatalf("object named %s not found in %#v", name, values)
	return nil
}

func nestedString(t *testing.T, object map[string]any, keys ...string) string {
	t.Helper()

	current := object
	for _, key := range keys[:len(keys)-1] {
		current = requireMap(t, current, key)
	}
	return stringValue(t, current, keys[len(keys)-1])
}

func requireMap(t *testing.T, object map[string]any, key string) map[string]any {
	t.Helper()

	value, ok := object[key]
	if !ok {
		t.Fatalf("missing key %s in %#v", key, object)
	}
	return requireMapFromValue(t, value, key)
}

func requireMapFromValue(t *testing.T, value any, name string) map[string]any {
	t.Helper()

	object, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("expected %s to be a map, got %T %#v", name, value, value)
	}
	return object
}

func requireSlice(t *testing.T, object map[string]any, key string) []any {
	t.Helper()

	value, ok := object[key]
	if !ok {
		t.Fatalf("missing key %s in %#v", key, object)
	}
	slice, ok := value.([]any)
	if !ok {
		t.Fatalf("expected %s to be a slice, got %T %#v", key, value, value)
	}
	return slice
}

func stringValue(t *testing.T, object map[string]any, key string) string {
	t.Helper()

	value, ok := object[key].(string)
	if !ok {
		t.Fatalf("expected string key %s in %#v", key, object)
	}
	return value
}

func numberValue(t *testing.T, object map[string]any, key string) int {
	t.Helper()

	switch value := object[key].(type) {
	case int:
		return value
	case int64:
		return int(value)
	case float64:
		return int(value)
	default:
		t.Fatalf("expected numeric key %s in %#v", key, object)
		return 0
	}
}

func sortedKeys(objects map[string]map[string]any) []string {
	keys := make([]string, 0, len(objects))
	for key := range objects {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
