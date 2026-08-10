package portal

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
)

func patchRESTClient(t *testing.T, handler http.Handler) rest.Interface {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	client, err := rest.RESTClientFor(&rest.Config{Host: server.URL, APIPath: "/api", ContentConfig: rest.ContentConfig{GroupVersion: &schema.GroupVersion{Version: "v1"}, NegotiatedSerializer: scheme.Codecs.WithoutConversion()}})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestKubernetesPatcherUsesOneExactJSONPatchAndMetadataResponse(t *testing.T) {
	requests := 0
	client := patchRESTClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Method != http.MethodPatch || r.URL.Path != "/api/v1/namespaces/nvt/secrets/portal-seed" || r.Header.Get("Content-Type") != "application/json-patch+json" {
			t.Errorf("unexpected request %s %s %s", r.Method, r.URL.Path, r.Header.Get("Content-Type"))
		}
		if !strings.Contains(r.Header.Get("Accept"), "PartialObjectMetadata") {
			t.Errorf("patch did not request metadata-only response")
		}
		var operations []struct{ Op, Path, Value string }
		if err := json.NewDecoder(r.Body).Decode(&operations); err != nil {
			t.Error(err)
		}
		if len(operations) != 1 || operations[0].Op != "add" || operations[0].Path != "/data/nested~0~1key" {
			t.Errorf("unexpected JSON patch operation metadata")
		}
		decoded, err := base64.StdEncoding.DecodeString(operations[0].Value)
		if err != nil || string(decoded) != "secret" {
			t.Errorf("unexpected patch value")
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{"apiVersion": "meta.k8s.io/v1", "kind": "PartialObjectMetadata", "metadata": map[string]string{"name": "portal-seed"}})
	}))
	if err := (KubernetesSecretPatcher{Client: client}).Patch(context.Background(), "nvt", "portal-seed", "nested~/key", []byte("secret")); err != nil {
		t.Fatal(err)
	}
	if requests != 1 {
		t.Fatalf("patcher performed %d API requests", requests)
	}
}

func TestKubernetesPatcherDoesNotCreateOrRetryMissingSecret(t *testing.T) {
	requests := 0
	client := patchRESTClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		http.Error(w, `{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"NotFound","code":404}`, http.StatusNotFound)
	}))
	if err := (KubernetesSecretPatcher{Client: client}).Patch(context.Background(), "nvt", "missing", "auth.json", []byte("secret")); err == nil {
		t.Fatal("missing pre-created Secret was accepted")
	}
	if requests != 1 {
		t.Fatalf("patcher performed %d API requests", requests)
	}
}
