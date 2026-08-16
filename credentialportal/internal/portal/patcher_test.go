package portal

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
)

func TestLocalFilePatcherAtomicSlotIsolationAndValidation(t *testing.T) {
	directory := t.TempDir()
	patcher, err := NewLocalFilePatcher(directory, "nvt", []Slot{
		{Name: "codex", SecretName: "local-seed", DataKey: "codex.json"},
		{Name: "claude", SecretName: "local-seed", DataKey: "claude.json"},
	})
	if err != nil {
		t.Fatal(err)
	}
	credential := []byte(`{"tokens":{"access_token":"synthetic"}}`)
	if err := patcher.Patch(context.Background(), "nvt", "local-seed", "codex.json", credential); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "codex")
	got, err := os.ReadFile(path)
	if err != nil || string(got) != string(credential) {
		t.Fatalf("credential = %q, %v", got, err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, %v", info.Mode().Perm(), err)
	}
	if _, err := os.Stat(filepath.Join(directory, "claude")); !os.IsNotExist(err) {
		t.Fatal("unselected slot changed")
	}
	staging, err := os.ReadDir(filepath.Join(directory, localStagingDirectory))
	if err != nil || len(staging) != 0 {
		t.Fatalf("local staging was not cleaned: %v %#v", err, staging)
	}
	if err := patcher.Patch(context.Background(), "other", "local-seed", "codex.json", credential); err == nil {
		t.Fatal("cross-namespace destination accepted")
	}
	if err := patcher.Patch(context.Background(), "nvt", "local-seed", "../codex.json", credential); err == nil {
		t.Fatal("cross-slot destination accepted")
	}

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("claude", path); err != nil {
		t.Fatal(err)
	}
	if err := patcher.Patch(context.Background(), "nvt", "local-seed", "codex.json", credential); err == nil {
		t.Fatal("symlink target accepted")
	}
}

func TestLocalFilePatcherRejectsUnsafeStagingDirectory(t *testing.T) {
	directory := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(directory, localStagingDirectory)); err != nil {
		t.Fatal(err)
	}
	if _, err := NewLocalFilePatcher(directory, "nvt", []Slot{{Name: "codex", SecretName: "seed", DataKey: "auth"}}); err == nil {
		t.Fatal("symlink staging directory accepted")
	}
}

func patchRESTClient(t *testing.T, handler http.Handler) rest.Interface {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	client, err := rest.RESTClientFor(
		&rest.Config{
			Host:    server.URL,
			APIPath: "/api",
			ContentConfig: rest.ContentConfig{
				GroupVersion:         &schema.GroupVersion{Version: "v1"},
				NegotiatedSerializer: scheme.Codecs.WithoutConversion(),
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestKubernetesPatcherUsesOneExactJSONPatchAndMetadataResponse(t *testing.T) {
	requests := 0
	client := patchRESTClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Method != http.MethodPatch || r.URL.Path != "/api/v1/namespaces/nvt/secrets/portal-seed" ||
			r.Header.Get("Content-Type") != "application/json-patch+json" {
			t.Errorf("unexpected request %s %s %s", r.Method, r.URL.Path, r.Header.Get("Content-Type"))
		}
		if !strings.Contains(r.Header.Get("Accept"), "PartialObjectMetadata") {
			t.Errorf("patch did not request metadata-only response")
		}
		var operations []struct {
			Op    string `json:"op"`
			Path  string `json:"path"`
			Value string `json:"value"`
		}
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
		if err := json.NewEncoder(w).
			Encode(map[string]any{"apiVersion": "meta.k8s.io/v1", "kind": "PartialObjectMetadata", "metadata": map[string]string{"name": testPortalSeed}}); err != nil {
			t.Error(err)
		}
	}))
	if err := (KubernetesSecretPatcher{Client: client}).Patch(
		context.Background(),
		"nvt",
		testPortalSeed,
		"nested~/key",
		[]byte("secret"),
	); err != nil {
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
		http.Error(
			w,
			`{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"NotFound","code":404}`,
			http.StatusNotFound,
		)
	}))
	if err := (KubernetesSecretPatcher{Client: client}).Patch(
		context.Background(),
		"nvt",
		"missing",
		"auth.json",
		[]byte("secret"),
	); err == nil {
		t.Fatal("missing pre-created Secret was accepted")
	}
	if requests != 1 {
		t.Fatalf("patcher performed %d API requests", requests)
	}
}
