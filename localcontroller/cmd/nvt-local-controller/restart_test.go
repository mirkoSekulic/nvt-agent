package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/mirkoSekulic/nvt-agent/localcontroller/internal/controller"
)

// Exercise the actual main dispatch used by docker exec. This must never open
// the controller database, bootstrap workstations, or validate deployment config.
func TestRestartClientEntrypoint(t *testing.T) {
	if os.Getenv("NVT_RESTART_CLIENT_TEST") == "1" {
		os.Args = []string{"nvt-local-controller", "restart-workstation", "personal", "5s"}
		main()
		return
	}
	const bearer = "fixture-admin-bearer-not-a-real-secret-000000"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/runs/personal/restart" || r.Header.Get("Authorization") != "Bearer "+bearer {
			t.Error("incorrect administrator client request")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var input struct {
			RequestID string `json:"request_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			t.Error(err)
		}
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(controller.Run{APIVersion: controller.APIVersion, RunID: "personal", State: controller.StateRunning, RestartID: input.RequestID, RestartPhase: "complete"})
	}))
	defer server.Close()
	endpoint, _ := url.Parse(server.URL)
	tokenPath := filepath.Join(t.TempDir(), "admin")
	if err := os.WriteFile(tokenPath, []byte(bearer), 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestRestartClientEntrypoint$")
	command.Env = []string{
		"NVT_RESTART_CLIENT_TEST=1", "NVT_LOCAL_CONTROLLER_BIND=" + endpoint.Host,
		"NVT_LOCAL_CONTROLLER_ADMIN_TOKEN_FILE=" + tokenPath,
		"NVT_LOCAL_CONTROLLER_MAX_ACTIVE_RUNS=not-a-valid-controller-configuration",
		"NVT_LOCAL_CONTROLLER_STATE=" + filepath.Join(t.TempDir(), "must-not-create.sqlite3"),
	}
	output, err := command.CombinedOutput()
	if err != nil || string(output) != "ready\n" {
		t.Fatalf("client entrypoint output=%q error=%v", output, err)
	}
}
