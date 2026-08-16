package producer

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestExternalProducerFixtureImageHasExactAdmissionAuthority(t *testing.T) {
	if os.Getenv("NVT_LOCAL_PRODUCER_FIXTURE_IMAGE_TEST") != "1" {
		t.Skip("set NVT_LOCAL_PRODUCER_FIXTURE_IMAGE_TEST=1 to run the Docker fixture")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatal("docker is required for the fixture-image test")
	}
	token := "fixture-admission-token-0123456789abcdef"
	listener, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: fixtureAdmissionHandler(t, token)}
	serverErrors := make(chan error, 1)
	go func() { serverErrors <- server.Serve(listener) }()
	t.Cleanup(func() {
		_ = server.Close()
		<-serverErrors
	})

	directory, err := os.MkdirTemp(".", ".fixture-")
	if err != nil {
		t.Fatal(err)
	}
	directory, err = filepath.Abs(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	if err := os.Chmod(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(directory, "config.json")
	tokenPath := filepath.Join(directory, "token")
	config := externalConfiguration{
		APIVersion: "nvt.dev/local-producer/v1", Name: "fixture", Workflow: "exact-workflow",
		PublicConfig: map[string]any{"mode": "fixture"}, SecretFiles: map[string]string{"hook": "/contract/hook"},
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, encoded, 0o444); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tokenPath, []byte(token), 0o444); err != nil {
		t.Fatal(err)
	}
	hookPath := filepath.Join(directory, "hook")
	if err := os.WriteFile(hookPath, []byte("fixture-private-value"), 0o444); err != nil {
		t.Fatal(err)
	}
	fixtureUID, fixtureGID := os.Geteuid(), os.Getegid()
	if fixtureUID == 0 {
		fixtureUID, fixtureGID = 65532, 65532
		for _, path := range []string{directory, configPath, tokenPath, hookPath} {
			if err := os.Chown(path, fixtureUID, fixtureGID); err != nil {
				t.Fatal(err)
			}
		}
	}

	image := "nvt-local-external-producer-fixture:test"
	build := exec.Command("docker", "build", "-f", "producer/testfixture/Dockerfile", "-t", image, ".")
	build.Dir = ".."
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build fixture image: %v\n%s", err, output)
	}
	inspect := exec.Command("docker", "image", "inspect", "--format", "{{.Id}}", image)
	imageID, err := inspect.Output()
	if err != nil || !strings.HasPrefix(strings.TrimSpace(string(imageID)), "sha256:") {
		t.Fatalf("inspect fixture image: %v %q", err, imageID)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	run := exec.Command("docker", "run", "--rm", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
		"--user", fmt.Sprintf("%d:%d", fixtureUID, fixtureGID),
		"--pids-limit=128", "--memory=256m", "--cpus=1", "--add-host=host.docker.internal:host-gateway",
		"-e", "NVT_PRODUCER_CONFIG_FILE=/contract/config.json",
		"-e", fmt.Sprintf("NVT_SCHEDULE_ADMISSION_URL=http://host.docker.internal:%d/admit", port),
		"-e", "NVT_SCHEDULE_ADMISSION_TOKEN_FILE=/contract/token",
		"-v", directory+":/contract:ro", strings.TrimSpace(string(imageID)))
	output, err := run.CombinedOutput()
	if err != nil || string(bytes.TrimSpace(output)) != "authorized=1 denied=6" {
		t.Fatalf("fixture run: %v output=%q", err, output)
	}
	if bytes.Contains(output, []byte(token)) || bytes.Contains(output, []byte("fixture-private-value")) {
		t.Fatal("fixture disclosed private input")
	}
}

func fixtureAdmissionHandler(t *testing.T, token string) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/admit" || request.Header.Get("Authorization") != "Bearer "+token {
			http.Error(response, "denied", http.StatusUnauthorized)
			return
		}
		body, err := io.ReadAll(io.LimitReader(request.Body, 64<<10))
		if err != nil {
			http.Error(response, "denied", http.StatusBadRequest)
			return
		}
		var envelope struct {
			Workflow string `json:"workflow"`
			Work     struct {
				ID, Title, URL, Repository string
				Principal                  struct{ Issuer, Subject, DisplayName string }
			} `json:"work"`
			Input struct{ Prompt string } `json:"input"`
		}
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&envelope) != nil || envelope.Workflow != "exact-workflow" || envelope.Work.ID == "" ||
			envelope.Work.Principal.Issuer != "https://fixture.example" || envelope.Input.Prompt == "" {
			http.Error(response, "denied", http.StatusBadRequest)
			return
		}
		response.WriteHeader(http.StatusCreated)
	})
}
