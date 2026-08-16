package producer

import (
	"bytes"
	"context"
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
	inspector := DockerImageInspector{Runner: fixtureDockerRunner{}}
	resolved, err := inspector.InspectImage(context.Background(), image)
	if err != nil || !validExternalImageConfiguration(resolved) {
		t.Fatalf("inspect fixture image: resolved=%#v err=%v", resolved, err)
	}
	volumeImage := "nvt-local-external-producer-volume-fixture:test"
	volumeBuild := exec.Command("docker", "build", "-t", volumeImage, "-")
	volumeBuild.Stdin = strings.NewReader("FROM " + image + "\nVOLUME /producer-state\n")
	if output, err := volumeBuild.CombinedOutput(); err != nil {
		t.Fatalf("build volume fixture image: %v\n%s", err, output)
	}
	volumeResolved, err := inspector.InspectImage(context.Background(), volumeImage)
	if err != nil || validExternalImageConfiguration(volumeResolved) || strings.Join(volumeResolved.DeclaredVolumes, ",") != "/producer-state" {
		t.Fatalf("image-declared volume was not rejected: resolved=%#v err=%v", volumeResolved, err)
	}

	port := listener.Addr().(*net.TCPAddr).Port
	create := exec.Command("docker", "create", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
		"--user", fmt.Sprintf("%d:%d", fixtureUID, fixtureGID),
		"--pids-limit=128", "--memory=256m", "--cpus=1", "--add-host=host.docker.internal:host-gateway",
		"-e", "NVT_PRODUCER_CONFIG_FILE=/contract/config.json",
		"-e", fmt.Sprintf("NVT_SCHEDULE_ADMISSION_URL=http://host.docker.internal:%d/admit", port),
		"-e", "NVT_SCHEDULE_ADMISSION_TOKEN_FILE=/contract/token",
		"-v", directory+":/contract:ro", resolved.ID)
	created, err := create.CombinedOutput()
	containerID := strings.TrimSpace(string(created))
	if err != nil || containerID == "" {
		t.Fatalf("create fixture container: %v output=%q", err, created)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", containerID).Run() })
	inspectMounts := exec.Command("docker", "inspect", "--format", "{{json .Mounts}}", containerID)
	mountOutput, err := inspectMounts.Output()
	if err != nil {
		t.Fatalf("inspect fixture mounts: %v", err)
	}
	var mounts []struct {
		Type        string
		Destination string
		RW          bool
	}
	if err := json.Unmarshal(mountOutput, &mounts); err != nil || len(mounts) != 1 || mounts[0].Type != "bind" || mounts[0].Destination != "/contract" || mounts[0].RW {
		t.Fatalf("fixture container mount set = %#v err=%v", mounts, err)
	}
	start := exec.Command("docker", "start", "--attach", containerID)
	output, err := start.CombinedOutput()
	if err != nil || string(bytes.TrimSpace(output)) != "authorized=1 denied=6" {
		t.Fatalf("fixture run: %v output=%q", err, output)
	}
	if bytes.Contains(output, []byte(token)) || bytes.Contains(output, []byte("fixture-private-value")) {
		t.Fatal("fixture disclosed private input")
	}
}

type fixtureDockerRunner struct{}

func (fixtureDockerRunner) Run(ctx context.Context, stdin io.Reader, arguments ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, "docker", arguments...)
	command.Stdin = stdin
	return command.CombinedOutput()
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
