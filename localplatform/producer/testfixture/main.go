// Command external-producer-fixture exercises the public local OCI producer
// contract. It is intentionally provider-neutral and exists only for tests.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

type configuration struct {
	APIVersion   string            `json:"apiVersion"`
	Name         string            `json:"name"`
	Workflow     string            `json:"workflow"`
	PublicConfig map[string]any    `json:"publicConfig,omitempty"`
	SecretFiles  map[string]string `json:"secretFiles,omitempty"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "fixture producer failed:", err)
		os.Exit(1)
	}
	fmt.Println("authorized=1 denied=6")
}

func run() error {
	configPath := os.Getenv("NVT_PRODUCER_CONFIG_FILE")
	endpoint := os.Getenv("NVT_SCHEDULE_ADMISSION_URL")
	tokenPath := os.Getenv("NVT_SCHEDULE_ADMISSION_TOKEN_FILE")
	if configPath == "" || endpoint == "" || tokenPath == "" {
		return errors.New("contract unavailable")
	}
	configBytes, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}
	var config configuration
	decoder := json.NewDecoder(bytes.NewReader(configBytes))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&config) != nil || config.APIVersion != "nvt.dev/local-producer/v1" || config.Name == "" || config.Workflow == "" {
		return errors.New("invalid config")
	}
	token, err := os.ReadFile(tokenPath)
	if err != nil {
		return err
	}
	token = bytes.TrimSpace(token)
	if len(token) < 32 {
		return errors.New("invalid token")
	}
	base := map[string]any{
		"workflow": config.Workflow,
		"work": map[string]any{
			"id": "fixture/external/producer/work/0001", "title": "fixture", "url": "https://source.example/work/1",
			"repository": "presentation/metadata", "principal": map[string]any{"issuer": "https://fixture.example", "subject": "fixture-user", "displayName": "Fixture"},
		},
		"input": map[string]any{"prompt": "fixture admission"},
	}
	if status, err := submit(endpoint, token, base); err != nil || status != http.StatusCreated {
		return errors.New("authorized request denied")
	}
	variants := []map[string]any{}
	workflow := clone(base)
	workflow["workflow"] = "arbitrary-workflow"
	variants = append(variants, workflow)
	for _, field := range []string{"profile", "backend", "image", "credential", "repository"} {
		variant := clone(base)
		variant[field] = "arbitrary-" + field
		variants = append(variants, variant)
	}
	for _, variant := range variants {
		status, err := submit(endpoint, token, variant)
		if err != nil || status < 400 || status > 499 {
			return errors.New("authority override accepted")
		}
	}
	return nil
}

func submit(endpoint string, token []byte, body map[string]any) (int, error) {
	encoded, err := json.Marshal(body)
	if err != nil {
		return 0, err
	}
	request, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(encoded))
	if err != nil {
		return 0, err
	}
	request.Header.Set("Authorization", "Bearer "+string(token))
	request.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 5 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		return 0, err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	_ = response.Body.Close()
	return response.StatusCode, nil
}

func clone(value map[string]any) map[string]any {
	result := make(map[string]any, len(value)+1)
	for key, item := range value {
		result[key] = item
	}
	return result
}
