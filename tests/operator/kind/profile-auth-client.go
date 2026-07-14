package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

var client = &http.Client{Timeout: 30 * time.Second}

func main() {
	url := mustEnv("ADMISSION_URL")
	switch mustEnv("MODE") {
	case "allowed":
		correct := readToken("/var/run/nvt-tokens/correct")
		wrongAudience := readToken("/var/run/nvt-tokens/wrong-audience")
		expectStatus(url, correct, map[string]any{
			"work":  map[string]any{"id": "profile-auth-accepted"},
			"input": map[string]any{"prompt": "fixture"},
		}, http.StatusCreated)
		expectStatus(url, wrongAudience, map[string]any{
			"work": map[string]any{"id": "profile-auth-wrong-audience"},
		}, http.StatusUnauthorized)
		expectStatus(url, correct, map[string]any{
			"work":     map[string]any{"id": "profile-auth-injected"},
			"input":    map[string]any{"prompt": "fixture"},
			"profile":  "attacker-profile",
			"provider": "attacker-provider",
			"broker":   map[string]any{"grants": []any{}},
			"agentRun": map[string]any{"spec": map[string]any{"egress": "direct"}},
		}, http.StatusBadRequest)
	case "unlisted":
		expectStatus(url, readToken("/var/run/nvt-token/token"), map[string]any{
			"work": map[string]any{"id": "profile-auth-unlisted"},
		}, http.StatusForbidden)
	default:
		fatalf("unsupported MODE")
	}
}

func expectStatus(url, token string, payload map[string]any, want int) {
	body, err := json.Marshal(payload)
	if err != nil {
		fatalf("encode request: %v", err)
	}
	request, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		fatalf("build request: %v", err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		fatalf("send request: %v", err)
	}
	defer response.Body.Close()
	responseBody, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
	if response.StatusCode != want {
		fatalf("admission status=%d want=%d body=%q", response.StatusCode, want, responseBody)
	}
}

func readToken(path string) string {
	value, err := os.ReadFile(path)
	if err != nil {
		fatalf("read projected token: %v", err)
	}
	token := strings.TrimSpace(string(value))
	if token == "" {
		fatalf("projected token is empty")
	}
	return token
}

func mustEnv(name string) string {
	value := os.Getenv(name)
	if value == "" {
		fatalf("%s is required", name)
	}
	return value
}

func fatalf(format string, values ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", values...)
	os.Exit(1)
}
