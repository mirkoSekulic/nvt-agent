// profile-auth-client is a test-only in-cluster client for the operator Kind suite.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/mirkoSekulic/nvt-agent/producers/github-comments/internal/producer"
)

var client = &http.Client{Timeout: 30 * time.Second}

func main() {
	url := mustEnv("ADMISSION_URL")
	switch mustEnv("MODE") {
	case "allowed":
		expectProducerAdmission(url, "/var/run/nvt-tokens/correct", 11, true)
		expectProducerAdmission(url, "/var/run/nvt-tokens/wrong-audience", 12, false)
		expectInjectedRequestRejected(url, "/var/run/nvt-tokens/correct")
	case "unlisted":
		expectProducerAdmission(url, "/var/run/nvt-token/token", 13, false)
	default:
		fatalf("unsupported MODE")
	}
}

func expectProducerAdmission(url, tokenFile string, issueNumber int, wantSuccess bool) {
	baseURL, namespace, schedule := splitAdmissionURL(url)
	cfg := producer.Config{
		Submission: producer.SubmissionConfig{
			Mode:               producer.SubmissionModeScheduleAdmission,
			AdmissionMode:      producer.AdmissionModeProfiled,
			AdmissionBaseURL:   baseURL,
			AdmissionTokenFile: tokenFile,
			ScheduleNamespace:  namespace,
			ScheduleName:       schedule,
		},
	}
	submitter := producer.NewAgentRunSubmitterWithHTTP(nil, client, cfg)
	created, _, err := submitter.Submit(
		context.Background(),
		producer.Repository{Owner: "fixture", Name: "profile-auth"},
		producer.GitHubIssue{
			Number:  issueNumber,
			Title:   "Profile authentication",
			HTMLURL: fmt.Sprintf("https://github.example/fixture/profile-auth/issues/%d", issueNumber),
		},
		nil,
		producer.GitHubIssueComment{
			ID:      int64(1000 + issueNumber),
			Body:    "/nvtagent verify profile auth",
			HTMLURL: fmt.Sprintf("https://github.example/fixture/profile-auth/issues/%d#issuecomment", issueNumber),
			User:    producer.GitHubUser{ID: 424242, Login: "octocat"},
		},
		producer.Command{Prefix: "/nvtagent", AdditionalInstructions: "verify profile auth"},
	)
	if wantSuccess && (err != nil || !created) {
		fatalf("profiled producer admission failed: created=%v err=%v", created, err)
	}
	if !wantSuccess && err == nil {
		fatalf("profiled producer admission unexpectedly succeeded")
	}
}

func splitAdmissionURL(value string) (string, string, string) {
	const marker = "/v1/schedules/"
	index := strings.Index(value, marker)
	if index <= 0 {
		fatalf("invalid admission URL")
	}
	parts := strings.Split(strings.TrimPrefix(value[index:], marker), "/")
	if len(parts) != 3 || parts[2] != "admissions" || parts[0] == "" || parts[1] == "" {
		fatalf("invalid admission URL path")
	}
	return value[:index], parts[0], parts[1]
}

func expectInjectedRequestRejected(url, tokenFile string) {
	token := readToken(tokenFile)
	payload := map[string]any{
		"work":     map[string]any{"id": "profile-auth-injected"},
		"input":    map[string]any{"prompt": "fixture"},
		"profile":  "attacker-profile",
		"provider": "attacker-provider",
		"broker":   map[string]any{"grants": []any{}},
		"agentRun": map[string]any{"spec": map[string]any{"egress": "direct"}},
	}
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
	if response.StatusCode != http.StatusBadRequest {
		fatalf("injected admission status=%d want=%d body=%q", response.StatusCode, http.StatusBadRequest, responseBody)
	}
}

func readToken(path string) string {
	value, err := os.ReadFile(path)
	if err != nil {
		fatalf("read projected token")
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
