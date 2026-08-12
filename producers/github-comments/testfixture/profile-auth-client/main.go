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
		expectProducerAdmission(url, "/var/run/nvt-tokens/correct", 11, 424242, http.StatusCreated, "")
		expectProducerAdmission(url, "/var/run/nvt-tokens/wrong-audience", 12, 424242, http.StatusUnauthorized, "")
		expectInjectedRequestRejected(url, "/var/run/nvt-tokens/correct")
	case "unlisted":
		expectProducerAdmission(url, "/var/run/nvt-token/token", 13, 424242, http.StatusForbidden, "")
	case "dynamic-isolation":
		// The producer is authenticated and issuer-authorized, but this exact
		// second immutable subject owns no broker account. Admission must not
		// resolve or reuse the first principal's dynamic provider.
		expectProducerAdmission(
			url, "/var/run/nvt-tokens/correct", 14, 424243,
			http.StatusForbidden, "principal-not-enrolled",
		)
	default:
		fatalf("unsupported MODE")
	}
}

func expectProducerAdmission(
	url, tokenFile string,
	issueNumber int,
	userID int64,
	wantStatus int,
	wantReason string,
) {
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
	recorder := &statusRecordingTransport{next: http.DefaultTransport}
	httpClient := &http.Client{Transport: recorder, Timeout: 30 * time.Second}
	submitter := producer.NewAgentRunSubmitterWithHTTP(nil, httpClient, cfg)
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
			User:    producer.GitHubUser{ID: userID, Login: "octocat"},
		},
		producer.Command{Prefix: "/nvtagent", AdditionalInstructions: "verify profile auth"},
	)
	if recorder.status != wantStatus {
		fatalf("profiled producer admission status=%d want=%d", recorder.status, wantStatus)
	}
	if wantReason != "" {
		var denial struct {
			Scheduled bool   `json:"scheduled"`
			Reason    string `json:"reason"`
		}
		decoder := json.NewDecoder(bytes.NewReader(recorder.body))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&denial); err != nil || decoder.Decode(&struct{}{}) != io.EOF ||
			denial.Scheduled || denial.Reason != wantReason {
			fatalf("profiled producer denial did not prove exact account isolation")
		}
	}
	if wantStatus == http.StatusCreated && (err != nil || !created) {
		fatalf("profiled producer admission failed: created=%v err=%v", created, err)
	}
	if wantStatus != http.StatusCreated && err == nil {
		fatalf("profiled producer admission unexpectedly succeeded")
	}
}

type statusRecordingTransport struct {
	next   http.RoundTripper
	status int
	body   []byte
}

func (t *statusRecordingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := t.next.RoundTrip(request)
	if response != nil {
		t.status = response.StatusCode
		body, readErr := io.ReadAll(io.LimitReader(response.Body, 4097))
		_ = response.Body.Close()
		if readErr != nil || len(body) > 4096 {
			return nil, fmt.Errorf("bounded admission response unavailable")
		}
		t.body = bytes.Clone(body)
		response.Body = io.NopCloser(bytes.NewReader(body))
	}
	return response, err
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
