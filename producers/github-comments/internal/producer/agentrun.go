//nolint:funlen // AgentRun rendering mirrors the CRD shape in one place for reviewability.
package producer

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	nvtv1alpha1 "github.com/mirkoSekulic/nvt-agent/operator/api/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

type AgentRunSubmitter struct {
	client     ctrlclient.Client
	httpClient *http.Client
	config     Config
}

type agentRunIdentity struct {
	Key  string
	Name string
}

func NewAgentRunSubmitter(k8sClient ctrlclient.Client, cfg Config) AgentRunSubmitter {
	return AgentRunSubmitter{client: k8sClient, httpClient: http.DefaultClient, config: cfg}
}

func NewAgentRunSubmitterWithHTTP(k8sClient ctrlclient.Client, httpClient *http.Client, cfg Config) AgentRunSubmitter {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return AgentRunSubmitter{client: k8sClient, httpClient: httpClient, config: cfg}
}

func NewKubernetesClient(kubeconfig string) (ctrlclient.Client, error) {
	s := runtime.NewScheme()
	if err := scheme.AddToScheme(s); err != nil {
		return nil, fmt.Errorf("add kubernetes scheme: %w", err)
	}
	if err := nvtv1alpha1.AddToScheme(s); err != nil {
		return nil, fmt.Errorf("add nvt scheme: %w", err)
	}
	var restConfig *rest.Config
	var err error
	if kubeconfig != "" {
		restConfig, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
	} else {
		restConfig, err = rest.InClusterConfig()
		if err != nil {
			loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
			restConfig, err = clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
				loadingRules,
				&clientcmd.ConfigOverrides{},
			).ClientConfig()
		}
	}
	if err != nil {
		return nil, fmt.Errorf("load kubernetes config: %w", err)
	}
	client, err := ctrlclient.New(restConfig, ctrlclient.Options{Scheme: s})
	if err != nil {
		return nil, fmt.Errorf("create kubernetes client: %w", err)
	}
	return client, nil
}

func (s AgentRunSubmitter) Submit(
	ctx context.Context,
	repo Repository,
	issue GitHubIssue,
	comments []GitHubIssueComment,
	commandComment GitHubIssueComment,
	command Command,
) (bool, string, error) {
	identity := s.agentRunIdentity(repo, issue, commandComment)
	if s.submissionMode() == SubmissionModeScheduleAdmission {
		return s.submitScheduleAdmission(ctx, repo, issue, comments, commandComment, command, identity)
	}
	return s.submitDirect(ctx, repo, issue, comments, commandComment, command, identity)
}

var ErrSubmissionDeferred = errors.New("submission deferred")

func (s AgentRunSubmitter) submitDirect(
	ctx context.Context,
	repo Repository,
	issue GitHubIssue,
	comments []GitHubIssueComment,
	commandComment GitHubIssueComment,
	command Command,
	identity agentRunIdentity,
) (bool, string, error) {
	existing, err := s.hasExistingIdempotencyKey(ctx, identity.Key)
	if err != nil {
		return false, "", err
	}
	if existing {
		return false, identity.Key, nil
	}
	run, err := s.buildAgentRun(repo, issue, comments, commandComment, command, identity)
	if err != nil {
		return false, "", err
	}
	if err := s.client.Create(ctx, run); err != nil {
		if apierrors.IsAlreadyExists(err) {
			return false, identity.Key, nil
		}
		return false, "", fmt.Errorf("create AgentRun: %w", err)
	}
	return true, identity.Key, nil
}

const githubPrincipalIssuer = "https://github.com"
const maxScheduleAdmissionResponseBytes = 64 * 1024

type legacyScheduleAdmissionRequest struct {
	Work     scheduleAdmissionWork `json:"work"`
	AgentRun nvtv1alpha1.AgentRun  `json:"agentRun"`
}

// scheduleAdmissionRequest retains the legacy test and migration contract name.
type scheduleAdmissionRequest = legacyScheduleAdmissionRequest

type scheduleAdmissionWork struct {
	ID    string `json:"id"`
	Title string `json:"title,omitempty"`
	URL   string `json:"url,omitempty"`
}

type profiledScheduleAdmissionRequest struct {
	Workflow string                         `json:"workflow,omitempty"`
	Work     profiledScheduleAdmissionWork  `json:"work"`
	Input    profiledScheduleAdmissionInput `json:"input"`
}

type profiledScheduleAdmissionWork struct {
	ID         string                     `json:"id"`
	Title      string                     `json:"title"`
	URL        string                     `json:"url"`
	Repository string                     `json:"repository"`
	Principal  profiledAdmissionPrincipal `json:"principal"`
}

type profiledAdmissionPrincipal struct {
	Issuer      string `json:"issuer"`
	Subject     string `json:"subject"`
	DisplayName string `json:"displayName"`
}

type profiledScheduleAdmissionInput struct {
	Prompt string `json:"prompt"`
}

type scheduleAdmissionResponse struct {
	Scheduled bool                       `json:"scheduled"`
	Reason    string                     `json:"reason,omitempty"`
	AgentRun  *scheduleAdmissionAgentRun `json:"agentRun,omitempty"`
}

type scheduleAdmissionAgentRun struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

func (s AgentRunSubmitter) submitScheduleAdmission(
	ctx context.Context,
	repo Repository,
	issue GitHubIssue,
	comments []GitHubIssueComment,
	commandComment GitHubIssueComment,
	command Command,
	identity agentRunIdentity,
) (bool, string, error) {
	payload, token, err := s.scheduleAdmissionPayload(repo, issue, comments, commandComment, command, identity)
	if err != nil {
		return false, "", err
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return false, "", fmt.Errorf("marshal schedule admission: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, s.scheduleAdmissionURL(), bytes.NewReader(body))
	if err != nil {
		return false, "", fmt.Errorf("build schedule admission request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}

	response, err := s.httpClient.Do(request)
	if err != nil {
		return false, "", fmt.Errorf("post schedule admission: %w", err)
	}
	defer response.Body.Close()

	responseBody, err := io.ReadAll(io.LimitReader(response.Body, maxScheduleAdmissionResponseBytes+1))
	if err != nil {
		return false, "", errors.New("read schedule admission response")
	}
	switch response.StatusCode {
	case http.StatusCreated:
		decoded, decodeErr := decodeScheduleAdmissionContract(responseBody)
		if decodeErr != nil {
			return false, "", decodeErr
		}
		if !decoded.Scheduled {
			return false, "", fmt.Errorf("schedule admission returned 201 without scheduled=true")
		}
		return true, identity.Key, nil
	case http.StatusAccepted:
		decoded, decodeErr := decodeScheduleAdmissionContract(responseBody)
		if decodeErr != nil {
			return false, "", decodeErr
		}
		if decoded.Scheduled {
			return true, identity.Key, nil
		}
		switch decoded.Reason {
		case "duplicate-work":
			return false, identity.Key, nil
		case "schedule-suspended":
			return false, identity.Key, ErrSubmissionDeferred
		default:
			return false, "", fmt.Errorf("schedule admission returned 202 with unsupported reason %q", decoded.Reason)
		}
	case http.StatusTooManyRequests:
		decoded, decodeErr := decodeScheduleAdmissionContract(responseBody)
		if decodeErr != nil {
			return false, "", decodeErr
		}
		if decoded.Reason == "max-parallelism-reached" {
			return false, identity.Key, ErrSubmissionDeferred
		}
		return false, "", fmt.Errorf("schedule admission rejected with 429 reason %q", decoded.Reason)
	default:
		reason := safeScheduleAdmissionReason(responseBody)
		if reason != "" {
			return false, "", fmt.Errorf("schedule admission failed with HTTP %d reason %q", response.StatusCode, reason)
		}
		return false, "", fmt.Errorf("schedule admission failed with HTTP %d", response.StatusCode)
	}
}

func decodeScheduleAdmissionContract(body []byte) (scheduleAdmissionResponse, error) {
	if len(body) > maxScheduleAdmissionResponseBytes {
		return scheduleAdmissionResponse{}, errors.New("schedule admission response exceeds size limit")
	}
	var decoded scheduleAdmissionResponse
	if err := json.Unmarshal(body, &decoded); err != nil {
		return scheduleAdmissionResponse{}, errors.New("decode schedule admission response")
	}
	return decoded, nil
}

func safeScheduleAdmissionReason(body []byte) string {
	if len(body) > maxScheduleAdmissionResponseBytes {
		return ""
	}
	var decoded scheduleAdmissionResponse
	if json.Unmarshal(body, &decoded) != nil {
		return ""
	}
	switch decoded.Reason {
	case "duplicate-work",
		"schedule-suspended",
		"max-parallelism-reached",
		"profile-selection-denied",
		"workflow-selection-denied",
		"invalid-execution-profile-configuration",
		"response-encode-failed":
		return decoded.Reason
	default:
		return ""
	}
}

func (s AgentRunSubmitter) scheduleAdmissionPayload(
	repo Repository,
	issue GitHubIssue,
	comments []GitHubIssueComment,
	commandComment GitHubIssueComment,
	command Command,
	identity agentRunIdentity,
) (any, string, error) {
	if s.admissionMode() == AdmissionModeProfiled {
		if commandComment.User.ID <= 0 {
			return nil, "", errors.New("profiled admission requires a valid GitHub author identity")
		}
		token, err := readAdmissionToken(s.config.Submission.AdmissionTokenFile)
		if err != nil {
			return nil, "", err
		}
		return profiledScheduleAdmissionRequest{
			Workflow: s.config.Submission.Workflow,
			Work: profiledScheduleAdmissionWork{
				ID:         identity.Key,
				Title:      issue.Title,
				URL:        sourceURLForCommand(issue, commandComment),
				Repository: repo.Owner + "/" + repo.Name,
				Principal: profiledAdmissionPrincipal{
					Issuer:      githubPrincipalIssuer,
					Subject:     strconv.FormatInt(commandComment.User.ID, 10),
					DisplayName: commandComment.User.Login,
				},
			},
			Input: profiledScheduleAdmissionInput{
				Prompt: buildPrompt(repo, issue, comments, commandComment, command),
			},
		}, token, nil
	}

	run, err := s.buildAgentRun(repo, issue, comments, commandComment, command, identity)
	if err != nil {
		return nil, "", err
	}
	return legacyScheduleAdmissionRequest{
		Work: scheduleAdmissionWork{
			ID:    identity.Key,
			Title: issue.Title,
			URL:   sourceURLForCommand(issue, commandComment),
		},
		AgentRun: *run,
	}, "", nil
}

func readAdmissionToken(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", errors.New("read profiled admission token")
	}
	token := strings.TrimSpace(string(data))
	parts := strings.Split(token, ".")
	if len(parts) != 3 || strings.ContainsAny(token, " \t\r\n") {
		return "", errors.New("invalid profiled admission token")
	}
	decoded := make([][]byte, len(parts))
	for index, part := range parts {
		if part == "" {
			return "", errors.New("invalid profiled admission token")
		}
		value, decodeErr := base64.RawURLEncoding.DecodeString(part)
		if decodeErr != nil || len(value) == 0 {
			return "", errors.New("invalid profiled admission token")
		}
		decoded[index] = value
	}
	for _, claims := range decoded[:2] {
		var object map[string]any
		if json.Unmarshal(claims, &object) != nil || object == nil {
			return "", errors.New("invalid profiled admission token")
		}
	}
	return token, nil
}

func (s AgentRunSubmitter) hasExistingIdempotencyKey(ctx context.Context, key string) (bool, error) {
	var runs nvtv1alpha1.AgentRunList
	if err := s.client.List(ctx, &runs, ctrlclient.InNamespace(s.config.AgentRun.Namespace)); err != nil {
		return false, fmt.Errorf("list AgentRuns for idempotency: %w", err)
	}
	for i := range runs.Items {
		if runs.Items[i].Annotations[IdempotencyAnnotation] == key {
			return true, nil
		}
	}
	return false, nil
}

func (s AgentRunSubmitter) buildAgentRun(
	repo Repository,
	issue GitHubIssue,
	comments []GitHubIssueComment,
	commandComment GitHubIssueComment,
	command Command,
	identity agentRunIdentity,
) (*nvtv1alpha1.AgentRun, error) {
	workspace, err := configuredAgentRunWorkspace(s.config.AgentRun)
	if err != nil {
		return nil, err
	}
	agentConfigMap, err := AgentConfigWithEventWebhook(
		s.config.AgentConfig,
		s.operatorCallbackURL(s.config.AgentRun.Namespace, identity.Name),
	)
	if err != nil {
		return nil, err
	}
	agentConfig, err := AgentConfigJSON(agentConfigMap)
	if err != nil {
		return nil, err
	}
	prompt := buildPrompt(repo, issue, comments, commandComment, command)
	run := &nvtv1alpha1.AgentRun{
		TypeMeta: metav1.TypeMeta{
			APIVersion: nvtv1alpha1.GroupVersion.String(),
			Kind:       "AgentRun",
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: s.config.AgentRun.Namespace,
			Name:      identity.Name,
			Annotations: map[string]string{
				IdempotencyAnnotation: identity.Key,
				RequestedByAnnotation: commandComment.User.Login,
			},
		},
		Spec: nvtv1alpha1.AgentRunSpec{
			Runtime: nvtv1alpha1.AgentRunRuntime{
				Type:     s.config.AgentRun.RuntimeType,
				Autonomy: s.config.AgentRun.RuntimeAutonomy,
			},
			Image:     s.config.AgentRun.RuntimeImage,
			Workspace: workspace,
			Prompt:    &nvtv1alpha1.AgentRunPrompt{Text: prompt},
			Agent:     nvtv1alpha1.AgentRunAgent{Config: agentConfig},
			Lifecycle: &nvtv1alpha1.AgentRunLifecycle{
				CompleteOn: []string{
					"plugin.github.pr.merged",
					"plugin.github.pr.closed",
				},
				FailOn: []string{},
			},
		},
	}
	if ttl := agentRunTTL(s.config.AgentRun.TTL); ttl != nil {
		run.Spec.TTL = ttl
	}
	if s.config.AgentRun.RuntimeClassName != "" {
		run.Spec.RuntimeClassName = &s.config.AgentRun.RuntimeClassName
	}
	if s.config.AgentRun.RuntimeAuthSecret != "" {
		run.Spec.RuntimeAuth = &nvtv1alpha1.AgentRunRuntimeAuth{
			SecretName: s.config.AgentRun.RuntimeAuthSecret,
			MountPath:  s.config.AgentRun.RuntimeAuthMountPath,
		}
	}
	if len(s.config.AgentRun.BrokerGrants) > 0 {
		run.Spec.Broker = &nvtv1alpha1.AgentRunBroker{}
		for _, grant := range s.config.AgentRun.BrokerGrants {
			run.Spec.Broker.Grants = append(run.Spec.Broker.Grants, nvtv1alpha1.AgentRunBrokerGrant{
				Provider:     grant.Provider,
				Repositories: grant.Repositories,
			})
		}
	}
	return run, nil
}

func buildPrompt(
	repo Repository,
	issue GitHubIssue,
	comments []GitHubIssueComment,
	commandComment GitHubIssueComment,
	command Command,
) string {
	issueComments := make([]IssueComment, 0, len(comments))
	for _, comment := range comments {
		issueComments = append(issueComments, IssueComment{
			ID:        comment.ID,
			Body:      comment.Body,
			UserLogin: comment.User.Login,
			HTMLURL:   comment.HTMLURL,
			CreatedAt: formatOptionalTime(comment.CreatedAt),
			UpdatedAt: formatOptionalTime(comment.UpdatedAt),
		})
	}
	return BuildPrompt(PromptInput{
		Owner: repo.Owner,
		Repo:  repo.Name,
		Issue: Issue{
			Number:  issue.Number,
			URL:     issue.URL,
			Title:   issue.Title,
			Body:    issue.Body,
			HTMLURL: issue.HTMLURL,
		},
		Comments: issueComments,
		CommandComment: IssueComment{
			ID:        commandComment.ID,
			Body:      commandComment.Body,
			UserLogin: commandComment.User.Login,
			HTMLURL:   commandComment.HTMLURL,
			CreatedAt: formatOptionalTime(commandComment.CreatedAt),
			UpdatedAt: formatOptionalTime(commandComment.UpdatedAt),
		},
		Sender:                 commandComment.User.Login,
		AdditionalInstructions: command.AdditionalInstructions,
	})
}

func (s AgentRunSubmitter) submissionMode() SubmissionMode {
	if s.config.Submission.Mode == "" {
		return SubmissionModeDirect
	}
	return s.config.Submission.Mode
}

func (s AgentRunSubmitter) admissionMode() AdmissionMode {
	if s.config.Submission.AdmissionMode == "" {
		return AdmissionModeLegacy
	}
	return s.config.Submission.AdmissionMode
}

func (s AgentRunSubmitter) scheduleAdmissionURL() string {
	baseURL := s.config.Submission.AdmissionBaseURL
	if baseURL == "" {
		baseURL = defaultOperatorCallbackBaseURL
	}
	namespace := s.config.Submission.ScheduleNamespace
	if namespace == "" {
		namespace = s.config.AgentRun.Namespace
	}
	scheduleName := s.config.Submission.ScheduleName
	if scheduleName == "" {
		scheduleName = defaultScheduleName
	}
	return strings.TrimRight(baseURL, "/") +
		"/v1/schedules/" + url.PathEscape(namespace) + "/" + url.PathEscape(scheduleName) + "/admissions"
}

func sourceURLForCommand(issue GitHubIssue, commandComment GitHubIssueComment) string {
	if issue.HTMLURL != "" {
		return issue.HTMLURL
	}
	return commandComment.HTMLURL
}

func agentRunTTL(config AgentRunTTL) *nvtv1alpha1.AgentRunTTL {
	if config.ActiveDeadlineSeconds == nil &&
		config.CompletedTTLSeconds == nil &&
		config.FailedTTLSeconds == nil &&
		config.RunRetentionSeconds == nil {
		return nil
	}
	return &nvtv1alpha1.AgentRunTTL{
		ActiveDeadlineSeconds: cloneInt64(config.ActiveDeadlineSeconds),
		CompletedTTLSeconds:   cloneInt64(config.CompletedTTLSeconds),
		FailedTTLSeconds:      cloneInt64(config.FailedTTLSeconds),
		RunRetentionSeconds:   cloneInt64(config.RunRetentionSeconds),
	}
}

func cloneInt64(value *int64) *int64 {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func (s AgentRunSubmitter) agentRunIdentity(repo Repository, issue GitHubIssue, commandComment GitHubIssueComment) agentRunIdentity {
	switch s.idempotencyScope() {
	case IdempotencyScopeComment:
		return agentRunIdentity{
			Key:  CommentIdempotencyKey(repo.Owner, repo.Name, issue.Number, commandComment.ID),
			Name: CommentAgentRunName(repo.Owner, repo.Name, issue.Number, commandComment.ID),
		}
	default:
		return agentRunIdentity{
			Key:  IdempotencyKey(repo.Owner, repo.Name, issue.Number),
			Name: AgentRunName(repo.Owner, repo.Name, issue.Number),
		}
	}
}

func (s AgentRunSubmitter) idempotencyScope() IdempotencyScope {
	if s.config.Idempotency.Scope == "" {
		return IdempotencyScopeIssue
	}
	return s.config.Idempotency.Scope
}

func (s AgentRunSubmitter) operatorCallbackURL(namespace, name string) string {
	baseURL := s.config.OperatorCallbackBaseURL
	if baseURL == "" {
		baseURL = defaultOperatorCallbackBaseURL
	}
	return strings.TrimRight(baseURL, "/") +
		"/v1/agentruns/" + namespace + "/" + name + "/events"
}

func AgentConfigWithEventWebhook(config map[string]any, callbackURL string) (map[string]any, error) {
	copied := map[string]any{}
	if config != nil {
		data, err := json.Marshal(config)
		if err != nil {
			return nil, fmt.Errorf("marshal agent config for event-webhook injection: %w", err)
		}
		if err := json.Unmarshal(data, &copied); err != nil {
			return nil, fmt.Errorf("copy agent config for event-webhook injection: %w", err)
		}
	}

	rawPlugins, ok := copied["plugins"]
	if !ok {
		copied["plugins"] = []any{eventWebhookPlugin(callbackURL)}
		return copied, nil
	}
	plugins, ok := rawPlugins.([]any)
	if !ok {
		return nil, fmt.Errorf("agentConfig.plugins must be a list")
	}
	for _, rawPlugin := range plugins {
		plugin, ok := rawPlugin.(map[string]any)
		if !ok {
			continue
		}
		name, _ := plugin["name"].(string)
		if name == "event-webhook" {
			return copied, nil
		}
	}
	copied["plugins"] = append(plugins, eventWebhookPlugin(callbackURL))
	return copied, nil
}

func eventWebhookPlugin(callbackURL string) map[string]any {
	return map[string]any{
		"name":    "event-webhook",
		"source":  "builtin",
		"when":    "after-agent",
		"restart": "always",
		"config": map[string]any{
			"url": callbackURL,
			"auth": map[string]any{
				"type": "bearer-env",
				"env":  "NVT_OPERATOR_CALLBACK_TOKEN",
			},
			"filters": []any{
				"plugin.github.pr.",
			},
			"delivery": map[string]any{
				"retry": map[string]any{
					"backoff-seconds": float64(1),
				},
			},
		},
	}
}

func (s AgentRunSubmitter) Get(ctx context.Context, namespace, name string) (*nvtv1alpha1.AgentRun, error) {
	var run nvtv1alpha1.AgentRun
	if err := s.client.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, &run); err != nil {
		return nil, fmt.Errorf("get AgentRun: %w", err)
	}
	return &run, nil
}

func formatOptionalTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}
