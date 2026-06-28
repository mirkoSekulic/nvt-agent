//nolint:funlen // AgentRun rendering mirrors the CRD shape in one place for reviewability.
package producer

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	nvtv1alpha1 "github.com/mirkoSekulic/nvt-agent/operator/api/v1alpha1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

type AgentRunSubmitter struct {
	client ctrlclient.Client
	config Config
}

func NewAgentRunSubmitter(k8sClient ctrlclient.Client, cfg Config) AgentRunSubmitter {
	return AgentRunSubmitter{client: k8sClient, config: cfg}
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
	key := IdempotencyKey(repo.Owner, repo.Name, issue.Number)
	existing, err := s.hasExistingIdempotencyKey(ctx, key)
	if err != nil {
		return false, "", err
	}
	if existing {
		return false, key, nil
	}
	run, err := s.buildAgentRun(repo, issue, comments, commandComment, command, key)
	if err != nil {
		return false, "", err
	}
	if err := s.client.Create(ctx, run); err != nil {
		if errors.IsAlreadyExists(err) {
			return false, key, nil
		}
		return false, "", fmt.Errorf("create AgentRun: %w", err)
	}
	return true, key, nil
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
	key string,
) (*nvtv1alpha1.AgentRun, error) {
	runName := AgentRunName(repo.Owner, repo.Name, issue.Number)
	agentConfigMap, err := AgentConfigWithEventWebhook(
		s.config.AgentConfig,
		s.operatorCallbackURL(s.config.AgentRun.Namespace, runName),
	)
	if err != nil {
		return nil, err
	}
	agentConfig, err := AgentConfigJSON(agentConfigMap)
	if err != nil {
		return nil, err
	}
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
	prompt := BuildPrompt(PromptInput{
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
	run := &nvtv1alpha1.AgentRun{
		TypeMeta: metav1.TypeMeta{
			APIVersion: nvtv1alpha1.GroupVersion.String(),
			Kind:       "AgentRun",
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: s.config.AgentRun.Namespace,
			Name:      runName,
			Annotations: map[string]string{
				IdempotencyAnnotation: key,
			},
		},
		Spec: nvtv1alpha1.AgentRunSpec{
			Runtime: nvtv1alpha1.AgentRunRuntime{
				Type:     s.config.AgentRun.RuntimeType,
				Autonomy: s.config.AgentRun.RuntimeAutonomy,
			},
			Image: s.config.AgentRun.RuntimeImage,
			Workspace: nvtv1alpha1.AgentRunWorkspace{
				Mode: s.config.AgentRun.WorkspaceMode,
			},
			Prompt: &nvtv1alpha1.AgentRunPrompt{Text: prompt},
			Agent:  nvtv1alpha1.AgentRunAgent{Config: agentConfig},
			Lifecycle: &nvtv1alpha1.AgentRunLifecycle{
				CompleteOn: []string{
					"plugin.github.pr.merged",
					"plugin.github.pr.closed",
				},
				FailOn: []string{},
			},
		},
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
