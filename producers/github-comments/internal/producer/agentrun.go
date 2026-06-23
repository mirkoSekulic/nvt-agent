package producer

import (
	"context"
	"fmt"
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
		return nil, err
	}
	if err := nvtv1alpha1.AddToScheme(s); err != nil {
		return nil, err
	}
	var restConfig *rest.Config
	var err error
	if kubeconfig != "" {
		restConfig, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
	} else {
		restConfig, err = rest.InClusterConfig()
		if err != nil {
			loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
			restConfig, err = clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, &clientcmd.ConfigOverrides{}).ClientConfig()
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

func (s AgentRunSubmitter) Submit(ctx context.Context, repo Repository, issue GitHubIssue, comments []GitHubIssueComment, commandComment GitHubIssueComment, command Command) (bool, string, error) {
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

func (s AgentRunSubmitter) buildAgentRun(repo Repository, issue GitHubIssue, comments []GitHubIssueComment, commandComment GitHubIssueComment, command Command, key string) (*nvtv1alpha1.AgentRun, error) {
	agentConfig, err := AgentConfigJSON(s.config.AgentConfig)
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
			Name:      AgentRunName(repo.Owner, repo.Name, issue.Number),
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

func (s AgentRunSubmitter) Get(ctx context.Context, namespace, name string) (*nvtv1alpha1.AgentRun, error) {
	var run nvtv1alpha1.AgentRun
	if err := s.client.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, &run); err != nil {
		return nil, err
	}
	return &run, nil
}

func formatOptionalTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}
