package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/mirkoSekulic/nvt-agent/producers/github-comments/internal/producer"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

var errConfigPathRequired = errors.New("config path is required via --config or NVT_GITHUB_COMMENTS_CONFIG")

func main() {
	if err := run(context.Background(), os.Args[1:]); err != nil {
		slog.Error("producer failed", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("github-comments", flag.ContinueOnError)
	configPath := flags.String("config", "", "Path to producer config YAML")
	kubeconfig := flags.String(
		"kubeconfig",
		"",
		"Path to kubeconfig; defaults to in-cluster config then local kubeconfig",
	)
	if err := flags.Parse(args); err != nil {
		return fmt.Errorf("parse flags: %w", err)
	}
	if *configPath == "" {
		*configPath = os.Getenv("NVT_GITHUB_COMMENTS_CONFIG")
	}
	if *configPath == "" {
		return errConfigPathRequired
	}
	cfg, err := producer.LoadConfig(*configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	httpClient := http.DefaultClient
	tokenSource, err := producer.NewInstallationTokenSource(cfg.GitHubApp, cfg.GitHubAPIBaseURL, httpClient)
	if err != nil {
		return fmt.Errorf("create GitHub App token source: %w", err)
	}
	githubClient := producer.NewGitHubAPIClient(cfg.GitHubAPIBaseURL, cfg.UserAgent, tokenSource, httpClient)
	var k8sClient ctrlclient.Client
	if cfg.Submission.Mode == producer.SubmissionModeDirect {
		k8sClient, err = producer.NewKubernetesClient(*kubeconfig)
		if err != nil {
			return fmt.Errorf("create Kubernetes client: %w", err)
		}
	}
	stateStore, err := producer.OpenSQLiteStateStore(ctx, cfg.State.SQLitePath)
	if err != nil {
		return fmt.Errorf("open SQLite state: %w", err)
	}
	submitter := producer.NewAgentRunSubmitterWithHTTP(k8sClient, httpClient, cfg)
	poller := producer.NewPoller(cfg, githubClient, submitter, stateStore, slog.Default())
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	if err := poller.Run(ctx); err != nil && ctx.Err() == nil {
		if closeErr := stateStore.Close(); closeErr != nil {
			return fmt.Errorf("producer stopped: %w; close SQLite state: %w", err, closeErr)
		}
		stop()
		return fmt.Errorf("producer stopped: %w", err)
	}
	if err := stateStore.Close(); err != nil {
		return fmt.Errorf("close SQLite state: %w", err)
	}
	stop()
	return nil
}
