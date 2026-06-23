package main

import (
	"context"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/mirkoSekulic/nvt-agent/producers/github-comments/internal/producer"
)

func main() {
	configPath := flag.String("config", "", "Path to producer config YAML")
	kubeconfig := flag.String("kubeconfig", "", "Path to kubeconfig; defaults to in-cluster config then local kubeconfig")
	flag.Parse()
	if *configPath == "" {
		*configPath = os.Getenv("NVT_GITHUB_COMMENTS_CONFIG")
	}
	if *configPath == "" {
		slog.Error("config path is required via --config or NVT_GITHUB_COMMENTS_CONFIG")
		os.Exit(2)
	}
	cfg, err := producer.LoadConfig(*configPath)
	if err != nil {
		slog.Error("load config failed", "error", err)
		os.Exit(1)
	}
	httpClient := http.DefaultClient
	tokenSource, err := producer.NewInstallationTokenSource(cfg.GitHubApp, cfg.GitHubAPIBaseURL, httpClient)
	if err != nil {
		slog.Error("create GitHub App token source failed", "error", err)
		os.Exit(1)
	}
	githubClient := producer.NewGitHubAPIClient(cfg.GitHubAPIBaseURL, cfg.UserAgent, tokenSource, httpClient)
	k8sClient, err := producer.NewKubernetesClient(*kubeconfig)
	if err != nil {
		slog.Error("create Kubernetes client failed", "error", err)
		os.Exit(1)
	}
	submitter := producer.NewAgentRunSubmitter(k8sClient, cfg)
	poller := producer.NewPoller(cfg, githubClient, submitter, slog.Default())
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := poller.Run(ctx); err != nil && ctx.Err() == nil {
		slog.Error("producer stopped", "error", err)
		os.Exit(1)
	}
}
