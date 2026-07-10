package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/mirkoSekulic/nvt-agent/captured/internal/capture"
)

func env(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func main() {
	server := &capture.Server{
		ExplicitListen:    env("NVT_CAPTURED_EXPLICIT_LISTEN", capture.DefaultExplicitListen),
		TransparentListen: env("NVT_CAPTURED_TRANSPARENT_LISTEN", capture.DefaultTransparentListen),
		EgressProxy:       os.Getenv("NVT_EGRESS_PROXY"),
		Logger:            log.New(os.Stdout, "", 0),
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	if err := server.Run(ctx); err != nil {
		log.Printf("captured: %v", err)
		os.Exit(1)
	}
}
