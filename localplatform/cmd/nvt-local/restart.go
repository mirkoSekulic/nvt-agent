package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"
)

func parseRestartArgs(args []string) (string, time.Duration, error) {
	if len(args) == 0 || !runIDPattern.MatchString(args[0]) {
		return "", 0, errors.New("usage: nvt-local restart <workstation-name> [--timeout 2m]")
	}
	flags := flag.NewFlagSet("restart", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	timeout := flags.Duration("timeout", 2*time.Minute, "readiness timeout")
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 || *timeout < time.Second || *timeout > 15*time.Minute {
		return "", 0, errors.New("restart accepts only --timeout with a duration from 1s to 15m")
	}
	return args[0], *timeout, nil
}

func (application app) restart(ctx context.Context, name string, timeout time.Duration) error {
	if !runIDPattern.MatchString(name) || timeout < time.Second || timeout > 15*time.Minute {
		return errors.New("invalid workstation restart request")
	}
	// Docker is only the trusted transport to the admin client. It does not
	// restart containers or apply configuration; all lifecycle work is via HTTP.
	output, err := application.docker.Run(ctx, nil, "ps", "-q", "--filter", "label=nvt.dev/local-platform-owner="+application.project, "--filter", "label=nvt.dev/local-platform-version=1", "--filter", "label=com.docker.compose.service=local-controller")
	ids := strings.Fields(string(output))
	if err != nil || len(ids) != 1 || !containerIDPattern.MatchString(ids[0]) {
		return errors.New("exactly one running local controller is required; no configuration was applied")
	}
	labels, err := application.containerLabels(ctx, ids[0])
	if err != nil || !application.validPlatformContainer(labels) || labels["com.docker.compose.service"] != "local-controller" {
		return errors.New("local controller ownership is ambiguous")
	}
	output, err = application.docker.Run(ctx, nil, "exec", ids[0], "/nvt-local-controller", "restart-workstation", name, timeout.String())
	result := strings.TrimSpace(string(output))
	clear(output)
	if ctx.Err() != nil {
		result = "timeout"
	}
	if err == nil && result == "ready" {
		return nil
	}
	switch result {
	case "restart-conflict":
		return errors.New("restart conflicts with preparation, stopping, a rollout, or a non-workstation target; wait for reconciliation to finish and verify the target")
	case "timeout":
		return errors.New("restart readiness timeout; accepted controller intent remains active, check status before retrying")
	case "not-administrator-workstation":
		return errors.New("restart target is not an administrator-owned persistent workstation")
	case "restart-backend-rejected":
		return errors.New("backend refused restart; verify retained data, exact resource ownership, and backend restart support (storage was not pruned)")
	case "not-found", "gone", "not-authorized", "authentication-unavailable", "capacity-exceeded", "failed", "superseded", "invalid-request", "unavailable":
		return fmt.Errorf("workstation restart: %s", result)
	default:
		return errors.New("workstation restart client unavailable; controller image must support restart (no configuration was applied)")
	}
}
