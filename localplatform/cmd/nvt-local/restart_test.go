package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"
)

type restartCommand func(context.Context, io.Reader, ...string) ([]byte, error)

func (f restartCommand) Run(ctx context.Context, input io.Reader, args ...string) ([]byte, error) {
	return f(ctx, input, args...)
}

func TestRestartSyntax(t *testing.T) {
	name, timeout, err := parseRestartArgs([]string{"personal"})
	if err != nil || name != "personal" || timeout != 2*time.Minute {
		t.Fatalf("default=%s %s %v", name, timeout, err)
	}
	_, timeout, err = parseRestartArgs([]string{"personal", "--timeout", "45s"})
	if err != nil || timeout != 45*time.Second {
		t.Fatalf("timeout=%s %v", timeout, err)
	}
	for _, args := range [][]string{nil, {"../personal"}, {"personal", "other"}, {"personal", "--timeout", "0s"}, {"personal", "--timeout", "16m"}, {"personal", "--apply"}, {"personal", "--timeout"}} {
		if _, _, err := parseRestartArgs(args); err == nil {
			t.Fatalf("accepted %q", args)
		}
	}
}

func TestRestartUsesOnlyExactOwnedControllerClient(t *testing.T) {
	for _, result := range []string{"ready", "timeout", "failed", "restart-conflict", "not-authorized", "not-found", "gone", "not-administrator-workstation", "restart-backend-rejected", "unavailable", "RAW-CREDENTIAL-ERROR-CANARY"} {
		t.Run(result, func(t *testing.T) {
			// An invalid manifest path proves this command never prepares/applies it.
			t.Setenv("NVT_LOCAL_MANIFEST", "/nonexistent/do-not-read.yaml")
			id := strings.Repeat("a", 64)
			calls := [][]string{}
			application := app{project: "fixture"}
			application.docker = restartCommand(func(_ context.Context, input io.Reader, args ...string) ([]byte, error) {
				if input != nil {
					t.Fatal("unexpected secret/config stdin")
				}
				calls = append(calls, append([]string{}, args...))
				switch len(calls) {
				case 1:
					return []byte(id + "\n"), nil
				case 2:
					return json.Marshal(map[string]string{"nvt.dev/local-platform-owner": "fixture", "nvt.dev/local-platform-version": "1", "com.docker.compose.project": "fixture", "com.docker.compose.service": "local-controller"})
				case 3:
					if result == "ready" {
						return []byte(result + "\n"), nil
					}
					return []byte(result + "\n"), errors.New("raw-error-not-for-display")
				default:
					t.Fatal("unexpected command")
					return nil, nil
				}
			})
			err := application.restart(context.Background(), "personal", 45*time.Second)
			if (err == nil) != (result == "ready") {
				t.Fatalf("result=%s err=%v", result, err)
			}
			if err != nil && (strings.Contains(err.Error(), "CANARY") || strings.Contains(err.Error(), "raw-error")) {
				t.Fatal("raw command output escaped")
			}
			want := []string{"exec", id, "/nvt-local-controller", "restart-workstation", "personal", "45s"}
			if len(calls) != 3 || !reflect.DeepEqual(calls[2], want) {
				t.Fatalf("calls=%v", calls)
			}
			if calls[0][0] != "ps" || calls[1][0] != "container" {
				t.Fatalf("unexpected lifecycle mutation: %v", calls)
			}
		})
	}
}

func TestRestartRejectsAmbiguousControllerWithoutExec(t *testing.T) {
	for _, mode := range []string{"absent", "multiple", "wrong-owner", "wrong-service"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			application := app{project: "fixture", docker: restartCommand(func(_ context.Context, _ io.Reader, args ...string) ([]byte, error) {
				calls++
				if args[0] == "exec" {
					t.Fatal("executed ambiguous controller")
				}
				if calls == 1 {
					if mode == "absent" {
						return nil, nil
					}
					if mode == "multiple" {
						return []byte(strings.Repeat("a", 64) + "\n" + strings.Repeat("b", 64)), nil
					}
					return []byte(strings.Repeat("a", 64)), nil
				}
				labels := map[string]string{"nvt.dev/local-platform-owner": "fixture", "nvt.dev/local-platform-version": "1", "com.docker.compose.project": "fixture", "com.docker.compose.service": "local-controller"}
				if mode == "wrong-owner" {
					labels["nvt.dev/local-platform-owner"] = "other"
				} else {
					labels["com.docker.compose.service"] = "gateway"
				}
				return json.Marshal(labels)
			})}
			if err := application.restart(context.Background(), "personal", time.Minute); err == nil {
				t.Fatal("accepted ambiguous controller")
			}
		})
	}
}
