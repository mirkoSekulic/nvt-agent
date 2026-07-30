package host_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/mirkoSekulic/nvt-agent/operator/executiondriver"
	driverhost "github.com/mirkoSekulic/nvt-agent/operator/executiondriver/host"
)

const internalFailureCanary = "EXECUTION-DRIVER-INTERNAL-SECRET-CANARY"

var fakeDriverBinary string

func TestMain(m *testing.M) {
	temporaryDirectory, err := os.MkdirTemp("", "nvt-local-execution-driver-host-*")
	if err != nil {
		fmt.Fprintln(os.Stderr, "create local execution-driver host build directory")
		os.Exit(1)
	}
	fakeDriverBinary = filepath.Join(temporaryDirectory, "fake-execution-driver")
	command := exec.Command("go", "build", "-trimpath", "-o", fakeDriverBinary, "../testdata/fake-driver")
	if output, buildErr := command.CombinedOutput(); buildErr != nil {
		fmt.Fprintf(os.Stderr, "build fake execution driver: %v\n%s", buildErr, output)
		_ = os.RemoveAll(temporaryDirectory)
		os.Exit(1)
	}
	exitCode := m.Run()
	if err := os.RemoveAll(temporaryDirectory); err != nil && exitCode == 0 {
		fmt.Fprintln(os.Stderr, "remove local execution-driver host build directory")
		exitCode = 1
	}
	os.Exit(exitCode)
}

func TestLocalExecutableLifecycle(t *testing.T) {
	client, _, _ := newFakeHost(t, "", nil)
	desired := testDesired(t, "run-lifecycle", map[string]any{"ready": true})

	running, err := client.Reconcile(testContext(t), desired)
	if err != nil || !running.Ready || running.Phase != executiondriver.PhaseRunning {
		t.Fatalf("reconcile status=%#v error=%v", running, err)
	}
	observed, err := client.Observe(testContext(t), desired.ExecutionID)
	if err != nil || observed.ExternalResourceID != running.ExternalResourceID || !observed.Ready {
		t.Fatalf("observe status=%#v error=%v", observed, err)
	}

	var deleted executiondriver.Status
	for attempt := 0; attempt < 4; attempt++ {
		deleted, err = client.Delete(testContext(t), desired.ExecutionID)
		if err != nil {
			t.Fatalf("delete attempt %d: %v", attempt, err)
		}
		if deleted.Phase == executiondriver.PhaseDeleted {
			break
		}
	}
	if deleted.Phase != executiondriver.PhaseDeleted {
		t.Fatalf("delete did not converge: %#v", deleted)
	}
	if err := client.Shutdown(testContext(t)); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	if _, err := client.Observe(testContext(t), desired.ExecutionID); !errors.Is(err, driverhost.ErrClosed) {
		t.Fatalf("observe after shutdown error=%v", err)
	}
}

func TestLocalExecutableValidatesCommandAndConfiguration(t *testing.T) {
	nonExecutable := filepath.Join(t.TempDir(), "driver")
	if err := os.WriteFile(nonExecutable, []byte("not executable"), 0o600); err != nil {
		t.Fatalf("write non-executable fixture: %v", err)
	}
	base := validConfig(fakeDriverBinary)
	tests := map[string]driverhost.LocalExecutableConfig{
		"relative command": func() driverhost.LocalExecutableConfig {
			value := base
			value.ExecutablePath = "fake-driver"
			return value
		}(),
		"missing command": func() driverhost.LocalExecutableConfig {
			value := base
			value.ExecutablePath = filepath.Join(t.TempDir(), "missing")
			return value
		}(),
		"non-executable command": func() driverhost.LocalExecutableConfig {
			value := base
			value.ExecutablePath = nonExecutable
			return value
		}(),
		"invalid environment name": func() driverhost.LocalExecutableConfig {
			value := base
			value.PassEnv = []string{"INVALID-NAME"}
			return value
		}(),
		"duplicate environment name": func() driverhost.LocalExecutableConfig {
			value := base
			value.PassEnv = []string{"PATH", "PATH"}
			return value
		}(),
		"missing operation deadline": func() driverhost.LocalExecutableConfig {
			value := base
			value.OperationTimeout = 0
			return value
		}(),
	}
	for name, config := range tests {
		t.Run(name, func(t *testing.T) {
			client, err := driverhost.NewLocalExecutable(testContext(t), config)
			if err == nil {
				_ = client.Shutdown(testContext(t))
				t.Fatal("invalid configuration unexpectedly accepted")
			}
		})
	}
}

func TestLocalExecutableUsesOnlyAllowlistedEnvironment(t *testing.T) {
	t.Setenv("NVT_FAKE_DRIVER_SECRET", internalFailureCanary)
	t.Setenv("NVT_FAKE_DRIVER_ALLOWED", "allowed")
	client, _, _ := newFakeHost(t, "clean-environment", func(config *driverhost.LocalExecutableConfig) {
		config.PassEnv = append(config.PassEnv, "NVT_FAKE_DRIVER_ALLOWED")
	})
	if err := client.Shutdown(testContext(t)); err != nil {
		t.Fatalf("clean-environment shutdown: %v", err)
	}
}

func TestLocalExecutablePassesOnlyTheDeterministicEnrollmentSocket(t *testing.T) {
	client, _, _ := newFakeHost(t, "enrollment-environment", func(config *driverhost.LocalExecutableConfig) {
		config.EnrollmentSocket = "/tmp/nvt-test-enrollment.sock"
	})
	if err := client.Shutdown(testContext(t)); err != nil {
		t.Fatalf("enrollment environment shutdown: %v", err)
	}
}

func TestLocalExecutableStartsCommandWithoutShell(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "shell-expanded")
	client, _, _ := newFakeHost(t, "", func(config *driverhost.LocalExecutableConfig) {
		config.Args = []string{"$(touch " + marker + ")"}
	})
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("command argument was interpreted by a shell: %v", err)
	}
	if err := client.Shutdown(testContext(t)); err != nil {
		t.Fatalf("shutdown direct command: %v", err)
	}
}

func TestLocalExecutableRejectsIncompatibleInitializeAndUnsolicitedOutput(t *testing.T) {
	for _, mode := range []string{
		"incompatible-initialize",
		"missing-capability-initialize",
		"unsolicited-initialize",
	} {
		t.Run(mode, func(t *testing.T) {
			_, config, pidFile := configureFake(t, mode, func(config *driverhost.LocalExecutableConfig) {
				config.PassEnv = append(config.PassEnv, "NVT_FAKE_DRIVER_PID_FILE")
			})
			_, err := driverhost.NewLocalExecutable(testContext(t), config)
			if err == nil || !errors.Is(err, driverhost.ErrProtocol) {
				t.Fatalf("initialize error=%v", err)
			}
			pid := waitForPID(t, pidFile)
			requireProcessGone(t, pid)
		})
	}
}

func TestLocalExecutableRejectsMalformedDriverOutput(t *testing.T) {
	for _, mode := range []string{
		"malformed-reconcile",
		"oversized-reconcile",
		"mismatched-reconcile",
		"duplicate-reconcile",
		"invalid-utf8-reconcile",
	} {
		t.Run(mode, func(t *testing.T) {
			client, _, _ := newFakeHost(t, mode, nil)
			_, err := client.Reconcile(testContext(t), testDesired(t, "run-"+mode, map[string]any{}))
			if err == nil || !errors.Is(err, driverhost.ErrProtocol) {
				t.Fatalf("malformed output error=%v", err)
			}
			if strings.Contains(err.Error(), internalFailureCanary) {
				t.Fatalf("driver output escaped into error: %v", err)
			}
			if _, err := client.Observe(testContext(t), "run-after-failure"); !errors.Is(err, driverhost.ErrRestartBackoff) {
				t.Fatalf("call during restart backoff error=%v", err)
			}
		})
	}
}

func TestLocalExecutableTerminatesOnIdleUnsolicitedOutput(t *testing.T) {
	stateDirectory := t.TempDir()
	pidFile := filepath.Join(t.TempDir(), "driver.pid")
	markerFile := filepath.Join(t.TempDir(), "unsolicited")
	t.Setenv("NVT_FAKE_DRIVER_STATE_DIR", stateDirectory)
	t.Setenv("NVT_FAKE_DRIVER_MODE", "idle-unsolicited")
	t.Setenv("NVT_FAKE_DRIVER_PID_FILE", pidFile)
	t.Setenv("NVT_FAKE_DRIVER_UNSOLICITED_FILE", markerFile)
	config := validConfig(fakeDriverBinary)
	config.PassEnv = []string{
		"NVT_FAKE_DRIVER_MODE",
		"NVT_FAKE_DRIVER_PID_FILE",
		"NVT_FAKE_DRIVER_STATE_DIR",
		"NVT_FAKE_DRIVER_UNSOLICITED_FILE",
	}
	client, err := driverhost.NewLocalExecutable(testContext(t), config)
	if err != nil {
		t.Fatalf("start idle-unsolicited host: %v", err)
	}
	t.Cleanup(func() {
		context, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = client.Shutdown(context)
	})
	pid := waitForPID(t, pidFile)
	waitForPath(t, markerFile)
	requireProcessGone(t, pid)
	waitForHostNotReady(t, client)
	if _, err := client.Reconcile(testContext(t), testDesired(t, "run-unsolicited", map[string]any{})); !errors.Is(err, driverhost.ErrUnavailable) {
		t.Fatalf("call after unsolicited output error=%v", err)
	}
	stateFiles, err := filepath.Glob(filepath.Join(stateDirectory, "*.json"))
	if err != nil || len(stateFiles) != 0 {
		t.Fatalf("unsolicited process reached provider state: files=%v error=%v", stateFiles, err)
	}
}

func TestLocalExecutableTimeoutTerminatesAndReaps(t *testing.T) {
	client, _, pidFile := newFakeHost(t, "", func(config *driverhost.LocalExecutableConfig) {
		config.PassEnv = append(config.PassEnv, "NVT_FAKE_DRIVER_PID_FILE")
		config.OperationTimeout = 30 * time.Millisecond
		config.TerminationGrace = 20 * time.Millisecond
	})
	pid := waitForPID(t, pidFile)
	_, err := client.Reconcile(context.Background(), testDesired(t, "run-timeout", map[string]any{
		"delay_milliseconds": 5_000,
	}))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout error=%v", err)
	}
	requireProcessGone(t, pid)
}

func TestLocalExecutableInitializeTimeoutTerminatesAndReaps(t *testing.T) {
	_, config, pidFile := configureFake(t, "hang-initialize", func(config *driverhost.LocalExecutableConfig) {
		config.PassEnv = append(config.PassEnv, "NVT_FAKE_DRIVER_PID_FILE")
		config.InitializeTimeout = 30 * time.Millisecond
		config.TerminationGrace = 20 * time.Millisecond
	})
	_, err := driverhost.NewLocalExecutable(context.Background(), config)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("initialize timeout error=%v", err)
	}
	pid := waitForPID(t, pidFile)
	requireProcessGone(t, pid)
}

func TestLocalExecutableCrashBackoffAndExplicitRestart(t *testing.T) {
	client, _, pidFile := newFakeHost(t, "crash-once-reconcile", func(config *driverhost.LocalExecutableConfig) {
		config.PassEnv = append(config.PassEnv, "NVT_FAKE_DRIVER_PID_FILE")
		config.RestartBackoff = 30 * time.Millisecond
	})
	firstPID := waitForPID(t, pidFile)
	desired := testDesired(t, "run-crash", map[string]any{"ready": true})
	_, err := client.Reconcile(testContext(t), desired)
	if err == nil || !errors.Is(err, driverhost.ErrTransport) {
		t.Fatalf("crash error=%v", err)
	}
	requireProcessGone(t, firstPID)
	if _, err := client.Observe(testContext(t), desired.ExecutionID); !errors.Is(err, driverhost.ErrRestartBackoff) {
		t.Fatalf("immediate post-crash error=%v", err)
	}
	time.Sleep(40 * time.Millisecond)
	observed, err := client.Observe(testContext(t), desired.ExecutionID)
	if err != nil || observed.Phase != executiondriver.PhaseDeleted {
		t.Fatalf("explicit restart observation=%#v error=%v", observed, err)
	}
	secondPID := waitForDifferentPID(t, pidFile, firstPID)
	if secondPID == firstPID {
		t.Fatalf("driver did not restart: PID=%d", secondPID)
	}
}

func TestLocalExecutableShutdownKillsAndReapsHungProcess(t *testing.T) {
	client, _, pidFile := newFakeHost(t, "hang-after-shutdown-ignore-term", func(config *driverhost.LocalExecutableConfig) {
		config.PassEnv = append(config.PassEnv, "NVT_FAKE_DRIVER_PID_FILE")
		config.ShutdownTimeout = 40 * time.Millisecond
		config.TerminationGrace = 20 * time.Millisecond
	})
	pid := waitForPID(t, pidFile)
	err := client.Shutdown(context.Background())
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("hung shutdown error=%v", err)
	}
	requireProcessGone(t, pid)
	if err := client.Shutdown(testContext(t)); err != nil {
		t.Fatalf("repeated shutdown: %v", err)
	}
}

func TestLocalExecutableShutdownStopsActiveOperation(t *testing.T) {
	stateDirectory := t.TempDir()
	activeFile := filepath.Join(t.TempDir(), "driver.active")
	pidFile := filepath.Join(t.TempDir(), "driver.pid")
	t.Setenv("NVT_FAKE_DRIVER_STATE_DIR", stateDirectory)
	t.Setenv("NVT_FAKE_DRIVER_MODE", "")
	t.Setenv("NVT_FAKE_DRIVER_ACTIVE_FILE", activeFile)
	t.Setenv("NVT_FAKE_DRIVER_PID_FILE", pidFile)
	config := validConfig(fakeDriverBinary)
	config.PassEnv = []string{
		"NVT_FAKE_DRIVER_ACTIVE_FILE",
		"NVT_FAKE_DRIVER_MODE",
		"NVT_FAKE_DRIVER_PID_FILE",
		"NVT_FAKE_DRIVER_STATE_DIR",
	}
	config.OperationTimeout = 5 * time.Second
	config.ShutdownTimeout = 2 * time.Second
	config.TerminationGrace = 30 * time.Millisecond
	client, err := driverhost.NewLocalExecutable(testContext(t), config)
	if err != nil {
		t.Fatalf("start active-shutdown host: %v", err)
	}
	t.Cleanup(func() {
		context, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = client.Shutdown(context)
	})
	pid := waitForPID(t, pidFile)
	activeResult := make(chan error, 1)
	desired := testDesired(t, "run-active-shutdown", map[string]any{"delay_milliseconds": 5_000})
	go func() {
		_, err := client.Reconcile(context.Background(), desired)
		activeResult <- err
	}()
	waitForPath(t, activeFile)
	shutdownContext, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	if err := client.Shutdown(shutdownContext); err != nil {
		t.Fatalf("authoritative shutdown: %v", err)
	}
	requireProcessGone(t, pid)
	select {
	case err := <-activeResult:
		if err == nil || (!errors.Is(err, driverhost.ErrTransport) && !errors.Is(err, driverhost.ErrProtocol)) {
			t.Fatalf("active reconcile shutdown error=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("active reconcile outlived shutdown")
	}
	if _, err := client.Observe(testContext(t), desired.ExecutionID); !errors.Is(err, driverhost.ErrClosed) {
		t.Fatalf("call after authoritative shutdown error=%v", err)
	}
}

func TestLocalExecutableRequiresPassEnvironmentOnStartupAndRestart(t *testing.T) {
	t.Run("startup", func(t *testing.T) {
		stateDirectory := t.TempDir()
		pidFile := filepath.Join(t.TempDir(), "driver.pid")
		t.Setenv("NVT_FAKE_DRIVER_STATE_DIR", stateDirectory)
		t.Setenv("NVT_FAKE_DRIVER_MODE", "")
		t.Setenv("NVT_FAKE_DRIVER_PID_FILE", pidFile)
		unsetEnvironment(t, "NVT_FAKE_DRIVER_REQUIRED_MISSING")
		config := validConfig(fakeDriverBinary)
		config.PassEnv = []string{
			"NVT_FAKE_DRIVER_MODE",
			"NVT_FAKE_DRIVER_PID_FILE",
			"NVT_FAKE_DRIVER_REQUIRED_MISSING",
			"NVT_FAKE_DRIVER_STATE_DIR",
		}
		client, err := driverhost.NewLocalExecutable(testContext(t), config)
		if client != nil || !errors.Is(err, driverhost.ErrRequiredEnvironment) {
			t.Fatalf("missing startup environment client=%v error=%v", client, err)
		}
		if _, err := os.Stat(pidFile); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("driver started with missing required environment: %v", err)
		}
	})

	t.Run("restart", func(t *testing.T) {
		t.Setenv("NVT_FAKE_DRIVER_REQUIRED", "present")
		client, _, pidFile := newFakeHost(t, "crash-once-reconcile", func(config *driverhost.LocalExecutableConfig) {
			config.PassEnv = append(config.PassEnv, "NVT_FAKE_DRIVER_PID_FILE", "NVT_FAKE_DRIVER_REQUIRED")
			config.RestartBackoff = 30 * time.Millisecond
		})
		firstPID := waitForPID(t, pidFile)
		desired := testDesired(t, "run-missing-restart-env", map[string]any{})
		if _, err := client.Reconcile(testContext(t), desired); !errors.Is(err, driverhost.ErrTransport) {
			t.Fatalf("crash error=%v", err)
		}
		requireProcessGone(t, firstPID)
		if err := os.Unsetenv("NVT_FAKE_DRIVER_REQUIRED"); err != nil {
			t.Fatalf("unset restart environment: %v", err)
		}
		time.Sleep(40 * time.Millisecond)
		if _, err := client.Observe(testContext(t), desired.ExecutionID); !errors.Is(err, driverhost.ErrRequiredEnvironment) {
			t.Fatalf("missing restart environment error=%v", err)
		}
		if currentPID := waitForPID(t, pidFile); currentPID != firstPID {
			t.Fatalf("driver restarted without required environment: before=%d after=%d", firstPID, currentPID)
		}
	})
}

func TestLocalExecutableRejectsMalformedShutdownResult(t *testing.T) {
	for _, mode := range []string{"null-shutdown", "array-shutdown", "nonempty-shutdown"} {
		t.Run(mode, func(t *testing.T) {
			client, _, pidFile := newFakeHost(t, mode, func(config *driverhost.LocalExecutableConfig) {
				config.PassEnv = append(config.PassEnv, "NVT_FAKE_DRIVER_PID_FILE")
			})
			pid := waitForPID(t, pidFile)
			err := client.Shutdown(testContext(t))
			if !errors.Is(err, driverhost.ErrProtocol) {
				t.Fatalf("malformed shutdown result error=%v", err)
			}
			requireProcessGone(t, pid)
			if _, err := client.Observe(testContext(t), "run-after-malformed-shutdown"); !errors.Is(err, driverhost.ErrClosed) {
				t.Fatalf("call after malformed shutdown error=%v", err)
			}
		})
	}
}

func TestLocalExecutableSerializesConcurrentCalls(t *testing.T) {
	client, _, activeFile := newFakeHost(t, "", func(config *driverhost.LocalExecutableConfig) {
		config.PassEnv = append(config.PassEnv, "NVT_FAKE_DRIVER_ACTIVE_FILE")
		config.OperationTimeout = time.Second
	})
	desired := testDesired(t, "run-serialized", map[string]any{
		"delay_milliseconds": 150,
	})
	firstDone := make(chan error, 1)
	go func() {
		_, err := client.Reconcile(context.Background(), desired)
		firstDone <- err
	}()
	waitForPath(t, activeFile)
	waitingContext, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := client.Observe(waitingContext, "run-serialized"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("concurrent waiting call error=%v", err)
	}
	if err := <-firstDone; err != nil {
		t.Fatalf("active serialized call: %v", err)
	}
	if _, err := client.Observe(testContext(t), "run-serialized"); err != nil {
		t.Fatalf("host unusable after waiting caller cancellation: %v", err)
	}
}

func TestLocalExecutableDoesNotExposeStderr(t *testing.T) {
	client, _, _ := newFakeHost(t, "stderr-canary-reconcile", nil)
	_, err := client.Reconcile(testContext(t), testDesired(t, "run-stderr", map[string]any{}))
	if err == nil || !errors.Is(err, driverhost.ErrTransport) {
		t.Fatalf("stderr crash error=%v", err)
	}
	if strings.Contains(err.Error(), internalFailureCanary) {
		t.Fatalf("raw stderr escaped into host error: %v", err)
	}
}

func TestLocalExecutableReturnsSanitizedDriverErrorWithoutRestart(t *testing.T) {
	client, _, pidFile := newFakeHost(t, "", func(config *driverhost.LocalExecutableConfig) {
		config.PassEnv = append(config.PassEnv, "NVT_FAKE_DRIVER_PID_FILE")
	})
	pid := waitForPID(t, pidFile)
	desired := testDesired(t, "run-driver-error", map[string]any{"ready": true})
	if _, err := client.Reconcile(testContext(t), desired); err != nil {
		t.Fatalf("initial reconcile: %v", err)
	}
	divergent := testDesired(t, desired.ExecutionID, map[string]any{"ready": false})
	_, err := client.Reconcile(testContext(t), divergent)
	var driverError *driverhost.DriverError
	if !errors.As(err, &driverError) || driverError.Failure.Reason != "generation-conflict" || driverError.Failure.Retryable {
		t.Fatalf("driver error=%#v raw=%v", driverError, err)
	}
	if strings.Contains(err.Error(), internalFailureCanary) {
		t.Fatalf("driver error exposed secret material: %v", err)
	}
	if _, err := client.Observe(testContext(t), desired.ExecutionID); err != nil {
		t.Fatalf("valid driver error invalidated process: %v", err)
	}
	if currentPID := waitForPID(t, pidFile); currentPID != pid {
		t.Fatalf("valid driver error restarted process: before=%d after=%d", pid, currentPID)
	}
}

func newFakeHost(
	t *testing.T,
	mode string,
	mutate func(*driverhost.LocalExecutableConfig),
) (*driverhost.LocalExecutable, string, string) {
	t.Helper()
	stateDirectory, config, auxiliaryPath := configureFake(t, mode, mutate)
	client, err := driverhost.NewLocalExecutable(testContext(t), config)
	if err != nil {
		t.Fatalf("start local executable host: %v", err)
	}
	t.Cleanup(func() {
		context, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = client.Shutdown(context)
	})
	return client, stateDirectory, auxiliaryPath
}

func configureFake(
	t *testing.T,
	mode string,
	mutate func(*driverhost.LocalExecutableConfig),
) (string, driverhost.LocalExecutableConfig, string) {
	t.Helper()
	stateDirectory := t.TempDir()
	t.Setenv("NVT_FAKE_DRIVER_STATE_DIR", stateDirectory)
	t.Setenv("NVT_FAKE_DRIVER_MODE", mode)
	config := validConfig(fakeDriverBinary)
	config.PassEnv = []string{"NVT_FAKE_DRIVER_MODE", "NVT_FAKE_DRIVER_STATE_DIR"}
	auxiliaryPath := ""
	if mutate != nil {
		mutate(&config)
	}
	for _, name := range config.PassEnv {
		switch name {
		case "NVT_FAKE_DRIVER_PID_FILE":
			auxiliaryPath = filepath.Join(t.TempDir(), "driver.pid")
			t.Setenv(name, auxiliaryPath)
		case "NVT_FAKE_DRIVER_ACTIVE_FILE":
			auxiliaryPath = filepath.Join(t.TempDir(), "driver.active")
			t.Setenv(name, auxiliaryPath)
		}
	}
	return stateDirectory, config, auxiliaryPath
}

func validConfig(executable string) driverhost.LocalExecutableConfig {
	return driverhost.LocalExecutableConfig{
		DriverInstanceName: "fake-driver",
		ExecutablePath:     executable,
		InitializeTimeout:  time.Second,
		OperationTimeout:   500 * time.Millisecond,
		ShutdownTimeout:    500 * time.Millisecond,
		TerminationGrace:   25 * time.Millisecond,
		RestartBackoff:     100 * time.Millisecond,
	}
}

func testDesired(t *testing.T, executionID string, configuration any) executiondriver.DesiredExecution {
	t.Helper()
	encodedConfiguration, err := json.Marshal(configuration)
	if err != nil {
		t.Fatalf("marshal desired configuration: %v", err)
	}
	tuple := struct {
		WorkloadKind  executiondriver.WorkloadKind `json:"workload_kind"`
		ClassName     string                       `json:"class_name"`
		Configuration json.RawMessage              `json:"configuration"`
	}{
		WorkloadKind:  executiondriver.WorkloadKindVM,
		ClassName:     "fake-small",
		Configuration: encodedConfiguration,
	}
	encodedTuple, err := json.Marshal(tuple)
	if err != nil {
		t.Fatalf("marshal desired tuple: %v", err)
	}
	digest := sha256.Sum256(encodedTuple)
	return executiondriver.DesiredExecution{
		ExecutionID:        executionID,
		Generation:         1,
		DesiredFingerprint: fmt.Sprintf("sha256:%x", digest[:]),
		WorkloadKind:       tuple.WorkloadKind,
		ClassName:          tuple.ClassName,
		Configuration:      encodedConfiguration,
	}
}

func testContext(t *testing.T) context.Context {
	t.Helper()
	context, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(cancel)
	return context
}

func waitForPID(t *testing.T, path string) int {
	t.Helper()
	waitForPath(t, path)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read driver PID: %v", err)
	}
	pid, err := strconv.Atoi(string(data))
	if err != nil || pid <= 0 {
		t.Fatalf("driver PID=%q error=%v", data, err)
	}
	return pid
}

func waitForDifferentPID(t *testing.T, path string, previous int) int {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		pid := waitForPID(t, path)
		if pid != previous {
			return pid
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("driver PID did not change from %d", previous)
	return 0
}

func waitForPath(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("stat %s: %v", path, err)
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("path %s was not created", path)
}

func requireProcessGone(t *testing.T, pid int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		err := syscall.Kill(pid, 0)
		if errors.Is(err, syscall.ESRCH) {
			return
		}
		if err != nil {
			t.Fatalf("inspect driver process %d: %v", pid, err)
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("driver process %d was not reaped", pid)
}

func waitForHostNotReady(t *testing.T, client *driverhost.LocalExecutable) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if !client.Ready() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("execution driver host retained readiness after process exit")
}

func unsetEnvironment(t *testing.T, name string) {
	t.Helper()
	value, present := os.LookupEnv(name)
	if err := os.Unsetenv(name); err != nil {
		t.Fatalf("unset %s: %v", name, err)
	}
	t.Cleanup(func() {
		if present {
			_ = os.Setenv(name, value)
		} else {
			_ = os.Unsetenv(name)
		}
	})
}
