package executiondriver_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mirkoSekulic/nvt-agent/operator/executiondriver"
)

const internalFailureCanary = "EXECUTION-DRIVER-INTERNAL-SECRET-CANARY"

var fakeDriverBinary string

func TestMain(m *testing.M) {
	temporaryDirectory, err := os.MkdirTemp("", "nvt-fake-execution-driver-*")
	if err != nil {
		fmt.Fprintln(os.Stderr, "create fake execution-driver build directory")
		os.Exit(1)
	}

	fakeDriverBinary = filepath.Join(temporaryDirectory, "fake-execution-driver")
	command := exec.Command("go", "build", "-trimpath", "-o", fakeDriverBinary, "./testdata/fake-driver")
	if output, buildErr := command.CombinedOutput(); buildErr != nil {
		fmt.Fprintf(os.Stderr, "build fake execution driver: %v\n%s", buildErr, output)
		_ = os.RemoveAll(temporaryDirectory)
		os.Exit(1)
	}
	exitCode := m.Run()
	if err := os.RemoveAll(temporaryDirectory); err != nil && exitCode == 0 {
		fmt.Fprintln(os.Stderr, "remove fake execution-driver build directory")
		exitCode = 1
	}
	os.Exit(exitCode)
}

type driverClient struct {
	command              *exec.Cmd
	stdin                *bufio.Writer
	stdout               *bufio.Scanner
	stderr               bytes.Buffer
	waitOnce             sync.Once
	waitErr              error
	shutdownAcknowledged bool
}

type rpcCallError struct {
	failure executiondriver.Failure
}

func (e *rpcCallError) Error() string {
	if e.failure.Message == "" {
		return "execution driver failed: " + e.failure.Reason
	}
	return "execution driver failed: " + e.failure.Reason + ": " + e.failure.Message
}

func requireRPCFailure(t *testing.T, err error, reason string, retryable bool) {
	t.Helper()
	var callError *rpcCallError
	if !errors.As(err, &callError) || callError.failure.Reason != reason || callError.failure.Retryable != retryable {
		t.Fatalf("RPC failure = %v, want reason=%q retryable=%t", err, reason, retryable)
	}
}

func startDriver(t *testing.T, stateDirectory, mode string) *driverClient {
	t.Helper()
	command := exec.Command(fakeDriverBinary)
	command.Env = append(os.Environ(),
		"NVT_FAKE_DRIVER_STATE_DIR="+stateDirectory,
		"NVT_FAKE_DRIVER_MODE="+mode,
	)
	stdinPipe, err := command.StdinPipe()
	if err != nil {
		t.Fatalf("fake driver stdin: %v", err)
	}
	stdoutPipe, err := command.StdoutPipe()
	if err != nil {
		t.Fatalf("fake driver stdout: %v", err)
	}
	client := &driverClient{command: command}
	client.stdin = bufio.NewWriter(stdinPipe)
	client.stdout = bufio.NewScanner(stdoutPipe)
	client.stdout.Buffer(make([]byte, 64<<10), executiondriver.MaxMessageBytes)
	command.Stderr = &client.stderr
	if err := command.Start(); err != nil {
		t.Fatalf("start fake driver: %v", err)
	}
	t.Cleanup(func() {
		client.stop()
	})
	return client
}

func (c *driverClient) wait() error {
	c.waitOnce.Do(func() {
		c.waitErr = c.command.Wait()
	})
	return c.waitErr
}

func (c *driverClient) stop() {
	if c.command.Process != nil && c.command.ProcessState == nil {
		_ = c.command.Process.Kill()
	}
	_ = c.wait()
}

func (c *driverClient) call(ctx context.Context, id string, method executiondriver.Method, params any, result any) error {
	request, err := executiondriver.MarshalRequest(id, method, params)
	if err != nil {
		return err
	}
	if _, err := c.stdin.Write(request); err != nil {
		return errors.New("execution driver request write failed")
	}
	if err := c.stdin.WriteByte('\n'); err != nil {
		return errors.New("execution driver request framing failed")
	}
	if err := c.stdin.Flush(); err != nil {
		return errors.New("execution driver request flush failed")
	}

	type scanResult struct {
		line []byte
		err  error
	}
	responseChannel := make(chan scanResult, 1)
	go func() {
		if !c.stdout.Scan() {
			err := c.stdout.Err()
			if err == nil {
				err = errors.New("driver output closed")
			}
			responseChannel <- scanResult{err: err}
			return
		}
		line := append([]byte(nil), c.stdout.Bytes()...)
		responseChannel <- scanResult{line: line}
	}()

	var scanned scanResult
	select {
	case scanned = <-responseChannel:
	case <-ctx.Done():
		c.stop()
		<-responseChannel
		return fmt.Errorf("execution driver request timed out: %w", ctx.Err())
	}
	if scanned.err != nil {
		return errors.New("execution driver response framing failed")
	}
	if len(scanned.line)+1 > executiondriver.MaxMessageBytes {
		return errors.New("execution driver response exceeds the message limit")
	}

	var response executiondriver.Response
	if executiondriver.DecodeStrictJSON(scanned.line, &response) != nil {
		return errors.New("execution driver returned a malformed response")
	}
	if response.JSONRPC != executiondriver.JSONRPCVersion || response.ID != id {
		return errors.New("execution driver returned an invalid response envelope")
	}
	if (response.Error == nil) == (len(response.Result) == 0) {
		return errors.New("execution driver response must contain exactly one result or error")
	}
	if response.Error != nil {
		if executiondriver.ValidateRPCError(*response.Error) != nil {
			return errors.New("execution driver returned an invalid sanitized error")
		}
		return &rpcCallError{failure: response.Error.Data}
	}
	if executiondriver.DecodeStrictJSON(response.Result, result) != nil {
		return errors.New("execution driver returned a malformed result")
	}
	return nil
}

func (c *driverClient) initialize(ctx context.Context) error {
	var result executiondriver.InitializeResult
	if err := c.call(ctx, "initialize", executiondriver.MethodInitialize, executiondriver.InitializeParams{
		ProtocolVersion:    executiondriver.ProtocolVersion,
		DriverInstanceName: "conformance-driver",
	}, &result); err != nil {
		return err
	}
	return executiondriver.ValidateInitializeResult(result)
}

func (c *driverClient) reconcile(ctx context.Context, id string, desired executiondriver.DesiredExecution) (executiondriver.Status, error) {
	var result executiondriver.Status
	err := c.call(ctx, id, executiondriver.MethodReconcile, executiondriver.ReconcileParams{Desired: desired}, &result)
	if err == nil {
		err = executiondriver.ValidateReconcileStatus(result)
	}
	return result, err
}

func (c *driverClient) observe(ctx context.Context, id, executionID string) (executiondriver.Status, error) {
	var result executiondriver.Status
	err := c.call(ctx, id, executiondriver.MethodObserve, executiondriver.ExecutionParams{ExecutionID: executionID}, &result)
	if err == nil {
		err = executiondriver.ValidateObserveStatus(result)
	}
	return result, err
}

func (c *driverClient) delete(ctx context.Context, id, executionID string) (executiondriver.Status, error) {
	var result executiondriver.Status
	err := c.call(ctx, id, executiondriver.MethodDelete, executiondriver.ExecutionParams{ExecutionID: executionID}, &result)
	if err == nil {
		err = executiondriver.ValidateDeleteStatus(result)
	}
	return result, err
}

func (c *driverClient) shutdown(ctx context.Context) error {
	var result executiondriver.ShutdownResult
	if err := c.call(ctx, "shutdown", executiondriver.MethodShutdown, struct{}{}, &result); err != nil {
		return err
	}
	c.shutdownAcknowledged = true
	waitChannel := make(chan error, 1)
	go func() {
		waitChannel <- c.wait()
	}()
	select {
	case err := <-waitChannel:
		return err
	case <-ctx.Done():
		if c.command.Process != nil {
			_ = c.command.Process.Kill()
		}
		<-waitChannel
		return fmt.Errorf("execution driver shutdown timed out: %w", ctx.Err())
	}
}

func TestFakeExecutionDriverLifecycleIdempotencyAndRestartRecovery(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stateDirectory := t.TempDir()
	executionID := "issuer.example/subject/run-123"

	first := startDriver(t, stateDirectory, "")
	if _, err := first.observe(ctx, "pre-initialize", executionID); err == nil || !strings.Contains(err.Error(), "not-initialized") {
		t.Fatalf("observe before initialize error = %v", err)
	}
	if err := first.initialize(ctx); err != nil {
		t.Fatalf("initialize first process: %v", err)
	}

	notReady := false
	desired := executiondriver.DesiredExecution{
		ExecutionID:   executionID,
		Generation:    1,
		WorkloadKind:  executiondriver.WorkloadKindVM,
		ClassName:     "fake-small",
		Configuration: mustJSON(t, map[string]any{"ready": notReady}),
	}
	provisioning, err := first.reconcile(ctx, "reconcile-1", desired)
	if err != nil {
		t.Fatalf("initial reconcile: %v", err)
	}
	if provisioning.Phase != executiondriver.PhaseProvisioning || provisioning.Ready || provisioning.ExternalResourceID == "" {
		t.Fatalf("initial reconcile status = %#v", provisioning)
	}

	desired.Configuration = mustJSON(t, map[string]any{"ready": true})
	desired.Generation = 2
	running, err := first.reconcile(ctx, "reconcile-2", desired)
	if err != nil {
		t.Fatalf("ready reconcile: %v", err)
	}
	repeated, err := first.reconcile(ctx, "reconcile-3", desired)
	if err != nil {
		t.Fatalf("repeated reconcile: %v", err)
	}
	if running.ExternalResourceID != repeated.ExternalResourceID || !repeated.Ready {
		t.Fatalf("repeated reconcile was not idempotent: first=%#v repeated=%#v", running, repeated)
	}
	stateFiles, err := filepath.Glob(filepath.Join(stateDirectory, "*.json"))
	if err != nil || len(stateFiles) != 1 {
		t.Fatalf("durable resource state files=%v error=%v", stateFiles, err)
	}
	var persisted struct {
		Generation         int64  `json:"generation"`
		DesiredFingerprint string `json:"desired_fingerprint"`
		CreateCount        int    `json:"create_count"`
	}
	stateData, err := os.ReadFile(stateFiles[0])
	if err != nil || json.Unmarshal(stateData, &persisted) != nil || persisted.CreateCount != 1 ||
		persisted.Generation != 2 || persisted.DesiredFingerprint == "" {
		t.Fatalf("idempotent reconcile durable state=%q error=%v", stateData, err)
	}
	stateInfo, err := os.Stat(stateFiles[0])
	if err != nil {
		t.Fatalf("stat durable state: %v", err)
	}
	if stateInfo.Mode().Perm() != 0o600 {
		t.Fatalf("durable state mode=%v, want 0600", stateInfo.Mode().Perm())
	}
	first.stop() // Model an ungraceful driver-process restart.

	second := startDriver(t, stateDirectory, "")
	if err := second.initialize(ctx); err != nil {
		t.Fatalf("initialize replacement process: %v", err)
	}
	recovered, err := second.observe(ctx, "observe-after-restart", executionID)
	if err != nil {
		t.Fatalf("observe after restart: %v", err)
	}
	if recovered.ExternalResourceID != running.ExternalResourceID || !recovered.Ready {
		t.Fatalf("restart did not recover durable state: before=%#v after=%#v", running, recovered)
	}

	lowerGeneration := desired
	lowerGeneration.Generation = 1
	lowerGeneration.Configuration = mustJSON(t, map[string]any{"ready": false})
	_, err = second.reconcile(ctx, "reconcile-stale-generation", lowerGeneration)
	requireRPCFailure(t, err, "stale-generation", false)
	divergentGeneration := desired
	divergentGeneration.Configuration = mustJSON(t, map[string]any{"ready": false})
	_, err = second.reconcile(ctx, "reconcile-divergent-generation", divergentGeneration)
	requireRPCFailure(t, err, "generation-conflict", false)
	idempotentAfterRestart, err := second.reconcile(ctx, "reconcile-after-restart", desired)
	if err != nil {
		t.Fatalf("idempotent reconcile after restart: %v", err)
	}
	if idempotentAfterRestart.ExternalResourceID != running.ExternalResourceID || idempotentAfterRestart.ObservedGeneration != 2 {
		t.Fatalf("generation rejection regressed durable state: %#v", idempotentAfterRestart)
	}
	unchanged, err := second.observe(ctx, "observe-after-generation-rejections", executionID)
	if err != nil || unchanged.ExternalResourceID != running.ExternalResourceID || unchanged.ObservedGeneration != 2 || !unchanged.Ready {
		t.Fatalf("generation rejection changed provider state: status=%#v error=%v", unchanged, err)
	}
	if err := second.shutdown(ctx); err != nil {
		t.Fatalf("bounded shutdown: %v", err)
	}

	third := startDriver(t, stateDirectory, "")
	if err := third.initialize(ctx); err != nil {
		t.Fatalf("initialize after shutdown: %v", err)
	}
	recoveredAfterShutdown, err := third.observe(ctx, "observe-after-shutdown", executionID)
	if err != nil || recoveredAfterShutdown.ExternalResourceID != running.ExternalResourceID {
		t.Fatalf("shutdown mutated provider state: status=%#v error=%v", recoveredAfterShutdown, err)
	}
	deleting, err := third.delete(ctx, "delete-start", executionID)
	if err != nil || deleting.Phase != executiondriver.PhaseDeleting {
		t.Fatalf("initial delete status=%#v error=%v", deleting, err)
	}
	observedDeleting, err := third.observe(ctx, "observe-deleting", executionID)
	if err != nil || observedDeleting.Phase != executiondriver.PhaseDeleting ||
		observedDeleting.ExternalResourceID != running.ExternalResourceID {
		t.Fatalf("observe while deleting status=%#v error=%v", observedDeleting, err)
	}
	third.stop() // Deletion progress must survive abrupt process replacement.

	fourth := startDriver(t, stateDirectory, "")
	if err := fourth.initialize(ctx); err != nil {
		t.Fatalf("initialize during deletion: %v", err)
	}
	recoveredDeleting, err := fourth.observe(ctx, "observe-deleting-after-restart", executionID)
	if err != nil || recoveredDeleting.Phase != executiondriver.PhaseDeleting {
		t.Fatalf("deletion recovery status=%#v error=%v", recoveredDeleting, err)
	}
	continuedDeleting, err := fourth.delete(ctx, "delete-continue", executionID)
	if err != nil || continuedDeleting.Phase != executiondriver.PhaseDeleting {
		t.Fatalf("continued delete status=%#v error=%v", continuedDeleting, err)
	}
	deleted, err := fourth.delete(ctx, "delete-complete", executionID)
	if err != nil || deleted.Phase != executiondriver.PhaseDeleted {
		t.Fatalf("completed delete status=%#v error=%v", deleted, err)
	}
	deletedAgain, err := fourth.delete(ctx, "delete-after-absence", executionID)
	if err != nil || deletedAgain.Phase != executiondriver.PhaseDeleted {
		t.Fatalf("repeated delete status=%#v error=%v", deletedAgain, err)
	}
	observedDeleted, err := fourth.observe(ctx, "observe-deleted", executionID)
	if err != nil || observedDeleted.Phase != executiondriver.PhaseDeleted {
		t.Fatalf("observe deleted status=%#v error=%v", observedDeleted, err)
	}
	if matches, err := filepath.Glob(filepath.Join(stateDirectory, "*.json")); err != nil || len(matches) != 0 {
		t.Fatalf("driver resource state was not cleaned up: matches=%v error=%v", matches, err)
	}
	if err := fourth.shutdown(ctx); err != nil {
		t.Fatalf("shutdown cleanup process: %v", err)
	}
}

func TestFakeExecutionDriverFailureIsSanitized(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client := startDriver(t, t.TempDir(), "")
	if err := client.initialize(ctx); err != nil {
		t.Fatalf("initialize: %v", err)
	}

	status, err := client.reconcile(ctx, "failure", executiondriver.DesiredExecution{
		ExecutionID:   "run-failure",
		Generation:    1,
		WorkloadKind:  executiondriver.WorkloadKindVM,
		ClassName:     "fake-small",
		Configuration: mustJSON(t, map[string]any{"fail": true}),
	})
	if err != nil {
		t.Fatalf("failed provider observation should be a valid status: %v", err)
	}
	encodedStatus := string(mustJSON(t, status))
	if status.Phase != executiondriver.PhaseFailed || status.Failure == nil ||
		status.Failure.Reason != "provider-operation-failed" {
		t.Fatalf("failure status = %#v", status)
	}
	if err := client.shutdown(ctx); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	if strings.Contains(encodedStatus, internalFailureCanary) || strings.Contains(client.stderr.String(), internalFailureCanary) {
		t.Fatalf("internal failure material escaped sanitization: status=%s stderr=%q", encodedStatus, client.stderr.String())
	}
}

func TestFakeExecutionDriverRejectsMalformedProtocol(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client := startDriver(t, t.TempDir(), "malformed-reconcile")
	if err := client.initialize(ctx); err != nil {
		t.Fatalf("initialize: %v", err)
	}

	_, err := client.reconcile(ctx, "malformed", executiondriver.DesiredExecution{
		ExecutionID:   "run-malformed",
		Generation:    1,
		WorkloadKind:  executiondriver.WorkloadKindVM,
		ClassName:     "fake-small",
		Configuration: mustJSON(t, map[string]any{}),
	})
	if err == nil || err.Error() != "execution driver returned a malformed response" {
		t.Fatalf("malformed response error = %v", err)
	}
	if strings.Contains(err.Error(), "{malformed") {
		t.Fatalf("malformed driver output escaped into error: %v", err)
	}
}

func TestFakeExecutionDriverRejectsDuplicateConfigurationKeys(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stateDirectory := t.TempDir()
	client := startDriver(t, stateDirectory, "")
	if err := client.initialize(ctx); err != nil {
		t.Fatalf("initialize: %v", err)
	}

	_, err := client.reconcile(ctx, "duplicate-configuration", executiondriver.DesiredExecution{
		ExecutionID:   "run-duplicate",
		Generation:    1,
		WorkloadKind:  executiondriver.WorkloadKindVM,
		ClassName:     "fake-small",
		Configuration: json.RawMessage(`{"nested":{"ready":true,"ready":false}}`),
	})
	if err == nil || err.Error() != "JSON-RPC request contains invalid or ambiguous JSON" {
		t.Fatalf("duplicate configuration error = %v", err)
	}
	if matches, globErr := filepath.Glob(filepath.Join(stateDirectory, "*.json")); globErr != nil || len(matches) != 0 {
		t.Fatalf("ambiguous desired state reached the provider: matches=%v error=%v", matches, globErr)
	}
	if err := client.shutdown(ctx); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
}

func TestFakeExecutionDriverTimeoutCancelsAndReapsProcess(t *testing.T) {
	t.Parallel()
	client := startDriver(t, t.TempDir(), "")
	initializeContext, initializeCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer initializeCancel()
	if err := client.initialize(initializeContext); err != nil {
		t.Fatalf("initialize: %v", err)
	}

	requestContext, requestCancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer requestCancel()
	_, err := client.reconcile(requestContext, "timeout", executiondriver.DesiredExecution{
		ExecutionID:   "run-timeout",
		Generation:    1,
		WorkloadKind:  executiondriver.WorkloadKindVM,
		ClassName:     "fake-small",
		Configuration: mustJSON(t, map[string]any{"delay_milliseconds": 5_000}),
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout error = %v", err)
	}
	if client.command.ProcessState == nil {
		t.Fatalf("timed-out driver process was not reaped: %#v", client.command.ProcessState)
	}
	if strings.Contains(err.Error(), internalFailureCanary) || strings.Contains(client.stderr.String(), internalFailureCanary) {
		t.Fatalf("timeout exposed internal failure material: error=%v stderr=%q", err, client.stderr.String())
	}
}

func TestFakeExecutionDriverShutdownDeadlineKillsAndReapsProcess(t *testing.T) {
	t.Parallel()
	client := startDriver(t, t.TempDir(), "hang-after-shutdown")
	initializeContext, initializeCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer initializeCancel()
	if err := client.initialize(initializeContext); err != nil {
		t.Fatalf("initialize: %v", err)
	}

	shutdownContext, shutdownCancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer shutdownCancel()
	err := client.shutdown(shutdownContext)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("shutdown timeout error = %v", err)
	}
	if !client.shutdownAcknowledged {
		t.Fatal("fake driver did not acknowledge shutdown before remaining alive")
	}
	if client.command.ProcessState == nil {
		t.Fatal("non-exiting driver process was not reaped")
	}
}

func mustJSON(t *testing.T, value any) json.RawMessage {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal test JSON: %v", err)
	}
	return encoded
}
