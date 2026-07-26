package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/mirkoSekulic/nvt-agent/operator/executiondriver"
)

const internalFailureCanary = "EXECUTION-DRIVER-INTERNAL-SECRET-CANARY"

type fakeConfiguration struct {
	Ready             *bool `json:"ready,omitempty"`
	Fail              bool  `json:"fail,omitempty"`
	DelayMilliseconds int   `json:"delay_milliseconds,omitempty"`
	DeleteSteps       int   `json:"delete_steps,omitempty"`
}

type durableState struct {
	ExecutionID          string                 `json:"execution_id"`
	Generation           int64                  `json:"generation"`
	DesiredFingerprint   string                 `json:"desired_fingerprint"`
	CreateCount          int                    `json:"create_count"`
	DeleteStepsRemaining int                    `json:"delete_steps_remaining"`
	Status               executiondriver.Status `json:"status"`
}

type driver struct {
	stateDir    string
	initialized bool
}

func main() {
	stateDir := os.Getenv("NVT_FAKE_DRIVER_STATE_DIR")
	if stateDir == "" {
		fmt.Fprintln(os.Stderr, "fake execution driver: state directory is required")
		os.Exit(2)
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		fmt.Fprintln(os.Stderr, "fake execution driver: state directory is unavailable")
		os.Exit(2)
	}
	if pidFile := os.Getenv("NVT_FAKE_DRIVER_PID_FILE"); pidFile != "" {
		if err := os.WriteFile(pidFile, []byte(fmt.Sprintf("%d", os.Getpid())), 0o600); err != nil {
			fmt.Fprintln(os.Stderr, "fake execution driver: PID file is unavailable")
			os.Exit(2)
		}
	}
	if os.Getenv("NVT_FAKE_DRIVER_MODE") == "hang-after-shutdown-ignore-term" {
		signal.Ignore(syscall.SIGTERM)
	}

	d := &driver{stateDir: stateDir}
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 64<<10), executiondriver.MaxMessageBytes)
	for scanner.Scan() {
		shouldExit := d.handle(scanner.Bytes())
		if shouldExit {
			return
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "fake execution driver: request framing failed")
		os.Exit(2)
	}
}

func (d *driver) handle(line []byte) bool {
	var request executiondriver.Request
	if len(line)+1 > executiondriver.MaxMessageBytes || executiondriver.DecodeStrictJSON(line, &request) != nil ||
		request.JSONRPC != executiondriver.JSONRPCVersion || request.ID == "" {
		d.respondError(request.ID, "invalid-request", "request is invalid", false)
		return false
	}

	if request.Method != executiondriver.MethodInitialize && !d.initialized {
		d.respondError(request.ID, "not-initialized", "driver is not initialized", false)
		return false
	}

	switch request.Method {
	case executiondriver.MethodInitialize:
		var params executiondriver.InitializeParams
		if executiondriver.DecodeStrictJSON(request.Params, &params) != nil || executiondriver.ValidateInitializeParams(params) != nil {
			d.respondError(request.ID, "invalid-request", "initialize parameters are invalid", false)
			return false
		}
		mode := os.Getenv("NVT_FAKE_DRIVER_MODE")
		if mode == "hang-initialize" {
			select {}
		}
		if mode == "clean-environment" && !hasExpectedCleanEnvironment() {
			d.respondError(request.ID, "environment-invalid", "driver environment is invalid", false)
			return false
		}
		result := executiondriver.InitializeResult{
			ProtocolVersion: executiondriver.ProtocolVersion,
			Capabilities: []executiondriver.Capability{
				executiondriver.CapabilityReconcile,
				executiondriver.CapabilityObserve,
				executiondriver.CapabilityDelete,
			},
		}
		switch mode {
		case "incompatible-initialize":
			result.ProtocolVersion = "nvt.execution-driver/v999"
		case "missing-capability-initialize":
			result.Capabilities = result.Capabilities[:2]
		case "unsolicited-initialize":
			d.respondResult("unsolicited", result)
		}
		d.initialized = true
		d.respondResult(request.ID, result)
		if mode == "idle-unsolicited" {
			go func() {
				time.Sleep(10 * time.Millisecond)
				if marker := os.Getenv("NVT_FAKE_DRIVER_UNSOLICITED_FILE"); marker != "" {
					_ = os.WriteFile(marker, []byte("emitted"), 0o600)
				}
				d.respondResult("idle-unsolicited", result)
			}()
		}
	case executiondriver.MethodReconcile:
		var params executiondriver.ReconcileParams
		if executiondriver.DecodeStrictJSON(request.Params, &params) != nil || executiondriver.ValidateReconcileParams(params) != nil {
			d.respondError(request.ID, "invalid-request", "reconcile parameters are invalid", false)
			return false
		}
		mode := os.Getenv("NVT_FAKE_DRIVER_MODE")
		testStatus := executiondriver.Status{
			Phase:              executiondriver.PhasePending,
			ObservedGeneration: params.Desired.Generation,
		}
		switch mode {
		case "malformed-reconcile":
			fmt.Fprintln(os.Stdout, "{malformed")
			return false
		case "oversized-reconcile":
			_, _ = os.Stdout.Write(append(bytes.Repeat([]byte{'x'}, executiondriver.MaxMessageBytes), '\n'))
			return false
		case "mismatched-reconcile":
			d.respondResult("mismatched", testStatus)
			return false
		case "duplicate-reconcile":
			d.respondResultTwice(request.ID, testStatus)
			return false
		case "invalid-utf8-reconcile":
			prefix := fmt.Sprintf(`{"jsonrpc":"2.0","id":%q,"result":{"phase":"`, request.ID)
			response := append([]byte(prefix), 0xff)
			response = append(response, []byte(`"}}`)...)
			response = append(response, '\n')
			_, _ = os.Stdout.Write(response)
			return false
		case "crash-once-reconcile":
			marker := filepath.Join(d.stateDir, ".crash-once-complete")
			if _, err := os.Stat(marker); errors.Is(err, os.ErrNotExist) {
				if err := os.WriteFile(marker, []byte("crashed"), 0o600); err != nil {
					os.Exit(18)
				}
				os.Exit(17)
			}
		case "stderr-canary-reconcile":
			fmt.Fprintln(os.Stderr, internalFailureCanary)
			os.Exit(19)
		}
		if activeFile := os.Getenv("NVT_FAKE_DRIVER_ACTIVE_FILE"); activeFile != "" {
			if err := os.WriteFile(activeFile, []byte("active"), 0o600); err != nil {
				d.respondError(request.ID, "reconcile-failed", "provider convergence failed", true)
				return false
			}
		}
		status, err := d.reconcile(params)
		if err != nil {
			if errors.Is(err, errStaleGeneration) {
				d.respondError(request.ID, "stale-generation", "desired generation regressed", false)
				return false
			}
			if errors.Is(err, errGenerationConflict) {
				d.respondError(request.ID, "generation-conflict", "desired state changed without a new generation", false)
				return false
			}
			if errors.Is(err, errDeletionInProgress) {
				d.respondError(request.ID, "deletion-in-progress", "execution deletion is in progress", false)
				return false
			}
			d.respondError(request.ID, "reconcile-failed", "provider convergence failed", true)
			return false
		}
		d.respondResult(request.ID, status)
	case executiondriver.MethodObserve:
		var params executiondriver.ExecutionParams
		if executiondriver.DecodeStrictJSON(request.Params, &params) != nil || executiondriver.ValidateExecutionParams(params) != nil {
			d.respondError(request.ID, "invalid-request", "observe parameters are invalid", false)
			return false
		}
		status, err := d.observe(params.ExecutionID)
		if err != nil {
			d.respondError(request.ID, "observe-failed", "provider observation failed", true)
			return false
		}
		d.respondResult(request.ID, status)
	case executiondriver.MethodDelete:
		var params executiondriver.ExecutionParams
		if executiondriver.DecodeStrictJSON(request.Params, &params) != nil || executiondriver.ValidateExecutionParams(params) != nil {
			d.respondError(request.ID, "invalid-request", "delete parameters are invalid", false)
			return false
		}
		status, err := d.delete(params.ExecutionID)
		if err != nil {
			d.respondError(request.ID, "delete-failed", "provider cleanup failed", true)
			return false
		}
		d.respondResult(request.ID, status)
	case executiondriver.MethodShutdown:
		var params struct{}
		if executiondriver.DecodeStrictJSON(request.Params, &params) != nil {
			d.respondError(request.ID, "invalid-request", "shutdown parameters are invalid", false)
			return false
		}
		switch os.Getenv("NVT_FAKE_DRIVER_MODE") {
		case "null-shutdown":
			d.respondRawResult(request.ID, json.RawMessage(`null`))
		case "array-shutdown":
			d.respondRawResult(request.ID, json.RawMessage(`[]`))
		case "nonempty-shutdown":
			d.respondRawResult(request.ID, json.RawMessage(`{"unexpected":true}`))
		default:
			d.respondResult(request.ID, executiondriver.ShutdownResult{})
		}
		if mode := os.Getenv("NVT_FAKE_DRIVER_MODE"); mode == "hang-after-shutdown" || mode == "hang-after-shutdown-ignore-term" {
			select {}
		}
		return true
	default:
		d.respondError(request.ID, "method-not-supported", "method is not supported", false)
	}
	return false
}

func hasExpectedCleanEnvironment() bool {
	expected := []string{
		"NVT_FAKE_DRIVER_ALLOWED=allowed",
		"NVT_FAKE_DRIVER_MODE=clean-environment",
	}
	for _, entry := range os.Environ() {
		if strings.HasPrefix(entry, "NVT_FAKE_DRIVER_STATE_DIR=") {
			expected = append(expected, entry)
		}
	}
	sort.Strings(expected)
	actual := append([]string(nil), os.Environ()...)
	sort.Strings(actual)
	return strings.Join(actual, "\n") == strings.Join(expected, "\n")
}

var (
	errStaleGeneration    = errors.New("stale desired generation")
	errGenerationConflict = errors.New("desired generation conflict")
	errDeletionInProgress = errors.New("execution deletion is in progress")
)

func (d *driver) reconcile(params executiondriver.ReconcileParams) (executiondriver.Status, error) {
	var configuration fakeConfiguration
	if err := executiondriver.DecodeStrictJSON(params.Desired.Configuration, &configuration); err != nil {
		return executiondriver.Status{}, err
	}
	if configuration.DelayMilliseconds < 0 || configuration.DelayMilliseconds > 60_000 ||
		configuration.DeleteSteps < 0 || configuration.DeleteSteps > 10 {
		return executiondriver.Status{}, errors.New("invalid fake configuration")
	}
	fingerprint := params.Desired.DesiredFingerprint

	state, err := d.readState(params.Desired.ExecutionID)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return executiondriver.Status{}, err
	}
	if errors.Is(err, os.ErrNotExist) {
		digest := sha256.Sum256([]byte(params.Desired.ExecutionID))
		state = durableState{
			ExecutionID:        params.Desired.ExecutionID,
			CreateCount:        1,
			DesiredFingerprint: fingerprint,
			Status: executiondriver.Status{
				ExternalResourceID: "fake-" + hex.EncodeToString(digest[:8]),
			},
		}
	} else {
		switch {
		case params.Desired.Generation < state.Generation:
			return executiondriver.Status{}, errStaleGeneration
		case params.Desired.Generation == state.Generation && fingerprint != state.DesiredFingerprint:
			return executiondriver.Status{}, errGenerationConflict
		case state.Status.Phase == executiondriver.PhaseDeleting:
			return executiondriver.Status{}, errDeletionInProgress
		}
	}

	if configuration.DelayMilliseconds > 0 {
		time.Sleep(time.Duration(configuration.DelayMilliseconds) * time.Millisecond)
	}
	if configuration.Fail {
		return failedStatus(params.Desired.Generation, errors.New(internalFailureCanary)), nil
	}

	ready := true
	if configuration.Ready != nil {
		ready = *configuration.Ready
	}
	state.Generation = params.Desired.Generation
	state.DesiredFingerprint = fingerprint
	state.DeleteStepsRemaining = configuration.DeleteSteps
	if state.DeleteStepsRemaining == 0 {
		state.DeleteStepsRemaining = 2
	}
	state.Status.ObservedGeneration = params.Desired.Generation
	state.Status.Failure = nil
	if ready {
		state.Status.Phase = executiondriver.PhaseRunning
		state.Status.Ready = true
		state.Status.Endpoint = &executiondriver.Endpoint{
			Scheme: executiondriver.EndpointSchemeHTTPS,
			Host:   "fake-driver.invalid",
			Port:   443,
		}
		state.Status.RetryAfterSeconds = nil
	} else {
		retryAfter := int32(1)
		state.Status.Phase = executiondriver.PhaseProvisioning
		state.Status.Ready = false
		state.Status.Endpoint = nil
		state.Status.RetryAfterSeconds = &retryAfter
	}
	if err := d.writeState(state); err != nil {
		return executiondriver.Status{}, err
	}
	if err := d.ensureSubordinate(state); err != nil {
		return executiondriver.Status{}, err
	}
	return state.Status, nil
}

func failedStatus(generation int64, internal error) executiondriver.Status {
	_ = internal // Deliberately never returned, serialized, or logged.
	return executiondriver.Status{
		Phase:              executiondriver.PhaseFailed,
		ObservedGeneration: generation,
		Failure: &executiondriver.Failure{
			Reason:    "provider-operation-failed",
			Message:   "provider operation failed",
			Retryable: false,
		},
	}
}

func (d *driver) observe(executionID string) (executiondriver.Status, error) {
	state, err := d.readState(executionID)
	if errors.Is(err, os.ErrNotExist) {
		if _, resourceErr := os.Stat(d.subordinatePath(executionID)); resourceErr == nil {
			return executiondriver.Status{}, errors.New("orphaned provider resource exists")
		} else if !errors.Is(resourceErr, os.ErrNotExist) {
			return executiondriver.Status{}, resourceErr
		}
		return executiondriver.Status{Phase: executiondriver.PhaseDeleted}, nil
	}
	if err != nil {
		return executiondriver.Status{}, err
	}
	if state.Status.Phase != executiondriver.PhaseDeleting && !d.subordinateMatches(state) {
		retryAfter := int32(1)
		return executiondriver.Status{
			Phase:              executiondriver.PhaseProvisioning,
			Ready:              false,
			ExternalResourceID: state.Status.ExternalResourceID,
			ObservedGeneration: state.Generation,
			RetryAfterSeconds:  &retryAfter,
		}, nil
	}
	return state.Status, nil
}

func (d *driver) delete(executionID string) (executiondriver.Status, error) {
	state, err := d.readState(executionID)
	if errors.Is(err, os.ErrNotExist) {
		if removeErr := os.Remove(d.subordinatePath(executionID)); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			return executiondriver.Status{}, removeErr
		}
		return executiondriver.Status{Phase: executiondriver.PhaseDeleted}, nil
	}
	if err != nil {
		return executiondriver.Status{}, err
	}
	if state.Status.Phase != executiondriver.PhaseDeleting {
		retryAfter := int32(1)
		state.Status.Phase = executiondriver.PhaseDeleting
		state.Status.Ready = false
		state.Status.Endpoint = nil
		state.Status.Failure = nil
		state.Status.RetryAfterSeconds = &retryAfter
		if err := d.writeState(state); err != nil {
			return executiondriver.Status{}, err
		}
		return state.Status, nil
	}
	if state.DeleteStepsRemaining > 1 {
		state.DeleteStepsRemaining--
		if err := d.writeState(state); err != nil {
			return executiondriver.Status{}, err
		}
		return state.Status, nil
	}
	if err := os.Remove(d.subordinatePath(executionID)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return executiondriver.Status{}, err
	}
	if err := os.Remove(d.statePath(executionID)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return executiondriver.Status{}, err
	}
	return executiondriver.Status{Phase: executiondriver.PhaseDeleted}, nil
}

func (d *driver) readState(executionID string) (durableState, error) {
	data, err := os.ReadFile(d.statePath(executionID))
	if err != nil {
		return durableState{}, err
	}
	var state durableState
	if executiondriver.DecodeStrictJSON(data, &state) != nil || state.ExecutionID != executionID || state.CreateCount != 1 ||
		state.Generation < 1 || executiondriver.ValidateDesiredFingerprint(state.DesiredFingerprint) != nil ||
		state.DeleteStepsRemaining < 1 ||
		state.Status.ObservedGeneration != state.Generation ||
		executiondriver.ValidateStatus(state.Status) != nil {
		return durableState{}, errors.New("durable state is invalid")
	}
	return state, nil
}

func (d *driver) writeState(state durableState) error {
	encoded, err := json.Marshal(state)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(d.stateDir, ".state-*")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(encoded); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryName, d.statePath(state.ExecutionID))
}

func (d *driver) statePath(executionID string) string {
	digest := sha256.Sum256([]byte(executionID))
	return filepath.Join(d.stateDir, hex.EncodeToString(digest[:])+".json")
}

func (d *driver) subordinatePath(executionID string) string {
	digest := sha256.Sum256([]byte(executionID))
	return filepath.Join(d.stateDir, hex.EncodeToString(digest[:])+".subordinate")
}

func (d *driver) subordinateMatches(state durableState) bool {
	data, err := os.ReadFile(d.subordinatePath(state.ExecutionID))
	return err == nil && string(data) == state.Status.ExternalResourceID
}

func (d *driver) ensureSubordinate(state durableState) error {
	if d.subordinateMatches(state) {
		return nil
	}
	path := d.subordinatePath(state.ExecutionID)
	temporary, err := os.CreateTemp(d.stateDir, ".subordinate-*")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.WriteString(state.Status.ExternalResourceID); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryName, path)
}

func (d *driver) respondResult(id string, result any) {
	encoded, err := json.Marshal(result)
	if err != nil {
		d.respondError(id, "internal-error", "result encoding failed", true)
		return
	}
	d.respond(executiondriver.Response{JSONRPC: executiondriver.JSONRPCVersion, ID: id, Result: encoded})
}

func (d *driver) respondRawResult(id string, result json.RawMessage) {
	d.respond(executiondriver.Response{JSONRPC: executiondriver.JSONRPCVersion, ID: id, Result: result})
}

func (d *driver) respondResultTwice(id string, result any) {
	encodedResult, err := json.Marshal(result)
	if err != nil {
		os.Exit(2)
	}
	response := executiondriver.Response{
		JSONRPC: executiondriver.JSONRPCVersion,
		ID:      id,
		Result:  encodedResult,
	}
	encodedResponse, err := json.Marshal(response)
	if err != nil || len(encodedResponse)+1 > executiondriver.MaxMessageBytes {
		os.Exit(2)
	}
	combined := make([]byte, 0, (len(encodedResponse)+1)*2)
	combined = append(combined, encodedResponse...)
	combined = append(combined, '\n')
	combined = append(combined, encodedResponse...)
	combined = append(combined, '\n')
	_, _ = os.Stdout.Write(combined)
}

func (d *driver) respondError(id, reason, message string, retryable bool) {
	d.respond(executiondriver.Response{
		JSONRPC: executiondriver.JSONRPCVersion,
		ID:      id,
		Error: &executiondriver.RPCError{
			Code:    -32000,
			Message: "driver error",
			Data: executiondriver.Failure{
				Reason:    reason,
				Message:   message,
				Retryable: retryable,
			},
		},
	})
}

func (d *driver) respond(response executiondriver.Response) {
	encoded, err := json.Marshal(response)
	if err != nil || len(encoded)+1 > executiondriver.MaxMessageBytes {
		fmt.Fprintln(os.Stderr, "fake execution driver: response encoding failed")
		os.Exit(2)
	}
	fmt.Fprintln(os.Stdout, string(encoded))
}
