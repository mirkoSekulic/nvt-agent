package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/mirkoSekulic/nvt-agent/operator/executiondriver"
)

const internalFailureCanary = "EXECUTION-DRIVER-INTERNAL-SECRET-CANARY"

type fakeConfiguration struct {
	Ready             *bool `json:"ready,omitempty"`
	Fail              bool  `json:"fail,omitempty"`
	DelayMilliseconds int   `json:"delay_milliseconds,omitempty"`
}

type durableState struct {
	ExecutionID string                 `json:"execution_id"`
	Generation  int64                  `json:"generation"`
	CreateCount int                    `json:"create_count"`
	Status      executiondriver.Status `json:"status"`
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
		d.initialized = true
		d.respondResult(request.ID, executiondriver.InitializeResult{
			ProtocolVersion: executiondriver.ProtocolVersion,
			Capabilities: []executiondriver.Capability{
				executiondriver.CapabilityReconcile,
				executiondriver.CapabilityObserve,
				executiondriver.CapabilityDelete,
			},
		})
	case executiondriver.MethodReconcile:
		if os.Getenv("NVT_FAKE_DRIVER_MODE") == "malformed-reconcile" {
			fmt.Fprintln(os.Stdout, "{malformed")
			return false
		}
		var params executiondriver.ReconcileParams
		if executiondriver.DecodeStrictJSON(request.Params, &params) != nil || executiondriver.ValidateReconcileParams(params) != nil {
			d.respondError(request.ID, "invalid-request", "reconcile parameters are invalid", false)
			return false
		}
		status, err := d.reconcile(params)
		if err != nil {
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
		if err := d.delete(params.ExecutionID); err != nil {
			d.respondError(request.ID, "delete-failed", "provider cleanup failed", true)
			return false
		}
		d.respondResult(request.ID, executiondriver.Status{Phase: executiondriver.PhaseDeleted})
	case executiondriver.MethodShutdown:
		var params struct{}
		if executiondriver.DecodeStrictJSON(request.Params, &params) != nil {
			d.respondError(request.ID, "invalid-request", "shutdown parameters are invalid", false)
			return false
		}
		d.respondResult(request.ID, executiondriver.ShutdownResult{})
		return true
	default:
		d.respondError(request.ID, "method-not-supported", "method is not supported", false)
	}
	return false
}

func (d *driver) reconcile(params executiondriver.ReconcileParams) (executiondriver.Status, error) {
	var configuration fakeConfiguration
	if err := executiondriver.DecodeStrictJSON(params.Desired.Configuration, &configuration); err != nil {
		return executiondriver.Status{}, err
	}
	if configuration.DelayMilliseconds < 0 || configuration.DelayMilliseconds > 60_000 {
		return executiondriver.Status{}, errors.New("invalid fake delay")
	}
	if configuration.DelayMilliseconds > 0 {
		time.Sleep(time.Duration(configuration.DelayMilliseconds) * time.Millisecond)
	}
	if configuration.Fail {
		return failedStatus(params.Desired.Generation, errors.New(internalFailureCanary)), nil
	}

	state, err := d.readState(params.Desired.ExecutionID)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return executiondriver.Status{}, err
	}
	if errors.Is(err, os.ErrNotExist) {
		digest := sha256.Sum256([]byte(params.Desired.ExecutionID))
		state = durableState{
			ExecutionID: params.Desired.ExecutionID,
			CreateCount: 1,
			Status: executiondriver.Status{
				ExternalResourceID: "fake-" + hex.EncodeToString(digest[:8]),
			},
		}
	}

	ready := true
	if configuration.Ready != nil {
		ready = *configuration.Ready
	}
	state.Generation = params.Desired.Generation
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
		return executiondriver.Status{Phase: executiondriver.PhaseDeleted}, nil
	}
	if err != nil {
		return executiondriver.Status{}, err
	}
	return state.Status, nil
}

func (d *driver) delete(executionID string) error {
	err := os.Remove(d.statePath(executionID))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func (d *driver) readState(executionID string) (durableState, error) {
	data, err := os.ReadFile(d.statePath(executionID))
	if err != nil {
		return durableState{}, err
	}
	var state durableState
	if executiondriver.DecodeStrictJSON(data, &state) != nil || state.ExecutionID != executionID || state.CreateCount != 1 ||
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

func (d *driver) respondResult(id string, result any) {
	encoded, err := json.Marshal(result)
	if err != nil {
		d.respondError(id, "internal-error", "result encoding failed", true)
		return
	}
	d.respond(executiondriver.Response{JSONRPC: executiondriver.JSONRPCVersion, ID: id, Result: encoded})
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
