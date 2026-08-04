package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/mirkoSekulic/nvt-agent/executiondrivers/azure/internal/driver"
	"github.com/mirkoSekulic/nvt-agent/operator/executiondriver"
	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment"
)

type process struct {
	cloud          driver.Cloud
	bootstrap      driver.Bootstrapper
	stateRoot      string
	implementation *driver.Driver
	initialized    bool
	stopHandoff    func()
}

func main() {
	stateRoot, stateErr := driver.PrepareStateRoot(os.Getenv("NVT_EXECUTION_DRIVER_STATE_DIR"))
	cloud, err := driver.NewWorkloadIdentityCloud()
	if err != nil || stateErr != nil {
		fatal("Workload Identity or state is unavailable")
	}
	bootstrap, err := driver.NewSSHBootstrapper(stateRoot)
	if err != nil {
		fatal("protected bootstrap input is unavailable")
	}
	process := &process{cloud: cloud, bootstrap: bootstrap, stateRoot: stateRoot, stopHandoff: func() {}}
	defer process.stopHandoff()
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 64<<10), executiondriver.MaxMessageBytes)
	for scanner.Scan() {
		if process.handle(scanner.Bytes()) {
			return
		}
	}
	if scanner.Err() != nil {
		fatal("protocol framing failed")
	}
}

func (process *process) handle(line []byte) bool {
	var request executiondriver.Request
	if len(line)+1 > executiondriver.MaxMessageBytes || executiondriver.DecodeStrictJSON(line, &request) != nil || request.JSONRPC != executiondriver.JSONRPCVersion || request.ID == "" {
		respondError(request.ID, executiondriver.Failure{Reason: "invalid-request", Message: "request is invalid", Retryable: false})
		return false
	}
	if request.Method != executiondriver.MethodInitialize && !process.initialized {
		respondError(request.ID, executiondriver.Failure{Reason: "not-initialized", Message: "driver is not initialized", Retryable: false})
		return false
	}
	switch request.Method {
	case executiondriver.MethodInitialize:
		var params executiondriver.InitializeParams
		if process.initialized || executiondriver.DecodeStrictJSON(request.Params, &params) != nil || executiondriver.ValidateInitializeParams(params) != nil {
			respondError(request.ID, executiondriver.Failure{Reason: "invalid-initialize", Message: "initialize request is invalid", Retryable: false})
			return false
		}
		instance, err := driver.New(process.stateRoot, params.DriverInstanceName, process.cloud, process.bootstrap, driver.DefaultResolver())
		if err != nil {
			respondError(request.ID, executiondriver.Failure{Reason: "driver-unavailable", Message: "Azure driver could not initialize", Retryable: true})
			return false
		}
		stop, err := startHandoff(instance)
		if err != nil {
			respondError(request.ID, executiondriver.Failure{Reason: "handoff-unavailable", Message: "Azure enrollment handoff could not initialize", Retryable: true})
			return false
		}
		process.implementation, process.stopHandoff, process.initialized = instance, stop, true
		respondResult(request.ID, executiondriver.InitializeResult{ProtocolVersion: executiondriver.ProtocolVersion, Capabilities: []executiondriver.Capability{executiondriver.CapabilityReconcile, executiondriver.CapabilityObserve, executiondriver.CapabilityDelete}})
	case executiondriver.MethodReconcile:
		var params executiondriver.ReconcileParams
		if executiondriver.DecodeStrictJSON(request.Params, &params) != nil || executiondriver.ValidateReconcileParams(params) != nil {
			respondInvalid(request.ID)
			return false
		}
		status, err := process.implementation.Reconcile(context.Background(), params.Desired)
		process.respondOperation(request.ID, status, err)
	case executiondriver.MethodObserve, executiondriver.MethodDelete:
		var params executiondriver.ExecutionParams
		if executiondriver.DecodeStrictJSON(request.Params, &params) != nil || executiondriver.ValidateExecutionParams(params) != nil {
			respondInvalid(request.ID)
			return false
		}
		var status executiondriver.Status
		var err error
		if request.Method == executiondriver.MethodObserve {
			status, err = process.implementation.Observe(context.Background(), params.ExecutionID)
		} else {
			status, err = process.implementation.Delete(context.Background(), params.ExecutionID)
		}
		process.respondOperation(request.ID, status, err)
	case executiondriver.MethodShutdown:
		var params struct{}
		if executiondriver.DecodeStrictJSON(request.Params, &params) != nil {
			respondInvalid(request.ID)
			return false
		}
		process.stopHandoff()
		process.stopHandoff = func() {}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := process.implementation.Shutdown(ctx)
		cancel()
		if err != nil {
			respondError(request.ID, executiondriver.Failure{Reason: "shutdown-failed", Message: "Azure shutdown did not converge", Retryable: true})
			return false
		}
		respondResult(request.ID, executiondriver.ShutdownResult{})
		return true
	default:
		respondError(request.ID, executiondriver.Failure{Reason: "method-unsupported", Message: "method is unsupported", Retryable: false})
	}
	return false
}

func (process *process) respondOperation(id string, status executiondriver.Status, err error) {
	if err == nil {
		respondResult(id, status)
		return
	}
	var failure *driver.Error
	if errors.As(err, &failure) && executiondriver.ValidateFailure(failure.Failure) == nil {
		respondError(id, failure.Failure)
		return
	}
	respondError(id, executiondriver.Failure{Reason: "driver-unavailable", Message: "Azure operation is unavailable", Retryable: true})
}

func startHandoff(implementation *driver.Driver) (func(), error) {
	socket := os.Getenv("NVT_EXECUTION_DRIVER_ENROLLMENT_SOCKET")
	if socket == "" {
		return func() {}, nil
	}
	_ = os.Remove(socket)
	listener, err := net.Listen("unix", socket)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(socket, 0o600); err != nil {
		listener.Close()
		return nil, err
	}
	server := &http.Server{Handler: handoffHandler(implementation), ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: guestenrollment.MaxOperationDuration, WriteTimeout: guestenrollment.MaxOperationDuration, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 8 << 10}
	go func() { _ = server.Serve(listener) }()
	var once sync.Once
	return func() {
		once.Do(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_ = server.Shutdown(ctx)
			_ = os.Remove(socket)
		})
	}, nil
}

func handoffHandler(implementation *driver.Driver) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.Header.Get("Content-Type") != "application/json" {
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		body, err := io.ReadAll(io.LimitReader(request.Body, int64(guestenrollment.MaxHandoffRequestBytes+1)))
		if err != nil || len(body) > guestenrollment.MaxHandoffRequestBytes {
			zero(body)
			response.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
		defer zero(body)
		ctx, cancel := context.WithTimeout(request.Context(), guestenrollment.MaxOperationDuration)
		defer cancel()
		response.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/v1/prepare":
			value, decodeErr := guestenrollment.DecodeHandoffPrepareRequest(body)
			if decodeErr != nil {
				writeHandoff(response, nil, decodeErr, nil)
				return
			}
			result, callErr := implementation.Prepare(ctx, value)
			writeHandoff(response, result, nil, callErr)
		case "/v1/replace":
			value, decodeErr := guestenrollment.DecodeHandoffReplaceRequest(body)
			if decodeErr != nil {
				writeHandoff(response, nil, decodeErr, nil)
				return
			}
			result, callErr := implementation.Replace(ctx, value)
			writeHandoff(response, result, nil, callErr)
		case "/v1/deliver":
			value, decodeErr := guestenrollment.DecodeHandoffDeliverRequest(body)
			if decodeErr != nil {
				writeHandoff(response, nil, decodeErr, nil)
				return
			}
			callErr := implementation.Deliver(ctx, value)
			writeHandoff(response, guestenrollment.HandoffAcknowledgement{ContractVersion: guestenrollment.HandoffVersion}, nil, callErr)
		default:
			response.WriteHeader(http.StatusNotFound)
		}
	})
}

func writeHandoff(response http.ResponseWriter, result any, decodeErr, callErr error) {
	if decodeErr != nil {
		response.WriteHeader(http.StatusBadRequest)
		return
	}
	if callErr != nil {
		response.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	_ = json.NewEncoder(response).Encode(result)
}
func respondInvalid(id string) {
	respondError(id, executiondriver.Failure{Reason: "invalid-request", Message: "request is invalid", Retryable: false})
}
func respondResult(id string, result any) {
	payload, _ := json.Marshal(result)
	response, _ := json.Marshal(executiondriver.Response{JSONRPC: executiondriver.JSONRPCVersion, ID: id, Result: payload})
	_, _ = os.Stdout.Write(append(response, '\n'))
}
func respondError(id string, failure executiondriver.Failure) {
	response, _ := json.Marshal(executiondriver.Response{JSONRPC: executiondriver.JSONRPCVersion, ID: id, Error: &executiondriver.RPCError{Code: -32000, Message: "driver error", Data: failure}})
	_, _ = os.Stdout.Write(append(response, '\n'))
}
func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
func fatal(message string) { fmt.Fprintln(os.Stderr, "nvt-azure-driver: "+message); os.Exit(1) }
