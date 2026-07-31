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
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/mirkoSekulic/nvt-agent/executiondrivers/qemu/internal/driver"
	"github.com/mirkoSekulic/nvt-agent/operator/executiondriver"
	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment"
)

type process struct {
	driver      *driver.Driver
	machines    *driver.QEMUManager
	initialized bool
	stopHandoff func()
}

func main() {
	stateRoot := os.Getenv("NVT_EXECUTION_DRIVER_STATE_DIR")
	machines, err := driver.NewQEMUManager(driver.QEMUConfig{
		Binary: "/usr/bin/qemu-system-x86_64", Kernel: "/opt/nvt-qemu/guest/vmlinuz",
		Initramfs: "/opt/nvt-qemu/guest/initramfs", DiskTemplate: "/opt/nvt-qemu/guest/root.qcow2",
		StateRoot: stateRoot, ScratchRoot: "/tmp", ReaperBinary: "/sbin/tini",
	})
	if err != nil || stateRoot == "" {
		fatal("runtime artifacts are unavailable")
	}
	var shutdownOnce sync.Once
	shutdownMachines := func() {
		shutdownOnce.Do(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = machines.Shutdown(ctx)
			cancel()
		})
	}
	termination := make(chan os.Signal, 1)
	signal.Notify(termination, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(termination)
	go func() {
		<-termination
		// The execution-driver host cancels an in-flight child exchange by
		// terminating this process group. Reap the independently grouped QEMU,
		// its tini subreaper, and guestfwd helpers before this parent exits.
		// Pdeathsig remains the fail-closed fallback for an uncatchable exit.
		shutdownMachines()
		os.Exit(0)
	}()
	process := &process{machines: machines, stopHandoff: func() {}}
	defer process.stopHandoff()
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 64<<10), executiondriver.MaxMessageBytes)
	for scanner.Scan() {
		if process.handle(scanner.Bytes()) {
			return
		}
	}
	if scanner.Err() != nil {
		shutdownMachines()
		fatal("protocol framing failed")
	}
	// The host closes stdin before delivering SIGTERM when an in-flight call is
	// canceled. Treat clean EOF as the same authoritative shutdown path so the
	// QEMU process tree is reaped before this parent returns.
	shutdownMachines()
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
		instance, err := driver.New(process.machinesStateRoot(), params.DriverInstanceName, process.machines)
		if err != nil {
			respondError(request.ID, executiondriver.Failure{Reason: "driver-unavailable", Message: "QEMU driver could not initialize", Retryable: true})
			return false
		}
		stop, err := startHandoff(instance)
		if err != nil {
			respondError(request.ID, executiondriver.Failure{Reason: "handoff-unavailable", Message: "QEMU enrollment handoff could not initialize", Retryable: true})
			return false
		}
		process.driver, process.stopHandoff, process.initialized = instance, stop, true
		respondResult(request.ID, executiondriver.InitializeResult{ProtocolVersion: executiondriver.ProtocolVersion, Capabilities: []executiondriver.Capability{
			executiondriver.CapabilityReconcile, executiondriver.CapabilityObserve, executiondriver.CapabilityDelete,
		}})
	case executiondriver.MethodReconcile:
		var params executiondriver.ReconcileParams
		if executiondriver.DecodeStrictJSON(request.Params, &params) != nil || executiondriver.ValidateReconcileParams(params) != nil {
			respondError(request.ID, executiondriver.Failure{Reason: "invalid-request", Message: "reconcile request is invalid", Retryable: false})
			return false
		}
		status, err := process.driver.Reconcile(context.Background(), params.Desired)
		process.respondOperation(request.ID, status, err)
	case executiondriver.MethodObserve, executiondriver.MethodDelete:
		var params executiondriver.ExecutionParams
		if executiondriver.DecodeStrictJSON(request.Params, &params) != nil || executiondriver.ValidateExecutionParams(params) != nil {
			respondError(request.ID, executiondriver.Failure{Reason: "invalid-request", Message: "execution request is invalid", Retryable: false})
			return false
		}
		var status executiondriver.Status
		var err error
		if request.Method == executiondriver.MethodObserve {
			status, err = process.driver.Observe(context.Background(), params.ExecutionID)
		} else {
			status, err = process.driver.Delete(context.Background(), params.ExecutionID)
		}
		process.respondOperation(request.ID, status, err)
	case executiondriver.MethodShutdown:
		var params struct{}
		if executiondriver.DecodeStrictJSON(request.Params, &params) != nil {
			respondError(request.ID, executiondriver.Failure{Reason: "invalid-request", Message: "shutdown request is invalid", Retryable: false})
			return false
		}
		process.stopHandoff()
		process.stopHandoff = func() {}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err := process.driver.Shutdown(ctx)
		cancel()
		if err != nil {
			respondError(request.ID, executiondriver.Failure{Reason: "shutdown-failed", Message: "QEMU shutdown did not converge", Retryable: true})
			return false
		}
		respondResult(request.ID, executiondriver.ShutdownResult{})
		return true
	default:
		respondError(request.ID, executiondriver.Failure{Reason: "method-unsupported", Message: "method is unsupported", Retryable: false})
	}
	return false
}

func (process *process) machinesStateRoot() string {
	return os.Getenv("NVT_EXECUTION_DRIVER_STATE_DIR")
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
	respondError(id, executiondriver.Failure{Reason: "driver-unavailable", Message: "QEMU operation is unavailable", Retryable: true})
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
	server := &http.Server{
		Handler: handoffHandler(implementation), ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: guestenrollment.MaxOperationDuration, WriteTimeout: guestenrollment.MaxOperationDuration,
		IdleTimeout: 5 * time.Second, MaxHeaderBytes: 8 << 10,
	}
	go func() { _ = server.Serve(listener) }()
	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
		_ = os.Remove(socket)
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

func fatal(message string) {
	fmt.Fprintln(os.Stderr, "nvt-qemu-driver: "+message)
	os.Exit(1)
}
