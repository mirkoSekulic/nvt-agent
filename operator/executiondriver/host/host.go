// Package host provides process-independent clients for execution drivers.
// LocalExecutable is the trusted local-process transport; it is deliberately
// not wired into AgentRun reconciliation in this phase.
package host

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/mirkoSekulic/nvt-agent/operator/executiondriver"
)

const (
	maxCommandArguments        = 128
	maxCommandArgumentBytes    = 16 << 10
	maxEnvironmentVariables    = 128
	maxRetainedDiagnosticBytes = 4 << 10
	maxConfiguredDuration      = 10 * time.Minute
)

var (
	// ErrClosed indicates that Shutdown completed for the client.
	ErrClosed = errors.New("execution driver host is closed")
	// ErrRestartBackoff indicates that a failed process may not be restarted yet.
	ErrRestartBackoff = errors.New("execution driver restart backoff is active")
	// ErrUnavailable indicates that the selected process exited unexpectedly.
	ErrUnavailable = errors.New("execution driver process is unavailable")
	// ErrTransport indicates a bounded stdin/stdout or process failure.
	ErrTransport = errors.New("execution driver transport failed")
	// ErrProtocol indicates malformed or ambiguous driver output.
	ErrProtocol = errors.New("execution driver protocol failed")
	// ErrRequiredEnvironment indicates that a configured PassEnv name was not
	// present in the host environment for this process generation.
	ErrRequiredEnvironment = errors.New("execution driver required environment variable is unavailable")

	environmentNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

// Client is the topology-neutral operator-side execution-driver boundary. A
// later dedicated driver-host workload can implement the same interface.
type Client interface {
	Reconcile(context.Context, executiondriver.DesiredExecution) (executiondriver.Status, error)
	Observe(context.Context, string) (executiondriver.Status, error)
	Delete(context.Context, string) (executiondriver.Status, error)
	Shutdown(context.Context) error
}

var _ Client = (*LocalExecutable)(nil)

// DriverError is a protocol-valid, bounded, sanitized error returned by the
// selected driver. Raw stderr and request or response payloads are never
// included.
type DriverError struct {
	Failure executiondriver.Failure
}

func (e *DriverError) Error() string {
	if e.Failure.Message == "" {
		return "execution driver failed: " + e.Failure.Reason
	}
	return "execution driver failed: " + e.Failure.Reason + ": " + e.Failure.Message
}

// LocalExecutableConfig configures one trusted executable. ExecutablePath must
// be absolute. Every PassEnv name is required to exist and its value is copied
// from the current process; every other environment variable is omitted. The
// child starts in / and is invoked directly without a shell.
type LocalExecutableConfig struct {
	DriverInstanceName string
	ExecutablePath     string
	Args               []string
	PassEnv            []string
	InitializeTimeout  time.Duration
	OperationTimeout   time.Duration
	ShutdownTimeout    time.Duration
	TerminationGrace   time.Duration
	RestartBackoff     time.Duration
}

// LocalExecutable supervises exactly one configured local driver. Calls are
// serialized. A failed in-flight call is never replayed; a later caller may
// start the same executable after RestartBackoff.
type LocalExecutable struct {
	config           LocalExecutableConfig
	serial           chan struct{}
	stateMu          sync.Mutex
	process          *localProcess
	nextStart        time.Time
	requestID        uint64
	closed           bool
	shutdownDone     chan struct{}
	shutdownComplete sync.Once
}

type localProcess struct {
	command       *exec.Cmd
	stdin         io.WriteCloser
	stdout        *bufio.Reader
	stdoutPipe    io.ReadCloser
	done          chan struct{}
	readerDone    chan struct{}
	waitErr       error
	closeInput    sync.Once
	closeOutput   sync.Once
	responseMu    sync.Mutex
	pending       *pendingCall
	fatal         error
	fatalCh       chan struct{}
	fatalOnce     sync.Once
	terminateOnce sync.Once
	terminated    chan struct{}
	stderr        *boundedDiagnosticSink
}

type pendingCall struct {
	id        string
	method    executiondriver.Method
	delivered bool
	response  chan executiondriver.Response
}

type boundedDiagnosticSink struct {
	mu   sync.Mutex
	data []byte
}

func (w *boundedDiagnosticSink) Write(value []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	remaining := maxRetainedDiagnosticBytes - len(w.data)
	if remaining > len(value) {
		remaining = len(value)
	}
	if remaining > 0 {
		w.data = append(w.data, value[:remaining]...)
	}
	return len(value), nil
}

// NewLocalExecutable validates, starts, and negotiates with one configured
// executable. No driver is selected by fallback.
func NewLocalExecutable(ctx context.Context, config LocalExecutableConfig) (*LocalExecutable, error) {
	validated, err := validateLocalExecutableConfig(config)
	if err != nil {
		return nil, err
	}
	host := &LocalExecutable{
		config:       validated,
		serial:       make(chan struct{}, 1),
		shutdownDone: make(chan struct{}),
	}
	initializeContext, cancel := context.WithTimeout(ctx, validated.InitializeTimeout)
	defer cancel()
	if err := host.startLocked(initializeContext); err != nil {
		return nil, err
	}
	return host, nil
}

func validateLocalExecutableConfig(config LocalExecutableConfig) (LocalExecutableConfig, error) {
	if err := executiondriver.ValidateInitializeParams(executiondriver.InitializeParams{
		ProtocolVersion:    executiondriver.ProtocolVersion,
		DriverInstanceName: config.DriverInstanceName,
	}); err != nil {
		return LocalExecutableConfig{}, errors.New("execution driver instance name is invalid")
	}
	if config.ExecutablePath == "" || !filepath.IsAbs(config.ExecutablePath) || strings.IndexByte(config.ExecutablePath, 0) >= 0 {
		return LocalExecutableConfig{}, errors.New("execution driver executable path must be absolute")
	}
	info, err := os.Stat(config.ExecutablePath)
	if err != nil {
		return LocalExecutableConfig{}, errors.New("execution driver executable is unavailable")
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return LocalExecutableConfig{}, errors.New("execution driver executable is not executable")
	}
	if len(config.Args) > maxCommandArguments {
		return LocalExecutableConfig{}, errors.New("execution driver command has too many arguments")
	}
	totalArgumentBytes := 0
	for _, argument := range config.Args {
		if !utf8.ValidString(argument) || strings.IndexByte(argument, 0) >= 0 {
			return LocalExecutableConfig{}, errors.New("execution driver command argument is invalid")
		}
		totalArgumentBytes += len(argument)
		if totalArgumentBytes > maxCommandArgumentBytes {
			return LocalExecutableConfig{}, errors.New("execution driver command arguments are too large")
		}
	}
	if len(config.PassEnv) > maxEnvironmentVariables {
		return LocalExecutableConfig{}, errors.New("execution driver environment allowlist is too large")
	}
	seenEnvironment := make(map[string]struct{}, len(config.PassEnv))
	for _, name := range config.PassEnv {
		if !environmentNamePattern.MatchString(name) {
			return LocalExecutableConfig{}, errors.New("execution driver environment allowlist contains an invalid name")
		}
		if _, duplicate := seenEnvironment[name]; duplicate {
			return LocalExecutableConfig{}, errors.New("execution driver environment allowlist contains a duplicate name")
		}
		seenEnvironment[name] = struct{}{}
	}
	for name, duration := range map[string]time.Duration{
		"initialize":        config.InitializeTimeout,
		"operation":         config.OperationTimeout,
		"shutdown":          config.ShutdownTimeout,
		"termination grace": config.TerminationGrace,
		"restart backoff":   config.RestartBackoff,
	} {
		if duration <= 0 || duration > maxConfiguredDuration {
			return LocalExecutableConfig{}, fmt.Errorf("execution driver %s duration is invalid", name)
		}
	}
	validated := config
	validated.Args = append([]string(nil), config.Args...)
	validated.PassEnv = append([]string(nil), config.PassEnv...)
	sort.Strings(validated.PassEnv)
	return validated, nil
}

func (h *LocalExecutable) Reconcile(ctx context.Context, desired executiondriver.DesiredExecution) (executiondriver.Status, error) {
	params := executiondriver.ReconcileParams{Desired: desired}
	if err := executiondriver.ValidateReconcileParams(params); err != nil {
		return executiondriver.Status{}, errors.New("execution driver reconcile request is invalid")
	}
	var result executiondriver.Status
	err := h.operation(ctx, executiondriver.MethodReconcile, params, &result, func() error {
		return executiondriver.ValidateReconcileStatus(result)
	})
	return result, err
}

func (h *LocalExecutable) Observe(ctx context.Context, executionID string) (executiondriver.Status, error) {
	params := executiondriver.ExecutionParams{ExecutionID: executionID}
	if err := executiondriver.ValidateExecutionParams(params); err != nil {
		return executiondriver.Status{}, errors.New("execution driver observe request is invalid")
	}
	var result executiondriver.Status
	err := h.operation(ctx, executiondriver.MethodObserve, params, &result, func() error {
		return executiondriver.ValidateObserveStatus(result)
	})
	return result, err
}

func (h *LocalExecutable) Delete(ctx context.Context, executionID string) (executiondriver.Status, error) {
	params := executiondriver.ExecutionParams{ExecutionID: executionID}
	if err := executiondriver.ValidateExecutionParams(params); err != nil {
		return executiondriver.Status{}, errors.New("execution driver delete request is invalid")
	}
	var result executiondriver.Status
	err := h.operation(ctx, executiondriver.MethodDelete, params, &result, func() error {
		return executiondriver.ValidateDeleteStatus(result)
	})
	return result, err
}

func (h *LocalExecutable) operation(
	ctx context.Context,
	method executiondriver.Method,
	params, result any,
	validateResult func() error,
) error {
	if h.isClosed() {
		return ErrClosed
	}
	operationContext, cancel := context.WithTimeout(ctx, h.config.OperationTimeout)
	defer cancel()
	if err := h.acquire(operationContext); err != nil {
		return fmt.Errorf("execution driver operation did not start: %w", err)
	}
	defer h.release()
	if h.isClosed() {
		return ErrClosed
	}

	process, err := h.ensureProcessLocked(operationContext)
	if err != nil {
		return err
	}
	err = h.callProcess(operationContext, process, method, params, result)
	if err == nil && validateResult != nil {
		if validationErr := validateResult(); validationErr != nil {
			err = fmt.Errorf("%w: operation result is invalid", ErrProtocol)
		}
	}
	if err == nil {
		return nil
	}
	var driverError *DriverError
	if errors.As(err, &driverError) {
		return err
	}
	h.failProcessLocked(process)
	return err
}

// Shutdown permanently and authoritatively closes the client. An idle process
// receives protocol shutdown. An active operation is not allowed to delay
// closure: its process generation is terminated and reaped, which unblocks the
// active call without replay.
func (h *LocalExecutable) Shutdown(ctx context.Context) error {
	shutdownContext, cancel := context.WithTimeout(ctx, h.config.ShutdownTimeout)
	defer cancel()
	process, first := h.beginShutdown()
	if !first {
		select {
		case <-h.shutdownDone:
			return nil
		case <-shutdownContext.Done():
			return fmt.Errorf("execution driver shutdown wait timed out: %w", shutdownContext.Err())
		}
	}
	defer h.finishShutdown()

	if h.tryAcquire() {
		defer h.release()
		h.clearProcess(process)
		return h.shutdownIdleProcess(shutdownContext, process)
	}

	// An operation owns serialization. Killing its exact process generation
	// makes the blocked exchange return; the operation then releases serial.
	// Cleanup is bounded by TerminationGrace even if the caller deadline is
	// shorter, because returning while the child remains alive is unsafe.
	if process != nil {
		process.terminateAndReap(h.config.TerminationGrace)
		h.clearProcess(process)
	}
	cleanupContext, cleanupCancel := context.WithTimeout(context.Background(), h.config.TerminationGrace)
	defer cleanupCancel()
	if err := h.acquire(cleanupContext); err != nil {
		return fmt.Errorf("execution driver active operation did not stop: %w", err)
	}
	h.release()
	return nil
}

func (h *LocalExecutable) shutdownIdleProcess(ctx context.Context, process *localProcess) error {
	if process == nil {
		return nil
	}
	if process.exited() {
		process.closePipes()
		process.killRemainingGroup()
		process.waitForReader()
		return nil
	}

	var result executiondriver.ShutdownResult
	err := h.callProcess(ctx, process, executiondriver.MethodShutdown, struct{}{}, &result)
	process.closeStdin()
	if err == nil {
		select {
		case <-process.done:
			process.closePipes()
			process.killRemainingGroup()
			process.waitForReader()
			if process.waitErr != nil {
				return ErrTransport
			}
			return nil
		case <-ctx.Done():
			err = fmt.Errorf("execution driver shutdown timed out: %w", ctx.Err())
		}
	}
	process.terminateAndReap(h.config.TerminationGrace)
	return err
}

func (h *LocalExecutable) beginShutdown() (*localProcess, bool) {
	h.stateMu.Lock()
	defer h.stateMu.Unlock()
	if h.closed {
		return nil, false
	}
	h.closed = true
	return h.process, true
}

func (h *LocalExecutable) isClosed() bool {
	h.stateMu.Lock()
	defer h.stateMu.Unlock()
	return h.closed
}

func (h *LocalExecutable) finishShutdown() {
	h.shutdownComplete.Do(func() {
		close(h.shutdownDone)
	})
}

func (h *LocalExecutable) tryAcquire() bool {
	select {
	case h.serial <- struct{}{}:
		return true
	default:
		return false
	}
}

func (h *LocalExecutable) acquire(ctx context.Context) error {
	select {
	case h.serial <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (h *LocalExecutable) release() {
	<-h.serial
}

func (h *LocalExecutable) ensureProcessLocked(ctx context.Context) (*localProcess, error) {
	h.stateMu.Lock()
	if h.closed {
		h.stateMu.Unlock()
		return nil, ErrClosed
	}
	process := h.process
	if process != nil {
		if !process.exited() {
			h.stateMu.Unlock()
			return process, nil
		}
		h.process = nil
		h.nextStart = time.Now().Add(h.config.RestartBackoff)
		h.stateMu.Unlock()
		process.closePipes()
		process.killRemainingGroup()
		process.waitForReader()
		return nil, ErrUnavailable
	}
	if time.Now().Before(h.nextStart) {
		h.stateMu.Unlock()
		return nil, ErrRestartBackoff
	}
	h.stateMu.Unlock()
	if err := h.startLocked(ctx); err != nil {
		h.stateMu.Lock()
		if !h.closed {
			h.nextStart = time.Now().Add(h.config.RestartBackoff)
		}
		h.stateMu.Unlock()
		return nil, err
	}
	h.stateMu.Lock()
	defer h.stateMu.Unlock()
	if h.closed {
		return nil, ErrClosed
	}
	return h.process, nil
}

func (h *LocalExecutable) startLocked(ctx context.Context) error {
	environment, err := h.childEnvironment()
	if err != nil {
		return err
	}
	command := exec.Command(h.config.ExecutablePath, h.config.Args...)
	command.Args = append([]string{h.config.ExecutablePath}, h.config.Args...)
	command.Dir = "/"
	command.Env = environment
	configureProcessGroup(command)
	stdin, err := command.StdinPipe()
	if err != nil {
		return errors.New("execution driver stdin is unavailable")
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		return errors.New("execution driver stdout is unavailable")
	}
	stderr := &boundedDiagnosticSink{}
	command.Stderr = stderr
	if err := command.Start(); err != nil {
		_ = stdin.Close()
		_ = stdout.Close()
		return errors.New("execution driver process could not be started")
	}
	process := &localProcess{
		command:    command,
		stdin:      stdin,
		stdout:     bufio.NewReaderSize(stdout, executiondriver.MaxMessageBytes),
		stdoutPipe: stdout,
		done:       make(chan struct{}),
		readerDone: make(chan struct{}),
		fatalCh:    make(chan struct{}),
		terminated: make(chan struct{}),
		stderr:     stderr,
	}
	go func() {
		process.waitErr = command.Wait()
		close(process.done)
	}()
	go process.readResponses()
	h.stateMu.Lock()
	if h.closed {
		h.stateMu.Unlock()
		process.terminateAndReap(h.config.TerminationGrace)
		return ErrClosed
	}
	h.process = process
	h.stateMu.Unlock()

	initializeContext, cancel := context.WithTimeout(ctx, h.config.InitializeTimeout)
	defer cancel()
	params := executiondriver.InitializeParams{
		ProtocolVersion:    executiondriver.ProtocolVersion,
		DriverInstanceName: h.config.DriverInstanceName,
	}
	var result executiondriver.InitializeResult
	if err := h.callProcess(initializeContext, process, executiondriver.MethodInitialize, params, &result); err != nil {
		process.terminateAndReap(h.config.TerminationGrace)
		h.clearProcess(process)
		return fmt.Errorf("execution driver initialization failed: %w", err)
	}
	if err := executiondriver.ValidateInitializeResult(result); err != nil {
		process.terminateAndReap(h.config.TerminationGrace)
		h.clearProcess(process)
		return fmt.Errorf("%w: initialize negotiation is incompatible", ErrProtocol)
	}
	return nil
}

func (h *LocalExecutable) childEnvironment() ([]string, error) {
	environment := make([]string, 0, len(h.config.PassEnv))
	for _, name := range h.config.PassEnv {
		value, present := os.LookupEnv(name)
		if !present {
			return nil, ErrRequiredEnvironment
		}
		if strings.IndexByte(value, 0) >= 0 {
			return nil, errors.New("execution driver allowlisted environment value is invalid")
		}
		environment = append(environment, name+"="+value)
	}
	return environment, nil
}

func (h *LocalExecutable) callProcess(ctx context.Context, process *localProcess, method executiondriver.Method, params, result any) error {
	h.requestID++
	requestID := fmt.Sprintf("request-%d", h.requestID)
	request, err := executiondriver.MarshalRequest(requestID, method, params)
	if err != nil {
		return fmt.Errorf("%w: request is invalid", ErrProtocol)
	}
	request = append(request, '\n')
	pending, err := process.registerPending(requestID, method)
	if err != nil {
		return err
	}
	defer process.clearPending(pending)

	written := make(chan error, 1)
	go func() {
		written <- writeAll(process.stdin, request)
	}()

	select {
	case err := <-written:
		if err != nil {
			return ErrTransport
		}
	case <-process.fatalCh:
		process.closeStdin()
		process.terminateAndReap(h.config.TerminationGrace)
		<-written
		return process.fatalError()
	case <-ctx.Done():
		process.closeStdin()
		process.terminateAndReap(h.config.TerminationGrace)
		<-written
		return fmt.Errorf("execution driver operation timed out: %w", ctx.Err())
	}

	var response executiondriver.Response
	select {
	case response = <-pending.response:
	case <-process.fatalCh:
		return process.fatalError()
	case <-ctx.Done():
		process.closeStdin()
		process.terminateAndReap(h.config.TerminationGrace)
		return fmt.Errorf("execution driver operation timed out: %w", ctx.Err())
	}
	if response.Error != nil {
		return &DriverError{Failure: response.Error.Data}
	}
	if method == executiondriver.MethodShutdown {
		var object map[string]json.RawMessage
		if err := executiondriver.DecodeStrictJSON(response.Result, &object); err != nil || object == nil || len(object) != 0 {
			return fmt.Errorf("%w: shutdown result must be an empty object", ErrProtocol)
		}
	}
	if err := executiondriver.DecodeStrictJSON(response.Result, result); err != nil {
		return fmt.Errorf("%w: result is malformed", ErrProtocol)
	}
	return nil
}

func (p *localProcess) readResponses() {
	defer close(p.readerDone)
	for {
		line, err := p.stdout.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) || len(line) > executiondriver.MaxMessageBytes {
			p.failProtocol(fmt.Errorf("%w: response exceeds the message limit", ErrProtocol))
			return
		}
		if err != nil || len(line) == 0 || line[len(line)-1] != '\n' {
			p.failProtocol(ErrTransport)
			return
		}
		if p.stdout.Buffered() != 0 {
			p.failProtocol(fmt.Errorf("%w: unsolicited or duplicate response", ErrProtocol))
			return
		}
		var response executiondriver.Response
		if err := executiondriver.DecodeStrictJSON(line[:len(line)-1], &response); err != nil {
			p.failProtocol(fmt.Errorf("%w: response is malformed", ErrProtocol))
			return
		}
		if response.JSONRPC != executiondriver.JSONRPCVersion {
			p.failProtocol(fmt.Errorf("%w: response version is invalid", ErrProtocol))
			return
		}
		if (response.Error == nil) == (len(response.Result) == 0) {
			p.failProtocol(fmt.Errorf("%w: response must contain exactly one result or error", ErrProtocol))
			return
		}
		if response.Error != nil && executiondriver.ValidateRPCError(*response.Error) != nil {
			p.failProtocol(fmt.Errorf("%w: driver error is not sanitized", ErrProtocol))
			return
		}

		p.responseMu.Lock()
		pending := p.pending
		if p.fatal != nil {
			p.responseMu.Unlock()
			return
		}
		if pending == nil {
			p.responseMu.Unlock()
			p.failProtocol(fmt.Errorf("%w: unsolicited or duplicate response", ErrProtocol))
			return
		}
		if response.ID != pending.id {
			p.responseMu.Unlock()
			p.failProtocol(fmt.Errorf("%w: response envelope does not match the request", ErrProtocol))
			return
		}
		if pending.delivered {
			p.responseMu.Unlock()
			p.failProtocol(fmt.Errorf("%w: duplicate response", ErrProtocol))
			return
		}
		pending.delivered = true
		select {
		case pending.response <- response:
			shutdown := pending.method == executiondriver.MethodShutdown
			p.responseMu.Unlock()
			if shutdown {
				return
			}
		default:
			p.responseMu.Unlock()
			p.failProtocol(fmt.Errorf("%w: duplicate response", ErrProtocol))
			return
		}
	}
}

func (p *localProcess) registerPending(id string, method executiondriver.Method) (*pendingCall, error) {
	p.responseMu.Lock()
	defer p.responseMu.Unlock()
	if p.fatal != nil {
		return nil, p.fatal
	}
	if p.pending != nil {
		return nil, fmt.Errorf("%w: concurrent process exchange", ErrProtocol)
	}
	pending := &pendingCall{id: id, method: method, response: make(chan executiondriver.Response, 1)}
	p.pending = pending
	return pending, nil
}

func (p *localProcess) clearPending(pending *pendingCall) {
	p.responseMu.Lock()
	defer p.responseMu.Unlock()
	if p.pending == pending {
		p.pending = nil
	}
}

func (p *localProcess) failProtocol(err error) {
	p.fatalOnce.Do(func() {
		p.responseMu.Lock()
		p.fatal = err
		close(p.fatalCh)
		p.responseMu.Unlock()
		p.closeStdin()
		if p.command.Process != nil {
			_ = signalProcessGroup(p.command.Process.Pid, syscall.SIGKILL)
		}
	})
}

func (p *localProcess) fatalError() error {
	p.responseMu.Lock()
	defer p.responseMu.Unlock()
	if p.fatal == nil {
		return ErrTransport
	}
	return p.fatal
}

func writeAll(writer io.Writer, value []byte) error {
	for len(value) > 0 {
		written, err := writer.Write(value)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		value = value[written:]
	}
	return nil
}

func (h *LocalExecutable) failProcessLocked(process *localProcess) {
	h.stateMu.Lock()
	current := h.process == process
	if current {
		h.process = nil
		if !h.closed {
			h.nextStart = time.Now().Add(h.config.RestartBackoff)
		}
	}
	h.stateMu.Unlock()
	if !current {
		return
	}
	process.terminateAndReap(h.config.TerminationGrace)
}

func (h *LocalExecutable) clearProcess(process *localProcess) {
	h.stateMu.Lock()
	defer h.stateMu.Unlock()
	if h.process == process {
		h.process = nil
	}
}

func (p *localProcess) exited() bool {
	select {
	case <-p.done:
		return true
	default:
		return false
	}
}

func (p *localProcess) closeStdin() {
	p.closeInput.Do(func() {
		_ = p.stdin.Close()
	})
}

func (p *localProcess) closePipes() {
	p.closeStdin()
	p.closeOutput.Do(func() {
		_ = p.stdoutPipe.Close()
	})
}

func (p *localProcess) waitForReader() {
	<-p.readerDone
}

func (p *localProcess) terminateAndReap(grace time.Duration) {
	p.terminateOnce.Do(func() {
		defer close(p.terminated)
		p.closeStdin()
		if !p.exited() {
			_ = signalProcessGroup(p.command.Process.Pid, syscall.SIGTERM)
			timer := time.NewTimer(grace)
			select {
			case <-p.done:
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
			case <-timer.C:
				_ = signalProcessGroup(p.command.Process.Pid, syscall.SIGKILL)
				<-p.done
			}
		}
		p.killRemainingGroup()
		p.closePipes()
		p.waitForReader()
	})
	<-p.terminated
}

func (p *localProcess) killRemainingGroup() {
	if p.command.Process != nil {
		_ = signalProcessGroup(p.command.Process.Pid, syscall.SIGKILL)
	}
}

func configureProcessGroup(command *exec.Cmd) {
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

func signalProcessGroup(pid int, signal syscall.Signal) error {
	err := syscall.Kill(-pid, signal)
	if errors.Is(err, syscall.ESRCH) {
		return nil
	}
	return err
}
