package portal

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/creack/pty"
)

const (
	enrollmentStarting       = "starting"
	enrollmentActionRequired = "action-required"
	enrollmentSucceeded      = "success"
	enrollmentFailed         = "failure"
	enrollmentCancelled      = "cancelled"
	maxEnrollmentCodeBytes   = 8192
	codexCommand             = "codex"
	claudeCommand            = "claude"
	loginCommand             = "login"
	cliModeDevice            = "device"
	cliModePaste             = "paste"
	reasonProcessFailed      = "process-failed"
	reasonMalformedOutput    = "malformed-cli-output"
	//nolint:gosec // This is a fixed non-secret audit reason, not credential material.
	reasonCredentialUnsafe   = "credential-unsafe"
	reasonTimeout            = "timeout"
	reasonSecretUpdateFailed = "secret-update-failed"
	dynamicActionEnroll      = "enroll"
	dynamicActionReconnect   = "reconnect"
)

var (
	ErrEnrollmentNotFound = errors.New("enrollment session not found")
	ErrEnrollmentBusy     = errors.New("enrollment capacity is exhausted")
	ErrEnrollmentState    = errors.New("enrollment session state does not permit this operation")
	errMalformedCLIOutput = errors.New("credential CLI output was malformed")

	outputURLPattern  = regexp.MustCompile(`https://[^\s\x00-\x20\x7f]+`)
	deviceCodePattern = regexp.MustCompile(`\b[A-Z0-9]{3,12}(?:-[A-Z0-9]{3,12})+\b`)
	terminalCSI       = regexp.MustCompile(`\x1b\[[0-?]*[ -/]*[@-~]`)
)

type EnrollmentStatus struct {
	ID               string `json:"id"`
	Slot             string `json:"slot"`
	Adapter          string `json:"adapter"`
	Status           string `json:"status"`
	AuthorizationURL string `json:"authorizationURL,omitempty"`
	UserCode         string `json:"userCode,omitempty"`
	Reason           string `json:"reason,omitempty"`
	NeedsCode        bool   `json:"needsCode,omitempty"`
}

type cliEnrollmentAdapter struct {
	Name               string
	Command            string
	CredentialRelative string
	Mode               string
	Args               []string
	Environment        []string
}

type providerAction struct {
	AuthorizationURL string
	UserCode         string
	NeedsCode        bool
}

type enrollmentSession struct {
	ExpiresAt            time.Time
	EligibilityExpiresAt time.Time
	TerminalAt           time.Time
	Cancel               context.CancelFunc
	Code                 chan string
	Slot                 Slot
	Principal            Principal
	AuthorizationURL     string
	UserCode             string
	Reason               string
	ID                   string
	Status               string
	CancelReason         string
	DynamicAction        string
	OperationID          string
	NeedsCode            bool
	CodeUsed             bool
}

type CredentialRunner interface {
	Run(
		ctx context.Context,
		sessionID, adapter string,
		code <-chan string,
		publish func(providerAction),
	) ([]byte, string)
	Acknowledge(ctx context.Context, sessionID string) error
	Cancel(ctx context.Context, sessionID string) error
	Ready(ctx context.Context) error
}

//nolint:govet // Adapter, limits, and temp-root grouping keeps the trusted runner configuration easy to audit.
type CLICredentialRunner struct {
	adapters map[string]cliEnrollmentAdapter
	config   EnrollmentConfig
	tempRoot string
}

type EnrollmentManager struct {
	patcher   SecretPatcher
	broker    PrincipalAccountBroker
	audit     *AuditLogger
	runner    CredentialRunner
	sessions  map[string]*enrollmentSession
	semaphore chan struct{}
	now       func() time.Time
	namespace string
	config    EnrollmentConfig
	mu        sync.Mutex
	wg        sync.WaitGroup
}

type cliRead struct {
	Err  error
	Data []byte
}

func defaultEnrollmentAdapters() map[string]cliEnrollmentAdapter {
	return map[string]cliEnrollmentAdapter{
		AdapterCodexOAuthFile: {
			Name: AdapterCodexOAuthFile, Command: codexCommand, Args: []string{loginCommand, "--device-auth"},
			CredentialRelative: filepath.Join(".codex", "auth.json"), Mode: cliModeDevice,
		},
		AdapterClaudeOAuthFile: {
			Name: AdapterClaudeOAuthFile, Command: claudeCommand, Args: []string{"auth", loginCommand, "--claudeai"},
			CredentialRelative: filepath.Join(".claude", ".credentials.json"), Mode: cliModePaste,
		},
	}
}

func NewEnrollmentManager(
	cfg Config,
	patcher SecretPatcher,
	audit *AuditLogger,
	runner CredentialRunner,
	brokers ...PrincipalAccountBroker,
) *EnrollmentManager {
	manager := &EnrollmentManager{
		patcher:   patcher,
		audit:     audit,
		runner:    runner,
		sessions:  map[string]*enrollmentSession{},
		namespace: cfg.Namespace,
		semaphore: make(chan struct{}, cfg.Enrollment.MaxConcurrent),
		now:       time.Now,
		config:    cfg.Enrollment,
	}
	if len(brokers) == 1 {
		manager.broker = brokers[0]
	}
	return manager
}

func (m *EnrollmentManager) Start(
	ctx context.Context,
	principal Principal,
	slot Slot,
	authExpiresAt time.Time,
) (EnrollmentStatus, error) {
	if !principal.Owns(slot) {
		return EnrollmentStatus{}, ErrEnrollmentNotFound
	}
	return m.start(ctx, principal, slot, "", authExpiresAt)
}

func (m *EnrollmentManager) StartDynamic(
	ctx context.Context,
	principal Principal,
	template DynamicCredentialTemplate,
	action string,
	authExpiresAt time.Time,
) (EnrollmentStatus, error) {
	if m.broker == nil || (action != dynamicActionEnroll && action != dynamicActionReconnect) {
		return EnrollmentStatus{}, ErrEnrollmentState
	}
	slot := Slot{
		Name: template.Name, Label: template.Label, Adapter: template.Adapter, Owner: principal,
	}
	return m.start(ctx, principal, slot, action, authExpiresAt)
}

func (m *EnrollmentManager) start(
	ctx context.Context,
	principal Principal,
	slot Slot,
	dynamicAction string,
	authExpiresAt time.Time,
) (EnrollmentStatus, error) {
	select {
	case m.semaphore <- struct{}{}:
	default:
		return EnrollmentStatus{}, ErrEnrollmentBusy
	}
	id, err := randomToken(32)
	if err != nil {
		<-m.semaphore
		return EnrollmentStatus{}, fmt.Errorf("create enrollment identifier: %w", err)
	}
	operationID := ""
	if dynamicAction != "" {
		operationID, err = randomToken(32)
		if err != nil {
			<-m.semaphore
			return EnrollmentStatus{}, fmt.Errorf("create broker operation identifier: %w", err)
		}
	}
	now := m.now()
	deadline := now.Add(time.Duration(m.config.TimeoutSeconds) * time.Second)
	if authExpiresAt.Before(deadline) {
		deadline = authExpiresAt
	}
	if !deadline.After(now) {
		<-m.semaphore
		return EnrollmentStatus{}, ErrEnrollmentState
	}
	enrollmentContext, cancel := context.WithDeadline(context.WithoutCancel(ctx), deadline)
	session := &enrollmentSession{
		Cancel: cancel, Code: make(chan string, 1), ID: id, Status: enrollmentStarting,
		Principal: principal, Slot: slot, ExpiresAt: deadline,
		EligibilityExpiresAt: authExpiresAt, DynamicAction: dynamicAction,
		OperationID: operationID,
	}
	m.mu.Lock()
	m.pruneLocked(now)
	if len(m.sessions) >= m.config.MaxSessions {
		m.mu.Unlock()
		cancel()
		<-m.semaphore
		return EnrollmentStatus{}, ErrEnrollmentBusy
	}
	m.sessions[id] = session
	initialStatus := publicEnrollmentStatus(session)
	m.wg.Add(1)
	m.mu.Unlock()
	m.audit.Enrollment(principal, slot, "attempt", "")
	go func() {
		defer m.wg.Done()
		m.run(enrollmentContext, session)
	}()

	return initialStatus, nil
}

func (m *EnrollmentManager) Status(principal Principal, id string) (EnrollmentStatus, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pruneLocked(m.now())
	session, ok := m.sessions[id]
	if !ok || !samePrincipal(session.Principal, principal) {
		return EnrollmentStatus{}, ErrEnrollmentNotFound
	}

	return publicEnrollmentStatus(session), nil
}

func (m *EnrollmentManager) ProvideCode(principal Principal, id, code string) error {
	if !validEnrollmentCode(code) {
		return ErrEnrollmentState
	}
	m.mu.Lock()
	session, ok := m.sessions[id]
	if !ok || !samePrincipal(session.Principal, principal) {
		m.mu.Unlock()
		return ErrEnrollmentNotFound
	}
	if session.Status != enrollmentActionRequired || !session.NeedsCode || session.CodeUsed {
		m.mu.Unlock()
		return ErrEnrollmentState
	}
	session.CodeUsed = true
	codeChannel := session.Code
	m.mu.Unlock()
	codeChannel <- code

	return nil
}

func (m *EnrollmentManager) Cancel(principal Principal, id string) error {
	m.mu.Lock()
	session, ok := m.sessions[id]
	if !ok || !samePrincipal(session.Principal, principal) {
		m.mu.Unlock()
		return ErrEnrollmentNotFound
	}
	if terminalEnrollmentStatus(session.Status) || session.CancelReason != "" {
		m.mu.Unlock()
		return ErrEnrollmentState
	}
	m.cancelLocked(session, "cancelled")
	m.mu.Unlock()

	return nil
}

func (m *EnrollmentManager) CancelPrincipal(principal Principal) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, session := range m.sessions {
		if samePrincipal(session.Principal, principal) && !terminalEnrollmentStatus(session.Status) &&
			session.CancelReason == "" {
			m.cancelLocked(session, "logout")
		}
	}
}

func (m *EnrollmentManager) Close() {
	m.mu.Lock()
	for _, session := range m.sessions {
		if !terminalEnrollmentStatus(session.Status) && session.CancelReason == "" {
			m.cancelLocked(session, "shutdown")
		}
	}
	m.mu.Unlock()
	m.wg.Wait()
}

func (m *EnrollmentManager) cancelLocked(session *enrollmentSession, reason string) {
	session.CancelReason = reason
	session.AuthorizationURL = ""
	session.UserCode = ""
	session.Cancel()
}

//nolint:nestif // Validation, exact patching, acknowledgment, and cleanup form one ordered fail-closed transition.
func (m *EnrollmentManager) run(ctx context.Context, session *enrollmentSession) {
	document, reason := m.runner.Run(ctx, session.ID, session.Slot.Adapter, session.Code, func(action providerAction) {
		m.publishAction(session, action)
	})
	defer clearBytes(document)
	status := enrollmentSucceeded
	if reason != "" {
		status = enrollmentFailed
	}
	m.mu.Lock()
	if session.CancelReason != "" {
		status, reason = enrollmentCancelled, session.CancelReason
	}
	m.mu.Unlock()
	if status == enrollmentSucceeded {
		if err := ValidateCredential(session.Slot.Adapter, document); err != nil {
			status, reason = enrollmentFailed, "invalid-credential"
		} else if session.DynamicAction != "" {
			var completionError error
			switch session.DynamicAction {
			case dynamicActionEnroll:
				completionError = m.broker.CompleteEnrollment(
					ctx, session.Principal, session.Slot.Name, session.OperationID,
					document, session.EligibilityExpiresAt,
				)
			case dynamicActionReconnect:
				completionError = m.broker.Reconnect(
					ctx, session.Principal, session.OperationID, document, session.EligibilityExpiresAt,
				)
			default:
				completionError = ErrBrokerRejected
			}
			if completionError != nil {
				status, reason = enrollmentFailed, brokerCompletionReason(completionError)
			}
		} else if err := m.patcher.Patch(
			ctx, m.namespace, session.Slot.SecretName, session.Slot.DataKey, document,
		); err != nil {
			status, reason = enrollmentFailed, reasonSecretUpdateFailed
		}
		if status == enrollmentSucceeded {
			ackContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
			ackErr := m.runner.Acknowledge(ackContext, session.ID)
			cancel()
			if ackErr != nil {
				status, reason = enrollmentFailed, "runner-acknowledgment-failed"
			}
		}
	}
	if status != enrollmentSucceeded {
		cancelContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		ignoreCleanupError(m.runner.Cancel(cancelContext, session.ID))
		cancel()
	}
	// Capacity is available before the terminal state becomes observable. This
	// makes terminal status imply that process teardown and cleanup completed.
	<-m.semaphore
	m.finish(session, status, reason)
}

func NewCLICredentialRunner(config EnrollmentConfig) *CLICredentialRunner {
	return &CLICredentialRunner{adapters: defaultEnrollmentAdapters(), config: config}
}

func (r *CLICredentialRunner) Acknowledge(_ context.Context, _ string) error { return nil }
func (r *CLICredentialRunner) Cancel(_ context.Context, _ string) error      { return nil }
func (r *CLICredentialRunner) Ready(_ context.Context) error                 { return nil }

func (r *CLICredentialRunner) Run(
	ctx context.Context,
	_ string,
	adapterName string,
	code <-chan string,
	publish func(providerAction),
) ([]byte, string) {
	adapter, ok := r.adapters[adapterName]
	if !ok {
		return nil, "adapter-unavailable"
	}
	home, err := os.MkdirTemp(r.tempRoot, "nvt-credential-enrollment-")
	if err != nil {
		return nil, "runner-start-failed"
	}
	document, reason := r.runCLI(ctx, adapter, home, code, publish)
	if removeErr := os.RemoveAll(home); removeErr != nil {
		clearBytes(document)
		return nil, "cleanup-failed"
	}

	return document, reason
}

//nolint:gocognit,gocyclo // The process state machine keeps output, input, timeout, and exit handling fail-closed.
func (r *CLICredentialRunner) runCLI(
	ctx context.Context,
	adapter cliEnrollmentAdapter,
	home string,
	code <-chan string,
	publish func(providerAction),
) ([]byte, string) {
	// #nosec G204,G702 -- commands and arguments come only from compiled, trusted adapters.
	command := exec.CommandContext(ctx, adapter.Command, adapter.Args...)
	command.Dir = home
	command.Env = isolatedCLIEnvironment(home, adapter.Environment)
	terminal, err := pty.Start(command)
	if err != nil {
		return nil, "runner-start-failed"
	}
	reads := make(chan cliRead, 1)
	readerDone := make(chan struct{})
	defer close(readerDone)
	go readCLI(terminal, reads, readerDone)
	var output []byte
	actionSeen := false
	for {
		select {
		case <-ctx.Done():
			stopCLI(command, terminal)
			return nil, reasonTimeout
		case providedCode := <-code:
			input := append([]byte(providedCode), '\n')
			_, writeErr := terminal.Write(input)
			clearBytes(input)
			if writeErr != nil {
				stopCLI(command, terminal)
				return nil, reasonProcessFailed
			}
			clearString(&providedCode)
		case result := <-reads:
			if len(result.Data) > 0 {
				if len(output)+len(result.Data) > r.config.MaxOutputBytes {
					clearBytes(result.Data)
					stopCLI(command, terminal)
					clearBytes(output)
					return nil, "output-too-large"
				}
				output = append(output, result.Data...)
				clearBytes(result.Data)
				action, found, parseErr := adapter.action(output)
				if parseErr != nil {
					stopCLI(command, terminal)
					clearBytes(output)
					return nil, reasonMalformedOutput
				}
				if found && !actionSeen {
					actionSeen = true
					publish(action)
				}
			}
			if result.Err == nil {
				continue
			}
			waitErr := command.Wait()
			closeErr := terminal.Close()
			clearBytes(output)
			if ctx.Err() != nil {
				return nil, reasonTimeout
			}
			if waitErr != nil || closeErr != nil {
				return nil, reasonProcessFailed
			}
			if !actionSeen {
				return nil, reasonMalformedOutput
			}

			return readCredentialFile(home, adapter.CredentialRelative, int64(r.config.MaxOutputBytes))
		}
	}
}

func readCLI(terminal *os.File, results chan<- cliRead, done <-chan struct{}) {
	buffer := make([]byte, 4096)
	for {
		count, err := terminal.Read(buffer)
		chunk := append([]byte(nil), buffer[:count]...)
		select {
		case results <- cliRead{Data: chunk, Err: err}:
		case <-done:
			clearBytes(chunk)
			return
		}
		if err != nil {
			return
		}
	}
}

func stopCLI(command *exec.Cmd, terminal *os.File) {
	if command.Process != nil {
		ignoreCleanupError(syscall.Kill(-command.Process.Pid, syscall.SIGKILL))
		ignoreCleanupError(command.Process.Kill())
	}
	ignoreCleanupError(terminal.Close())
	ignoreCleanupError(command.Wait())
}

func ignoreCleanupError(_ error) {}

func (m *EnrollmentManager) publishAction(session *enrollmentSession, action providerAction) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if terminalEnrollmentStatus(session.Status) {
		return
	}
	session.Status = enrollmentActionRequired
	session.AuthorizationURL = action.AuthorizationURL
	session.UserCode = action.UserCode
	session.NeedsCode = action.NeedsCode
}

func (m *EnrollmentManager) finish(session *enrollmentSession, status, reason string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if terminalEnrollmentStatus(session.Status) {
		return
	}
	session.Status = status
	session.Reason = reason
	session.TerminalAt = m.now()
	session.AuthorizationURL = ""
	session.UserCode = ""
	session.Cancel()
	if status == enrollmentSucceeded {
		m.audit.Enrollment(session.Principal, session.Slot, "success", "")
		return
	}
	m.audit.Enrollment(session.Principal, session.Slot, "failure", reason)
}

func (m *EnrollmentManager) pruneLocked(now time.Time) {
	for id, session := range m.sessions {
		if terminalEnrollmentStatus(session.Status) && now.After(session.TerminalAt.Add(time.Minute)) {
			delete(m.sessions, id)
		}
	}
}

func publicEnrollmentStatus(session *enrollmentSession) EnrollmentStatus {
	return EnrollmentStatus{
		ID: session.ID, Slot: session.Slot.Name, Adapter: session.Slot.Adapter, Status: session.Status,
		AuthorizationURL: session.AuthorizationURL, UserCode: session.UserCode, Reason: session.Reason,
		NeedsCode: session.NeedsCode,
	}
}

func (adapter cliEnrollmentAdapter) action(output []byte) (providerAction, bool, error) {
	if len(output) == 0 || !utf8.Valid(output) {
		return providerAction{}, false, nil
	}
	urls := enrollmentOutputURLs(output)
	switch adapter.Mode {
	case cliModeDevice:
		return codexDeviceAction(output, urls)
	case cliModePaste:
		return claudePasteAction(urls)
	default:
		return providerAction{}, false, errMalformedCLIOutput
	}
}

func enrollmentOutputURLs(output []byte) []*url.URL {
	result := []*url.URL{}
	urls := outputURLPattern.FindAllString(string(output), -1)
	for _, raw := range urls {
		parsed, err := url.Parse(strings.TrimRight(raw, ").,;\"'"))
		if err != nil || parsed.Scheme != httpsScheme || parsed.User != nil || parsed.Port() != "" ||
			parsed.Fragment != "" {
			continue
		}
		result = append(result, parsed)
	}
	return result
}

func codexDeviceAction(output []byte, urls []*url.URL) (providerAction, bool, error) {
	for _, parsed := range urls {
		if parsed.Hostname() != "auth.openai.com" || parsed.Path != "/codex/device" || parsed.RawQuery != "" {
			continue
		}
		plainOutput := terminalCSI.ReplaceAll(output, nil)
		code := deviceCodePattern.FindString(string(plainOutput))
		clearBytes(plainOutput)
		if code == "" {
			return providerAction{}, false, nil
		}
		return providerAction{AuthorizationURL: parsed.String(), UserCode: code}, true, nil
	}
	return providerAction{}, false, nil
}

func claudePasteAction(urls []*url.URL) (providerAction, bool, error) {
	for _, parsed := range urls {
		if parsed.Hostname() == "claude.com" && parsed.Path == "/cai/oauth/authorize" {
			return providerAction{AuthorizationURL: parsed.String(), NeedsCode: true}, true, nil
		}
	}
	return providerAction{}, false, nil
}

func readCredentialFile(home, relative string, limit int64) ([]byte, string) {
	credentialPath := filepath.Join(home, relative)
	info, err := os.Lstat(credentialPath)
	if err != nil {
		return nil, "credential-missing"
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > limit {
		return nil, reasonCredentialUnsafe
	}
	// #nosec G304 -- the path is a fixed adapter-relative path below a private home after the CLI exits.
	file, err := os.Open(credentialPath)
	if err != nil {
		return nil, "credential-missing"
	}
	document, readErr := io.ReadAll(io.LimitReader(file, limit+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || int64(len(document)) > limit {
		clearBytes(document)
		return nil, reasonCredentialUnsafe
	}

	return document, ""
}

func isolatedCLIEnvironment(home string, extra []string) []string {
	environment := []string{
		"HOME=" + home,
		"XDG_CONFIG_HOME=" + filepath.Join(home, ".config"),
		"TMPDIR=" + home,
		"BROWSER=/bin/false",
		"LANG=C.UTF-8",
		"TERM=xterm-256color",
	}
	for _, name := range []string{
		"PATH", "HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "NO_PROXY", "SSL_CERT_FILE", "SSL_CERT_DIR",
		"NODE_EXTRA_CA_CERTS",
	} {
		if value, ok := os.LookupEnv(name); ok {
			environment = append(environment, name+"="+value)
		}
	}

	return append(environment, extra...)
}

func validEnrollmentCode(code string) bool {
	if code == "" || len(code) > maxEnrollmentCodeBytes || !utf8.ValidString(code) || strings.TrimSpace(code) != code {
		return false
	}
	for _, character := range code {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}

	return true
}

func terminalEnrollmentStatus(status string) bool {
	return status == enrollmentSucceeded || status == enrollmentFailed || status == enrollmentCancelled
}

func samePrincipal(left, right Principal) bool {
	return left.Issuer == right.Issuer && left.Subject == right.Subject
}

func clearBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func clearString(value *string) {
	*value = ""
}
