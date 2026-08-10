package portal

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	runnerTimestampHeader   = "X-Nvt-Runner-Timestamp"
	runnerNonceHeader       = "X-Nvt-Runner-Nonce"
	runnerSignatureHeader   = "X-Nvt-Runner-Signature"
	runnerStatusRunning     = "running"
	runnerStatusSuccess     = "success"
	runnerStatusFailure     = "failure"
	runnerStatusReady       = "ready"
	runnerMaxClockSkew      = 30 * time.Second
	runnerMaxRequestBytes   = 12 * 1024
	runnerPollInterval      = 20 * time.Millisecond
	runnerKeyBytes          = 32
	minimumRunnerKeyBytes   = 32
	reasonRunnerUnavailable = "runner-unavailable"
)

var (
	runnerIDPattern          = regexp.MustCompile(`^[A-Za-z0-9_-]{32,64}$`)
	errInvalidRunnerServer   = errors.New("invalid credential runner server configuration")
	errInvalidRunnerClient   = errors.New("invalid credential runner client configuration")
	errRunnerRequestRejected = errors.New("credential runner rejected request")
	errInvalidRunnerKey      = errors.New("invalid runner key")
)

type runnerStartRequest struct {
	Adapter   string `json:"adapter"`
	ExpiresAt int64  `json:"expiresAt"`
}

type runnerCodeRequest struct {
	Code string `json:"code"`
}

type runnerResponse struct {
	AuthorizationURL string `json:"authorizationURL,omitempty"`
	UserCode         string `json:"userCode,omitempty"`
	Reason           string `json:"reason,omitempty"`
	Status           string `json:"status"`
	Document         []byte `json:"document,omitempty"`
	NeedsCode        bool   `json:"needsCode,omitempty"`
}

//nolint:govet // Keeping the security-sensitive runner state grouped by lifecycle is clearer than padding-driven order.
type runnerSession struct {
	cancel           context.CancelFunc
	code             chan string
	done             chan struct{}
	document         []byte
	authorizationURL string
	userCode         string
	reason           string
	status           string
	needsCode        bool
	codeUsed         bool
	expiresAt        time.Time
	timer            *time.Timer
}

//nolint:govet // Keeping dependencies, state maps, and synchronization grouped makes the boundary auditable.
type RunnerServer struct {
	runner    CredentialRunner
	key       []byte
	sessions  map[string]*runnerSession
	seenIDs   map[string]time.Time
	ackedIDs  map[string]time.Time
	nonces    map[string]time.Time
	semaphore chan struct{}
	config    EnrollmentConfig
	now       func() time.Time
	mu        sync.Mutex
	wg        sync.WaitGroup
}

//nolint:govet // Dependency and protocol-limit grouping is more useful here than a small padding reduction.
type HTTPRunnerClient struct {
	client         *http.Client
	baseURL        *url.URL
	key            []byte
	maxOutputBytes int
	now            func() time.Time
}

func NewRunnerServer(key []byte, config EnrollmentConfig, runner CredentialRunner) (*RunnerServer, error) {
	if len(key) < minimumRunnerKeyBytes || runner == nil || config.MaxSessions < 1 || config.MaxSessions > 256 ||
		config.MaxConcurrent < 1 || config.MaxConcurrent > 8 || config.MaxConcurrent > config.MaxSessions ||
		config.TimeoutSeconds < 60 || config.TimeoutSeconds > 1800 || config.MaxOutputBytes < 4096 ||
		config.MaxOutputBytes > 1024*1024 {
		return nil, errInvalidRunnerServer
	}

	return &RunnerServer{
		runner: runner, key: bytes.Clone(key), config: config, now: time.Now,
		sessions: map[string]*runnerSession{}, seenIDs: map[string]time.Time{}, ackedIDs: map[string]time.Time{},
		nonces:    map[string]time.Time{},
		semaphore: make(chan struct{}, config.MaxConcurrent),
	}, nil
}

func NewHTTPRunnerClient(rawURL string, key []byte, maxOutputBytes int) (*HTTPRunnerClient, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme != "http" || parsed.Hostname() != "127.0.0.1" || parsed.Port() == "" ||
		parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" ||
		len(key) < minimumRunnerKeyBytes || maxOutputBytes < 4096 || maxOutputBytes > 1024*1024 {
		return nil, errInvalidRunnerClient
	}

	return &HTTPRunnerClient{
		client: &http.Client{Timeout: 15 * time.Second}, baseURL: parsed, key: bytes.Clone(key),
		maxOutputBytes: maxOutputBytes, now: time.Now,
	}, nil
}

func (c *HTTPRunnerClient) Run(
	ctx context.Context,
	sessionID, adapter string,
	code <-chan string,
	publish func(providerAction),
) ([]byte, string) {
	deadline, ok := ctx.Deadline()
	if !ok {
		return nil, reasonRunnerUnavailable
	}
	start := runnerStartRequest{Adapter: adapter, ExpiresAt: deadline.Unix()}
	if _, err := c.request(ctx, http.MethodPost, "/v1/sessions/"+sessionID, start); err != nil {
		c.cancelRemote(ctx, sessionID)
		return nil, reasonRunnerUnavailable
	}
	ticker := time.NewTicker(runnerPollInterval)
	defer ticker.Stop()
	actionPublished := false
	for {
		select {
		case <-ctx.Done():
			c.cancelRemote(ctx, sessionID)
			return nil, reasonTimeout
		case providedCode := <-code:
			_, err := c.request(
				ctx,
				http.MethodPost,
				"/v1/sessions/"+sessionID+"/code",
				runnerCodeRequest{Code: providedCode},
			)
			clearString(&providedCode)
			if err != nil {
				c.cancelRemote(ctx, sessionID)
				return nil, reasonRunnerUnavailable
			}
		case <-ticker.C:
			response, err := c.request(ctx, http.MethodGet, "/v1/sessions/"+sessionID, nil)
			if err != nil {
				c.cancelRemote(ctx, sessionID)
				return nil, reasonRunnerUnavailable
			}
			switch response.Status {
			case runnerStatusRunning:
				if response.AuthorizationURL != "" && !actionPublished {
					actionPublished = true
					publish(providerAction{
						AuthorizationURL: response.AuthorizationURL,
						UserCode:         response.UserCode,
						NeedsCode:        response.NeedsCode,
					})
				}
			case runnerStatusSuccess:
				return response.Document, ""
			case runnerStatusFailure:
				c.cancelRemote(ctx, sessionID)
				return nil, response.Reason
			default:
				clearBytes(response.Document)
				c.cancelRemote(ctx, sessionID)
				return nil, reasonRunnerUnavailable
			}
		}
	}
}

func (c *HTTPRunnerClient) Acknowledge(ctx context.Context, sessionID string) error {
	var lastErr error
	for range 3 {
		_, err := c.request(ctx, http.MethodPost, "/v1/sessions/"+sessionID+"/ack", nil)
		if err == nil {
			return nil
		}
		lastErr = err
		select {
		case <-ctx.Done():
			return fmt.Errorf("acknowledge runner result: %w", ctx.Err())
		case <-time.After(runnerPollInterval):
		}
	}

	return lastErr
}

func (c *HTTPRunnerClient) Cancel(ctx context.Context, sessionID string) error {
	_, err := c.request(ctx, http.MethodDelete, "/v1/sessions/"+sessionID, nil)

	return err
}

func (c *HTTPRunnerClient) Ready(ctx context.Context) error {
	response, err := c.request(ctx, http.MethodGet, "/readyz", nil)
	if err != nil {
		return err
	}
	if response.Status != runnerStatusReady {
		return errRunnerRequestRejected
	}

	return nil
}

func (c *HTTPRunnerClient) cancelRemote(ctx context.Context, sessionID string) {
	cancelContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	ignoreCleanupError(c.Cancel(cancelContext, sessionID))
	cancel()
}

func (c *HTTPRunnerClient) request(
	ctx context.Context,
	method, path string,
	requestBody any,
) (runnerResponse, error) {
	var body []byte
	var err error
	if requestBody != nil {
		body, err = json.Marshal(requestBody)
		if err != nil {
			return runnerResponse{}, fmt.Errorf("encode runner request: %w", err)
		}
	}
	payload := bytes.Clone(body)
	request, err := http.NewRequestWithContext(
		ctx,
		method,
		c.baseURL.String()+path,
		bytes.NewReader(payload),
	)
	if err != nil {
		clearBytes(body)
		clearBytes(payload)
		return runnerResponse{}, fmt.Errorf("create runner request: %w", err)
	}
	if len(body) > 0 {
		request.Header.Set("Content-Type", jsonContentType)
	}
	if signErr := signRunnerRequest(request, body, c.key, c.now()); signErr != nil {
		clearBytes(body)
		clearBytes(payload)
		return runnerResponse{}, signErr
	}
	clearBytes(body)
	response, err := c.client.Do(request)
	clearBytes(payload)
	if err != nil {
		return runnerResponse{}, fmt.Errorf("call credential runner: %w", err)
	}
	defer func() { ignoreCleanupError(response.Body.Close()) }()
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusAccepted {
		_, copyErr := io.Copy(io.Discard, io.LimitReader(response.Body, 1024))
		ignoreCleanupError(copyErr)
		return runnerResponse{}, errRunnerRequestRejected
	}
	var result runnerResponse
	decoder := json.NewDecoder(io.LimitReader(response.Body, int64(c.maxOutputBytes)*2+4096))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return runnerResponse{}, fmt.Errorf("decode credential runner response: %w", err)
	}

	return result, nil
}

//nolint:cyclop,gocyclo // Central routing keeps authentication and the fixed protocol operations in one fail-closed gate.
func (s *RunnerServer) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Content-Type", jsonContentType)
	response.Header().Set("X-Content-Type-Options", "nosniff")
	if request.URL.RawQuery != "" {
		http.NotFound(response, request)
		return
	}
	if request.URL.Path == "/healthz" && request.Method == http.MethodGet {
		response.WriteHeader(http.StatusOK)
		return
	}
	body, ok := readRunnerBody(response, request)
	if !ok {
		return
	}
	defer clearBytes(body)
	if !s.authenticate(request, body) {
		http.Error(response, "unauthorized", http.StatusUnauthorized)
		return
	}
	if request.URL.Path == "/readyz" && request.Method == http.MethodGet && request.URL.RawQuery == "" {
		writeRunnerJSON(response, http.StatusOK, runnerResponse{Status: runnerStatusReady})
		return
	}
	parts := strings.Split(strings.TrimPrefix(request.URL.Path, "/v1/sessions/"), "/")
	if !strings.HasPrefix(request.URL.Path, "/v1/sessions/") || len(parts) < 1 || len(parts) > 2 ||
		!runnerIDPattern.MatchString(parts[0]) {
		http.NotFound(response, request)
		return
	}
	switch {
	case len(parts) == 1 && request.Method == http.MethodPost:
		s.start(context.WithoutCancel(request.Context()), response, parts[0], body)
	case len(parts) == 1 && request.Method == http.MethodGet:
		s.status(response, parts[0])
	case len(parts) == 1 && request.Method == http.MethodDelete:
		s.cancel(response, parts[0])
	case len(parts) == 2 && parts[1] == "code" && request.Method == http.MethodPost:
		s.provideCode(response, parts[0], body)
	case len(parts) == 2 && parts[1] == "ack" && request.Method == http.MethodPost:
		s.acknowledge(response, parts[0])
	default:
		http.NotFound(response, request)
	}
}

func (s *RunnerServer) start(baseContext context.Context, response http.ResponseWriter, id string, body []byte) {
	var start runnerStartRequest
	if !strictRunnerJSON(body, &start) ||
		(start.Adapter != AdapterCodexOAuthFile && start.Adapter != AdapterClaudeOAuthFile) {
		http.Error(response, "invalid request", http.StatusBadRequest)
		return
	}
	now := s.now()
	requestedDeadline := time.Unix(start.ExpiresAt, 0)
	maximumDeadline := now.Add(time.Duration(s.config.TimeoutSeconds) * time.Second)
	if !requestedDeadline.After(now) || requestedDeadline.After(maximumDeadline.Add(time.Second)) {
		http.Error(response, "invalid request", http.StatusBadRequest)
		return
	}
	select {
	case s.semaphore <- struct{}{}:
	default:
		http.Error(response, "busy", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithDeadline(baseContext, requestedDeadline)
	session := &runnerSession{
		cancel: cancel, code: make(chan string, 1), done: make(chan struct{}), status: runnerStatusRunning,
		expiresAt: requestedDeadline,
	}
	s.mu.Lock()
	s.pruneLocked(now)
	if _, exists := s.seenIDs[id]; exists || len(s.sessions) >= s.config.MaxSessions {
		s.mu.Unlock()
		cancel()
		<-s.semaphore
		http.Error(response, "rejected", http.StatusConflict)
		return
	}
	s.seenIDs[id] = requestedDeadline.Add(runnerMaxClockSkew)
	s.sessions[id] = session
	s.wg.Add(1)
	session.timer = time.AfterFunc(time.Until(requestedDeadline), func() { s.expire(id, session) })
	s.mu.Unlock()
	go func() {
		defer s.wg.Done()
		s.run(ctx, id, start.Adapter, session)
	}()
	writeRunnerJSON(response, http.StatusAccepted, runnerResponse{Status: runnerStatusRunning})
}

func (s *RunnerServer) Close() {
	s.mu.Lock()
	for _, session := range s.sessions {
		session.cancel()
	}
	s.mu.Unlock()
	s.wg.Wait()
	s.mu.Lock()
	for id, session := range s.sessions {
		s.removeSessionLocked(id, session)
	}
	clearBytes(s.key)
	s.key = nil
	s.mu.Unlock()
}

func (s *RunnerServer) run(ctx context.Context, id, adapter string, session *runnerSession) {
	document, reason := s.runner.Run(ctx, id, adapter, session.code, func(action providerAction) {
		s.mu.Lock()
		if session.status == runnerStatusRunning {
			session.authorizationURL = action.AuthorizationURL
			session.userCode = action.UserCode
			session.needsCode = action.NeedsCode
		}
		s.mu.Unlock()
	})
	<-s.semaphore
	s.mu.Lock()
	if reason != "" {
		clearBytes(document)
		session.status, session.reason = runnerStatusFailure, reason
	} else {
		session.status, session.document = runnerStatusSuccess, document
	}
	session.authorizationURL, session.userCode = "", ""
	session.cancel()
	s.mu.Unlock()
	close(session.done)
}

func (s *RunnerServer) status(response http.ResponseWriter, id string) {
	s.mu.Lock()
	session, ok := s.sessions[id]
	if !ok {
		s.mu.Unlock()
		http.NotFound(response, nil)
		return
	}
	if !session.expiresAt.After(s.now()) {
		s.mu.Unlock()
		s.expire(id, session)
		http.NotFound(response, nil)
		return
	}
	result := runnerResponse{
		Status: session.status, AuthorizationURL: session.authorizationURL, UserCode: session.userCode,
		NeedsCode: session.needsCode, Reason: session.reason,
	}
	if session.status == runnerStatusSuccess {
		result.Document = bytes.Clone(session.document)
	}
	s.mu.Unlock()
	defer clearBytes(result.Document)
	writeRunnerJSON(response, http.StatusOK, result)
}

func (s *RunnerServer) provideCode(response http.ResponseWriter, id string, body []byte) {
	var request runnerCodeRequest
	if !strictRunnerJSON(body, &request) || !validEnrollmentCode(request.Code) {
		http.Error(response, "invalid request", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	session, ok := s.sessions[id]
	if !ok || session.status != runnerStatusRunning || !session.needsCode || session.codeUsed {
		s.mu.Unlock()
		http.Error(response, "rejected", http.StatusConflict)
		return
	}
	session.codeUsed = true
	codeChannel := session.code
	s.mu.Unlock()
	codeChannel <- request.Code
	clearString(&request.Code)
	writeRunnerJSON(response, http.StatusOK, runnerResponse{Status: runnerStatusRunning})
}

func (s *RunnerServer) cancel(response http.ResponseWriter, id string) {
	s.mu.Lock()
	session, ok := s.sessions[id]
	if ok {
		session.cancel()
	}
	s.mu.Unlock()
	if !ok {
		http.NotFound(response, nil)
		return
	}
	<-session.done
	s.mu.Lock()
	if current, exists := s.sessions[id]; exists && current == session {
		s.removeSessionLocked(id, session)
	}
	s.mu.Unlock()
	writeRunnerJSON(response, http.StatusOK, runnerResponse{Status: runnerStatusRunning})
}

func (s *RunnerServer) acknowledge(response http.ResponseWriter, id string) {
	now := s.now()
	s.mu.Lock()
	s.pruneLocked(now)
	if expiry, ok := s.ackedIDs[id]; ok && expiry.After(now) {
		s.mu.Unlock()
		writeRunnerJSON(response, http.StatusOK, runnerResponse{Status: runnerStatusSuccess})
		return
	}
	session, ok := s.sessions[id]
	if !ok || session.status != runnerStatusSuccess || !session.expiresAt.After(now) {
		s.mu.Unlock()
		http.Error(response, "rejected", http.StatusConflict)
		return
	}
	expiry := session.expiresAt.Add(runnerMaxClockSkew)
	s.removeSessionLocked(id, session)
	s.ackedIDs[id] = expiry
	s.mu.Unlock()
	writeRunnerJSON(response, http.StatusOK, runnerResponse{Status: runnerStatusSuccess})
}

func (s *RunnerServer) expire(id string, session *runnerSession) {
	session.cancel()
	<-session.done
	s.mu.Lock()
	if current, ok := s.sessions[id]; ok && current == session {
		s.removeSessionLocked(id, session)
	}
	s.mu.Unlock()
}

func (s *RunnerServer) removeSessionLocked(id string, session *runnerSession) {
	if session.timer != nil {
		session.timer.Stop()
	}
	clearBytes(session.document)
	session.document = nil
	delete(s.sessions, id)
}

func (s *RunnerServer) authenticate(request *http.Request, body []byte) bool {
	timestampText := request.Header.Get(runnerTimestampHeader)
	nonce := request.Header.Get(runnerNonceHeader)
	signatureText := request.Header.Get(runnerSignatureHeader)
	timestamp, err := strconv.ParseInt(timestampText, 10, 64)
	if err != nil || !runnerIDPattern.MatchString(nonce) {
		return false
	}
	now := s.now()
	requestTime := time.Unix(timestamp, 0)
	if requestTime.Before(now.Add(-runnerMaxClockSkew)) || requestTime.After(now.Add(runnerMaxClockSkew)) {
		return false
	}
	provided, err := base64.RawURLEncoding.DecodeString(signatureText)
	if err != nil {
		return false
	}
	expected := runnerRequestSignature(request.Method, request.URL.EscapedPath(), timestampText, nonce, body, s.key)
	valid := subtle.ConstantTimeCompare(provided, expected) == 1
	clearBytes(provided)
	clearBytes(expected)
	if !valid {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)
	if _, replayed := s.nonces[nonce]; replayed {
		return false
	}
	s.nonces[nonce] = now.Add(runnerMaxClockSkew)

	return true
}

func (s *RunnerServer) pruneLocked(now time.Time) {
	for nonce, expiry := range s.nonces {
		if !expiry.After(now) {
			delete(s.nonces, nonce)
		}
	}
	for id, expiry := range s.seenIDs {
		if !expiry.After(now) {
			delete(s.seenIDs, id)
		}
	}
	for id, expiry := range s.ackedIDs {
		if !expiry.After(now) {
			delete(s.ackedIDs, id)
		}
	}
}

func signRunnerRequest(request *http.Request, body, key []byte, now time.Time) error {
	nonceBytes := make([]byte, runnerKeyBytes)
	if _, err := rand.Read(nonceBytes); err != nil {
		return fmt.Errorf("generate runner request nonce: %w", err)
	}
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)
	clearBytes(nonceBytes)
	timestamp := strconv.FormatInt(now.Unix(), 10)
	signature := runnerRequestSignature(request.Method, request.URL.EscapedPath(), timestamp, nonce, body, key)
	request.Header.Set(runnerTimestampHeader, timestamp)
	request.Header.Set(runnerNonceHeader, nonce)
	request.Header.Set(runnerSignatureHeader, base64.RawURLEncoding.EncodeToString(signature))
	clearBytes(signature)

	return nil
}

func runnerRequestSignature(method, path, timestamp, nonce string, body, key []byte) []byte {
	digest := sha256.Sum256(body)
	message := strings.Join([]string{method, path, timestamp, nonce, hex.EncodeToString(digest[:])}, "\n")
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(message))

	return mac.Sum(nil)
}

func readRunnerBody(response http.ResponseWriter, request *http.Request) ([]byte, bool) {
	if request.ContentLength > runnerMaxRequestBytes {
		http.Error(response, "request too large", http.StatusRequestEntityTooLarge)
		return nil, false
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, runnerMaxRequestBytes+1))
	if err != nil || len(body) > runnerMaxRequestBytes {
		clearBytes(body)
		http.Error(response, "request too large", http.StatusRequestEntityTooLarge)
		return nil, false
	}

	return body, true
}

func strictRunnerJSON(body []byte, target any) bool {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	return decoder.Decode(target) == nil && decoder.Decode(&struct{}{}) == io.EOF
}

func writeRunnerJSON(response http.ResponseWriter, status int, value runnerResponse) {
	response.WriteHeader(status)
	ignoreCleanupError(json.NewEncoder(response).Encode(value))
}

func GenerateRunnerKeyFile(path string) error {
	key := make([]byte, runnerKeyBytes)
	if _, err := rand.Read(key); err != nil {
		return fmt.Errorf("generate runner key: %w", err)
	}
	defer clearBytes(key)
	encoded := []byte(base64.RawURLEncoding.EncodeToString(key))
	defer clearBytes(encoded)
	// #nosec G302,G304 -- the fixed tmpfs path needs group-read for the two distinct container UIDs.
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o440)
	if err != nil {
		return fmt.Errorf("create runner key: %w", err)
	}
	if _, err := file.Write(encoded); err != nil {
		ignoreCleanupError(file.Close())
		return fmt.Errorf("write runner key: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close runner key: %w", err)
	}

	return nil
}

func ReadRunnerKey(path string) ([]byte, error) {
	// #nosec G304 -- the chart fixes this path to a private per-pod tmpfs volume.
	encoded, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read runner key: %w", err)
	}
	defer clearBytes(encoded)
	if len(encoded) > 128 || bytes.ContainsAny(encoded, "\r\n\t ") {
		return nil, errInvalidRunnerKey
	}
	key := make([]byte, base64.RawURLEncoding.DecodedLen(len(encoded)))
	count, err := base64.RawURLEncoding.Decode(key, encoded)
	if err != nil || count != runnerKeyBytes {
		clearBytes(key)
		return nil, errInvalidRunnerKey
	}

	return key[:count], nil
}
