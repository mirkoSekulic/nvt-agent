package controller

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/mirkoSekulic/nvt-agent/protocol/resolvedrun"
)

const (
	SchedulingAPIVersion = "nvt.local-scheduling/v1"
	maxSchedulingConfig  = 1 << 20
)

type schedulingDocument struct {
	APIVersion        string           `json:"api_version"`
	ResolvedRunConfig json.RawMessage  `json:"resolved_run_config"`
	Schedules         []scheduleConfig `json:"schedules"`
}

type scheduleConfig struct {
	Name      string                   `json:"name"`
	Producers []scheduleProducerConfig `json:"producers"`
}

type scheduleProducerConfig struct {
	Identity                string              `json:"identity"`
	TokenFile               string              `json:"token_file"`
	AllowedPrincipalIssuers []string            `json:"allowed_principal_issuers"`
	Selections              []scheduleSelection `json:"selections"`
	DefaultWorkflow         string              `json:"default_workflow"`
	Retention               string              `json:"retention"`
	Backend                 string              `json:"backend,omitempty"`
}

type scheduleSelection struct {
	Profile  string `json:"profile"`
	Workflow string `json:"workflow"`
}

type schedulePolicy struct {
	identity        string
	tokenDigest     [32]byte
	allowedIssuers  map[string]struct{}
	selections      map[string]scheduleSelection
	defaultWorkflow string
	retention       string
	backend         string
	authorization   resolvedrun.AuthorizationContext
}

type schedule struct {
	name     string
	policies []schedulePolicy
}

type Scheduler struct {
	store     *Store
	resolver  *resolvedrun.Resolver
	schedules map[string]schedule
}

type scheduleAdmissionRequest struct {
	Workflow string                 `json:"workflow,omitempty"`
	Work     scheduleAdmissionWork  `json:"work"`
	Input    scheduleAdmissionInput `json:"input"`
}

type scheduleAdmissionWork struct {
	ID         string                     `json:"id"`
	Title      string                     `json:"title"`
	URL        string                     `json:"url"`
	Repository string                     `json:"repository"`
	Principal  scheduleAdmissionPrincipal `json:"principal"`
}

type scheduleAdmissionPrincipal struct {
	Issuer      string `json:"issuer"`
	Subject     string `json:"subject"`
	DisplayName string `json:"displayName"`
}

type scheduleAdmissionInput struct {
	Prompt string `json:"prompt"`
}

type scheduleAdmissionResponse struct {
	Scheduled bool                      `json:"scheduled"`
	Reason    string                    `json:"reason,omitempty"`
	State     State                     `json:"state,omitempty"`
	AgentRun  *scheduleAdmissionRunName `json:"agentRun,omitempty"`
}

type scheduleAdmissionRunName struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

func LoadScheduler(path string, store *Store) (*Scheduler, error) {
	if path == "" {
		return nil, nil
	}
	if store == nil || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ErrInvalidRequest
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > maxSchedulingConfig {
		return nil, ErrInvalidRequest
	}
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 || len(data) > maxSchedulingConfig || rejectDuplicateJSONKeys(data) != nil {
		return nil, ErrInvalidRequest
	}
	defer clear(data)
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var document schedulingDocument
	if decoder.Decode(&document) != nil || document.APIVersion != SchedulingAPIVersion || len(document.Schedules) == 0 || len(document.Schedules) > 64 {
		return nil, ErrInvalidRequest
	}
	var trailing any
	if !errors.Is(decoder.Decode(&trailing), io.EOF) {
		return nil, ErrInvalidRequest
	}
	trusted, err := resolvedrun.DecodeTrustedConfiguration(document.ResolvedRunConfig)
	if err != nil {
		return nil, ErrInvalidRequest
	}
	resolver, err := resolvedrun.NewResolver(trusted)
	if err != nil {
		return nil, ErrInvalidRequest
	}
	result := &Scheduler{store: store, resolver: resolver, schedules: make(map[string]schedule, len(document.Schedules))}
	seenTokens := map[[32]byte]struct{}{}
	for _, configured := range document.Schedules {
		if !validRunID(configured.Name) || len(configured.Producers) == 0 || len(configured.Producers) > 32 {
			return nil, ErrInvalidRequest
		}
		if _, duplicate := result.schedules[configured.Name]; duplicate {
			return nil, ErrInvalidRequest
		}
		compiled := schedule{name: configured.Name, policies: make([]schedulePolicy, 0, len(configured.Producers))}
		seenIdentities := map[string]struct{}{}
		for _, producer := range configured.Producers {
			policy, policyErr := compileSchedulePolicy(producer)
			if policyErr != nil {
				return nil, policyErr
			}
			if _, duplicate := seenIdentities[policy.identity]; duplicate {
				return nil, ErrInvalidRequest
			}
			seenIdentities[policy.identity] = struct{}{}
			if _, duplicate := seenTokens[policy.tokenDigest]; duplicate {
				return nil, ErrInvalidRequest
			}
			seenTokens[policy.tokenDigest] = struct{}{}
			compiled.policies = append(compiled.policies, policy)
		}
		result.schedules[configured.Name] = compiled
	}
	return result, nil
}

func compileSchedulePolicy(config scheduleProducerConfig) (schedulePolicy, error) {
	if !validOwner(config.Identity) || !filepath.IsAbs(config.TokenFile) || filepath.Clean(config.TokenFile) != config.TokenFile ||
		len(config.AllowedPrincipalIssuers) == 0 || len(config.AllowedPrincipalIssuers) > 32 ||
		len(config.Selections) == 0 || len(config.Selections) > resolvedrun.MaxWorkflows || !validRunID(config.DefaultWorkflow) ||
		!validRunID(config.Retention) || config.Backend != "" && !validRunID(config.Backend) {
		return schedulePolicy{}, ErrInvalidRequest
	}
	token, err := readSchedulingToken(config.TokenFile)
	if err != nil {
		return schedulePolicy{}, err
	}
	policy := schedulePolicy{
		identity: config.Identity, tokenDigest: sha256.Sum256(token), allowedIssuers: map[string]struct{}{},
		selections: map[string]scheduleSelection{}, defaultWorkflow: config.DefaultWorkflow,
		retention: config.Retention, backend: config.Backend,
	}
	clear(token)
	for _, issuer := range config.AllowedPrincipalIssuers {
		if !validIssuer(issuer) {
			return schedulePolicy{}, ErrInvalidRequest
		}
		if _, duplicate := policy.allowedIssuers[issuer]; duplicate {
			return schedulePolicy{}, ErrInvalidRequest
		}
		policy.allowedIssuers[issuer] = struct{}{}
	}
	byProfile := map[string][]string{}
	for _, selection := range config.Selections {
		if !validRunID(selection.Profile) || !validRunID(selection.Workflow) {
			return schedulePolicy{}, ErrInvalidRequest
		}
		if _, ambiguous := policy.selections[selection.Workflow]; ambiguous {
			return schedulePolicy{}, ErrInvalidRequest
		}
		policy.selections[selection.Workflow] = selection
		byProfile[selection.Profile] = append(byProfile[selection.Profile], selection.Workflow)
	}
	if _, exists := policy.selections[policy.defaultWorkflow]; !exists {
		return schedulePolicy{}, ErrInvalidRequest
	}
	for profile, workflows := range byProfile {
		policy.authorization.Selections = append(policy.authorization.Selections, resolvedrun.AuthorizedSelection{Profile: profile, Workflows: workflows})
	}
	return policy, nil
}

func readSchedulingToken(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() < 32 || info.Size() > 4096 {
		return nil, ErrInvalidRequest
	}
	data, err := os.ReadFile(path)
	if err != nil || len(data) > 4096 {
		clear(data)
		return nil, ErrInvalidRequest
	}
	token := bytes.TrimSpace(data)
	if len(token) < 32 || len(token) > 4096 || !utf8.Valid(token) || bytes.IndexFunc(token, func(character rune) bool { return character <= 0x20 || character == 0x7f }) >= 0 {
		clear(data)
		return nil, ErrInvalidRequest
	}
	result := append([]byte(nil), token...)
	clear(data)
	return result, nil
}

func validIssuer(raw string) bool {
	parsed, err := url.Parse(raw)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil && parsed.RawQuery == "" && parsed.Fragment == "" &&
		parsed.String() == raw && raw == strings.TrimSpace(raw) && !strings.ContainsAny(raw, "\x00\r\n")
}

func (scheduler *Scheduler) serveHTTP(server *HTTPServer, response http.ResponseWriter, request *http.Request) (int, string, string) {
	parts := strings.Split(strings.TrimPrefix(request.URL.Path, "/v1/schedules/"), "/")
	if len(parts) < 2 || !validRunID(parts[0]) {
		return server.writeError(response, ErrNotFound, "")
	}
	configured, exists := scheduler.schedules[parts[0]]
	if !exists {
		return server.writeError(response, ErrNotFound, "")
	}
	policy, ok := authenticateScheduleProducer(request, configured)
	if !ok {
		scheduler.writeResponse(server, response, http.StatusUnauthorized, scheduleAdmissionResponse{Reason: "producer-not-authorized"})
		return http.StatusUnauthorized, "producer-not-authorized", ""
	}
	if len(parts) == 2 && parts[1] == "admissions" {
		if request.Method != http.MethodPost || request.URL.RawQuery != "" {
			return server.writeMethod(response, "")
		}
		return scheduler.admit(server, response, request, configured, policy)
	}
	if len(parts) == 2 && parts[1] == "work" {
		workID, ok := scheduleWorkQuery(request)
		if request.Method != http.MethodGet || !ok {
			return server.writeMethod(response, "")
		}
		return scheduler.workStatus(server, response, request, configured, policy, workID)
	}
	if len(parts) == 3 && parts[1] == "work" && parts[2] == "cancel" {
		workID, ok := scheduleWorkQuery(request)
		if request.Method != http.MethodPost || !ok || !emptyBody(request) {
			return server.writeMethod(response, "")
		}
		return scheduler.cancelWork(server, response, request, configured, policy, workID)
	}
	return server.writeError(response, ErrNotFound, "")
}

func authenticateScheduleProducer(request *http.Request, configured schedule) (schedulePolicy, bool) {
	header := request.Header.Values("Authorization")
	if len(header) != 1 || !strings.HasPrefix(header[0], "Bearer ") || strings.Count(header[0], " ") != 1 {
		return schedulePolicy{}, false
	}
	token := []byte(strings.TrimPrefix(header[0], "Bearer "))
	defer clear(token)
	if len(token) < 32 || len(token) > 4096 {
		return schedulePolicy{}, false
	}
	digest := sha256.Sum256(token)
	for _, policy := range configured.policies {
		if subtle.ConstantTimeCompare(digest[:], policy.tokenDigest[:]) == 1 {
			return policy, true
		}
	}
	return schedulePolicy{}, false
}

func (scheduler *Scheduler) admit(server *HTTPServer, response http.ResponseWriter, request *http.Request, configured schedule, policy schedulePolicy) (int, string, string) {
	var input scheduleAdmissionRequest
	if decodeRequest(request, &input) != nil || !validScheduleWork(input.Work) || len(input.Input.Prompt) > resolvedrun.MaxPromptBytes || !utf8.ValidString(input.Input.Prompt) || strings.ContainsRune(input.Input.Prompt, 0) {
		scheduler.writeResponse(server, response, http.StatusBadRequest, scheduleAdmissionResponse{Reason: "invalid-request"})
		return http.StatusBadRequest, "invalid-request", ""
	}
	if _, allowed := policy.allowedIssuers[input.Work.Principal.Issuer]; !allowed {
		scheduler.writeResponse(server, response, http.StatusForbidden, scheduleAdmissionResponse{Reason: "principal-not-eligible"})
		return http.StatusForbidden, "principal-not-eligible", ""
	}
	workflow := input.Workflow
	if workflow == "" {
		workflow = policy.defaultWorkflow
	}
	selection, allowed := policy.selections[workflow]
	if !allowed {
		scheduler.writeResponse(server, response, http.StatusForbidden, scheduleAdmissionResponse{Reason: "workflow-selection-denied"})
		return http.StatusForbidden, "workflow-selection-denied", ""
	}
	principal := resolvedrun.Principal{Issuer: input.Work.Principal.Issuer, Subject: input.Work.Principal.Subject, DisplayName: input.Work.Principal.DisplayName}
	authorization := policy.authorization
	authorization.Principal = principal
	key, runID := localWorkIdentity(configured.name, policy.identity, input.Work.ID)
	resolved, err := scheduler.resolver.Resolve(authorization, resolvedrun.LocalRunRequest{
		RunID: runID, Profile: selection.Profile, Workflow: selection.Workflow, Retention: policy.retention,
		Backend: policy.backend, Prompt: input.Input.Prompt,
	})
	if err != nil {
		reason := "invalid-execution-profile-configuration"
		status := http.StatusBadRequest
		if errors.Is(err, resolvedrun.ErrSelectionDenied) || errors.Is(err, resolvedrun.ErrUnknownProfile) || errors.Is(err, resolvedrun.ErrUnknownWorkflow) {
			reason, status = "profile-selection-denied", http.StatusForbidden
		}
		scheduler.writeResponse(server, response, status, scheduleAdmissionResponse{Reason: reason})
		return status, reason, ""
	}
	encoded, err := encodeCanonicalResolved(resolved)
	if err != nil {
		scheduler.writeResponse(server, response, http.StatusServiceUnavailable, scheduleAdmissionResponse{Reason: "scheduling-unavailable"})
		return http.StatusServiceUnavailable, "scheduling-unavailable", ""
	}
	created, err := scheduler.store.Create(request.Context(), CreateInput{IdempotencyKey: key, ResolvedRun: encoded})
	clear(encoded)
	if err != nil {
		switch {
		case errors.Is(err, ErrCapacityExceeded):
			scheduler.writeResponse(server, response, http.StatusTooManyRequests, scheduleAdmissionResponse{Reason: "max-parallelism-reached"})
			return http.StatusTooManyRequests, "max-parallelism-reached", runID
		case errors.Is(err, ErrConflict), errors.Is(err, ErrGone):
			scheduler.writeResponse(server, response, http.StatusConflict, scheduleAdmissionResponse{Reason: "work-conflict"})
			return http.StatusConflict, "work-conflict", runID
		default:
			scheduler.writeResponse(server, response, http.StatusServiceUnavailable, scheduleAdmissionResponse{Reason: "scheduling-unavailable"})
			return http.StatusServiceUnavailable, "scheduling-unavailable", runID
		}
	}
	name := &scheduleAdmissionRunName{Namespace: "local", Name: created.Run.RunID}
	if !created.Created {
		scheduler.writeResponse(server, response, http.StatusAccepted, scheduleAdmissionResponse{Reason: "duplicate-work", AgentRun: nil})
		return http.StatusAccepted, "duplicate-work", created.Run.RunID
	}
	scheduler.writeResponse(server, response, http.StatusCreated, scheduleAdmissionResponse{Scheduled: true, State: created.Run.State, AgentRun: name})
	return http.StatusCreated, "scheduled", created.Run.RunID
}

func (scheduler *Scheduler) workStatus(server *HTTPServer, response http.ResponseWriter, request *http.Request, configured schedule, policy schedulePolicy, workID string) (int, string, string) {
	_, runID := localWorkIdentity(configured.name, policy.identity, workID)
	run, err := scheduler.store.Get(request.Context(), runID)
	if err != nil {
		return server.writeError(response, err, runID)
	}
	scheduler.writeResponse(server, response, http.StatusOK, scheduleAdmissionResponse{Scheduled: run.State.active(), State: run.State, AgentRun: &scheduleAdmissionRunName{Namespace: "local", Name: run.RunID}})
	return http.StatusOK, "ok", runID
}

func (scheduler *Scheduler) cancelWork(server *HTTPServer, response http.ResponseWriter, request *http.Request, configured schedule, policy schedulePolicy, workID string) (int, string, string) {
	_, runID := localWorkIdentity(configured.name, policy.identity, workID)
	run, err := scheduler.store.Cancel(request.Context(), runID)
	if err != nil {
		return server.writeError(response, err, runID)
	}
	scheduler.writeResponse(server, response, http.StatusAccepted, scheduleAdmissionResponse{State: run.State, AgentRun: &scheduleAdmissionRunName{Namespace: "local", Name: run.RunID}})
	return http.StatusAccepted, "cancel-requested", runID
}

func (scheduler *Scheduler) writeResponse(server *HTTPServer, response http.ResponseWriter, status int, value scheduleAdmissionResponse) {
	server.writeJSON(response, status, value)
}

func localWorkIdentity(scheduleName, producerIdentity, workID string) (string, string) {
	digest := sha256.Sum256([]byte("nvt.local-scheduling/v1\x00" + scheduleName + "\x00" + producerIdentity + "\x00" + workID))
	hexDigest := hex.EncodeToString(digest[:])
	return "local-work-" + hexDigest, "local-" + hexDigest[:32]
}

func scheduleWorkQuery(request *http.Request) (string, bool) {
	query, err := url.ParseQuery(request.URL.RawQuery)
	if err != nil || len(query) != 1 {
		return "", false
	}
	values, exists := query["work_id"]
	if !exists || len(values) != 1 || !validWorkID(values[0]) {
		return "", false
	}
	return values[0], true
}

func validScheduleWork(value scheduleAdmissionWork) bool {
	return validWorkID(value.ID) && validScheduleText(value.Title, 512, true) && validScheduleText(value.Repository, 512, false) &&
		validScheduleURL(value.URL) && validIssuer(value.Principal.Issuer) && validScheduleText(value.Principal.Subject, 1024, false) &&
		validScheduleText(value.Principal.DisplayName, 512, true)
}

func validWorkID(value string) bool {
	if len(value) < 16 || len(value) > 256 || value != strings.TrimSpace(value) {
		return false
	}
	for _, character := range value {
		if character < 0x21 || character > 0x7e || strings.ContainsRune("%\\?#", character) {
			return false
		}
	}
	return true
}

func validScheduleText(value string, maximum int, allowEmpty bool) bool {
	return (allowEmpty || value != "") && len(value) <= maximum && value == strings.TrimSpace(value) && utf8.ValidString(value) && !strings.ContainsAny(value, "\x00\r\n")
}

func validScheduleURL(raw string) bool {
	parsed, err := url.Parse(raw)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil && parsed.Fragment == "" && len(raw) <= 2048 && !strings.ContainsAny(raw, "\x00\r\n")
}
