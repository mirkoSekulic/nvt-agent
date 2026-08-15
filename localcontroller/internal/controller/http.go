package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/mirkoSekulic/nvt-agent/protocol/localroutes"
)

type HTTPServer struct {
	store         *Store
	logger        *log.Logger
	backendReady  func(context.Context) bool
	routeProvider RouteProvider
	scheduler     *Scheduler
}

type createRequest struct {
	APIVersion     string          `json:"api_version"`
	IdempotencyKey string          `json:"idempotency_key"`
	ResolvedRun    json.RawMessage `json:"resolved_run"`
}

type claimRequest struct {
	APIVersion       string `json:"api_version"`
	Owner            string `json:"owner"`
	ExpectedRevision int64  `json:"expected_revision"`
	LeaseSeconds     int64  `json:"lease_seconds"`
}

type statusRequest struct {
	APIVersion       string `json:"api_version"`
	Owner            string `json:"owner"`
	ExpectedRevision int64  `json:"expected_revision"`
	State            State  `json:"state"`
	TerminalTarget   State  `json:"terminal_target,omitempty"`
	Reason           string `json:"reason,omitempty"`
}

type errorEnvelope struct {
	Error apiError `json:"error"`
}

type apiError struct {
	Reason  string `json:"reason"`
	Message string `json:"message"`
}

func NewHTTPHandler(store *Store, logger *log.Logger) http.Handler {
	return NewHTTPHandlerWithBackend(store, logger, nil)
}

func NewHTTPHandlerWithBackend(store *Store, logger *log.Logger, backendReady func(context.Context) bool) http.Handler {
	return NewHTTPHandlerWithServices(store, logger, backendReady, nil, nil)
}

func NewHTTPHandlerWithServices(store *Store, logger *log.Logger, backendReady func(context.Context) bool, routeProvider RouteProvider, scheduler *Scheduler) http.Handler {
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}
	server := &HTTPServer{store: store, logger: logger, backendReady: backendReady, routeProvider: routeProvider, scheduler: scheduler}
	return http.HandlerFunc(server.serveHTTP)
}

func (server *HTTPServer) serveHTTP(response http.ResponseWriter, request *http.Request) {
	status, reason, runID := server.route(response, request)
	server.logger.Printf("request method=%s route=%s status=%d reason=%s run_id=%s", request.Method, routeClass(request.URL.Path), status, reason, runID)
}

func (server *HTTPServer) route(response http.ResponseWriter, request *http.Request) (int, string, string) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	if request.URL.EscapedPath() != request.URL.Path {
		return server.writeError(response, ErrNotFound, "")
	}
	if request.URL.RawQuery != "" && request.URL.Path != "/v1/runs" && request.URL.Path != "/v1/routes" && !strings.HasPrefix(request.URL.Path, "/v1/schedules/") {
		return server.writeError(response, ErrInvalidRequest, "")
	}
	switch request.URL.Path {
	case "/healthz":
		if request.Method != http.MethodGet {
			return server.writeMethod(response, "")
		}
		response.WriteHeader(http.StatusOK)
		return http.StatusOK, "ok", ""
	case "/readyz":
		if request.Method != http.MethodGet {
			return server.writeMethod(response, "")
		}
		ctx, cancel := context.WithTimeout(request.Context(), time.Second)
		defer cancel()
		if !server.store.Ready(ctx) || server.backendReady != nil && !server.backendReady(ctx) {
			return server.writeError(response, ErrStoreUnavailable, "")
		}
		response.WriteHeader(http.StatusOK)
		return http.StatusOK, "ok", ""
	case "/v1/runs":
		if request.Method == http.MethodPost {
			return server.create(response, request)
		}
		if request.Method == http.MethodGet {
			return server.list(response, request)
		}
		return server.writeMethod(response, "")
	case "/v1/routes":
		if request.Method != http.MethodGet {
			return server.writeMethod(response, "")
		}
		return server.listRoutes(response, request)
	}
	if strings.HasPrefix(request.URL.Path, "/v1/routes/") {
		if request.Method != http.MethodGet || request.URL.RawQuery != "" {
			return server.writeMethod(response, "")
		}
		runID := strings.TrimPrefix(request.URL.Path, "/v1/routes/")
		if !validRunID(runID) || strings.Contains(runID, "/") {
			return server.writeError(response, ErrNotFound, "")
		}
		return server.getRoute(response, request, runID)
	}
	if strings.HasPrefix(request.URL.Path, "/v1/schedules/") && server.scheduler != nil {
		return server.scheduler.serveHTTP(server, response, request)
	}
	if !strings.HasPrefix(request.URL.Path, "/v1/runs/") {
		return server.writeError(response, ErrNotFound, "")
	}
	parts := strings.Split(strings.TrimPrefix(request.URL.Path, "/v1/runs/"), "/")
	if len(parts) < 1 || len(parts) > 2 || !validRunID(parts[0]) {
		return server.writeError(response, ErrNotFound, "")
	}
	runID := parts[0]
	if len(parts) == 1 {
		switch request.Method {
		case http.MethodGet:
			return server.get(response, request, runID)
		case http.MethodDelete:
			return server.delete(response, request, runID)
		default:
			return server.writeMethod(response, runID)
		}
	}
	switch parts[1] {
	case "cancel":
		if request.Method != http.MethodPost {
			return server.writeMethod(response, runID)
		}
		return server.cancel(response, request, runID)
	case "claim":
		if request.Method != http.MethodPost {
			return server.writeMethod(response, runID)
		}
		return server.claim(response, request, runID)
	case "status":
		if request.Method != http.MethodPut {
			return server.writeMethod(response, runID)
		}
		return server.status(response, request, runID)
	default:
		return server.writeError(response, ErrNotFound, runID)
	}
}

func (server *HTTPServer) listRoutes(response http.ResponseWriter, request *http.Request) (int, string, string) {
	query, parseErr := url.ParseQuery(request.URL.RawQuery)
	if parseErr != nil {
		return server.writeError(response, ErrInvalidRequest, "")
	}
	for key, values := range query {
		if (key != "limit" && key != "after") || len(values) != 1 {
			return server.writeError(response, ErrInvalidRequest, "")
		}
	}
	limit := localroutes.MaxRunsPerPage
	if raw := query.Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil {
			return server.writeError(response, ErrInvalidRequest, "")
		}
		limit = parsed
	}
	result, err := server.routeList(request.Context(), limit, query.Get("after"))
	if err != nil {
		return server.writeError(response, err, "")
	}
	server.writeJSON(response, http.StatusOK, result)
	return http.StatusOK, "ok", ""
}

func (server *HTTPServer) getRoute(response http.ResponseWriter, request *http.Request, runID string) (int, string, string) {
	run, err := server.store.Get(request.Context(), runID)
	if err != nil {
		return server.writeError(response, err, runID)
	}
	route, err := server.routeForRun(request.Context(), run)
	if err != nil {
		return server.writeError(response, err, runID)
	}
	server.writeJSON(response, http.StatusOK, route)
	return http.StatusOK, "ok", runID
}

func (server *HTTPServer) create(response http.ResponseWriter, request *http.Request) (int, string, string) {
	var input createRequest
	if err := decodeRequest(request, &input); err != nil || input.APIVersion != APIVersion {
		return server.writeError(response, ErrInvalidRequest, "")
	}
	result, err := server.store.Create(request.Context(), CreateInput{IdempotencyKey: input.IdempotencyKey, ResolvedRun: input.ResolvedRun})
	if err != nil {
		return server.writeError(response, err, "")
	}
	status := http.StatusOK
	if result.Created {
		status = http.StatusCreated
	}
	server.writeJSON(response, status, map[string]any{"api_version": APIVersion, "created": result.Created, "run": result.Run})
	return status, "ok", result.Run.RunID
}

func (server *HTTPServer) get(response http.ResponseWriter, request *http.Request, runID string) (int, string, string) {
	run, err := server.store.Get(request.Context(), runID)
	if err != nil {
		return server.writeError(response, err, runID)
	}
	server.writeJSON(response, http.StatusOK, run)
	return http.StatusOK, "ok", runID
}

func (server *HTTPServer) list(response http.ResponseWriter, request *http.Request) (int, string, string) {
	query, parseErr := url.ParseQuery(request.URL.RawQuery)
	if parseErr != nil {
		return server.writeError(response, ErrInvalidRequest, "")
	}
	for key, values := range query {
		if (key != "limit" && key != "after") || len(values) != 1 {
			return server.writeError(response, ErrInvalidRequest, "")
		}
	}
	limit := 100
	if raw := query.Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil {
			return server.writeError(response, ErrInvalidRequest, "")
		}
		limit = parsed
	}
	result, err := server.store.List(request.Context(), limit, query.Get("after"))
	if err != nil {
		return server.writeError(response, err, "")
	}
	server.writeJSON(response, http.StatusOK, result)
	return http.StatusOK, "ok", ""
}

func (server *HTTPServer) cancel(response http.ResponseWriter, request *http.Request, runID string) (int, string, string) {
	if !emptyBody(request) {
		return server.writeError(response, ErrInvalidRequest, runID)
	}
	run, err := server.store.Cancel(request.Context(), runID)
	if err != nil {
		return server.writeError(response, err, runID)
	}
	server.writeJSON(response, http.StatusOK, run)
	return http.StatusOK, "ok", runID
}

func (server *HTTPServer) delete(response http.ResponseWriter, request *http.Request, runID string) (int, string, string) {
	if !emptyBody(request) {
		return server.writeError(response, ErrInvalidRequest, runID)
	}
	run, deleted, err := server.store.Delete(request.Context(), runID)
	if err != nil {
		return server.writeError(response, err, runID)
	}
	if deleted {
		response.WriteHeader(http.StatusNoContent)
		return http.StatusNoContent, "ok", runID
	}
	server.writeJSON(response, http.StatusAccepted, run)
	return http.StatusAccepted, "ok", runID
}

func (server *HTTPServer) claim(response http.ResponseWriter, request *http.Request, runID string) (int, string, string) {
	var input claimRequest
	if err := decodeRequest(request, &input); err != nil || input.APIVersion != APIVersion {
		return server.writeError(response, ErrInvalidRequest, runID)
	}
	run, err := server.store.Claim(request.Context(), ClaimInput{
		RunID: runID, Owner: input.Owner, ExpectedRevision: input.ExpectedRevision, Lease: time.Duration(input.LeaseSeconds) * time.Second,
	})
	if err != nil {
		return server.writeError(response, err, runID)
	}
	server.writeJSON(response, http.StatusOK, run)
	return http.StatusOK, "ok", runID
}

func (server *HTTPServer) status(response http.ResponseWriter, request *http.Request, runID string) (int, string, string) {
	var input statusRequest
	if err := decodeRequest(request, &input); err != nil || input.APIVersion != APIVersion {
		return server.writeError(response, ErrInvalidRequest, runID)
	}
	run, err := server.store.UpdateStatus(request.Context(), StatusInput{
		RunID: runID, Owner: input.Owner, ExpectedRevision: input.ExpectedRevision, State: input.State,
		TerminalTarget: input.TerminalTarget, Reason: input.Reason,
	})
	if err != nil {
		return server.writeError(response, err, runID)
	}
	server.writeJSON(response, http.StatusOK, run)
	return http.StatusOK, "ok", runID
}

func decodeRequest(request *http.Request, destination any) error {
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return ErrInvalidRequest
	}
	data, err := io.ReadAll(io.LimitReader(request.Body, MaxRequestBytes+1))
	if err != nil || len(data) == 0 || len(data) > MaxRequestBytes || !utf8.Valid(data) || rejectDuplicateJSONKeys(data) != nil {
		return ErrInvalidRequest
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return ErrInvalidRequest
	}
	var extra any
	if !errors.Is(decoder.Decode(&extra), io.EOF) {
		return ErrInvalidRequest
	}
	return nil
}

func rejectDuplicateJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := scanJSONValue(decoder, 0); err != nil {
		return err
	}
	var extra any
	if !errors.Is(decoder.Decode(&extra), io.EOF) {
		return ErrInvalidRequest
	}
	return nil
}

func scanJSONValue(decoder *json.Decoder, depth int) error {
	// The outer request plus resolved_run wrapper adds at most two levels to the
	// resolved-run decoder's own 64-level bound.
	if depth > 66 {
		return ErrInvalidRequest
	}
	token, err := decoder.Token()
	if err != nil {
		return ErrInvalidRequest
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]struct{}{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			key, keyOK := keyToken.(string)
			if err != nil || !keyOK {
				return ErrInvalidRequest
			}
			if _, duplicate := seen[key]; duplicate {
				return ErrInvalidRequest
			}
			seen[key] = struct{}{}
			if err := scanJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return ErrInvalidRequest
		}
	case '[':
		for decoder.More() {
			if err := scanJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return ErrInvalidRequest
		}
	default:
		return ErrInvalidRequest
	}
	return nil
}

func emptyBody(request *http.Request) bool {
	data, err := io.ReadAll(io.LimitReader(request.Body, MaxRequestBytes+1))
	return err == nil && len(data) <= MaxRequestBytes && len(bytes.TrimSpace(data)) == 0
}

func (server *HTTPServer) writeMethod(response http.ResponseWriter, runID string) (int, string, string) {
	server.writeJSON(response, http.StatusMethodNotAllowed, errorEnvelope{Error: apiError{Reason: "method-not-allowed", Message: "request denied"}})
	return http.StatusMethodNotAllowed, "method-not-allowed", runID
}

func (server *HTTPServer) writeError(response http.ResponseWriter, err error, runID string) (int, string, string) {
	status, reason := http.StatusInternalServerError, "internal-error"
	switch {
	case errors.Is(err, ErrInvalidRequest):
		status, reason = http.StatusBadRequest, "invalid-request"
	case errors.Is(err, ErrNotFound):
		status, reason = http.StatusNotFound, "not-found"
	case errors.Is(err, ErrGone):
		status, reason = http.StatusGone, "gone"
	case errors.Is(err, ErrConflict), errors.Is(err, ErrInvalidTransition), errors.Is(err, ErrOwnershipConflict):
		status, reason = http.StatusConflict, "conflict"
	case errors.Is(err, ErrCapacityExceeded):
		status, reason = http.StatusTooManyRequests, "capacity-exceeded"
	case errors.Is(err, ErrStoreUnavailable):
		status, reason = http.StatusServiceUnavailable, "unavailable"
	}
	server.writeJSON(response, status, errorEnvelope{Error: apiError{Reason: reason, Message: "request denied"}})
	return status, reason, runID
}

func (server *HTTPServer) writeJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}

func routeClass(path string) string {
	switch {
	case path == "/healthz":
		return "health"
	case path == "/readyz":
		return "ready"
	case path == "/v1/runs":
		return "runs"
	case path == "/v1/routes":
		return "routes"
	case strings.HasPrefix(path, "/v1/routes/"):
		return "route"
	case strings.HasPrefix(path, "/v1/schedules/"):
		return "schedule"
	case strings.HasSuffix(path, "/cancel"):
		return "run-cancel"
	case strings.HasSuffix(path, "/claim"):
		return "run-claim"
	case strings.HasSuffix(path, "/status"):
		return "run-status"
	case strings.HasPrefix(path, "/v1/runs/"):
		return "run"
	default:
		return "unknown"
	}
}
