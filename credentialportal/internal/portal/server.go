package portal

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"
)

type Server struct {
	patcher           SecretPatcher
	auth              *Authenticator
	audit             *AuditLogger
	enrollments       *EnrollmentManager
	runner            CredentialRunner
	broker            PrincipalAccountBroker
	switchCoordinator TemplateSwitchCoordinator
	cfg               Config
}

var errDynamicTemplateConflict = errors.New("dynamic credential template conflicts with the active account")

func NewServer(
	cfg Config,
	auth *Authenticator,
	patcher SecretPatcher,
	audit *AuditLogger,
	runner CredentialRunner,
	brokers ...PrincipalAccountBroker,
) *Server {
	var broker PrincipalAccountBroker
	if len(brokers) != 0 {
		broker = brokers[0]
	}
	return newServer(cfg, auth, patcher, audit, runner, broker, nil)
}

// NewServerWithSwitchCoordinator wires the optional target-free operator
// coordination dependency without broadening the static server constructor.
func NewServerWithSwitchCoordinator(
	cfg Config,
	auth *Authenticator,
	patcher SecretPatcher,
	audit *AuditLogger,
	runner CredentialRunner,
	broker PrincipalAccountBroker,
	coordinator TemplateSwitchCoordinator,
) *Server {
	return newServer(cfg, auth, patcher, audit, runner, broker, coordinator)
}

func newServer(
	cfg Config,
	auth *Authenticator,
	patcher SecretPatcher,
	audit *AuditLogger,
	runner CredentialRunner,
	broker PrincipalAccountBroker,
	coordinator TemplateSwitchCoordinator,
) *Server {
	server := &Server{
		cfg: cfg, auth: auth, patcher: patcher, audit: audit, runner: runner,
		broker: broker, switchCoordinator: coordinator,
	}
	if server.broker != nil {
		server.enrollments = NewEnrollmentManager(cfg, patcher, audit, runner, server.broker)
	} else {
		server.enrollments = NewEnrollmentManager(cfg, patcher, audit, runner)
	}
	return server
}

func (s *Server) Close() {
	s.enrollments.Close()
}

//nolint:cyclop,funlen,gocognit,gocyclo,nestif // Central routing keeps every path behind one admission gate.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().
		Set("Content-Security-Policy", "default-src 'none'; connect-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
	if s.cfg.basePath != "" && r.URL.Path == s.cfg.basePath && r.Method == http.MethodGet && r.URL.RawQuery == "" {
		http.Redirect(w, r, s.cfg.Path("/"), http.StatusPermanentRedirect)
		return
	}
	switch r.URL.Path {
	case "/healthz":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	case "/readyz":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := s.runner.Ready(ctx); err != nil {
			http.Error(w, "dependency unavailable", http.StatusServiceUnavailable)
			return
		}
		if s.cfg.Dynamic.Enabled && (s.broker == nil || s.broker.Ready(ctx) != nil) {
			http.Error(w, "dependency unavailable", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	case s.cfg.Path("/login"):
		s.auth.Login(w, r)
		return
	case s.cfg.Path(callbackPath(s.cfg)):
		s.auth.Callback(w, r)
		return
	}
	principal, csrf, authExpiresAt, eligibilityExpiresAt, authenticated := s.auth.Session(r)
	if !authenticated {
		if r.URL.Path == s.cfg.Path("/") && r.Method == http.MethodGet {
			w.Header().Set("Cache-Control", "no-store")
			http.Redirect(w, r, s.cfg.Path("/login"), http.StatusFound)
			return
		}
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return
	}
	if r.URL.Path == s.cfg.Path("/") {
		if r.Method != http.MethodGet || r.URL.RawQuery != "" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		s.dashboard(r.Context(), w, principal, csrf)
		return
	}
	if r.URL.Path == s.cfg.Path("/logout") {
		if r.Method != http.MethodPost || r.URL.RawQuery != "" || !sameOrigin(r, s.cfg.PublicOrigin()) ||
			!s.auth.Logout(w, r, csrf) {
			http.Error(w, "request rejected", http.StatusForbidden)
			return
		}
		s.enrollments.CancelPrincipal(principal)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if s.cfg.Dynamic.Enabled {
		if r.URL.Path == s.cfg.Path("/account") {
			s.dynamicAccount(w, r, principal)
			return
		}
		if r.URL.Path == s.cfg.Path("/account/revoke") {
			s.dynamicRevoke(w, r, principal, csrf)
			return
		}
		prefix := s.cfg.Path("/templates/")
		if strings.HasPrefix(r.URL.Path, prefix) && strings.HasSuffix(r.URL.Path, "/connect") {
			name := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, prefix), "/connect")
			if name == "" || strings.Contains(name, "/") {
				http.NotFound(w, r)
				return
			}
			s.dynamicConnect(w, r, principal, csrf, eligibilityExpiresAt, name)
			return
		}
		if strings.HasPrefix(r.URL.Path, prefix) && strings.HasSuffix(r.URL.Path, "/credential") {
			name := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, prefix), "/credential")
			if name == "" || strings.Contains(name, "/") {
				http.NotFound(w, r)
				return
			}
			s.dynamicRecovery(w, r, principal, csrf, name, eligibilityExpiresAt)
			return
		}
	} else {
		prefix := s.cfg.Path("/slots/")
		if strings.HasPrefix(r.URL.Path, prefix) && strings.HasSuffix(r.URL.Path, "/connect") {
			name := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, prefix), "/connect")
			if name == "" || strings.Contains(name, "/") {
				http.NotFound(w, r)
				return
			}
			s.connect(w, r, principal, csrf, authExpiresAt, name)
			return
		}
		if strings.HasPrefix(r.URL.Path, prefix) && strings.HasSuffix(r.URL.Path, "/credential") {
			name := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, prefix), "/credential")
			if name == "" || strings.Contains(name, "/") {
				http.NotFound(w, r)
				return
			}
			s.enroll(w, r, principal, csrf, name)
			return
		}
	}
	enrollmentPrefix := s.cfg.Path("/enrollments/")
	if tail, found := strings.CutPrefix(r.URL.Path, enrollmentPrefix); found {
		if id, isCode := strings.CutSuffix(tail, "/code"); isCode {
			if id == "" || strings.Contains(id, "/") {
				http.NotFound(w, r)
				return
			}
			s.enrollmentCode(w, r, principal, csrf, id)
			return
		}
		if tail == "" || strings.Contains(tail, "/") {
			http.NotFound(w, r)
			return
		}
		s.enrollment(w, r, principal, csrf, tail)
		return
	}
	http.NotFound(w, r)
}

func (s *Server) dashboard(ctx context.Context, w http.ResponseWriter, principal Principal, csrf string) {
	if s.cfg.Dynamic.Enabled {
		s.dynamicDashboard(ctx, w, principal, csrf)
		return
	}
	slots := []Slot{}
	for _, slot := range s.cfg.Slots {
		if principal.Owns(slot) {
			slots = append(slots, slot)
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := portalTemplate.Execute(w, struct {
		CSRF           string
		BasePath       string
		PrincipalName  string
		Slots          []Slot
		RecoveryUpload bool
	}{
		CSRF: csrf, BasePath: s.cfg.basePath, PrincipalName: principal.DisplayName,
		Slots: slots, RecoveryUpload: s.cfg.RecoveryUpload.Enabled,
	}); err != nil {
		return
	}
}

func (s *Server) dynamicDashboard(ctx context.Context, w http.ResponseWriter, principal Principal, csrf string) {
	account := DynamicAccountState{State: accountStateUnavailable}
	if s.broker != nil {
		if current, err := s.broker.Account(ctx, principal); err == nil {
			account = current
		}
	}
	actionLabel := "Connect"
	if account.State == accountStateReady || account.State == accountStateUnready {
		actionLabel = "Reconnect"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := dynamicPortalTemplate.Execute(w, struct {
		CSRF           string
		BasePath       string
		PrincipalName  string
		ActionLabel    string
		Account        DynamicAccountState
		Templates      []DynamicCredentialTemplate
		RecoveryUpload bool
	}{
		CSRF: csrf, BasePath: s.cfg.basePath, PrincipalName: principal.DisplayName,
		ActionLabel: actionLabel, Account: account, Templates: s.cfg.Dynamic.Templates,
		RecoveryUpload: s.cfg.RecoveryUpload.Enabled,
	}); err != nil {
		return
	}
}

func (s *Server) dynamicAccount(w http.ResponseWriter, r *http.Request, principal Principal) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet || r.URL.RawQuery != "" {
		http.NotFound(w, r)
		return
	}
	account, err := s.broker.Account(r.Context(), principal)
	if err != nil {
		http.Error(w, reasonBrokerUnavailable, http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, http.StatusOK, account)
}

func (s *Server) dynamicConnect(
	w http.ResponseWriter,
	r *http.Request,
	principal Principal,
	csrf string,
	authExpiresAt time.Time,
	templateName string,
) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost || r.URL.RawQuery != "" {
		http.NotFound(w, r)
		return
	}
	templateConfig, ok := s.dynamicTemplate(templateName)
	if !ok {
		http.NotFound(w, r)
		return
	}
	slot := dynamicAuditSlot(principal, templateConfig)
	if !validMutation(r, s.cfg.PublicOrigin(), csrf) {
		s.reject(w, principal, slot, http.StatusForbidden, "csrf")
		return
	}
	if r.Header.Get(confirmHeader) != confirmationReplace {
		s.reject(w, principal, slot, http.StatusBadRequest, "confirmation-required")
		return
	}
	action, err := s.dynamicAction(r.Context(), principal, templateName)
	if errors.Is(err, ErrTemplateSwitchDenied) {
		s.reject(w, principal, slot, http.StatusConflict, "active-agentruns")
		return
	}
	if errors.Is(err, errDynamicTemplateConflict) {
		s.reject(w, principal, slot, http.StatusConflict, "template-conflict")
		return
	}
	if err != nil {
		s.reject(w, principal, slot, http.StatusServiceUnavailable, reasonBrokerUnavailable)
		return
	}
	status, err := s.enrollments.StartDynamic(
		r.Context(), principal, templateConfig, action, authExpiresAt,
	)
	if errors.Is(err, ErrEnrollmentBusy) {
		s.reject(w, principal, slot, http.StatusTooManyRequests, "capacity")
		return
	}
	if err != nil {
		s.reject(w, principal, slot, http.StatusBadGateway, "runner-start-failed")
		return
	}
	writeJSON(w, http.StatusAccepted, status)
}

func (s *Server) dynamicRecovery(
	w http.ResponseWriter,
	r *http.Request,
	principal Principal,
	csrf, templateName string,
	authExpiresAt time.Time,
) {
	w.Header().Set("Cache-Control", "no-store")
	if !s.cfg.RecoveryUpload.Enabled || r.Method != http.MethodPut || r.URL.RawQuery != "" {
		http.NotFound(w, r)
		return
	}
	templateConfig, ok := s.dynamicTemplate(templateName)
	if !ok {
		http.NotFound(w, r)
		return
	}
	slot := dynamicAuditSlot(principal, templateConfig)
	s.audit.Enrollment(principal, slot, "attempt", "")
	if !validMutation(r, s.cfg.PublicOrigin(), csrf) {
		s.reject(w, principal, slot, http.StatusForbidden, "csrf")
		return
	}
	if r.Header.Get(confirmHeader) != confirmationReplace {
		s.reject(w, principal, slot, http.StatusBadRequest, "confirmation-required")
		return
	}
	action, actionErr := s.dynamicAction(r.Context(), principal, templateName)
	if errors.Is(actionErr, ErrTemplateSwitchDenied) {
		s.reject(w, principal, slot, http.StatusConflict, "active-agentruns")
		return
	}
	if errors.Is(actionErr, errDynamicTemplateConflict) {
		s.reject(w, principal, slot, http.StatusConflict, "template-conflict")
		return
	}
	if actionErr != nil {
		s.reject(w, principal, slot, http.StatusServiceUnavailable, reasonBrokerUnavailable)
		return
	}
	body, ok := s.readRecoveryCredential(w, r, principal, slot)
	if !ok {
		return
	}
	defer clearBytes(body)
	if err := ValidateCredential(templateConfig.Adapter, body); err != nil {
		s.reject(w, principal, slot, http.StatusBadRequest, "invalid-credential")
		return
	}
	operationID, err := randomToken(32)
	if err != nil {
		s.reject(w, principal, slot, http.StatusServiceUnavailable, reasonBrokerUnavailable)
		return
	}
	if action == dynamicActionEnroll {
		err = s.broker.CompleteEnrollment(r.Context(), principal, templateName, operationID, body, authExpiresAt)
	} else {
		err = s.broker.Reconnect(r.Context(), principal, operationID, body, authExpiresAt)
	}
	if err != nil {
		reason := brokerCompletionReason(err)
		status := http.StatusBadGateway
		if reason == "account-conflict" {
			status = http.StatusConflict
		}
		s.reject(w, principal, slot, status, reason)
		return
	}
	s.audit.Enrollment(principal, slot, "success", "")
	writeJSON(w, http.StatusOK, map[string]string{"outcome": "updated", "template": templateName})
}

func (s *Server) dynamicRevoke(w http.ResponseWriter, r *http.Request, principal Principal, csrf string) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost || r.URL.RawQuery != "" ||
		!validMutation(r, s.cfg.PublicOrigin(), csrf) || r.Header.Get(confirmHeader) != "revoke" {
		http.Error(w, "request rejected", http.StatusForbidden)
		return
	}
	operationID, err := randomToken(32)
	if err == nil {
		err = s.broker.Revoke(r.Context(), principal, operationID)
	}
	if err != nil {
		s.audit.DynamicAccount(principal, "revoke", "failure", brokerCompletionReason(err))
		http.Error(w, "account-update-failed", http.StatusBadGateway)
		return
	}
	s.enrollments.CancelPrincipal(principal)
	s.audit.DynamicAccount(principal, "revoke", "success", "")
	writeJSON(w, http.StatusOK, DynamicAccountState{State: accountStateRevoked})
}

func (s *Server) dynamicAction(
	ctx context.Context,
	principal Principal,
	templateName string,
) (string, error) {
	account, err := s.broker.Account(ctx, principal)
	if err != nil {
		return "", fmt.Errorf("read own dynamic account state: %w", err)
	}
	switch account.State {
	case accountStateNotEnrolled:
		return dynamicActionEnroll, nil
	case accountStateUnready:
		if account.Template != templateName {
			return "", errDynamicTemplateConflict
		}
		return dynamicActionReconnect, nil
	case accountStateRevoked:
		if account.Template == templateName {
			return dynamicActionEnroll, nil
		}
		if err := s.authorizeTemplateSwitch(ctx, principal); err != nil {
			return "", err
		}
		return dynamicActionEnroll, nil
	case accountStateReady:
		if account.Template != templateName {
			return "", errDynamicTemplateConflict
		}
		return dynamicActionReconnect, nil
	default:
		return "", ErrBrokerUnavailable
	}
}

func (s *Server) authorizeTemplateSwitch(ctx context.Context, principal Principal) error {
	if s.switchCoordinator == nil {
		return errDynamicTemplateConflict
	}
	operationID, err := randomToken(32)
	if err != nil {
		return ErrTemplateSwitchUnavailable
	}
	requestID, authorized, err := s.broker.RequestTemplateSwitch(ctx, principal, operationID)
	if err != nil {
		return fmt.Errorf("request target-free template switch: %w", err)
	}
	if authorized {
		return nil
	}
	if err := s.switchCoordinator.Authorize(ctx, requestID); err != nil {
		return fmt.Errorf("authorize target-free template switch: %w", err)
	}
	return nil
}

func (s *Server) dynamicTemplate(name string) (DynamicCredentialTemplate, bool) {
	for _, templateConfig := range s.cfg.Dynamic.Templates {
		if templateConfig.Name == name {
			return templateConfig, true
		}
	}
	return DynamicCredentialTemplate{}, false
}

func (s *Server) readRecoveryCredential(
	w http.ResponseWriter,
	r *http.Request,
	principal Principal,
	slot Slot,
) ([]byte, bool) {
	mediaType, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != jsonContentType || len(params) != 0 {
		s.reject(w, principal, slot, http.StatusUnsupportedMediaType, "content-type")
		return nil, false
	}
	if r.ContentLength > s.cfg.MaxUploadBytes {
		s.reject(w, principal, slot, http.StatusRequestEntityTooLarge, "too-large")
		return nil, false
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, s.cfg.MaxUploadBytes))
	if err != nil {
		clearBytes(body)
		s.reject(w, principal, slot, http.StatusRequestEntityTooLarge, "too-large")
		return nil, false
	}
	return body, true
}

func dynamicAuditSlot(principal Principal, templateConfig DynamicCredentialTemplate) Slot {
	return Slot{
		Name: templateConfig.Name, Label: templateConfig.Label, Owner: principal, Adapter: templateConfig.Adapter,
	}
}

func (s *Server) connect(
	w http.ResponseWriter,
	r *http.Request,
	principal Principal,
	csrf string,
	authExpiresAt time.Time,
	slotName string,
) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost || r.URL.RawQuery != "" {
		http.NotFound(w, r)
		return
	}
	slot, ok := s.ownedSlot(principal, slotName)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if !validMutation(r, s.cfg.PublicOrigin(), csrf) {
		s.reject(w, principal, slot, http.StatusForbidden, "csrf")
		return
	}
	if r.Header.Get(confirmHeader) != confirmationReplace {
		s.reject(w, principal, slot, http.StatusBadRequest, "confirmation-required")
		return
	}
	status, err := s.enrollments.Start(r.Context(), principal, slot, authExpiresAt)
	if errors.Is(err, ErrEnrollmentBusy) {
		s.reject(w, principal, slot, http.StatusTooManyRequests, "capacity")
		return
	}
	if err != nil {
		s.reject(w, principal, slot, http.StatusBadGateway, "runner-start-failed")
		return
	}
	writeJSON(w, http.StatusAccepted, status)
}

func (s *Server) enrollment(w http.ResponseWriter, r *http.Request, principal Principal, csrf, id string) {
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.RawQuery != "" {
		http.NotFound(w, r)
		return
	}
	if r.Method == http.MethodDelete {
		if !validMutation(r, s.cfg.PublicOrigin(), csrf) {
			http.Error(w, "request rejected", http.StatusForbidden)
			return
		}
		if err := s.enrollments.Cancel(principal, id); err != nil {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	status, err := s.enrollments.Status(principal, id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, http.StatusOK, status)
}

func (s *Server) enrollmentCode(w http.ResponseWriter, r *http.Request, principal Principal, csrf, id string) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost || r.URL.RawQuery != "" {
		http.NotFound(w, r)
		return
	}
	if !validMutation(r, s.cfg.PublicOrigin(), csrf) {
		http.Error(w, "request rejected", http.StatusForbidden)
		return
	}
	code, ok := readEnrollmentCode(w, r)
	if !ok {
		http.Error(w, "request rejected", http.StatusBadRequest)
		return
	}
	defer clearString(&code)
	if err := s.enrollments.ProvideCode(principal, id, code); errors.Is(err, ErrEnrollmentNotFound) {
		http.NotFound(w, r)
		return
	} else if err != nil {
		http.Error(w, "request rejected", http.StatusConflict)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) enroll(w http.ResponseWriter, r *http.Request, principal Principal, csrf, slotName string) {
	w.Header().Set("Cache-Control", "no-store")
	if !s.cfg.RecoveryUpload.Enabled || r.Method != http.MethodPut || r.URL.RawQuery != "" {
		http.NotFound(w, r)
		return
	}
	slot, ok := s.ownedSlot(principal, slotName)
	if !ok {
		http.NotFound(w, r)
		return
	}
	s.audit.Enrollment(principal, slot, "attempt", "")
	if !validMutation(r, s.cfg.PublicOrigin(), csrf) {
		s.reject(w, principal, slot, http.StatusForbidden, "csrf")
		return
	}
	if r.Header.Get(confirmHeader) != confirmationReplace {
		s.reject(w, principal, slot, http.StatusBadRequest, "confirmation-required")
		return
	}
	mediaType, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != jsonContentType || len(params) != 0 {
		s.reject(w, principal, slot, http.StatusUnsupportedMediaType, "content-type")
		return
	}
	if r.ContentLength > s.cfg.MaxUploadBytes {
		s.reject(w, principal, slot, http.StatusRequestEntityTooLarge, "too-large")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, s.cfg.MaxUploadBytes))
	defer func() {
		for i := range body {
			body[i] = 0
		}
		body = nil
	}()
	if err != nil {
		s.reject(w, principal, slot, http.StatusRequestEntityTooLarge, "too-large")
		return
	}
	if err := ValidateCredential(slot.Adapter, body); err != nil {
		s.reject(w, principal, slot, http.StatusBadRequest, "invalid-credential")
		return
	}
	if err := s.patcher.Patch(r.Context(), s.cfg.Namespace, slot.SecretName, slot.DataKey, body); err != nil {
		s.reject(w, principal, slot, http.StatusBadGateway, "secret-update-failed")
		return
	}
	s.audit.Enrollment(principal, slot, "success", "")
	w.Header().Set("Content-Type", jsonContentType)
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(map[string]string{"outcome": "updated", "slot": slot.Name}); err != nil {
		return
	}
}

func validMutation(r *http.Request, origin, csrf string) bool {
	return sameOrigin(r, origin) && subtle.ConstantTimeCompare([]byte(r.Header.Get(csrfHeader)), []byte(csrf)) == 1
}

func readEnrollmentCode(w http.ResponseWriter, r *http.Request) (string, bool) {
	mediaType, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != jsonContentType || len(params) != 0 || r.ContentLength > maxEnrollmentCodeBytes+64 {
		return "", false
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxEnrollmentCodeBytes+64))
	defer clearBytes(body)
	if err != nil || !json.Valid(body) || rejectDuplicateJSONKeys(body) != nil {
		return "", false
	}
	var request struct {
		Code string `json:"code"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil || !validEnrollmentCode(request.Code) {
		return "", false
	}

	return request.Code, true
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", jsonContentType)
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		return
	}
}

func (s *Server) reject(w http.ResponseWriter, principal Principal, slot Slot, status int, reason string) {
	s.audit.Enrollment(principal, slot, "failure", reason)
	http.Error(w, reason, status)
}

func (s *Server) ownedSlot(principal Principal, name string) (Slot, bool) {
	for _, slot := range s.cfg.Slots {
		if slot.Name == name && principal.Owns(slot) {
			return slot, true
		}
	}
	return Slot{}, false
}

var portalTemplate = template.Must(template.New("portal").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Credential enrollment</title><style>body{font:16px system-ui;margin:2rem;max-width:48rem;color:#17202a}fieldset{margin:1rem 0;padding:1rem}button,select,input{font:inherit;margin:.4rem 0}.status{min-height:1.5rem}.action{padding:1rem;background:#f4f6f7}.hidden{display:none}</style></head>
<body><header><h1>Manage credentials</h1>{{if .PrincipalName}}<p>Signed in as {{.PrincipalName}}</p>{{end}}</header>
<p>Connect or reconnect a configured provider account. The portal never reads or displays the current value and does not report provider health.</p>
{{if gt (len .Slots) 1}}<label for="slot">Enrollment slot</label><select id="slot"><option value="">Select a slot</option>{{range .Slots}}<option value="{{.Name}}">{{.Label}}{{if eq .Adapter "codex-oauth-file"}} (experimental device login){{end}}</option>{{end}}</select>{{else if eq (len .Slots) 1}}<input id="slot" type="hidden" value="{{(index .Slots 0).Name}}"><h2>{{(index .Slots 0).Label}}{{if eq (index .Slots 0).Adapter "codex-oauth-file"}} (experimental device login){{end}}</h2>{{end}}
<fieldset><legend>Option 1: Sign in with provider</legend><button id="connect" type="button">Connect / reconnect</button><div id="action" class="action hidden"><a id="provider" href="#" target="_blank" rel="noopener noreferrer">Continue with provider</a><p id="device"></p><div id="paste" class="hidden"><label for="code">Authorization code</label><br><input id="code" type="password" autocomplete="off"><button id="submit-code" type="button">Submit code</button></div><button id="cancel" type="button">Cancel</button></div><p class="status" id="status" role="status"></p></fieldset>
{{if .RecoveryUpload}}<fieldset><legend>Option 2: Upload an existing credential file</legend><p>Use this instead of provider sign-in when you already have a valid credential file. Uploading replaces the credential currently stored for the selected account.</p><input id="credential" type="file" accept="application/json,.json"><br><label><input id="confirm" type="checkbox"> I understand this replaces the credential currently stored for this account.</label><br><button id="upload" type="button">Upload credential file</button><p class="status" id="upload-status" role="status"></p></fieldset>{{end}}
<button id="logout" type="button">Log out</button>
<script>
const csrf={{.CSRF}},base={{.BasePath}},status=document.getElementById('status');
let enrollment='';
const headers={'X-CSRF-Token':csrf};
function setText(element,value){if(element.textContent!==value)element.textContent=value}
async function poll(){
if(!enrollment)return;
const r=await fetch(base+'/enrollments/'+encodeURIComponent(enrollment),{credentials:'same-origin'});
if(!r.ok){setText(status,'Enrollment failed.');return}
const value=await r.json();
if(value.status==='starting'){setTimeout(poll,500);return}
if(value.status==='action-required'){
document.getElementById('action').classList.remove('hidden');
const link=document.getElementById('provider');
if(link.getAttribute('href')!==value.authorizationURL)link.setAttribute('href',value.authorizationURL);
setText(document.getElementById('device'),value.userCode?'One-time code: '+value.userCode:'');
document.getElementById('paste').classList.toggle('hidden',!value.needsCode);
setText(status,'Complete sign-in with the provider.');
setTimeout(poll,1000);
return
}
document.getElementById('action').classList.add('hidden');
setText(status,value.status==='success'?'Credential seed updated. Broker import occurs independently.':'Enrollment failed.')
}
document.getElementById('connect').onclick=async()=>{
const slot=document.getElementById('slot').value;
if(!slot||!confirm('Continue and replace this slot after provider sign-in succeeds?'))return;
setText(status,'Starting provider login…');
const r=await fetch(base+'/slots/'+encodeURIComponent(slot)+'/connect',{method:'POST',credentials:'same-origin',headers:{...headers,'X-NVT-Confirm':'replace'}});
if(!r.ok){setText(status,'Enrollment failed.');return}
const value=await r.json();
enrollment=value.id;
poll()
};
document.getElementById('submit-code').onclick=async()=>{
const input=document.getElementById('code'),code=input.value;
input.value='';
if(!enrollment||!code)return;
const r=await fetch(base+'/enrollments/'+encodeURIComponent(enrollment)+'/code',{method:'POST',credentials:'same-origin',headers:{...headers,'Content-Type':'application/json'},body:JSON.stringify({code})});
setText(status,r.ok?'Completing provider login…':'Enrollment failed.')
};
document.getElementById('cancel').onclick=async()=>{
if(enrollment)await fetch(base+'/enrollments/'+encodeURIComponent(enrollment),{method:'DELETE',credentials:'same-origin',headers});
enrollment='';
document.getElementById('action').classList.add('hidden');
setText(status,'Enrollment cancelled.')
};
{{if .RecoveryUpload}}document.getElementById('upload').onclick=async()=>{
const uploadStatus=document.getElementById('upload-status'),slot=document.getElementById('slot').value,file=document.getElementById('credential').files[0];
if(!slot||!file||!document.getElementById('confirm').checked){setText(uploadStatus,'Select a slot and file, then confirm replacement.');return}
setText(uploadStatus,'Uploading…');
try{
const r=await fetch(base+'/slots/'+encodeURIComponent(slot)+'/credential',{method:'PUT',credentials:'same-origin',headers:{...headers,'Content-Type':'application/json','X-NVT-Confirm':'replace'},body:file});
setText(uploadStatus,r.ok?'Credential seed updated. Broker import occurs independently.':'Enrollment failed.')
}catch(_){setText(uploadStatus,'Enrollment failed.')}
};{{end}}
document.getElementById('logout').onclick=async()=>{
await fetch(base+'/logout',{method:'POST',credentials:'same-origin',headers});
location.href=base+'/'
};
</script></body></html>`))

var dynamicPortalTemplate = template.Must(template.New("dynamic-portal").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Credential enrollment</title><style>body{font:16px system-ui;margin:2rem;max-width:48rem;color:#17202a}fieldset{margin:1rem 0;padding:1rem}button,select,input{font:inherit;margin:.4rem 0}.status{min-height:1.5rem}.action{padding:1rem;background:#f4f6f7}.hidden{display:none}</style></head>
<body><header><h1>Manage credentials</h1>{{if .PrincipalName}}<p>Signed in as {{.PrincipalName}}</p>{{end}}</header>
<p>Choose one administrator-approved credential template. The portal never displays credential contents or selects broker providers, execution profiles, grants, capabilities, or runtime settings.</p>
<p id="account-state">Broker-reported account state: {{.Account.State}}{{if .Account.Template}} (template {{.Account.Template}}, generation {{.Account.Generation}}){{end}}.</p>
<label for="template">Credential template</label><select id="template"><option value="">Select a template</option>{{range .Templates}}<option value="{{.Name}}">{{.Label}}</option>{{end}}</select>
<fieldset><legend>Provider login</legend><button id="connect" type="button">{{.ActionLabel}}</button><div id="action" class="action hidden"><a id="provider" href="#" target="_blank" rel="noopener noreferrer">Continue with provider</a><p id="device"></p><div id="paste" class="hidden"><label for="code">Authorization code</label><br><input id="code" type="password" value="" autocomplete="off"><button id="submit-code" type="button">Submit authorization code</button></div><button id="cancel" type="button">Cancel</button></div><p class="status" id="status" role="status"></p></fieldset>
{{if .RecoveryUpload}}<fieldset><legend>Recovery upload (optional)</legend><p>This administrator-enabled alternative replaces provider login; it is not a prerequisite. Upload only a valid credential document for the selected template.</p><input id="credential" type="file" accept="application/json,.json"><br><label><input id="confirm" type="checkbox"> I understand this enrolls or replaces my current credential.</label><br><button id="upload" type="button">Upload recovery credential</button><p class="status" id="upload-status" role="status"></p></fieldset>{{end}}
{{if or (eq .Account.State "ready") (eq .Account.State "unready")}}<button id="revoke" type="button">Revoke credential account</button>{{end}} <button id="logout" type="button">Log out</button>
<script>
const csrf={{.CSRF}},base={{.BasePath}},status=document.getElementById('status');
let enrollment='';
const headers={'X-CSRF-Token':csrf};
function setText(element,value){if(element.textContent!==value)element.textContent=value}
async function poll(){
if(!enrollment)return;
const r=await fetch(base+'/enrollments/'+encodeURIComponent(enrollment),{credentials:'same-origin'});
if(!r.ok){setText(status,'Enrollment failed.');return}
const value=await r.json();
if(value.status==='starting'){setTimeout(poll,500);return}
if(value.status==='action-required'){
document.getElementById('action').classList.remove('hidden');
const link=document.getElementById('provider');
if(link.getAttribute('href')!==value.authorizationURL)link.setAttribute('href',value.authorizationURL);
setText(document.getElementById('device'),value.userCode?'One-time device code: '+value.userCode:'');
document.getElementById('paste').classList.toggle('hidden',!value.needsCode);
setText(status,value.needsCode?'Complete provider authorization, then enter the authorization code.':'Complete device authorization with the provider.');
setTimeout(poll,1000);return
}
document.getElementById('action').classList.add('hidden');
setText(status,value.status==='success'?'Credential stored by the broker.':'Enrollment failed.')
}
document.getElementById('connect').onclick=async()=>{
const selected=document.getElementById('template').value;
if(!selected||!confirm('Continue with this credential template? Active templates are never switched implicitly.'))return;
setText(status,'Starting provider login…');
const r=await fetch(base+'/templates/'+encodeURIComponent(selected)+'/connect',{method:'POST',credentials:'same-origin',headers:{...headers,'X-NVT-Confirm':'replace'}});
if(!r.ok){setText(status,r.status===409?'A different template is already active. Revoke explicitly before any later enrollment.':'Enrollment failed.');return}
const value=await r.json();enrollment=value.id;poll()
};
document.getElementById('submit-code').onclick=async()=>{
const input=document.getElementById('code'),code=input.value;input.value='';
if(!enrollment||!code)return;
const r=await fetch(base+'/enrollments/'+encodeURIComponent(enrollment)+'/code',{method:'POST',credentials:'same-origin',headers:{...headers,'Content-Type':'application/json'},body:JSON.stringify({code})});
setText(status,r.ok?'Completing provider login…':'Enrollment failed.')
};
document.getElementById('cancel').onclick=async()=>{if(enrollment)await fetch(base+'/enrollments/'+encodeURIComponent(enrollment),{method:'DELETE',credentials:'same-origin',headers});enrollment='';document.getElementById('action').classList.add('hidden');setText(status,'Enrollment cancelled.')};
{{if .RecoveryUpload}}document.getElementById('upload').onclick=async()=>{
const uploadStatus=document.getElementById('upload-status'),selected=document.getElementById('template').value,file=document.getElementById('credential').files[0];
if(!selected||!file||!document.getElementById('confirm').checked){setText(uploadStatus,'Select a template and file, then confirm replacement.');return}
const r=await fetch(base+'/templates/'+encodeURIComponent(selected)+'/credential',{method:'PUT',credentials:'same-origin',headers:{...headers,'Content-Type':'application/json','X-NVT-Confirm':'replace'},body:file});
setText(uploadStatus,r.ok?'Credential stored by the broker.':'Recovery enrollment failed.')
};{{end}}
const revoke=document.getElementById('revoke');if(revoke)revoke.onclick=async()=>{if(!confirm('Revoke this credential account? Running agents are not coordinated by this portal.'))return;const r=await fetch(base+'/account/revoke',{method:'POST',credentials:'same-origin',headers:{...headers,'X-NVT-Confirm':'revoke'}});if(r.ok)location.reload();else setText(status,'Account update failed.')};
document.getElementById('logout').onclick=async()=>{await fetch(base+'/logout',{method:'POST',credentials:'same-origin',headers});location.href=base+'/'};
</script></body></html>`))
