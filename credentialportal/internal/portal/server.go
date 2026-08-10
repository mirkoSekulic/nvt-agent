package portal

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"
)

type Server struct {
	patcher     SecretPatcher
	auth        *Authenticator
	audit       *AuditLogger
	enrollments *EnrollmentManager
	cfg         Config
}

func NewServer(
	cfg Config,
	auth *Authenticator,
	patcher SecretPatcher,
	audit *AuditLogger,
	runner CredentialRunner,
) *Server {
	return &Server{
		cfg: cfg, auth: auth, patcher: patcher, audit: audit,
		enrollments: NewEnrollmentManager(cfg, patcher, audit, runner),
	}
}

func (s *Server) Close() {
	s.enrollments.Close()
}

//nolint:cyclop,funlen,gocognit,gocyclo,nestif // Central routing keeps every path behind one admission gate.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().
		Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
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
		w.WriteHeader(http.StatusNoContent)
		return
	case s.cfg.Path("/login"):
		s.auth.Login(w, r)
		return
	case s.cfg.Path(callbackPath(s.cfg)):
		s.auth.Callback(w, r)
		return
	}
	principal, csrf, authExpiresAt, authenticated := s.auth.Session(r)
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
		s.dashboard(w, principal, csrf)
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

func (s *Server) dashboard(w http.ResponseWriter, principal Principal, csrf string) {
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
	if r.Header.Get(confirmHeader) != "replace" {
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
	if r.Header.Get(confirmHeader) != "replace" {
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
<fieldset><legend>Provider login</legend><button id="connect" type="button">Connect / reconnect</button><div id="action" class="action hidden"><a id="provider" href="#" target="_blank" rel="noopener noreferrer">Continue with provider</a><p id="device"></p><div id="paste" class="hidden"><label for="code">Authorization code</label><br><input id="code" type="password" autocomplete="off"><button id="submit-code" type="button">Submit code</button></div><button id="cancel" type="button">Cancel</button></div><p class="status" id="status" role="status"></p></fieldset>
{{if .RecoveryUpload}}<fieldset><legend>Administrator recovery upload</legend><p>This secondary recovery path replaces the configured seed with a credential file.</p><input id="credential" type="file" accept="application/json,.json"><br><label><input id="confirm" type="checkbox"> I understand this replaces the configured enrollment seed.</label><br><button id="upload" type="button">Upload recovery file</button><p class="status" id="upload-status" role="status"></p></fieldset>{{end}}
<button id="logout" type="button">Log out</button>
<script>const csrf={{printf "%q" .CSRF}},base={{printf "%q" .BasePath}},status=document.getElementById('status');let enrollment='';const headers={'X-CSRF-Token':csrf};async function poll(){if(!enrollment)return;const r=await fetch(base+'/enrollments/'+encodeURIComponent(enrollment),{credentials:'same-origin'});if(!r.ok){status.textContent='Enrollment failed.';return}const value=await r.json();if(value.status==='starting'){setTimeout(poll,500);return}if(value.status==='action-required'){document.getElementById('action').classList.remove('hidden');const link=document.getElementById('provider');link.href=value.authorizationURL;document.getElementById('device').textContent=value.userCode?'One-time code: '+value.userCode:'';document.getElementById('paste').classList.toggle('hidden',!value.needsCode);status.textContent='Complete sign-in with the provider.';setTimeout(poll,1000);return}document.getElementById('action').classList.add('hidden');status.textContent=value.status==='success'?'Credential seed updated. Broker import occurs independently.':'Enrollment failed.'}document.getElementById('connect').onclick=async()=>{const slot=document.getElementById('slot').value;if(!slot||!confirm('Continue and replace this slot after provider sign-in succeeds?'))return;status.textContent='Starting provider login…';const r=await fetch(base+'/slots/'+encodeURIComponent(slot)+'/connect',{method:'POST',credentials:'same-origin',headers:{...headers,'X-NVT-Confirm':'replace'}});if(!r.ok){status.textContent='Enrollment failed.';return}const value=await r.json();enrollment=value.id;poll()};document.getElementById('submit-code').onclick=async()=>{const input=document.getElementById('code'),code=input.value;input.value='';if(!enrollment||!code)return;const r=await fetch(base+'/enrollments/'+encodeURIComponent(enrollment)+'/code',{method:'POST',credentials:'same-origin',headers:{...headers,'Content-Type':'application/json'},body:JSON.stringify({code})});status.textContent=r.ok?'Completing provider login…':'Enrollment failed.'};document.getElementById('cancel').onclick=async()=>{if(enrollment)await fetch(base+'/enrollments/'+encodeURIComponent(enrollment),{method:'DELETE',credentials:'same-origin',headers});enrollment='';document.getElementById('action').classList.add('hidden');status.textContent='Enrollment cancelled.'};{{if .RecoveryUpload}}document.getElementById('upload').onclick=async()=>{const uploadStatus=document.getElementById('upload-status'),slot=document.getElementById('slot').value,file=document.getElementById('credential').files[0];if(!slot||!file||!document.getElementById('confirm').checked){uploadStatus.textContent='Select a slot and file, then confirm replacement.';return}uploadStatus.textContent='Uploading…';try{const r=await fetch(base+'/slots/'+encodeURIComponent(slot)+'/credential',{method:'PUT',credentials:'same-origin',headers:{...headers,'Content-Type':'application/json','X-NVT-Confirm':'replace'},body:file});uploadStatus.textContent=r.ok?'Credential seed updated. Broker import occurs independently.':'Enrollment failed.'}catch(_){uploadStatus.textContent='Enrollment failed.'}};{{end}}document.getElementById('logout').onclick=async()=>{await fetch(base+'/logout',{method:'POST',credentials:'same-origin',headers});location.href=base+'/'};</script></body></html>`))
