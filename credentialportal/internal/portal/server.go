package portal

import (
	"crypto/subtle"
	"encoding/json"
	"html/template"
	"io"
	"mime"
	"net/http"
	"strings"
)

type Server struct {
	cfg     Config
	auth    *Authenticator
	patcher SecretPatcher
	audit   *AuditLogger
}

func NewServer(cfg Config, auth *Authenticator, patcher SecretPatcher, audit *AuditLogger) *Server {
	return &Server{cfg: cfg, auth: auth, patcher: patcher, audit: audit}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
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
	principal, csrf, authenticated := s.auth.Session(r)
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
		if r.Method != http.MethodPost || r.URL.RawQuery != "" || !s.auth.Logout(w, r, csrf) {
			http.Error(w, "request rejected", http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	prefix := s.cfg.Path("/slots/")
	if strings.HasPrefix(r.URL.Path, prefix) && strings.HasSuffix(r.URL.Path, "/credential") {
		name := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, prefix), "/credential")
		if name == "" || strings.Contains(name, "/") {
			http.NotFound(w, r)
			return
		}
		s.enroll(w, r, principal, csrf, name)
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
	_ = portalTemplate.Execute(w, struct {
		Slots         []Slot
		CSRF          string
		BasePath      string
		PrincipalName string
	}{slots, csrf, s.cfg.basePath, principal.DisplayName})
}

func (s *Server) enroll(w http.ResponseWriter, r *http.Request, principal Principal, csrf, slotName string) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPut || r.URL.RawQuery != "" {
		http.NotFound(w, r)
		return
	}
	slot, ok := s.ownedSlot(principal, slotName)
	if !ok {
		http.NotFound(w, r)
		return
	}
	s.audit.Enrollment(principal, slot, "attempt", "")
	if !sameOrigin(r, s.cfg.PublicOrigin()) || subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(csrf)) != 1 {
		s.reject(w, principal, slot, http.StatusForbidden, "csrf")
		return
	}
	if r.Header.Get("X-NVT-Confirm") != "replace" {
		s.reject(w, principal, slot, http.StatusBadRequest, "confirmation-required")
		return
	}
	mediaType, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" || len(params) != 0 {
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
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"outcome": "updated", "slot": slot.Name})
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
<title>Credential enrollment</title><style>body{font:16px system-ui;margin:2rem;max-width:48rem;color:#17202a}fieldset{margin:1rem 0;padding:1rem}button,select,input{font:inherit;margin:.4rem 0}small{color:#59697a}.status{min-height:1.5rem}</style></head>
<body><header><h1>Manage credentials</h1>{{if .PrincipalName}}<p>Signed in as {{.PrincipalName}}</p>{{end}}</header>
<p>Enroll or replace a configured credential file. The portal never reads or displays the current value and does not report provider health.</p>
{{if gt (len .Slots) 1}}<label for="slot">Enrollment slot</label><select id="slot"><option value="">Select a slot</option>{{range .Slots}}<option value="{{.Name}}">{{.Label}}</option>{{end}}</select>{{else if eq (len .Slots) 1}}<input id="slot" type="hidden" value="{{(index .Slots 0).Name}}"><h2>{{(index .Slots 0).Label}}</h2>{{end}}
<fieldset><legend>Enroll or replace</legend><input id="credential" type="file" accept="application/json,.json"><br><label><input id="confirm" type="checkbox"> I understand this replaces the configured enrollment seed.</label><br><button id="upload" type="button">Enroll / replace</button><p class="status" id="status" role="status"></p></fieldset>
<button id="logout" type="button">Log out</button>
<script>const csrf={{printf "%q" .CSRF}},base={{printf "%q" .BasePath}};document.getElementById('upload').onclick=async()=>{const status=document.getElementById('status'),slot=document.getElementById('slot').value,file=document.getElementById('credential').files[0];if(!slot||!file||!document.getElementById('confirm').checked){status.textContent='Select a slot and file, then confirm replacement.';return}status.textContent='Uploading…';try{const r=await fetch(base+'/slots/'+encodeURIComponent(slot)+'/credential',{method:'PUT',credentials:'same-origin',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf,'X-NVT-Confirm':'replace'},body:file});status.textContent=r.ok?'Credential seed updated. Broker import occurs independently.':'Enrollment failed.'}catch(_){status.textContent='Enrollment failed.'}};document.getElementById('logout').onclick=async()=>{await fetch(base+'/logout',{method:'POST',credentials:'same-origin',headers:{'X-CSRF-Token':csrf}});location.href=base+'/'};</script></body></html>`))
