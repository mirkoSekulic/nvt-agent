package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const protocol = "nvt.broker-provider/v1"

type request struct {
	JSONRPC string         `json:"jsonrpc"`
	ID      string         `json:"id"`
	Method  string         `json:"method"`
	Params  map[string]any `json:"params"`
}

type server struct {
	mu        sync.Mutex
	config    map[string]any
	allow     map[string]any
	secret    string
	stateFile string
}

func main() {
	s := &server{secret: os.Getenv("FIXTURE_CREDENTIAL")}
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		var req request
		if json.Unmarshal(scanner.Bytes(), &req) != nil {
			return
		}
		if req.Method == "initialize" {
			s.handle(req)
			mode, _ := s.config["mode"].(string)
			if mode == "stop-reading" && s.firstFault("stop-reading") {
				select {}
			}
			continue
		}
		go s.handle(req)
	}
}

func (s *server) handle(req request) {
	if req.Method == "initialize" {
		s.config, _ = req.Params["config"].(map[string]any)
		s.allow, _ = req.Params["allow"].(map[string]any)
		s.stateFile, _ = s.config["state-file"].(string)
		if s.stateFile != "" {
			_ = os.WriteFile(s.stateFile+".pid", []byte(strconv.Itoa(os.Getpid())), 0o600)
		}
		mode, _ := s.config["mode"].(string)
		initialization := s.initializationCount()
		if mode == "initialize-error" {
			s.failure(req.ID, "initialize-denied", 503, "safe initialize failure")
			return
		}
		if mode == "restart-initialize-fail-once" && initialization == 2 {
			s.failure(req.ID, "initialize-retry", 503, "safe retry")
			return
		}
		capabilities := []string{"http.request", "token", "identity", "headers", "files", "placeholder-files", "injection.headers"}
		if mode == "token-only" {
			capabilities = []string{"token"}
		}
		if mode == "files-only" {
			capabilities = []string{"files"}
		}
		if mode == "unknown-capability" {
			capabilities = append(capabilities, "unknown")
		}
		if mode == "duplicate-capability" {
			capabilities = append(capabilities, "token")
		}
		result := map[string]any{
			"protocol_version":   protocol,
			"capabilities":       capabilities,
			"injection_hosts":    []string{"api.example.test"},
			"injection_git":      true,
			"bundle_ttl_seconds": 60,
		}
		if mode == "token-only" || mode == "files-only" || mode == "empty-injection-hosts" {
			result["injection_hosts"] = []string{}
			result["injection_git"] = false
		}
		if mode == "duplicate-hosts" {
			result["injection_hosts"] = []string{"api.example.test", "api.example.test"}
		}
		if mode == "malformed-host" {
			result["injection_hosts"] = []string{"bad_host.example"}
		}
		if mode == "uppercase-host" {
			result["injection_hosts"] = []string{"API.example.test"}
		}
		if mode == "port-host" {
			result["injection_hosts"] = []string{"api.example.test:443"}
		}
		if mode == "trailing-dot-host" {
			result["injection_hosts"] = []string{"api.example.test."}
		}
		if mode == "bad-metadata" {
			result["bundle_ttl_seconds"] = 0
		}
		s.success(req.ID, result)
		if mode == "restart-crash-after-initialize" && initialization == 2 {
			go func() { time.Sleep(10 * time.Millisecond); os.Exit(24) }()
		}
		return
	}

	if req.Method == "shutdown" {
		if s.stateFile != "" {
			_ = os.WriteFile(s.stateFile+".shutdown", []byte("attempted"), 0o600)
		}
		s.success(req.ID, map[string]any{"ok": true})
		return
	}

	target, _ := req.Params["target"].(string)
	if target == "slow" {
		time.Sleep(250 * time.Millisecond)
	}
	if strings.HasPrefix(target, "fault-") && s.firstFault(target) {
		s.fault(target, req.ID)
		return
	}
	if target == "declared-error" {
		s.failure(req.ID, "fixture-denied", 418, "safe fixture message")
		return
	}

	switch req.Method {
	case "target.normalize":
		if s.stateFile != "" {
			_ = os.WriteFile(s.stateFile+".normalized", []byte("called"), 0o600)
		}
		raw, _ := req.Params["target"].(string)
		raw = strings.TrimPrefix(raw, "github.com/")
		s.success(req.ID, map[string]any{"target": raw, "audit_target": "audit/" + raw})
	case "http.request":
		s.success(req.ID, map[string]any{"status": 200, "headers": map[string]string{"x-fixture": "yes"}, "body": `{\"fixture\":true}`, "audit_target": "audit/http"})
	case "token":
		s.success(req.ID, map[string]any{"token": s.secret, "expires_at": nil})
	case "identity":
		s.success(req.ID, map[string]any{"name": "Fixture Bot", "email": "fixture@example.test"})
	case "headers":
		s.success(req.ID, map[string]any{"headers": []string{"Authorization: Bearer " + s.secret}})
	case "files":
		s.success(req.ID, map[string]any{"files": []map[string]string{{"name": "fixture.txt", "content": s.secret, "mode": "0600"}}, "expires_at": nil})
	case "placeholder-files":
		s.success(req.ID, map[string]any{"files": []map[string]string{{"path": ".fixture/auth.json", "content": "placeholder", "mode": "0600"}}, "hosts": []string{"api.example.test"}, "expires_at": nil})
	case "injection.headers":
		s.success(req.ID, map[string]any{"headers": map[string]string{"authorization": "Bearer " + s.secret}, "expires_at": nil, "strip_request_headers": []string{"authorization"}})
	default:
		s.failure(req.ID, "method-not-found", 404, "unsupported provider method")
	}
}

func (s *server) initializationCount() int {
	if s.stateFile == "" {
		return 1
	}
	path := s.stateFile + ".initializations"
	data, _ := os.ReadFile(path)
	count, _ := strconv.Atoi(string(data))
	count++
	_ = os.WriteFile(path, []byte(strconv.Itoa(count)), 0o600)
	return count
}

func (s *server) firstFault(name string) bool {
	if s.stateFile == "" {
		return true
	}
	key := s.stateFile + "." + name
	if _, err := os.Stat(key); err == nil {
		return false
	}
	_ = os.WriteFile(key, []byte("faulted"), 0o600)
	return true
}

func (s *server) fault(name, id string) {
	// Deliberately secret-shaped diagnostics prove the broker drains and
	// discards stderr instead of surfacing it.
	_, _ = fmt.Fprintln(os.Stderr, s.secret)
	if strings.HasPrefix(name, "fault-crash-cycle-") {
		os.Exit(23)
	}
	switch name {
	case "fault-crash", "fault-eof":
		os.Exit(23)
	case "fault-timeout":
		time.Sleep(3 * time.Second)
	case "fault-malformed":
		s.raw("{not-json}\n")
	case "fault-nonobject":
		s.raw("[]\n")
	case "fault-oversized":
		s.raw(strings.Repeat("x", 1024*1024+1) + "\n")
	case "fault-unknown-id":
		s.success("not-"+id, map[string]any{})
	case "fault-duplicate-id":
		s.success(id, map[string]any{"token": "first", "expires_at": nil})
		s.success(id, map[string]any{"token": "second", "expires_at": nil})
	}
}

func (s *server) success(id string, result any) {
	s.write(map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
}

func (s *server) failure(id, reason string, status int, message string) {
	s.write(map[string]any{"jsonrpc": "2.0", "id": id, "error": map[string]any{
		"code": -32000, "message": "provider error", "data": map[string]any{"reason": reason, "status": status, "message": message},
	}})
}

func (s *server) write(value any) {
	data, _ := json.Marshal(value)
	s.raw(string(data) + "\n")
}

func (s *server) raw(value string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, _ = fmt.Fprint(os.Stdout, value)
}
