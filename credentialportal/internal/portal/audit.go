package portal

import (
	"encoding/json"
	"io"
	"sync"
	"time"
)

type AuditLogger struct {
	out io.Writer
	now func() time.Time
	mu  sync.Mutex
}

func NewAuditLogger(out io.Writer) *AuditLogger { return &AuditLogger{out: out, now: time.Now} }

func (a *AuditLogger) Enrollment(principal Principal, slot Slot, outcome, reason string) {
	event := struct {
		Event          string `json:"event"`
		Timestamp      string `json:"timestamp"`
		Issuer         string `json:"issuer"`
		Subject        string `json:"subject"`
		Slot           string `json:"slot"`
		Adapter        string `json:"adapter"`
		BrokerProvider string `json:"brokerProvider"`
		Outcome        string `json:"outcome"`
		Reason         string `json:"reason,omitempty"`
	}{"credential_enrollment", a.now().UTC().Format(time.RFC3339Nano), principal.Issuer, principal.Subject, slot.Name, slot.Adapter, slot.BrokerProvider, outcome, reason}
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := json.NewEncoder(a.out).Encode(event); err != nil {
		return
	}
}
