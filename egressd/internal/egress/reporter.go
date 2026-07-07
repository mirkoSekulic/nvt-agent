package egress

import (
	"context"
	"log"
	"strings"
	"sync/atomic"
	"time"
)

// pathClassMaxLen and pathClassAllowed mirror the broker's audit shape
// (^[a-z0-9._-]{1,64}$, protocol/injection.md). PathClass guarantees its
// output at the source so egressd can never emit a class the broker rejects.
const pathClassMaxLen = 64

// PathClass reduces a request path to a sanitized audit class, computed at the
// source so raw paths (repo names, file names) never leave egressd. git
// smart-HTTP paths map to the three git classes; every other path reduces to a
// sanitized form of its first segment, and "/" to "root". The result always
// matches ^[a-z0-9._-]{1,64}$ for any input, hostile or not.
func PathClass(path string) string {
	switch {
	case strings.HasSuffix(path, "/info/refs"):
		return "info-refs"
	case strings.HasSuffix(path, "/git-upload-pack"):
		return "git-upload-pack"
	case strings.HasSuffix(path, "/git-receive-pack"):
		return "git-receive-pack"
	}
	trimmed := strings.TrimPrefix(path, "/")
	if index := strings.IndexByte(trimmed, '/'); index >= 0 {
		trimmed = trimmed[:index]
	}
	if trimmed == "" {
		return "root"
	}
	class := sanitizePathClass(trimmed)
	if class == "" {
		// A non-empty segment made entirely of disallowed characters (e.g.
		// "@@@", a percent-escape, non-ASCII) collapses to a safe bucket
		// rather than leaking or emitting an invalid class.
		return "other"
	}
	return class
}

// sanitizePathClass lowercases the segment and keeps only the broker's allowed
// characters, capped at pathClassMaxLen. The kept runes are ASCII by
// construction, so the byte cast is safe.
func sanitizePathClass(segment string) string {
	var builder strings.Builder
	for _, r := range strings.ToLower(segment) {
		if builder.Len() >= pathClassMaxLen {
			break
		}
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
			builder.WriteByte(byte(r))
		}
	}
	return builder.String()
}

// Reporter batches per-request audit reports and flushes them to the broker
// asynchronously. It is observability, not a security control
// (protocol/injection.md): the queue is bounded and the flush is best-effort,
// so reporting never adds latency to a proxied request and never fails one.
// A full queue or a broker report failure drops the entry (counted, logged
// sanitized) rather than blocking.
//
// path_class is computed by the caller (PathClass) so raw request paths never
// enter the queue — only sanitized classes leave the process.
type Reporter struct {
	broker        *BrokerClient
	queue         chan ReportEntry
	batchSize     int
	flushInterval time.Duration
	dropped       int64
}

// ReportEntry is one audited outcome. A non-empty Decision marks a
// forward-proxy CONNECT (host/port/decision); otherwise it is a proxied HTTP
// request (method/path_class/status). No field is ever a header value.
type ReportEntry struct {
	Capability string
	Host       string
	Method     string
	PathClass  string
	Status     int
	Port       int
	Decision   string
}

func (e ReportEntry) toWire() map[string]any {
	if e.Decision != "" {
		return map[string]any{
			"capability": e.Capability,
			"host":       e.Host,
			"port":       e.Port,
			"decision":   e.Decision,
		}
	}
	return map[string]any{
		"capability": e.Capability,
		"host":       e.Host,
		"method":     e.Method,
		"path_class": e.PathClass,
		"status":     e.Status,
	}
}

const (
	defaultReportQueueSize     = 1024
	defaultReportBatchSize     = 100
	defaultReportFlushInterval = 2 * time.Second
)

// NewReporter builds a reporter over the shared broker client. A nil broker
// yields a nil reporter so callers can wire it unconditionally.
func NewReporter(broker *BrokerClient) *Reporter {
	if broker == nil {
		return nil
	}
	return &Reporter{
		broker:        broker,
		queue:         make(chan ReportEntry, defaultReportQueueSize),
		batchSize:     defaultReportBatchSize,
		flushInterval: defaultReportFlushInterval,
	}
}

// Enqueue offers an entry to the queue without ever blocking. When the queue
// is full the entry is dropped and counted — the request path must never wait
// on audit.
func (r *Reporter) Enqueue(entry ReportEntry) {
	if r == nil {
		return
	}
	select {
	case r.queue <- entry:
	default:
		atomic.AddInt64(&r.dropped, 1)
	}
}

// Dropped reports the number of entries dropped so far (test/observability).
func (r *Reporter) Dropped() int64 {
	if r == nil {
		return 0
	}
	return atomic.LoadInt64(&r.dropped)
}

// Run drains the queue on the flush tick or when a batch fills, until ctx is
// cancelled, then makes a best-effort final drain. Start it once per process.
func (r *Reporter) Run(ctx context.Context) {
	if r == nil {
		return
	}
	ticker := time.NewTicker(r.flushInterval)
	defer ticker.Stop()
	batch := make([]ReportEntry, 0, r.batchSize)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		r.send(ctx, batch)
		batch = batch[:0]
	}
	for {
		select {
		case <-ctx.Done():
			r.finalDrain(ctx, batch)
			return
		case entry := <-r.queue:
			batch = append(batch, entry)
			if len(batch) >= r.batchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

func (r *Reporter) finalDrain(ctx context.Context, batch []ReportEntry) {
	for {
		select {
		case entry := <-r.queue:
			batch = append(batch, entry)
			if len(batch) >= r.batchSize {
				r.send(ctx, batch)
				batch = batch[:0]
			}
		default:
			r.send(ctx, batch)
			return
		}
	}
}

func (r *Reporter) send(ctx context.Context, batch []ReportEntry) {
	if len(batch) == 0 {
		return
	}
	entries := make([]map[string]any, 0, len(batch))
	for _, entry := range batch {
		entries = append(entries, entry.toWire())
	}
	if err := r.broker.ReportRequests(ctx, entries); err != nil {
		// err carries broker machine reasons only, never header values.
		// Report failures are non-fatal by design: the batch is dropped.
		atomic.AddInt64(&r.dropped, int64(len(batch)))
		log.Printf("egressd: dropped %d audit reports: %v", len(batch), err)
	}
}
