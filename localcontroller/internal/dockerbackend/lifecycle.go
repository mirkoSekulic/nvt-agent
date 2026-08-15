package dockerbackend

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"

	"github.com/mirkoSekulic/nvt-agent/localcontroller/internal/controller"
)

const maxLifecycleEventsPerObservation = 1024

var (
	lifecycleEventPattern  = regexp.MustCompile(`^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$`)
	lifecycleCursorPattern = regexp.MustCompile(`^v1:[0-9]+:[0-9]+:[0-9]+$`)
)

// lifecycleEventReader runs inside the already-owned agent container. It
// reads only the append-only agentd event log, strips every field except a
// bounded event name, and returns an opaque file-generation/offset cursor.
// Payloads and raw records never cross the Docker boundary.
const lifecycleEventReader = `
import json, os, re, stat, sys

MAX_INPUT = 4096
MAX_BYTES = 1 << 20
MAX_LINES = 1024
MAX_LINE = 1 << 20
EVENT = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
CURSOR = re.compile(r"^v1:([0-9]+):([0-9]+):([0-9]+)$")

def stop(reason):
    print(json.dumps({"version": 1, "cursor": "", "events": [], "error": reason}, separators=(",", ":")))
    raise SystemExit(0)

raw = sys.stdin.buffer.read(MAX_INPUT + 1)
if not raw or len(raw) > MAX_INPUT:
    stop("input")
try:
    request = json.loads(raw)
except Exception:
    stop("input")
if not isinstance(request, dict) or set(request) != {"cursor"} or not isinstance(request["cursor"], str):
    stop("input")
cursor = request["cursor"]
state_dir = os.environ.get("NVT_STATE_DIR", "")
if not state_dir or not os.path.isabs(state_dir):
    stop("state-dir")
path = os.path.join(state_dir, "agentd", "events.jsonl")
try:
    metadata = os.stat(path, follow_symlinks=False)
except FileNotFoundError:
    if cursor:
        stop("event-missing")
    print(json.dumps({"version": 1, "cursor": "", "events": []}, separators=(",", ":")))
    raise SystemExit(0)
except OSError:
    stop("event-stat")
if not stat.S_ISREG(metadata.st_mode):
    stop("event-type")

offset = 0
if cursor:
    match = CURSOR.fullmatch(cursor)
    if match is None:
        stop("cursor")
    device, inode, offset = (int(value) for value in match.groups())
    if device != metadata.st_dev or inode != metadata.st_ino or offset > metadata.st_size:
        stop("generation")

events = []
try:
    with open(path, "rb", buffering=0) as handle:
        handle.seek(offset)
        chunk = handle.read(MAX_BYTES + 1)
except OSError:
    stop("event-read")

consumed = 0
lines = 0
while consumed < len(chunk) and lines < MAX_LINES:
    newline = chunk.find(b"\n", consumed)
    if newline < 0:
        if len(chunk) > MAX_BYTES and consumed == 0:
            stop("line-size")
        break
    end = newline + 1
    if end > MAX_BYTES or end - consumed > MAX_LINE:
        stop("line-size")
    line = chunk[consumed:newline]
    try:
        record = json.loads(line.decode("utf-8"))
    except Exception:
        stop("event-json")
    if not isinstance(record, dict):
        stop("event-json")
    if record.get("event") == "plugin.event":
        name = record.get("plugin_event")
        if not isinstance(name, str) or len(name.encode("utf-8")) > 256 or EVENT.fullmatch(name) is None:
            stop("event-name")
        events.append(name)
    consumed = end
    lines += 1

next_cursor = "v1:%d:%d:%d" % (metadata.st_dev, metadata.st_ino, offset + consumed)
print(json.dumps({"version": 1, "cursor": next_cursor, "events": events}, separators=(",", ":")))
`

type lifecycleReaderResponse struct {
	Version int      `json:"version"`
	Cursor  string   `json:"cursor"`
	Events  []string `json:"events"`
	Error   string   `json:"error,omitempty"`
}

func (backend *Backend) observeLifecycle(ctx context.Context, containerID string, desired controller.BackendRun) (string, controller.State, error) {
	return backend.readLifecycle(ctx, desired, "exec", "-i", containerID, "python3", "-c", lifecycleEventReader)
}

// observeStoppedLifecycle reads the retained state volume with the
// administrator-configured trusted seed image. It never starts or executes the
// mutable stopped agent. The helper has no network, capabilities, writable
// root, Docker socket, broker identity, or credential-bearing environment.
func (backend *Backend) observeStoppedLifecycle(ctx context.Context, desired controller.BackendRun, names resourceNames, labels ownedLabels) (string, controller.State, error) {
	if len(desired.Resolved.Lifecycle.CompleteOn) == 0 && len(desired.Resolved.Lifecycle.FailOn) == 0 {
		return desired.LifecycleCursor, "", nil
	}
	if err := backend.verifyObject(ctx, "volume", names.home, labels); err != nil {
		return "", "", fmt.Errorf("%w: lifecycle state unavailable", controller.ErrBackendRetryable)
	}
	arguments := []string{
		"run", "--rm", "-i", "--network", "none", "--read-only", "--cap-drop", "ALL",
		"--security-opt", "no-new-privileges", "--user", "0:0",
		"--env", "NVT_STATE_DIR=/state/.nvt-agent", "--volume", names.home + ":/state:ro",
	}
	arguments = append(arguments, labelArguments(labels)...)
	arguments = append(arguments, "--entrypoint", "python3", backend.config.SeedImage, "-c", lifecycleEventReader)
	return backend.readLifecycle(ctx, desired, arguments...)
}

func (backend *Backend) readLifecycle(ctx context.Context, desired controller.BackendRun, arguments ...string) (string, controller.State, error) {
	if len(desired.Resolved.Lifecycle.CompleteOn) == 0 && len(desired.Resolved.Lifecycle.FailOn) == 0 {
		return desired.LifecycleCursor, "", nil
	}
	request, _ := json.Marshal(map[string]string{"cursor": desired.LifecycleCursor})
	output, err := backend.docker.Run(ctx, bytes.NewReader(request), arguments...)
	clear(request)
	if err != nil {
		return "", "", fmt.Errorf("%w: lifecycle reader unavailable", controller.ErrBackendRetryable)
	}
	defer clear(output)
	decoder := json.NewDecoder(bytes.NewReader(output))
	decoder.DisallowUnknownFields()
	var response lifecycleReaderResponse
	if err := decoder.Decode(&response); err != nil || response.Version != 1 ||
		(response.Cursor != "" && !lifecycleCursorPattern.MatchString(response.Cursor)) ||
		len(response.Cursor) > controller.MaxLifecycleCursorBytes || response.Events == nil || len(response.Events) > maxLifecycleEventsPerObservation ||
		response.Error != "" {
		return "", "", controller.ErrBackendRetryable
	}
	var trailing any
	if !errors.Is(decoder.Decode(&trailing), io.EOF) {
		return "", "", controller.ErrBackendRetryable
	}
	complete := make(map[string]bool, len(desired.Resolved.Lifecycle.CompleteOn))
	fail := make(map[string]bool, len(desired.Resolved.Lifecycle.FailOn))
	for _, name := range desired.Resolved.Lifecycle.CompleteOn {
		complete[name] = true
	}
	for _, name := range desired.Resolved.Lifecycle.FailOn {
		fail[name] = true
	}
	for _, name := range response.Events {
		if len(name) > 256 || !lifecycleEventPattern.MatchString(name) {
			return "", "", controller.ErrBackendRetryable
		}
		if complete[name] {
			return response.Cursor, controller.StateCompleted, nil
		}
		if fail[name] {
			return response.Cursor, controller.StateFailed, nil
		}
	}
	return response.Cursor, "", nil
}
