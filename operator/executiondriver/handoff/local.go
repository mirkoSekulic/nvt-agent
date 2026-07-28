// Package handoff carries the separate sensitive guest-enrollment protocol
// between the generic driver host and the exact provider executable. It uses a
// private Unix socket and never changes the frozen execution-driver JSONL
// desired-state protocol.
package handoff

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment"
)

const EnvironmentSocket = "NVT_EXECUTION_DRIVER_ENROLLMENT_SOCKET"

var (
	ErrUnavailable = errors.New("execution driver enrollment handoff is unavailable")
	ErrRejected    = errors.New("execution driver enrollment handoff was rejected")
)

type LocalClient struct {
	socket string
	http   *http.Client
}

func NewLocalClient(socket string, timeout time.Duration) (*LocalClient, error) {
	if !filepath.IsAbs(socket) || filepath.Clean(socket) != socket || timeout <= 0 || timeout > guestenrollment.MaxOperationDuration {
		return nil, errors.New("execution driver enrollment handoff configuration is invalid")
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		info, err := os.Lstat(socket)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeSocket == 0 {
			return nil, ErrUnavailable
		}
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}
	return &LocalClient{socket: socket, http: &http.Client{Transport: transport, Timeout: timeout}}, nil
}

func (c *LocalClient) Prepare(ctx context.Context, request guestenrollment.HandoffPrepareRequest) (guestenrollment.HandoffPrepareResult, error) {
	if guestenrollment.ValidateHandoffPrepareRequest(request) != nil {
		return guestenrollment.HandoffPrepareResult{}, ErrRejected
	}
	body, status, err := c.call(ctx, "/v1/prepare", request)
	if err != nil {
		return guestenrollment.HandoffPrepareResult{}, err
	}
	defer zero(body)
	if status != http.StatusOK {
		return guestenrollment.HandoffPrepareResult{}, classify(status)
	}
	result, err := guestenrollment.DecodeHandoffPrepareResult(body)
	if err != nil {
		return guestenrollment.HandoffPrepareResult{}, ErrUnavailable
	}
	return result, nil
}

func (c *LocalClient) Replace(ctx context.Context, request guestenrollment.HandoffReplaceRequest) (guestenrollment.HandoffPrepareResult, error) {
	if guestenrollment.ValidateHandoffReplaceRequest(request) != nil {
		return guestenrollment.HandoffPrepareResult{}, ErrRejected
	}
	body, status, err := c.call(ctx, "/v1/replace", request)
	if err != nil {
		return guestenrollment.HandoffPrepareResult{}, err
	}
	defer zero(body)
	if status != http.StatusOK {
		return guestenrollment.HandoffPrepareResult{}, classify(status)
	}
	result, err := guestenrollment.DecodeHandoffPrepareResult(body)
	if err != nil {
		return guestenrollment.HandoffPrepareResult{}, ErrUnavailable
	}
	return result, nil
}

func (c *LocalClient) Deliver(ctx context.Context, request guestenrollment.HandoffDeliverRequest) error {
	if guestenrollment.ValidateHandoffDeliverRequest(request) != nil {
		return ErrRejected
	}
	body, status, err := c.call(ctx, "/v1/deliver", request)
	if err != nil {
		return err
	}
	defer zero(body)
	if status != http.StatusOK {
		return classify(status)
	}
	_, err = guestenrollment.DecodeHandoffAcknowledgement(body)
	if err != nil {
		return ErrUnavailable
	}
	return nil
}

func (c *LocalClient) call(ctx context.Context, path string, value any) ([]byte, int, error) {
	payload, err := json.Marshal(value)
	if err != nil || len(payload) > guestenrollment.MaxHandoffRequestBytes {
		return nil, 0, ErrRejected
	}
	defer zero(payload)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://unix"+path, bytes.NewReader(payload))
	if err != nil {
		return nil, 0, ErrUnavailable
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := c.http.Do(request)
	if err != nil {
		return nil, 0, ErrUnavailable
	}
	defer response.Body.Close()
	if response.Header.Get("Content-Type") != "application/json" {
		return nil, 0, ErrUnavailable
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, guestenrollment.MaxHandoffResponseBytes+1))
	if err != nil || len(body) > guestenrollment.MaxHandoffResponseBytes {
		zero(body)
		return nil, 0, ErrUnavailable
	}
	return body, response.StatusCode, nil
}

func classify(status int) error {
	if status >= 400 && status < 500 && status != http.StatusRequestTimeout && status != http.StatusTooManyRequests {
		return ErrRejected
	}
	return ErrUnavailable
}

func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

var _ guestenrollment.Handoff = (*LocalClient)(nil)
