package controller

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"time"
)

// RestartAndWait is an administrator client, not a lifecycle implementation.
// Its caller stays in the trusted controller container so the bearer is never
// copied to a workstation, host CLI argument, environment variable, or log.
// It returns only a fixed public result code, never transport error bodies.
func RestartAndWait(ctx context.Context, baseURL, tokenFile, name string) string {
	if !validRunID(name) {
		return "invalid-request"
	}
	token, err := readPrivateBearer(tokenFile)
	if err != nil {
		return "authentication-unavailable"
	}
	defer clear(token)
	transport := &http.Transport{} // No environment proxy for the trusted endpoint.
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return "unavailable"
	}
	requestID := hex.EncodeToString(id)
	body, _ := json.Marshal(map[string]string{"api_version": APIVersion, "request_id": requestID})
	method, path := http.MethodPost, baseURL+"/v1/runs/"+name+"/restart"
	operation := ""
	for {
		if ctx.Err() != nil {
			return "timeout"
		}
		request, err := http.NewRequestWithContext(ctx, method, path, bytes.NewReader(body))
		if err != nil {
			return "unavailable"
		}
		request.Header.Set("Authorization", "Bearer "+string(token))
		request.Header.Set("Content-Type", "application/json")
		response, err := client.Do(request)
		if err != nil {
			if ctx.Err() != nil {
				return "timeout"
			}
			// Lost submission responses retry the same idempotency key.
			if !restartPollWait(ctx) {
				return "timeout"
			}
			continue
		}
		raw, readErr := io.ReadAll(io.LimitReader(response.Body, 16<<10+1))
		_ = response.Body.Close()
		if readErr != nil || len(raw) > 16<<10 {
			clear(raw)
			return "unavailable"
		}
		status := response.StatusCode
		if status != http.StatusOK && status != http.StatusAccepted {
			var denied errorEnvelope
			_ = json.Unmarshal(raw, &denied)
			clear(raw)
			switch status {
			case http.StatusUnauthorized, http.StatusForbidden:
				return "not-authorized"
			case http.StatusNotFound:
				return "not-found"
			case http.StatusGone:
				return "gone"
			case http.StatusConflict:
				if denied.Error.Reason == "not-administrator-workstation" {
					return "not-administrator-workstation"
				}
				return "restart-conflict"
			case http.StatusTooManyRequests:
				return "capacity-exceeded"
			default:
				return "unavailable"
			}
		}
		var run Run
		err = json.Unmarshal(raw, &run)
		clear(raw)
		if err != nil || run.APIVersion != APIVersion || run.RunID != name || !validRestartState(run) || run.RestartID == "" {
			return "unavailable"
		}
		if operation == "" {
			operation = run.RestartID
		}
		if operation != run.RestartID {
			return "superseded"
		}
		if run.RestartPhase == "failed" || run.DeleteRequested || run.State.terminal() {
			if run.LastReason == "restart-backend-rejected" {
				return "restart-backend-rejected"
			}
			return "failed"
		}
		if run.RestartPhase == "complete" && run.State == StateRunning {
			return "ready"
		}
		method, path, body = http.MethodGet, baseURL+"/v1/runs/"+name, nil
		if !restartPollWait(ctx) {
			return "timeout"
		}
	}
}

func restartPollWait(ctx context.Context) bool {
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
