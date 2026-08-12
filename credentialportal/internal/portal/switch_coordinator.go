package portal

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"time"
)

var (
	ErrTemplateSwitchDenied      = errors.New("template switch denied")
	ErrTemplateSwitchUnavailable = errors.New("template switch coordination unavailable")
)

type TemplateSwitchCoordinator interface {
	Authorize(ctx context.Context, requestID string) error
}

type HTTPTemplateSwitchCoordinator struct {
	client      *http.Client
	endpoint    string
	maxResponse int64
}

func NewHTTPTemplateSwitchCoordinator(cfg TemplateSwitchConfig) (*HTTPTemplateSwitchCoordinator, error) {
	parsed, err := url.Parse(cfg.CoordinatorURL)
	if err != nil || parsed.Scheme != httpScheme || parsed.Host == "" || parsed.User != nil || parsed.Path != "" ||
		parsed.RawQuery != "" || parsed.Fragment != "" || cfg.CoordinatorURL != parsed.String() {
		return nil, ErrTemplateSwitchUnavailable
	}
	return &HTTPTemplateSwitchCoordinator{
		client: &http.Client{
			Timeout:       time.Duration(cfg.RequestTimeoutSeconds) * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
		},
		endpoint:    cfg.CoordinatorURL + "/v1/principal-accounts/authorize-template-switch",
		maxResponse: int64(cfg.MaxResponseBytes),
	}, nil
}

func (c *HTTPTemplateSwitchCoordinator) Authorize(ctx context.Context, requestID string) error {
	body, err := json.Marshal(map[string]string{"request_id": requestID})
	if err != nil || requestID == "" || len(requestID) > 128 {
		return ErrTemplateSwitchUnavailable
	}
	defer clearBytes(body)
	for range 2 {
		request, requestErr := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
		if requestErr != nil {
			return ErrTemplateSwitchUnavailable
		}
		request.Header.Set("Content-Type", jsonContentType)
		request.Header.Set("Accept", jsonContentType)
		response, requestErr := c.client.Do(request)
		if requestErr != nil {
			if ctx.Err() != nil {
				break
			}
			continue
		}
		retry, result := c.readAuthorizationResponse(response)
		if retry {
			continue
		}
		return result
	}
	return ErrTemplateSwitchUnavailable
}

func (c *HTTPTemplateSwitchCoordinator) readAuthorizationResponse(response *http.Response) (bool, error) {
	responseBody, readErr := io.ReadAll(io.LimitReader(response.Body, c.maxResponse+1))
	closeErr := response.Body.Close()
	defer clearBytes(responseBody)
	if readErr != nil || closeErr != nil || int64(len(responseBody)) > c.maxResponse ||
		response.Header.Get("Content-Type") != jsonContentType {
		return true, ErrTemplateSwitchUnavailable
	}
	var result struct { //nolint:govet // Wire fields stay in response order.
		Authorized bool   `json:"authorized"`
		Reason     string `json:"reason,omitempty"`
	}
	if !strictBrokerJSON(responseBody, &result) {
		return false, ErrTemplateSwitchUnavailable
	}
	if response.StatusCode == http.StatusOK && result.Authorized && result.Reason == "" {
		return false, nil
	}
	if response.StatusCode == http.StatusConflict && !result.Authorized && result.Reason == "active-agentruns" {
		return false, ErrTemplateSwitchDenied
	}
	return false, ErrTemplateSwitchUnavailable
}
