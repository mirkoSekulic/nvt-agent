// Package localroutes defines the bounded, non-secret route metadata exchanged
// between a trusted local controller and a gateway. It contains no proxy,
// authorization, Docker, or credential behavior.
package localroutes

import (
	"errors"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	APIVersion     = "nvt.local-routes/v1"
	MaxRuns        = 500
	MaxRunsPerPage = 8
	MaxExposures   = 64
	MaxNameBytes   = 63
)

type Principal struct {
	Issuer      string `json:"issuer"`
	Subject     string `json:"subject"`
	DisplayName string `json:"display_name,omitempty"`
}

type Endpoint struct {
	Host string `json:"host"`
	Path string `json:"path,omitempty"`
}

type Exposure struct {
	Name string `json:"name"`
	Host string `json:"host"`
}

type Run struct {
	APIVersion string     `json:"api_version"`
	RunID      string     `json:"run_id"`
	State      string     `json:"state"`
	Ready      bool       `json:"ready"`
	Principal  Principal  `json:"principal"`
	Profile    string     `json:"profile"`
	Workflow   string     `json:"workflow"`
	CreatedAt  time.Time  `json:"created_at"`
	Session    Endpoint   `json:"session"`
	Exposures  []Exposure `json:"exposures"`
}

type List struct {
	APIVersion string `json:"api_version"`
	Runs       []Run  `json:"runs"`
	NextAfter  string `json:"next_after,omitempty"`
}

func ValidateRun(value Run) error {
	if value.APIVersion != APIVersion || !validName(value.RunID) || !validState(value.State) ||
		value.Ready != (value.State == "running") || !validPrincipal(value.Principal) ||
		!validName(value.Profile) || !validName(value.Workflow) || value.CreatedAt.IsZero() ||
		value.CreatedAt.Location() != time.UTC || !validEndpoint(value.Session, true) ||
		len(value.Exposures) > MaxExposures {
		return errors.New("invalid local route")
	}
	seen := map[string]struct{}{}
	for _, exposure := range value.Exposures {
		if !validName(exposure.Name) || !validHost(exposure.Host) || exposure.Host == value.Session.Host {
			return errors.New("invalid local route")
		}
		if _, duplicate := seen[exposure.Name]; duplicate {
			return errors.New("invalid local route")
		}
		seen[exposure.Name] = struct{}{}
	}
	return nil
}

func ValidateList(value List) error {
	if value.APIVersion != APIVersion || value.Runs == nil || len(value.Runs) > MaxRunsPerPage ||
		(value.NextAfter != "" && !validName(value.NextAfter)) {
		return errors.New("invalid local route list")
	}
	seen := map[string]struct{}{}
	previous := ""
	for _, run := range value.Runs {
		if ValidateRun(run) != nil || previous != "" && run.RunID <= previous {
			return errors.New("invalid local route list")
		}
		if _, duplicate := seen[run.RunID]; duplicate {
			return errors.New("invalid local route list")
		}
		seen[run.RunID] = struct{}{}
		previous = run.RunID
	}
	return nil
}

func validPrincipal(value Principal) bool {
	return validHTTPSIssuer(value.Issuer) && validText(value.Subject, 1024, false) && validText(value.DisplayName, 512, true)
}

func validHTTPSIssuer(value string) bool {
	parsed, err := url.Parse(value)
	return len(value) > 0 && len(value) <= 2048 && err == nil && parsed.Scheme == "https" && parsed.Host != "" &&
		parsed.User == nil && parsed.RawQuery == "" && parsed.Fragment == "" && parsed.String() == value &&
		value == strings.TrimSpace(value) && !strings.ContainsAny(value, "\x00\r\n")
}

func validEndpoint(value Endpoint, requirePath bool) bool {
	if !validHost(value.Host) {
		return false
	}
	if requirePath {
		return validPath(value.Path)
	}
	return value.Path == ""
}

func validHost(value string) bool {
	if len(value) == 0 || len(value) > 253 || value != strings.ToLower(value) || strings.HasSuffix(value, ".") || strings.ContainsAny(value, ":/@?#\\\x00\r\n") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if !validName(label) {
			return false
		}
	}
	return true
}

func validPath(value string) bool {
	if len(value) < 3 || len(value) > 512 || value[0] != '/' || value[len(value)-1] != '/' || strings.Contains(value, "//") || strings.ContainsAny(value, "%\\?#\x00\r\n") {
		return false
	}
	for _, segment := range strings.Split(strings.Trim(value, "/"), "/") {
		if !validName(segment) {
			return false
		}
	}
	return true
}

func validState(value string) bool {
	switch value {
	case "pending", "preparing", "running", "stopping":
		return true
	default:
		return false
	}
}

func validName(value string) bool {
	if len(value) == 0 || len(value) > MaxNameBytes || !alphaNumeric(value[0]) {
		return false
	}
	for _, character := range value[1:] {
		if character != '-' && (character < 'a' || character > 'z') && (character < '0' || character > '9') {
			return false
		}
	}
	last := value[len(value)-1]
	return last != '-'
}

func alphaNumeric(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= '0' && value <= '9'
}

func validText(value string, maximum int, allowEmpty bool) bool {
	return (allowEmpty || value != "") && len(value) <= maximum && utf8.ValidString(value) && value == strings.TrimSpace(value) && !strings.ContainsAny(value, "\x00\r\n")
}
