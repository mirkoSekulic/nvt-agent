package gateway

import (
	"net/http"
	"net/url"
	"strings"
	"unicode/utf8"
)

const (
	routingModeSubdomain = "subdomain"
	routingModePath      = "path"
	maxAccessKeyBytes    = 253
)

func ParsePath(requestURL *url.URL) route {
	path, ok := unambiguousPath(requestURL)
	if !ok {
		return route{kind: routeNotFound}
	}
	if path == "/" {
		return route{kind: routeDashboard}
	}
	segments := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(segments) < 2 {
		return route{kind: routeNotFound}
	}
	for index, segment := range segments {
		if segment == "." || segment == ".." {
			return route{kind: routeNotFound}
		}
		if index > 0 && segment == "" && index != len(segments)-1 {
			return route{kind: routeNotFound}
		}
	}
	key := segments[0]
	if !validAccessKey(key) || reservedGatewayPath(key) {
		return route{kind: routeNotFound}
	}
	return route{kind: routeAgentRun, accessKey: key}
}

func unambiguousPath(requestURL *url.URL) (string, bool) {
	if requestURL == nil {
		return "", false
	}
	if requestURL.RawPath != "" {
		decoded, err := url.PathUnescape(requestURL.RawPath)
		if err != nil || decoded != requestURL.Path {
			return "", false
		}
	}
	escapedPath := requestURL.EscapedPath()
	lowerEscapedPath := strings.ToLower(escapedPath)
	if strings.Contains(lowerEscapedPath, "%2f") || strings.Contains(lowerEscapedPath, "%5c") {
		return "", false
	}
	path, err := url.PathUnescape(escapedPath)
	if err != nil || path != requestURL.Path || path == "" || path[0] != '/' || strings.ContainsRune(path, '\\') {
		return "", false
	}
	return path, true
}

func stripPathAccessKey(requestURL *url.URL, accessKey string) {
	prefix := "/" + accessKey
	requestURL.Path = strings.TrimPrefix(requestURL.Path, prefix)
	if requestURL.Path == "" {
		requestURL.Path = "/"
	}
	if requestURL.RawPath != "" {
		if separator := strings.Index(requestURL.RawPath[1:], "/"); separator >= 0 {
			requestURL.RawPath = requestURL.RawPath[separator+1:]
		} else {
			requestURL.RawPath = "/"
		}
	}
}

func validAccessKey(key string) bool {
	if key == "" || len(key) > maxAccessKeyBytes || !utf8.ValidString(key) || key == "." || key == ".." {
		return false
	}
	for _, r := range key {
		if r == '/' || r == '\\' || r == '%' || r < 0x21 || r == 0x7f {
			return false
		}
	}
	return true
}

func reservedGatewayPath(key string) bool {
	switch strings.ToLower(key) {
	case "healthz", "oauth2":
		return true
	default:
		return false
	}
}

func requestMatchesPublicOrigin(r *http.Request, publicURL string) bool {
	publicOrigin, err := url.Parse(publicURL)
	if err != nil {
		return false
	}
	return strings.EqualFold(r.Host, publicOrigin.Host)
}

func removeForwardingHeaders(header http.Header) {
	header.Del("Forwarded")
	for name := range header {
		if strings.HasPrefix(strings.ToLower(name), "x-forwarded-") {
			header.Del(name)
		}
	}
}

func publicForwardedPort(publicOrigin *url.URL) string {
	if port := publicOrigin.Port(); port != "" {
		return port
	}
	if publicOrigin.Scheme == "https" {
		return "443"
	}
	return "80"
}

func validOAuthCallbackPath(raw string) bool {
	callbackURL, err := url.Parse(raw)
	if err != nil || callbackURL.IsAbs() || callbackURL.Host != "" || callbackURL.RawQuery != "" || callbackURL.Fragment != "" {
		return false
	}
	path, ok := unambiguousPath(callbackURL)
	if !ok {
		return false
	}
	segments := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(segments) < 2 || segments[0] != "oauth2" {
		return false
	}
	for _, segment := range segments[1:] {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	return true
}
