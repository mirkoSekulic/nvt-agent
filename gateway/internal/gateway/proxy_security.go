package gateway

import (
	"net/http"
	"net/url"
	"strings"
)

func gatewayCookieNames(sessionCookieName string) map[string]struct{} {
	if sessionCookieName == "" {
		sessionCookieName = defaultSessionCookie
	}
	return map[string]struct{}{
		sessionCookieName: {},
		loginStateCookie:  {},
	}
}

func filterUpstreamRequestCookies(header http.Header, owned map[string]struct{}) {
	rawValues := header.Values("Cookie")
	header.Del("Cookie")
	kept := make([]string, 0)
	for _, raw := range rawValues {
		for _, field := range strings.Split(raw, ";") {
			field = strings.TrimSpace(field)
			name, _, ok := strings.Cut(field, "=")
			name = strings.TrimSpace(name)
			if !ok || !validCookieName(name) {
				continue
			}
			if _, isOwned := owned[name]; isOwned {
				continue
			}
			kept = append(kept, field)
		}
	}
	if len(kept) > 0 {
		header.Set("Cookie", strings.Join(kept, "; "))
	}
}

func filterUpstreamResponseCookies(response *http.Response, owned map[string]struct{}, pathPrefix string) {
	rawValues := response.Header.Values("Set-Cookie")
	response.Header.Del("Set-Cookie")
	for _, raw := range rawValues {
		cookie, err := http.ParseSetCookie(raw)
		if err != nil || !validCookieName(cookie.Name) || len(cookie.Unparsed) != 0 {
			continue
		}
		if _, isOwned := owned[cookie.Name]; isOwned {
			continue
		}
		if pathPrefix == "" {
			response.Header.Add("Set-Cookie", raw)
			continue
		}
		// __Host- cookies require Path=/ and cannot be safely narrowed.
		if strings.HasPrefix(cookie.Name, "__Host-") {
			continue
		}
		cookie.Domain = ""
		cookie.Path = pathPrefix
		if serialized := cookie.String(); serialized != "" {
			response.Header.Add("Set-Cookie", serialized)
		}
	}
}

func pathCookiePrefix(basePath, accessKey string) string {
	return basePath + "/" + url.PathEscape(accessKey) + "/"
}

func validCookieName(name string) bool {
	if name == "" {
		return false
	}
	for _, r := range name {
		if r <= 0x20 || r >= 0x7f || strings.ContainsRune("()<>@,;:\\\"/[]?={}", r) {
			return false
		}
	}
	return true
}
