package captureinspect

import (
	"encoding/base64"
	"net/http"
	"strings"
)

// CapabilityHintFromConnect implements the existing explicit CONNECT
// provider-selector contract. It returns only the non-secret provider name;
// proxy authorization framing and any password component are consumed locally
// and never enter the tunneled byte stream.
func CapabilityHintFromConnect(request *http.Request) (string, bool) {
	if request == nil {
		return "", false
	}
	values := request.Header.Values("X-NVT-Capability")
	if len(values) > 1 {
		return "", false
	}
	headerHint := ""
	if len(values) == 1 {
		headerHint = strings.TrimSpace(values[0])
		if headerHint == "" || strings.Contains(values[0], ",") {
			return "", false
		}
	}
	authorizations := request.Header.Values("Proxy-Authorization")
	if len(authorizations) > 1 {
		return "", false
	}
	authorizationHint := ""
	if len(authorizations) == 1 {
		value := strings.TrimSpace(authorizations[0])
		const prefix = "Basic "
		if len(value) <= len(prefix) || !strings.EqualFold(value[:len(prefix)], prefix) {
			return "", false
		}
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value[len(prefix):]))
		if err != nil || len(decoded) > 512 {
			return "", false
		}
		user, _, ok := strings.Cut(string(decoded), ":")
		for index := range decoded {
			decoded[index] = 0
		}
		if !ok || user == "" {
			return "", false
		}
		authorizationHint = user
	}
	if headerHint != "" && authorizationHint != "" && headerHint != authorizationHint {
		return "", false
	}
	if headerHint != "" {
		return headerHint, true
	}
	if authorizationHint != "" {
		return authorizationHint, true
	}
	return "", true
}
