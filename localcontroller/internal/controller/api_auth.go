package controller

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"
)

type apiAudience uint8

const (
	apiAudienceNone apiAudience = iota
	apiAudienceAdmin
	apiAudienceRoutes
)

// APIAuthorization contains only one-way digests of startup-loaded,
// audience-specific API credentials.
type APIAuthorization struct {
	admin  *[sha256.Size]byte
	routes *[sha256.Size]byte
}

func LoadAPIAuthorization(adminTokenFile, routeTokenFile string, scheduler *Scheduler) (*APIAuthorization, error) {
	result := &APIAuthorization{}
	var err error
	if adminTokenFile != "" {
		result.admin, err = privateBearerDigest(adminTokenFile)
		if err != nil {
			return nil, ErrInvalidRequest
		}
	}
	if routeTokenFile != "" {
		result.routes, err = privateBearerDigest(routeTokenFile)
		if err != nil {
			return nil, ErrInvalidRequest
		}
	}
	if result.admin != nil && result.routes != nil && subtle.ConstantTimeCompare(result.admin[:], result.routes[:]) == 1 {
		return nil, ErrInvalidRequest
	}
	if scheduler != nil && (scheduler.usesTokenDigest(result.admin) || scheduler.usesTokenDigest(result.routes)) {
		return nil, ErrInvalidRequest
	}
	return result, nil
}

func privateBearerDigest(path string) (*[sha256.Size]byte, error) {
	token, err := readPrivateBearer(path)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(token)
	clear(token)
	return &digest, nil
}

func (authorization *APIAuthorization) validate(routeProvider RouteProvider) error {
	if routeProvider != nil && (authorization == nil || authorization.routes == nil) {
		return ErrInvalidRequest
	}
	return nil
}

func (authorization *APIAuthorization) permits(request *http.Request, audience apiAudience) bool {
	if audience == apiAudienceNone {
		return true
	}
	var expected *[sha256.Size]byte
	if authorization != nil {
		switch audience {
		case apiAudienceAdmin:
			expected = authorization.admin
		case apiAudienceRoutes:
			expected = authorization.routes
		}
	}
	if expected == nil {
		return false
	}
	values := request.Header.Values("Authorization")
	if len(values) != 1 || len(values[0]) < len("Bearer ")+32 || len(values[0]) > len("Bearer ")+4096 ||
		values[0][:len("Bearer ")] != "Bearer " {
		return false
	}
	token := []byte(values[0][len("Bearer "):])
	defer clear(token)
	if len(token) < 32 || len(token) > 4096 {
		return false
	}
	digest := sha256.Sum256(token)
	return subtle.ConstantTimeCompare(digest[:], expected[:]) == 1
}

func apiAudienceForPath(path string) apiAudience {
	switch {
	case path == "/v1/routes", strings.HasPrefix(path, "/v1/routes/"):
		return apiAudienceRoutes
	case path == "/v1/runs", strings.HasPrefix(path, "/v1/runs/"):
		return apiAudienceAdmin
	default:
		return apiAudienceNone
	}
}

func (server *HTTPServer) writeUnauthorized(response http.ResponseWriter) (int, string, string) {
	response.Header().Set("WWW-Authenticate", "Bearer")
	server.writeJSON(response, http.StatusUnauthorized, errorEnvelope{Error: apiError{Reason: "not-authorized", Message: "request denied"}})
	return http.StatusUnauthorized, "not-authorized", ""
}

var errInvalidPrivateBearer = errors.New("invalid private bearer")
