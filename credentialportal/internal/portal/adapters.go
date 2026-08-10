package portal

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

var ErrInvalidCredential = errors.New("credential document is not valid for this enrollment slot")

var (
	errUnsupportedAdapter = errors.New("unsupported credential adapter")
	errDuplicateJSONKey   = errors.New("duplicate JSON key")
	errInvalidJSONToken   = errors.New("invalid JSON token")
	errTrailingJSONData   = errors.New("trailing JSON data")
)

//nolint:gocyclo // Each adapter's minimum shape is intentionally explicit and fail-closed.
func ValidateCredential(adapter string, document []byte) error {
	if len(document) == 0 || !json.Valid(document) {
		return ErrInvalidCredential
	}
	if err := rejectDuplicateJSONKeys(document); err != nil {
		return ErrInvalidCredential
	}
	var root map[string]any
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.UseNumber()
	if err := decoder.Decode(&root); err != nil || root == nil {
		return ErrInvalidCredential
	}
	switch adapter {
	case AdapterCodexOAuthFile:
		if _, cross := root["claudeAiOauth"]; cross {
			return ErrInvalidCredential
		}
		tokens, ok := object(root["tokens"])
		if !ok || !nonemptyString(tokens["access_token"]) || !nonemptyString(tokens["refresh_token"]) {
			return ErrInvalidCredential
		}
		access, accessOK := tokens["access_token"].(string)
		if !accessOK {
			return ErrInvalidCredential
		}
		if !jwtHasNumericExpiry(access) {
			return ErrInvalidCredential
		}
	case AdapterClaudeOAuthFile:
		if _, cross := root["tokens"]; cross {
			return ErrInvalidCredential
		}
		oauth, ok := object(root["claudeAiOauth"])
		if !ok || !nonemptyString(oauth["accessToken"]) || !nonemptyString(oauth["refreshToken"]) {
			return ErrInvalidCredential
		}
	default:
		return fmt.Errorf("%w: %s", errUnsupportedAdapter, adapter)
	}
	return nil
}

func object(value any) (map[string]any, bool) { v, ok := value.(map[string]any); return v, ok }
func nonemptyString(value any) bool           { v, ok := value.(string); return ok && strings.TrimSpace(v) != "" }

func jwtHasNumericExpiry(token string) bool {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		payload, err = base64.URLEncoding.DecodeString(parts[1])
	}
	if err != nil {
		return false
	}
	var claims map[string]any
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	if decoder.Decode(&claims) != nil {
		return false
	}
	exp, ok := claims["exp"].(json.Number)
	if !ok {
		return false
	}
	_, err = exp.Int64()
	return err == nil
}

//nolint:gocognit // Recursive token walking is required to reject duplicates at every nesting level.
func rejectDuplicateJSONKeys(document []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(document))
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return fmt.Errorf("read JSON token: %w", err)
		}
		delim, composite := token.(json.Delim)
		if !composite {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for decoder.More() {
				keyToken, keyErr := decoder.Token()
				if keyErr != nil {
					return fmt.Errorf("read JSON key: %w", keyErr)
				}
				key, ok := keyToken.(string)
				if !ok || seen[key] {
					return errDuplicateJSONKey
				}
				seen[key] = true
				if walkErr := walk(); walkErr != nil {
					return walkErr
				}
			}
			_, closeErr := decoder.Token()
			if closeErr != nil {
				return fmt.Errorf("close JSON object: %w", closeErr)
			}
			return nil
		case '[':
			for decoder.More() {
				if walkErr := walk(); walkErr != nil {
					return walkErr
				}
			}
			_, closeErr := decoder.Token()
			if closeErr != nil {
				return fmt.Errorf("close JSON array: %w", closeErr)
			}
			return nil
		default:
			return errInvalidJSONToken
		}
	}
	if err := walk(); err != nil {
		return err
	}
	if decoder.More() {
		return errTrailingJSONData
	}
	return nil
}
