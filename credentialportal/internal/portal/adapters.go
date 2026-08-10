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
		access, _ := tokens["access_token"].(string)
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
		return fmt.Errorf("unsupported adapter")
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

func rejectDuplicateJSONKeys(document []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(document))
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delim, composite := token.(json.Delim)
		if !composite {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok || seen[key] {
					return errors.New("duplicate key")
				}
				seen[key] = true
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		default:
			return errors.New("invalid delimiter")
		}
	}
	if err := walk(); err != nil {
		return err
	}
	if decoder.More() {
		return errors.New("trailing data")
	}
	return nil
}
