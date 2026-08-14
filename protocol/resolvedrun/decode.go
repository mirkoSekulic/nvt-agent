package resolvedrun

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

func DecodeLocalRunRequest(data []byte) (LocalRunRequest, error) {
	var result LocalRunRequest
	if err := decodeStrict(data, MaxDocumentBytes, &result); err != nil {
		return LocalRunRequest{}, ErrInvalidRequest
	}
	if err := ValidateLocalRunRequest(result); err != nil {
		return LocalRunRequest{}, ErrInvalidRequest
	}
	return result, nil
}

func DecodeTrustedConfiguration(data []byte) (TrustedConfiguration, error) {
	var result TrustedConfiguration
	if err := decodeStrict(data, MaxDocumentBytes, &result); err != nil {
		return TrustedConfiguration{}, ErrInvalidConfiguration
	}
	if _, err := NewResolver(result); err != nil {
		return TrustedConfiguration{}, ErrInvalidConfiguration
	}
	return result, nil
}

func DecodeResolvedAgentRun(data []byte) (ResolvedAgentRun, error) {
	var result ResolvedAgentRun
	if err := decodeStrict(data, MaxDocumentBytes, &result); err != nil {
		return ResolvedAgentRun{}, errors.New("invalid resolved-run document")
	}
	if err := ValidateResolvedAgentRun(result); err != nil {
		return ResolvedAgentRun{}, errors.New("invalid resolved-run document")
	}
	return result, nil
}

func decodeStrict(data []byte, maximum int, target any) error {
	if len(data) == 0 || len(data) > maximum {
		return errors.New("JSON document size is invalid")
	}
	if err := rejectDuplicateKeys(data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	return ensureDecoderEOF(decoder)
}

func rejectDuplicateKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := consumeUniqueValue(decoder, 0); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("JSON document contains trailing data")
	}
	return nil
}

func consumeUniqueValue(decoder *json.Decoder, depth int) error {
	if depth > 64 {
		return errors.New("JSON document exceeds maximum depth")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, compound := token.(json.Delim)
	if !compound {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]struct{}{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("JSON object key is invalid")
			}
			if _, duplicate := seen[key]; duplicate {
				return errors.New("JSON object contains a duplicate key")
			}
			seen[key] = struct{}{}
			if err := consumeUniqueValue(decoder, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := consumeUniqueValue(decoder, depth+1); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delimiter)
	}
	closing, err := decoder.Token()
	if err != nil {
		return err
	}
	wanted := json.Delim('}')
	if delimiter == '[' {
		wanted = ']'
	}
	if closing != wanted {
		return errors.New("JSON document is malformed")
	}
	return nil
}
