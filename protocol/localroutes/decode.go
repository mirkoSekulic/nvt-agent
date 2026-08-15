package localroutes

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"
)

const MaxDocumentBytes = 256 << 10

func DecodeRun(data []byte) (Run, error) {
	var value Run
	if decodeStrict(data, &value) != nil || ValidateRun(value) != nil {
		return Run{}, errors.New("invalid local route")
	}
	return value, nil
}

func DecodeList(data []byte) (List, error) {
	var value List
	if decodeStrict(data, &value) != nil || ValidateList(value) != nil {
		return List{}, errors.New("invalid local route list")
	}
	return value, nil
}

func decodeStrict(data []byte, target any) error {
	if len(data) == 0 || len(data) > MaxDocumentBytes || !utf8.Valid(data) || rejectDuplicateKeys(data) != nil {
		return errors.New("invalid local route document")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil {
		return errors.New("invalid local route document")
	}
	var trailing any
	if !errors.Is(decoder.Decode(&trailing), io.EOF) {
		return errors.New("invalid local route document")
	}
	return nil
}

func rejectDuplicateKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if consumeUnique(decoder, 0) != nil {
		return errors.New("invalid local route document")
	}
	var trailing any
	if !errors.Is(decoder.Decode(&trailing), io.EOF) {
		return errors.New("invalid local route document")
	}
	return nil
}

func consumeUnique(decoder *json.Decoder, depth int) error {
	if depth > 16 {
		return errors.New("invalid local route document")
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
			key, ok := keyToken.(string)
			if err != nil || !ok {
				return errors.New("invalid local route document")
			}
			if _, duplicate := seen[key]; duplicate {
				return errors.New("invalid local route document")
			}
			seen[key] = struct{}{}
			if consumeUnique(decoder, depth+1) != nil {
				return errors.New("invalid local route document")
			}
		}
	case '[':
		for decoder.More() {
			if consumeUnique(decoder, depth+1) != nil {
				return errors.New("invalid local route document")
			}
		}
	default:
		return errors.New("invalid local route document")
	}
	_, err = decoder.Token()
	return err
}
