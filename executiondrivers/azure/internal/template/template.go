package template

import (
	_ "embed"
	"encoding/json"
	"errors"
	"strings"
)

// Compiled is generated from deployment.bicep by the pinned Bicep compiler.
// Runtime deployment never invokes Bicep, Azure CLI, or a shell provisioner.
//
//go:embed deployment.json
var compiled []byte

func Compiled() (map[string]any, error) {
	var value map[string]any
	if len(compiled) == 0 || json.Unmarshal(compiled, &value) != nil || validate(value) != nil {
		return nil, errors.New("embedded Azure deployment template is invalid")
	}
	return value, nil
}

func Bytes() []byte { return append([]byte(nil), compiled...) }

func validate(value map[string]any) error {
	parameters, ok := value["parameters"].(map[string]any)
	if !ok {
		return errors.New("template parameters are invalid")
	}
	for name := range parameters {
		lower := strings.ToLower(name)
		for _, forbidden := range []string{"secret", "token", "credential", "privatekey", "envelope", "customdata", "userdata"} {
			if strings.Contains(lower, forbidden) {
				return errors.New("template contains a forbidden parameter")
			}
		}
	}
	if _, exists := value["outputs"]; exists {
		return errors.New("template outputs are forbidden")
	}
	encoded, _ := json.Marshal(value)
	lower := strings.ToLower(string(encoded))
	for _, forbidden := range []string{"customdata", "userdata", "publicipaddresses"} {
		if strings.Contains(lower, forbidden) {
			return errors.New("template contains forbidden infrastructure")
		}
	}
	return nil
}
