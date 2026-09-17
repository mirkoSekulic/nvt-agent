package manifest

// providerStringList accepts decoded YAML/JSON and programmatic public config.
func providerStringList(value any) ([]string, bool) {
	if values, ok := value.([]string); ok {
		return values, true
	}
	values, ok := value.([]any)
	if !ok {
		return nil, false
	}
	result := make([]string, len(values))
	for index, value := range values {
		text, ok := value.(string)
		if !ok {
			return nil, false
		}
		result[index] = text
	}
	return result, true
}
