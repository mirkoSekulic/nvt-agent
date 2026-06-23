package producer

import "strings"

type Command struct {
	Prefix                 string
	AdditionalInstructions string
}

func ParseCommand(body string, prefixes []string) (Command, bool) {
	lines := strings.Split(body, "\n")
	for index, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		for _, prefix := range prefixes {
			if trimmed == prefix+" pr create" {
				return Command{
					Prefix:                 prefix,
					AdditionalInstructions: strings.TrimSpace(strings.Join(lines[index+1:], "\n")),
				}, true
			}
		}
		return Command{}, false
	}
	return Command{}, false
}
