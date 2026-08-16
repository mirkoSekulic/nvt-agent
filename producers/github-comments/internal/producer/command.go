package producer

import "strings"

type CommandIntent string

const (
	CommandIntentPRCreate   CommandIntent = "pr-create"
	CommandIntentPRContinue CommandIntent = "pr-continue"
	CommandIntentReview     CommandIntent = "review"
	CommandIntentRun        CommandIntent = "run"
	CommandIntentHelp       CommandIntent = "help"
)

type Command struct {
	Prefix                 string
	Intent                 CommandIntent
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
			command, ok := parseCommandLine(trimmed, prefix)
			if !ok {
				continue
			}
			following := strings.TrimSpace(strings.Join(lines[index+1:], "\n"))
			command.AdditionalInstructions = joinInstructions(command.AdditionalInstructions, following)
			if command.Intent == CommandIntentRun && command.AdditionalInstructions == "" {
				return Command{}, false
			}
			if command.Intent == CommandIntentHelp && command.AdditionalInstructions != "" {
				return Command{}, false
			}
			return command, true
		}
		return Command{}, false
	}
	return Command{}, false
}

func parseCommandLine(line, prefix string) (Command, bool) {
	if !strings.HasPrefix(line, prefix+" ") {
		return Command{}, false
	}
	remainder := strings.TrimPrefix(line, prefix+" ")
	type candidate struct {
		text        string
		intent      CommandIntent
		allowInline bool
	}
	commands := []candidate{
		{text: "pr create", intent: CommandIntentPRCreate, allowInline: true},
		{text: "pr continue", intent: CommandIntentPRContinue, allowInline: true},
		{text: "review", intent: CommandIntentReview, allowInline: true},
		{text: "run", intent: CommandIntentRun, allowInline: true},
		{text: "--help", intent: CommandIntentHelp},
	}
	for _, candidate := range commands {
		if remainder == candidate.text {
			return Command{Prefix: prefix, Intent: candidate.intent}, true
		}
		separator := candidate.text + " -- "
		if strings.HasPrefix(remainder, separator) {
			if !candidate.allowInline {
				return Command{}, false
			}
			inline := strings.TrimSpace(strings.TrimPrefix(remainder, separator))
			if inline == "" || strings.HasPrefix(inline, "--") {
				return Command{}, false
			}
			return Command{Prefix: prefix, Intent: candidate.intent, AdditionalInstructions: inline}, true
		}
	}
	return Command{}, false
}

func joinInstructions(inline, following string) string {
	if inline == "" {
		return following
	}
	if following == "" {
		return inline
	}
	return inline + "\n" + following
}
