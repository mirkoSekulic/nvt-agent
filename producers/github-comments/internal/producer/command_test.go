//nolint:goconst // Tests repeat command text to keep cases self-contained.
package producer

import "testing"

func TestParseCommandWithConfigurablePrefix(t *testing.T) {
	command, ok := ParseCommand("\n/custom pr create\n\nplease keep this small\n", []string{"/custom"})
	if !ok {
		t.Fatal("expected command")
	}
	if command.Prefix != "/custom" {
		t.Fatalf("unexpected prefix %q", command.Prefix)
	}
	if command.AdditionalInstructions != "please keep this small" {
		t.Fatalf("unexpected instructions %q", command.AdditionalInstructions)
	}
}

func TestParseCommandIgnoresNonCommandFirstLine(t *testing.T) {
	if _, ok := ParseCommand("hello\n/nvtagent pr create", []string{"/nvtagent"}); ok {
		t.Fatal("expected non-command comment to be ignored")
	}
}

func TestParseCommandRequiresExactFirstNonEmptyLine(t *testing.T) {
	cases := []string{
		"/nvtagent pr create now",
		"/nvtagent  pr create",
		"/other pr create",
		"please /nvtagent pr create",
	}
	for _, body := range cases {
		if _, ok := ParseCommand(body, []string{"/nvtagent"}); ok {
			t.Fatalf("expected %q to be ignored", body)
		}
	}
}

func TestParseCommandGrammar(t *testing.T) {
	tests := []struct {
		name         string
		body         string
		wantIntent   CommandIntent
		wantPrompt   string
		wantAccepted bool
	}{
		{"pr multiline", "/nvtagent pr create\nkeep\nnewlines", CommandIntentPRCreate, "keep\nnewlines", true},
		{"help", "/nvtagent --help", CommandIntentHelp, "", true},
		{"review empty", "/nvtagent review", CommandIntentReview, "", true},
		{"review inline", "/nvtagent review -- focus on tests", CommandIntentReview, "focus on tests", true},
		{"run multiline unicode", "/nvtagent run\n調査して 🚀", CommandIntentRun, "調査して 🚀", true},
		{"combined", "/nvtagent run -- first\nsecond\nthird", CommandIntentRun, "first\nsecond\nthird", true},
		{"pr continue multiline unicode", "/nvtagent pr continue\n調査して 🚀", CommandIntentPRContinue, "調査して 🚀", true},
		{"pr continue inline", "/nvtagent pr continue -- fix checks", CommandIntentPRContinue, "fix checks", true},
		{"pr continue bare trailing", "/nvtagent pr continue do this", "", "", false},
		{"bare trailing", "/nvtagent run do this", "", "", false},
		{"unknown option", "/nvtagent review --focus", "", "", false},
		{"empty separator", "/nvtagent run --", "", "", false},
		{"repeated separator", "/nvtagent run -- -- nope", "", "", false},
		{"empty run", "/nvtagent run\n\n", "", "", false},
		{"unknown command", "/nvtagent help", "", "", false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, ok := ParseCommand(test.body, []string{"/nvtagent", "/nvtlocal"})
			if ok != test.wantAccepted {
				t.Fatalf("accepted = %v, want %v: %#v", ok, test.wantAccepted, got)
			}
			if ok && (got.Intent != test.wantIntent || got.AdditionalInstructions != test.wantPrompt) {
				t.Fatalf("command = %#v, want intent %q prompt %q", got, test.wantIntent, test.wantPrompt)
			}
		})
	}
}
