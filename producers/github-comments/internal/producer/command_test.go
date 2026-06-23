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
