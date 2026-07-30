package main

import (
	"strings"
	"testing"
)

func TestArgumentsCannotCarryCredentialsAndErrorsAreRedacted(t *testing.T) {
	credentialCanary := "nvt_eg1_argument-canary"
	for _, arguments := range [][]string{
		{"--credential", credentialCanary},
		{"--config", "/does/not/exist/" + credentialCanary},
		{credentialCanary},
	} {
		err := run(arguments)
		if err == nil {
			t.Fatal("invalid command arguments were accepted")
		}
		if strings.Contains(err.Error(), credentialCanary) {
			t.Fatalf("command error disclosed argument canary: %q", err)
		}
	}
}
