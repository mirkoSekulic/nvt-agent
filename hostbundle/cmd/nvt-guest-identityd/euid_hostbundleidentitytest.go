//go:build hostbundleidentitytest

package main

import (
	"os"
	"strconv"
)

func effectiveUID() int {
	value, err := strconv.Atoi(os.Getenv("NVT_GUEST_IDENTITY_TEST_EUID"))
	if err != nil {
		return 0
	}
	return value
}
