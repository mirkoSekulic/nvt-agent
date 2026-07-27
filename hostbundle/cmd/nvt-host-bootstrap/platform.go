//go:build !hostbundletest

package main

import (
	"os"
	"time"

	"github.com/mirkoSekulic/nvt-agent/hostbundle/oci"
)

func effectiveUID() int {
	return os.Geteuid()
}

func newOCIClient(timeout time.Duration) (*oci.Client, error) {
	return oci.NewClient(timeout)
}
