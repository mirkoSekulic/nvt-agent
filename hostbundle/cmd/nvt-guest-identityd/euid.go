//go:build !hostbundleidentitytest

package main

import "os"

func effectiveUID() int { return os.Geteuid() }
