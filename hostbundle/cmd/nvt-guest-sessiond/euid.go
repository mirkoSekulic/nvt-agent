//go:build !hostbundlesessiontest

package main

import "os"

func effectiveUID() int { return os.Geteuid() }
