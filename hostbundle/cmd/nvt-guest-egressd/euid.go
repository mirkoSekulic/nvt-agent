//go:build !hostbundleegresstest

package main

import "os"

func effectiveUID() int { return os.Geteuid() }
