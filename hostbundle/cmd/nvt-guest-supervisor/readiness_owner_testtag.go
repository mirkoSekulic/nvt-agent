//go:build hostbundlesupervisortest

package main

import "os"

func init() { readinessOwnerUID = uint32(os.Geteuid()) }
