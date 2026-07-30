//go:build hostbundlesupervisortest

package main

import (
	"os"
	"time"
)

func init() {
	readinessOwnerUID = uint32(os.Geteuid())
	if os.Getenv("NVT_TEST_SUPERVISOR_SHORT_DEADLINES") == "1" {
		agentdStartupTimeout = 2 * time.Second
		egressReadinessTimeout = 8 * time.Second
		sessionReadinessTimeout = 2 * time.Second
	}
}
