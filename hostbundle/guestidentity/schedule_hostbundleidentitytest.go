//go:build hostbundleidentitytest

package guestidentity

import "time"

func init() {
	// The real-QEMU conformance bundle accelerates one rotation without adding
	// a runtime flag or environment hook to the production binary.
	minimumRotationInterval = 5 * time.Second
	maximumRotationJitter = 0
	rotationRecoveryWindow = 2 * time.Second
	statusPollInterval = 500 * time.Millisecond
	retryInterval = 100 * time.Millisecond
}
