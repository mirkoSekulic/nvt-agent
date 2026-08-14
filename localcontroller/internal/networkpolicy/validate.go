package networkpolicy

import (
	"errors"
	"net/netip"
	"strings"
)

const (
	RunNetworkPrefixBits = 28
	maxProtectedCIDRs    = 256
	maxProtectedBytes    = 4096
)

var managedDockerPool = netip.MustParsePrefix("172.30.0.0/15")

type RunNetworkPolicy struct {
	Pool           netip.Prefix
	SubnetCapacity int
}

// ValidateRunNetworkPolicy validates the administrator-owned per-run pool and
// every protected destination together. IPv6 protected ranges remain valid,
// while an IPv4 protected range may never overlap a route the backend can
// install for a local run.
func ValidateRunNetworkPolicy(runPool, protectedCIDRs string) (RunNetworkPolicy, error) {
	pool, err := netip.ParsePrefix(runPool)
	if err != nil || !pool.Addr().Is4() || pool != pool.Masked() || pool.Bits() < 8 || pool.Bits() > RunNetworkPrefixBits-1 || pool.Overlaps(managedDockerPool) {
		return RunNetworkPolicy{}, errors.New("run network policy invalid")
	}
	if protectedCIDRs == "" || len(protectedCIDRs) > maxProtectedBytes || strings.ContainsAny(protectedCIDRs, "\x00\r\n") {
		return RunNetworkPolicy{}, errors.New("run network policy invalid")
	}
	protected := strings.Fields(protectedCIDRs)
	if len(protected) == 0 || len(protected) > maxProtectedCIDRs {
		return RunNetworkPolicy{}, errors.New("run network policy invalid")
	}
	for _, value := range protected {
		prefix, parseErr := netip.ParsePrefix(value)
		if parseErr != nil || prefix != prefix.Masked() {
			return RunNetworkPolicy{}, errors.New("run network policy invalid")
		}
		if prefix.Addr().Is4() && pool.Overlaps(prefix) {
			return RunNetworkPolicy{}, errors.New("run network policy invalid")
		}
	}
	return RunNetworkPolicy{
		Pool:           pool,
		SubnetCapacity: 1 << (RunNetworkPrefixBits - pool.Bits()),
	}, nil
}
