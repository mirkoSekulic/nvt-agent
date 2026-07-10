package egress

import (
	"context"
	"fmt"
	"net"
	"net/netip"
)

// IPResolver is the single DNS lookup seam used by the forward gateway.
type IPResolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

type destinationPolicy struct {
	denied []netip.Prefix
}

var defaultDeniedPrefixes = mustPrefixes(
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
	"169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
	"192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
	"224.0.0.0/4", "240.0.0.0/4",
	"::/128", "::1/128", "64:ff9b:1::/48", "100::/64", "2001:db8::/32",
	"fc00::/7", "fe80::/10", "ff00::/8",
)

func mustPrefixes(values ...string) []netip.Prefix {
	result := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		result = append(result, netip.MustParsePrefix(value))
	}
	return result
}

func newDestinationPolicy(configured []string) (destinationPolicy, error) {
	denied := append([]netip.Prefix(nil), defaultDeniedPrefixes...)
	for index, value := range configured {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return destinationPolicy{}, fmt.Errorf("deny_cidrs[%d] must be a valid CIDR: %w", index, err)
		}
		denied = append(denied, prefix.Masked())
	}
	return destinationPolicy{denied: denied}, nil
}

func (p destinationPolicy) allowed(address netip.Addr) bool {
	address = address.Unmap()
	if !address.IsValid() || address.IsUnspecified() || address.IsLoopback() || address.IsPrivate() ||
		address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() || address.IsMulticast() {
		return false
	}
	for _, prefix := range p.denied {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

func resolveAllowedAddress(ctx context.Context, resolver IPResolver, policy destinationPolicy, host string) (netip.Addr, error) {
	if literal, err := netip.ParseAddr(host); err == nil {
		literal = literal.Unmap()
		if !policy.allowed(literal) {
			return netip.Addr{}, fmt.Errorf("destination address is denied")
		}
		return literal, nil
	}
	addresses, err := resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("resolve destination: %w", err)
	}
	if len(addresses) == 0 {
		return netip.Addr{}, fmt.Errorf("resolve destination: no addresses")
	}
	var selected netip.Addr
	for _, candidate := range addresses {
		candidate = candidate.Unmap()
		if !policy.allowed(candidate) {
			return netip.Addr{}, fmt.Errorf("destination resolution contains denied address")
		}
		if !selected.IsValid() {
			selected = candidate
		}
	}
	return selected, nil
}

var _ IPResolver = (*net.Resolver)(nil)
