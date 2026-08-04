package driver

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"time"

	"github.com/mirkoSekulic/nvt-agent/executiondrivers/azure/internal/config"
	"github.com/mirkoSekulic/nvt-agent/operator/executiondriver"
)

const maxAddressesPerDestination = 4

type Resolver interface {
	LookupIPv4(context.Context, string, string) ([]netip.Addr, error)
}

type netResolver struct{}

func (netResolver) LookupIPv4(ctx context.Context, dnsServer, host string) ([]netip.Addr, error) {
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, net.JoinHostPort(dnsServer, "53"))
		},
	}
	return resolver.LookupNetIP(ctx, "ip4", host)
}

func DefaultResolver() Resolver { return netResolver{} }

func resolveAttachment(ctx context.Context, resolver Resolver, dnsServer string, attachment *executiondriver.NativeEgressAttachment) ([]PinnedDestination, error) {
	if attachment == nil {
		return nil, nil
	}
	if executiondriver.ValidateNativeEgressAttachment(*attachment) != nil || resolver == nil {
		return nil, errors.New("Azure native egress attachment is invalid")
	}
	type endpoint struct {
		purpose, host string
		port          uint16
	}
	endpoints := []endpoint{{purpose: "relay", host: attachment.Relay.Host, port: attachment.Relay.Port}}
	for _, value := range attachment.RequiredDestinations {
		endpoints = append(endpoints, endpoint{purpose: string(value.Purpose), host: value.Host, port: value.Port})
	}
	result := make([]PinnedDestination, 0, len(endpoints))
	seen := map[string]struct{}{}
	for _, value := range endpoints {
		addresses, err := resolveIPv4(ctx, resolver, dnsServer, value.host)
		if err != nil {
			return nil, errors.New("Azure native egress destination resolution failed")
		}
		for _, address := range addresses {
			key := value.purpose + "\x00" + value.host + "\x00" + strconv.Itoa(int(value.port)) + "\x00" + address.String()
			if _, duplicate := seen[key]; duplicate {
				continue
			}
			seen[key] = struct{}{}
			result = append(result, PinnedDestination{Purpose: value.purpose, Host: value.host, Port: value.port, Address: address.String()})
		}
	}
	return canonicalPinned(result), nil
}

func resolveIPv4(ctx context.Context, resolver Resolver, dnsServer, host string) ([]netip.Addr, error) {
	if address, err := netip.ParseAddr(host); err == nil {
		if !validFenceAddress(address) {
			return nil, errors.New("destination address is unsupported")
		}
		return []netip.Addr{address}, nil
	}
	addresses, err := resolver.LookupIPv4(ctx, dnsServer, host)
	if err != nil {
		return nil, err
	}
	unique := map[netip.Addr]struct{}{}
	for _, address := range addresses {
		address = address.Unmap()
		if !validFenceAddress(address) {
			return nil, errors.New("destination address set is invalid")
		}
		unique[address] = struct{}{}
	}
	ordered := make([]netip.Addr, 0, len(unique))
	for address := range unique {
		ordered = append(ordered, address)
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Less(ordered[j]) })
	if len(ordered) == 0 || len(ordered) > maxAddressesPerDestination {
		return nil, errors.New("destination address set is invalid")
	}
	return ordered, nil
}

func validFenceAddress(address netip.Addr) bool {
	return address.Is4() && address.IsGlobalUnicast() && !address.IsLoopback() && !address.IsLinkLocalUnicast() &&
		address != netip.MustParseAddr("169.254.169.254")
}

func validateAttachmentAgainstConfig(configuration config.Configuration, attachment *executiondriver.NativeEgressAttachment) error {
	if attachment == nil {
		return nil
	}
	if executiondriver.ValidateNativeEgressAttachment(*attachment) != nil {
		return errors.New("Azure native egress attachment is invalid")
	}
	if address := net.ParseIP(attachment.Relay.Host); address != nil && address.To4() == nil {
		return errors.New("Azure IPv6 relay is unsupported")
	}
	required := []struct {
		endpoint string
		purpose  executiondriver.NativeEgressDestinationPurpose
	}{
		{configuration.HostBundle.Repository, executiondriver.NativeEgressDestinationBootstrap},
		{configuration.EnrollmentEndpoint, executiondriver.NativeEgressDestinationBootstrap},
		{configuration.NativeSessionEndpoint, executiondriver.NativeEgressDestinationControl},
	}
	if configuration.NativeWorkspace != nil {
		required = append(required, struct {
			endpoint string
			purpose  executiondriver.NativeEgressDestinationPurpose
		}{configuration.NativeWorkspace.Endpoint, executiondriver.NativeEgressDestinationControl})
	}
	for _, item := range required {
		parsed, err := url.Parse(item.endpoint)
		if err != nil || !attachmentHas(*attachment, item.purpose, parsed.Hostname(), endpointPort(parsed)) {
			return errors.New("Azure trusted endpoint is outside the native egress attachment")
		}
	}
	return nil
}

func attachmentHas(attachment executiondriver.NativeEgressAttachment, purpose executiondriver.NativeEgressDestinationPurpose, host string, port int) bool {
	if port < 1 || port > 65535 {
		return false
	}
	for _, value := range attachment.RequiredDestinations {
		if value.Purpose == purpose && value.Host == host && value.Port == uint16(port) {
			return true
		}
	}
	return false
}

func endpointPort(value *url.URL) int {
	if value.Port() == "" {
		if value.Scheme == "https" {
			return 443
		}
		return 0
	}
	port, _ := strconv.Atoi(value.Port())
	return port
}
