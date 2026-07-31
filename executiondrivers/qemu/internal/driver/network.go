package driver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/mirkoSekulic/nvt-agent/executiondrivers/qemu/internal/wire"
	"github.com/mirkoSekulic/nvt-agent/operator/executiondriver"
)

type nativeEgressEndpoint struct {
	host string
	port uint16
}

func qemuNetworkArgument(state State) (string, error) {
	return qemuNetworkArgumentWithResolver(context.Background(), state, func(_ context.Context, host string) (string, error) {
		return host, nil
	})
}

func qemuNetworkArgumentWithResolver(ctx context.Context, state State, resolve func(context.Context, string) (string, error)) (string, error) {
	hostForward := fmt.Sprintf("hostfwd=tcp:127.0.0.1:%d-:8080", state.HostPort)
	if state.NativeEgressAttachment == nil {
		return "user,id=nvtnet," + hostForward, nil
	}
	attachment := *state.NativeEgressAttachment
	aliases, err := wire.NativeEgressHostAliases(attachment)
	if err != nil {
		return "", errors.New("QEMU native egress network is invalid")
	}
	addresses := make(map[string]string, len(aliases))
	for _, alias := range aliases {
		addresses[alias.Host] = alias.Address
	}
	unique := map[nativeEgressEndpoint]struct{}{{host: attachment.Relay.Host, port: attachment.Relay.Port}: {}}
	for _, destination := range attachment.RequiredDestinations {
		unique[nativeEgressEndpoint{host: destination.Host, port: destination.Port}] = struct{}{}
	}
	endpoints := make([]nativeEgressEndpoint, 0, len(unique))
	for endpoint := range unique {
		endpoints = append(endpoints, endpoint)
	}
	sort.Slice(endpoints, func(left, right int) bool {
		if endpoints[left].host != endpoints[right].host {
			return endpoints[left].host < endpoints[right].host
		}
		return endpoints[left].port < endpoints[right].port
	})
	options := []string{"user", "id=nvtnet", "ipv6=off", "restrict=on", hostForward}
	for _, endpoint := range endpoints {
		alias := addresses[endpoint.host]
		if alias == "" {
			return "", errors.New("QEMU native egress network is invalid")
		}
		target, err := resolve(ctx, endpoint.host)
		if err != nil || target == "" {
			return "", errors.New("QEMU native egress network is invalid")
		}
		if strings.Contains(target, ":") {
			target = "[" + target + "]"
		}
		options = append(options, fmt.Sprintf("guestfwd=tcp:%s:%d-cmd:/bin/busybox nc %s %d", alias, endpoint.port, target, endpoint.port))
	}
	return strings.Join(options, ","), nil
}

func resolveQEMUNetworkHost(ctx context.Context, host string) (string, error) {
	if address, err := netip.ParseAddr(host); err == nil {
		if address.Zone() != "" {
			return "", errors.New("QEMU network endpoint is invalid")
		}
		return address.String(), nil
	}
	lookupContext, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	addresses, err := net.DefaultResolver.LookupNetIP(lookupContext, "ip4", host)
	if err != nil || len(addresses) == 0 {
		return "", errors.New("QEMU network endpoint is unavailable")
	}
	values := make([]string, 0, len(addresses))
	for _, address := range addresses {
		if address.Is4() {
			values = append(values, address.String())
		}
	}
	if len(values) == 0 {
		return "", errors.New("QEMU network endpoint is unavailable")
	}
	sort.Strings(values)
	return values[0], nil
}

func readProcessArguments(pid int) ([]string, error) {
	if pid < 1 {
		return nil, errors.New("QEMU process identity is invalid")
	}
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cmdline")
	if err != nil || len(data) == 0 || data[len(data)-1] != 0 {
		return nil, errors.New("QEMU process arguments are unavailable")
	}
	parts := strings.Split(string(data[:len(data)-1]), "\x00")
	if len(parts) == 0 {
		return nil, errors.New("QEMU process arguments are unavailable")
	}
	return parts, nil
}

func readSingleChildProcess(parentPID int, expectedBinary string) (int, error) {
	if parentPID < 1 || expectedBinary == "" {
		return 0, errors.New("QEMU process identity is invalid")
	}
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/task/%d/children", parentPID, parentPID))
	if err != nil {
		return 0, errors.New("QEMU process identity is unavailable")
	}
	children := strings.Fields(string(data))
	if len(children) != 1 {
		return 0, errors.New("QEMU process identity is ambiguous")
	}
	pid, err := strconv.Atoi(children[0])
	if err != nil || pid < 1 {
		return 0, errors.New("QEMU process identity is invalid")
	}
	arguments, err := readProcessArguments(pid)
	if err != nil || len(arguments) == 0 || arguments[0] != expectedBinary {
		return 0, errors.New("QEMU process identity is invalid")
	}
	return pid, nil
}

func processHasExactNetwork(arguments []string, expected string) bool {
	count := 0
	for index := 0; index < len(arguments); index++ {
		if arguments[index] != "-netdev" {
			continue
		}
		if index+1 >= len(arguments) || arguments[index+1] != expected {
			return false
		}
		count++
		index++
	}
	return count == 1
}

func qemuConfinementStatus(state State, machine *activeMachine, arguments []string) *executiondriver.EgressConfinementStatus {
	if machine == nil || machine.attachmentGeneration == 0 || machine.attachmentDigest == "" {
		return nil
	}
	status := &executiondriver.EgressConfinementStatus{
		Boundary:             executiondriver.EgressConfinementBoundaryInfrastructure,
		AttachmentGeneration: machine.attachmentGeneration,
		AttachmentDigest:     machine.attachmentDigest,
	}
	if state.NativeEgressAttachment == nil || state.NativeEgressAttachment.Generation != machine.attachmentGeneration ||
		state.NativeEgressAttachment.Digest != machine.attachmentDigest || !processHasExactNetwork(arguments, machine.netdevArgument) ||
		!strings.Contains(machine.netdevArgument, ",restrict=on,") {
		return status
	}
	status.Ready = true
	return status
}

func qemuGuestAliases(state State) ([]wire.NativeEgressHostAlias, error) {
	if state.NativeEgressAttachment == nil {
		return nil, nil
	}
	return wire.NativeEgressHostAliases(*state.NativeEgressAttachment)
}
