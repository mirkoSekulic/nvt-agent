package dockerbackend

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/netip"

	"github.com/mirkoSekulic/nvt-agent/localcontroller/internal/networkpolicy"
)

const (
	runNetworkPrefixBits = networkpolicy.RunNetworkPrefixBits
	maxNetworkProbes     = 128
)

type dockerIPAMConfig struct {
	Subnet string `json:"Subnet"`
}

func (backend *Backend) ensureOwnedNetwork(ctx context.Context, name string, labels ownedLabels) error {
	if err := backend.verifyObject(ctx, "network", name, labels); err == nil {
		return backend.verifyRunNetworkSubnet(ctx, name)
	} else if errors.Is(err, errOwnershipConflict) {
		return err
	}
	pool := netip.MustParsePrefix(backend.config.RunNetworkPool)
	start := networkStartSlot(pool, labels.RunID, labels.Digest, name)
	capacity := uint64(1) << (runNetworkPrefixBits - pool.Bits())
	for probe := uint64(0); probe < maxNetworkProbes && probe < capacity; probe++ {
		subnet := networkSubnet(pool, (start+probe)%capacity)
		arguments := []string{"network", "create", "--subnet", subnet.String()}
		arguments = append(arguments, labelArguments(labels)...)
		arguments = append(arguments, name)
		if _, err := backend.docker.Run(ctx, nil, arguments...); err == nil {
			if err := backend.verifyObject(ctx, "network", name, labels); err != nil {
				return err
			}
			return backend.verifyRunNetworkSubnet(ctx, name)
		}
		if err := backend.verifyObject(ctx, "network", name, labels); err == nil {
			return backend.verifyRunNetworkSubnet(ctx, name)
		} else if errors.Is(err, errOwnershipConflict) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
	}
	return errors.New("backend network unavailable")
}

func (backend *Backend) verifyRunNetworkSubnet(ctx context.Context, name string) error {
	raw, err := backend.docker.Run(ctx, nil, "network", "inspect", "--format", "{{json .IPAM.Config}}", name)
	if err != nil {
		return err
	}
	var configurations []dockerIPAMConfig
	if err := json.Unmarshal(raw, &configurations); err != nil || len(configurations) != 1 {
		return errOwnershipConflict
	}
	subnet, err := netip.ParsePrefix(configurations[0].Subnet)
	pool := netip.MustParsePrefix(backend.config.RunNetworkPool)
	managed := netip.MustParsePrefix("172.30.0.0/15")
	if err != nil || subnet != subnet.Masked() || subnet.Bits() != runNetworkPrefixBits || !pool.Contains(subnet.Addr()) || subnet.Overlaps(managed) {
		return errOwnershipConflict
	}
	return nil
}

func networkStartSlot(pool netip.Prefix, runID, digest, name string) uint64 {
	value := sha256.Sum256([]byte("nvt.local-controller.network/v1\x00" + runID + "\x00" + digest + "\x00" + name))
	capacity := uint64(1) << (runNetworkPrefixBits - pool.Bits())
	return binary.BigEndian.Uint64(value[:8]) % capacity
}

func networkSubnet(pool netip.Prefix, slot uint64) netip.Prefix {
	address := pool.Addr().As4()
	base := binary.BigEndian.Uint32(address[:])
	base += uint32(slot << (32 - runNetworkPrefixBits))
	var value [4]byte
	binary.BigEndian.PutUint32(value[:], base)
	return netip.PrefixFrom(netip.AddrFrom4(value), runNetworkPrefixBits)
}
