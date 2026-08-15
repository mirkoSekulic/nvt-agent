package dockerbackend

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
)

const localGatewayLabel = "nvt.dev/local-gateway"

type dockerNetworkEndpoint struct {
	Name string `json:"Name"`
}

func (backend *Backend) ensureGatewayAttachment(ctx context.Context, network string, labels ownedLabels) error {
	if err := backend.verifyObject(ctx, "network", network, labels); err != nil {
		return err
	}
	if err := backend.verifyRunNetworkSubnet(ctx, network); err != nil {
		return err
	}
	if err := backend.verifyGateway(ctx); err != nil {
		return err
	}
	attached, err := backend.gatewayAttached(ctx, network)
	if err != nil || attached {
		return err
	}
	if _, err := backend.docker.Run(ctx, nil, "network", "connect", network, backend.config.GatewayContainer); err != nil {
		attached, inspectErr := backend.gatewayAttached(ctx, network)
		if inspectErr != nil || !attached {
			return errors.New("local gateway network unavailable")
		}
	}
	return nil
}

func (backend *Backend) removeGatewayAttachment(ctx context.Context, network string, labels ownedLabels) error {
	if err := backend.verifyObject(ctx, "network", network, labels); err != nil {
		missing, missingErr := backend.objectConfirmedMissing(ctx, "network", network)
		if missingErr == nil && missing {
			return nil
		}
		return err
	}
	if err := backend.verifyRunNetworkSubnet(ctx, network); err != nil {
		return err
	}
	attached, err := backend.gatewayAttached(ctx, network)
	if err != nil {
		return err
	}
	if !attached {
		return nil
	}
	if err := backend.verifyGateway(ctx); err != nil {
		return err
	}
	if _, err := backend.docker.Run(ctx, nil, "network", "disconnect", "-f", network, backend.config.GatewayContainer); err != nil {
		attached, inspectErr := backend.gatewayAttached(ctx, network)
		if inspectErr != nil || attached {
			return errors.New("local gateway network unavailable")
		}
	}
	return nil
}

func (backend *Backend) verifyGateway(ctx context.Context) error {
	labels, err := backend.containerLabels(ctx, backend.config.GatewayContainer)
	if err != nil || len(labels) == 0 || labels[localGatewayLabel] != "true" {
		return errors.New("local gateway unavailable")
	}
	return nil
}

func (backend *Backend) gatewayAttached(ctx context.Context, network string) (bool, error) {
	output, err := backend.docker.Run(ctx, nil, "network", "inspect", "--format", "{{json .Containers}}", network)
	if err != nil {
		return false, err
	}
	defer clear(output)
	endpoints := map[string]dockerNetworkEndpoint{}
	if json.Unmarshal(bytes.TrimSpace(output), &endpoints) != nil {
		return false, errors.New("local gateway network unavailable")
	}
	for _, endpoint := range endpoints {
		if endpoint.Name == backend.config.GatewayContainer {
			return true, nil
		}
	}
	return false, nil
}
