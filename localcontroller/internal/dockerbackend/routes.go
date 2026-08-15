package dockerbackend

import (
	"context"
	"strings"

	"github.com/mirkoSekulic/nvt-agent/localcontroller/internal/controller"
	"github.com/mirkoSekulic/nvt-agent/protocol/localroutes"
)

func (backend *Backend) Routes(_ context.Context, desired controller.BackendRun) (controller.BackendRoutes, error) {
	exposures, err := parseExposeRoutes(desired.Resolved.AgentConfig)
	if err != nil {
		return controller.BackendRoutes{}, err
	}
	runID := desired.Resolved.RunID
	names := namesFor(backend.config, runID, desired.SnapshotDigest)
	result := controller.BackendRoutes{
		Session: localroutes.Endpoint{
			Host:         runID + "." + backend.config.RouteBaseDomain,
			Path:         strings.TrimSuffix(backend.config.RoutePathPrefix, "/") + "/" + runID + "/",
			UpstreamHost: names.namespace, UpstreamPort: 4090,
		},
		Exposures: make([]localroutes.Exposure, 0, len(exposures)),
	}
	for _, exposure := range exposures {
		result.Exposures = append(result.Exposures, localroutes.Exposure{
			Name: exposure.Name, Host: exposure.Name + "." + runID + "." + backend.config.RouteBaseDomain,
			UpstreamHost: names.namespace, UpstreamPort: exposure.TargetPort,
		})
	}
	return result, nil
}
