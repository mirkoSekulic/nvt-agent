package controller

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/mirkoSekulic/nvt-agent/protocol/localroutes"
	"github.com/mirkoSekulic/nvt-agent/protocol/resolvedrun"
)

// BackendRoutes contains only backend-owned public names and bounded internal
// targets. Authorization policy remains exclusively gateway configuration.
type BackendRoutes struct {
	Session   localroutes.Endpoint
	Exposures []localroutes.Exposure
}

type RouteProvider interface {
	Routes(context.Context, BackendRun) (BackendRoutes, error)
}

func (server *HTTPServer) routeList(ctx context.Context, limit int, after string) (localroutes.List, error) {
	if server.routeProvider == nil {
		return localroutes.List{}, ErrNotFound
	}
	if limit < 1 || limit > localroutes.MaxRunsPerPage {
		return localroutes.List{}, ErrInvalidRequest
	}
	runs, err := server.store.listActive(ctx, limit, after)
	if err != nil {
		return localroutes.List{}, err
	}
	result := localroutes.List{APIVersion: localroutes.APIVersion, Runs: make([]localroutes.Run, 0, len(runs.Runs)), NextAfter: runs.NextAfter}
	for _, run := range runs.Runs {
		route, routeErr := server.routeForRun(ctx, run)
		if routeErr != nil {
			return localroutes.List{}, routeErr
		}
		result.Runs = append(result.Runs, route)
	}
	if localroutes.ValidateList(result) != nil {
		return localroutes.List{}, ErrStoreUnavailable
	}
	return result, nil
}

func (server *HTTPServer) routeForRun(ctx context.Context, run Run) (localroutes.Run, error) {
	if server.routeProvider == nil || run.State.terminal() {
		return localroutes.Run{}, ErrNotFound
	}
	snapshot, digest, err := server.store.ResolvedSnapshot(ctx, run.RunID)
	if err != nil {
		return localroutes.Run{}, err
	}
	resolved, err := resolvedrun.DecodeResolvedAgentRun(snapshot)
	clear(snapshot)
	if err != nil {
		return localroutes.Run{}, ErrStoreUnavailable
	}
	routes, err := server.routeProvider.Routes(ctx, BackendRun{Resolved: resolved, SnapshotDigest: digest})
	if err != nil {
		return localroutes.Run{}, ErrStoreUnavailable
	}
	result := localroutes.Run{
		APIVersion: localroutes.APIVersion, RunID: run.RunID, State: string(run.State), Ready: run.State == StateRunning,
		Principal: localroutes.Principal{Issuer: resolved.Principal.Issuer, Subject: resolved.Principal.Subject, DisplayName: resolved.Principal.DisplayName},
		SourceURL: resolved.SourceURL, Profile: resolved.Profile, Workflow: resolved.Workflow, CreatedAt: run.CreatedAt.UTC(),
		Session: routes.Session, Exposures: append([]localroutes.Exposure(nil), routes.Exposures...),
	}
	if localroutes.ValidateRun(result) != nil {
		return localroutes.Run{}, ErrStoreUnavailable
	}
	return result, nil
}

func encodeCanonicalResolved(value resolvedrun.ResolvedAgentRun) (json.RawMessage, error) {
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) > resolvedrun.MaxDocumentBytes {
		return nil, errors.New("resolved run unavailable")
	}
	return encoded, nil
}
