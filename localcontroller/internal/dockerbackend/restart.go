package dockerbackend

import (
	"context"
	"errors"
	"time"

	"github.com/mirkoSekulic/nvt-agent/localcontroller/internal/controller"
)

func (backend *Backend) QuiesceForRestart(ctx context.Context, desired controller.BackendRun) (controller.BackendObservation, error) {
	run := desired.Resolved
	if run.Execution.Kind != "container" || desired.DeleteRequested || desired.ConfigurationRollout || !run.Persistence.Workspace || !run.Persistence.RuntimeState || !run.Persistence.DockerData {
		return controller.BackendObservation{}, controller.ErrBackendDesiredRunInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, backend.config.OperationTimeout)
	defer cancel()
	names := namesFor(backend.config, run.RunID, desired.SnapshotDigest)
	labels := ownedLabels{Owner: backend.config.Owner, RunID: run.RunID, Digest: desired.SnapshotDigest}
	plan, err := renderCompose(backend.config, run, desired.SnapshotDigest, names)
	if err != nil {
		return controller.BackendObservation{}, controller.ErrBackendDesiredRunInvalid
	}
	if err := backend.preflightComposeMutation(ctx, names.project, plan, labels); err != nil {
		return controller.BackendObservation{}, restartBackendError(err)
	}
	// Missing durable data is a conflict, not permission to create an empty
	// replacement. Optional cleaned-up trust/config volumes may be re-prepared
	// by Ensure; anything still present must have the exact ownership labels.
	for _, volume := range backend.requiredVolumes(run, names) {
		if err := backend.verifyObject(ctx, "volume", volume, labels); err != nil {
			if errors.Is(err, errOwnershipConflict) {
				return controller.BackendObservation{}, controller.ErrBackendDesiredRunInvalid
			}
			missing, checkErr := backend.objectConfirmedMissing(ctx, "volume", volume)
			if checkErr != nil || !missing {
				return controller.BackendObservation{}, controller.ErrBackendRetryable
			}
			if volume == names.workspace || volume == names.home || volume == names.dockerData {
				return controller.BackendObservation{}, controller.ErrBackendDesiredRunInvalid
			}
		}
	}
	containers, err := backend.ownedContainerIDs(ctx, labels)
	if err != nil {
		return controller.BackendObservation{}, controller.ErrBackendRetryable
	}
	for _, id := range containers {
		if err := backend.verifyContainer(ctx, id, labels); err != nil {
			return controller.BackendObservation{}, restartBackendError(err)
		}
	}
	if len(containers) != 0 {
		// Give sessions and nested Docker a graceful shutdown. No volume/network
		// deletion, broker deregistration, CA rotation, or controller restart.
		stopCtx, stopCancel := context.WithTimeout(ctx, 45*time.Second)
		_, err = backend.docker.Run(stopCtx, nil, append([]string{"stop", "--time", "30"}, containers...)...)
		stopCancel()
		if err != nil {
			return controller.BackendObservation{}, controller.ErrBackendRetryable
		}
		if _, err := backend.docker.Run(ctx, nil, append([]string{"rm"}, containers...)...); err != nil {
			return controller.BackendObservation{}, controller.ErrBackendRetryable
		}
	}
	cursor, _, err := backend.stoppedLifecycle(ctx, desired, names, labels, true)
	return controller.BackendObservation{LifecycleCursor: cursor}, err
}

func restartBackendError(err error) error {
	if errors.Is(err, errOwnershipConflict) {
		return controller.ErrBackendDesiredRunInvalid
	}
	return controller.ErrBackendRetryable
}
