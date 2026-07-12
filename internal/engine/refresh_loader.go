package engine

import (
	"context"
	"errors"
	"fmt"

	"github.com/enboxorg/meshd/internal/control"
	"github.com/enboxorg/meshd/internal/dwn"
	"github.com/enboxorg/meshnet/types/netmap"
)

type controlStateLoader interface {
	LoadStateValidated(context.Context, control.PendingStateValidator) (*control.MapResponse, error)
	ApplyPendingStateValidated(context.Context, control.PendingStateValidator) (*control.MapResponse, error)
}

type controlStateConverter interface {
	Convert(*control.MapResponse) (*netmap.NetworkMap, error)
}

// refreshMapResponseFunc chooses the cheapest authoritative state transition
// for a coordinator batch, then converts and publishes exactly one final
// result. Topology and local expiry batches can be satisfied by staged local
// state; every other invalidation requires a full DWN reconciliation.
func refreshMapResponseFunc(
	loader controlStateLoader,
	converter controlStateConverter,
	onResult func(*control.MapResponse, error),
) func(context.Context, RefreshBatch) (*netmap.NetworkMap, error) {
	return func(ctx context.Context, batch RefreshBatch) (*netmap.NetworkMap, error) {
		if batchCanUsePendingState(batch) {
			var converted *netmap.NetworkMap
			var validationErr error
			resp, err := loader.ApplyPendingStateValidated(ctx, func(candidate *control.MapResponse) error {
				converted, validationErr = converter.Convert(candidate)
				return validationErr
			})
			if err == nil {
				if onResult != nil {
					onResult(resp, nil)
				}
				return converted, nil
			}
			if validationErr != nil {
				if onResult != nil {
					onResult(resp, err)
				}
				return nil, err
			}
			if deferFullReconciliation(ctx, err) || !errors.Is(err, control.ErrFullReconciliationRequired) {
				err = fmt.Errorf("loading DWN state: %w", err)
				if onResult != nil {
					onResult(nil, err)
				}
				return nil, err
			}
		}

		var converted *netmap.NetworkMap
		var validationErr error
		resp, err := loader.LoadStateValidated(ctx, func(candidate *control.MapResponse) error {
			converted, validationErr = converter.Convert(candidate)
			return validationErr
		})
		if err != nil {
			if validationErr != nil {
				if onResult != nil {
					onResult(resp, err)
				}
				return nil, err
			}
			err = fmt.Errorf("loading DWN state: %w", err)
			if onResult != nil {
				onResult(resp, err)
			}
			return nil, err
		}
		if onResult != nil {
			onResult(resp, nil)
		}
		return converted, nil
	}
}

func deferFullReconciliation(ctx context.Context, err error) bool {
	return ctx.Err() != nil || errors.Is(err, context.Canceled) ||
		errors.Is(err, context.DeadlineExceeded) || errors.Is(err, dwn.ErrRateLimited) ||
		errors.Is(err, dwn.ErrTransport)
}

func batchCanUsePendingState(batch RefreshBatch) bool {
	if len(batch.Reasons) == 0 {
		return false
	}
	for _, reason := range batch.Reasons {
		if reason != RefreshReasonTopology && reason != RefreshReasonExpiry {
			return false
		}
	}
	return true
}
