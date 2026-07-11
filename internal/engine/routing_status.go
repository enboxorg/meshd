package engine

import (
	"context"
	"log/slog"
)

const (
	RoutingPhaseUserspace = "userspace"
	RoutingPhaseSyncing   = "syncing"
	RoutingPhaseReady     = "ready"
	RoutingPhaseError     = "error"
)

// RoutingStatus describes whether applications can use the mesh through the
// host operating system. Ready remains true across transient control refresh
// failures when the last successfully installed route set is still active.
type RoutingStatus struct {
	Required  bool
	Ready     bool
	Phase     string
	LastError string
}

type routingState struct {
	required      bool
	routerReady   bool
	controlError  string
	routeError    string
	routePhase    string
	controlWarned bool
	routeWarned   bool
}

func (e *Engine) initializeRoutingStatus(required bool) {
	e.routingMu.Lock()
	defer e.routingMu.Unlock()
	e.routing = routingState{required: required}
	if !required {
		e.routing.routerReady = true
	}
}

// RoutingStatus returns a concurrency-safe snapshot of host routing readiness.
func (e *Engine) RoutingStatus() RoutingStatus {
	e.routingMu.RLock()
	defer e.routingMu.RUnlock()
	return e.routingStatusLocked()
}

func (e *Engine) routingStatusLocked() RoutingStatus {
	if !e.routing.required {
		return RoutingStatus{Ready: true, Phase: RoutingPhaseUserspace}
	}

	status := RoutingStatus{Required: true, Ready: e.routing.routerReady}
	switch {
	case e.routing.controlError != "":
		status.Phase = RoutingPhaseError
		status.LastError = e.routing.controlError
	case e.routing.routeError != "":
		status.Phase = e.routing.routePhase
		status.LastError = e.routing.routeError
	case e.routing.routerReady:
		status.Phase = RoutingPhaseReady
	default:
		status.Phase = RoutingPhaseSyncing
	}
	return status
}

func (e *Engine) recordControlMapError(ctx context.Context, err error) {
	e.updateRoutingStatus(ctx, func(state *routingState) {
		state.controlError = "loading control map: " + err.Error()
	})
}

func (e *Engine) recordRouteResult(ctx context.Context, err error, phase string, freshControlResult bool) {
	e.updateRoutingStatus(ctx, func(state *routingState) {
		if freshControlResult {
			state.controlError = ""
		}
		if err == nil {
			state.routerReady = true
			state.routeError = ""
			state.routePhase = ""
			return
		}
		state.routerReady = false
		state.routeError = err.Error()
		state.routePhase = phase
	})
}

func (e *Engine) updateRoutingStatus(ctx context.Context, update func(*routingState)) {
	e.routingMu.Lock()
	before := e.routingStatusLocked()
	update(&e.routing)
	after := e.routingStatusLocked()
	warnControl := e.routing.controlError != "" && !e.routing.controlWarned
	warnRoute := e.routing.routePhase == RoutingPhaseError && !e.routing.routeWarned
	if warnControl {
		e.routing.controlWarned = true
	}
	if warnRoute {
		e.routing.routeWarned = true
	}
	controlError := e.routing.controlError
	routeError := e.routing.routeError
	hadFailure := e.routing.controlWarned || e.routing.routeWarned
	recovered := after.Phase == RoutingPhaseReady && hadFailure
	becameReady := after.Phase == RoutingPhaseReady && before.Phase != RoutingPhaseReady
	if after.Phase == RoutingPhaseReady {
		e.routing.controlWarned = false
		e.routing.routeWarned = false
	}
	e.routingMu.Unlock()

	if warnControl {
		e.logger.WarnContext(ctx, "mesh control map load failed",
			slog.String("error", controlError),
		)
	}
	if warnRoute {
		e.logger.WarnContext(ctx, "mesh OS route reconciliation failed",
			slog.String("error", routeError),
		)
	}
	if recovered {
		e.logger.InfoContext(ctx, "mesh routing recovered")
	} else if becameReady {
		e.logger.InfoContext(ctx, "mesh routing ready")
	}
}
