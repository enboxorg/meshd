package engine

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"time"

	"github.com/enboxorg/meshnet/types/netmap"
	"github.com/enboxorg/meshnet/wgengine/router"
)

const tunRouteReconcileInterval = 5 * time.Second

func routerConfigFromNetMap(nm *netmap.NetworkMap) (*router.Config, bool) {
	if nm == nil {
		return nil, false
	}

	localAddrs := nm.GetAddresses().AsSlice()
	if len(localAddrs) == 0 {
		return nil, false
	}

	local := make(map[netip.Prefix]bool, len(localAddrs))
	for _, p := range localAddrs {
		local[p.Masked()] = true
	}

	routeSet := make(map[netip.Prefix]bool)
	addRoute := func(p netip.Prefix) {
		if !p.IsValid() || p.Bits() == 0 {
			return
		}
		p = p.Masked()
		if local[p] {
			return
		}
		routeSet[p] = true
	}

	for _, peer := range nm.Peers {
		allowed := peer.AllowedIPs()
		if allowed.Len() > 0 {
			for _, p := range allowed.All() {
				addRoute(p)
			}
			continue
		}
		for _, p := range peer.Addresses().All() {
			addRoute(p)
		}
	}

	routes := make([]netip.Prefix, 0, len(routeSet))
	for p := range routeSet {
		routes = append(routes, p)
	}
	sort.Slice(routes, func(i, j int) bool {
		return routes[i].String() < routes[j].String()
	})

	return &router.Config{
		LocalAddrs: localAddrs,
		Routes:     routes,
	}, true
}

func (e *Engine) reconcileTUNRoutes(ctx context.Context) error {
	if !e.RoutingStatus().Required {
		return nil
	}

	e.routeApplyMu.Lock()
	defer e.routeApplyMu.Unlock()
	return e.applyTUNRouteConfigLocked(ctx, e.routeConfig, e.routeConfig != nil, false)
}

func (e *Engine) handleControlMapResult(ctx context.Context, nm *netmap.NetworkMap, err error) {
	if !e.RoutingStatus().Required {
		return
	}

	e.routeApplyMu.Lock()
	defer e.routeApplyMu.Unlock()
	if err != nil {
		e.recordControlMapError(ctx, err)
		return
	}

	cfg, ok := routerConfigFromNetMap(nm)
	if ok {
		e.routeConfig = cfg
	} else {
		e.routeConfig = nil
	}
	_ = e.applyTUNRouteConfigLocked(ctx, cfg, ok, true)
}

// applyTUNRouteConfigLocked installs a route snapshot and updates readiness.
// Callers must hold routeApplyMu so an older retry cannot land after a newer
// control result and overwrite either the OS routes or their reported state.
func (e *Engine) applyTUNRouteConfigLocked(ctx context.Context, cfg *router.Config, usable bool, freshControlResult bool) error {
	if e.osRouter == nil {
		err := fmt.Errorf("OS router is unavailable")
		e.recordRouteResult(ctx, err, RoutingPhaseError, freshControlResult)
		return err
	}
	if !usable {
		err := fmt.Errorf("no usable network map addresses yet")
		e.recordRouteResult(ctx, err, RoutingPhaseSyncing, freshControlResult)
		return err
	}
	if err := e.osRouter.Set(cfg); err != nil {
		err = fmt.Errorf("configuring OS routes: %w", err)
		e.recordRouteResult(ctx, err, RoutingPhaseError, freshControlResult)
		return err
	}
	e.recordRouteResult(ctx, nil, RoutingPhaseReady, freshControlResult)
	return nil
}

func (e *Engine) waitForInitialTUNRoutes(ctx context.Context, timeout time.Duration) {
	if !e.RoutingStatus().Required {
		return
	}

	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		if err := e.reconcileTUNRoutes(ctx); err == nil {
			return
		}

		select {
		case <-ctx.Done():
			return
		case <-deadline.C:
			return
		case <-ticker.C:
		}
	}
}

func (e *Engine) runTUNRouteReconciler(ctx context.Context) {
	if !e.RoutingStatus().Required {
		return
	}

	ticker := time.NewTicker(tunRouteReconcileInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = e.reconcileTUNRoutes(ctx)
		}
	}
}
