package engine

import (
	"context"
	"fmt"
	"log/slog"
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
	if e.osRouter == nil {
		return nil
	}
	nm := e.backend.NetMap()
	cfg, ok := routerConfigFromNetMap(nm)
	if !ok {
		return fmt.Errorf("no usable network map addresses yet")
	}
	if err := e.osRouter.Set(cfg); err != nil {
		return err
	}
	e.logger.DebugContext(ctx, "TUN routes reconciled",
		slog.Int("localAddrs", len(cfg.LocalAddrs)),
		slog.Int("routes", len(cfg.Routes)),
	)
	return nil
}

func (e *Engine) waitForInitialTUNRoutes(ctx context.Context, timeout time.Duration) {
	if e.osRouter == nil {
		return
	}

	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	var lastErr error
	for {
		if err := e.reconcileTUNRoutes(ctx); err == nil {
			return
		} else {
			lastErr = err
		}

		select {
		case <-ctx.Done():
			return
		case <-deadline.C:
			e.logger.WarnContext(ctx, "TUN routes not ready yet; will keep retrying in background",
				slog.Any("error", lastErr),
			)
			return
		case <-ticker.C:
		}
	}
}

func (e *Engine) runTUNRouteReconciler(ctx context.Context) {
	if e.osRouter == nil {
		return
	}

	ticker := time.NewTicker(tunRouteReconcileInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := e.reconcileTUNRoutes(ctx); err != nil {
				e.logger.DebugContext(ctx, "TUN route reconcile skipped",
					slog.Any("error", err),
				)
			}
		}
	}
}
