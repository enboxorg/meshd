// macOS-specific router implementation for meshd.
//
// This is the minimal /dev/utun routing path used by the open-source
// Tailscale CLI daemon shape: configure addresses with ifconfig and point
// mesh routes at the utun interface with route(8).

//go:build darwin

package engine

import (
	"fmt"
	"net/netip"
	"os/exec"
	"strings"

	"github.com/enboxorg/meshnet/types/logger"
	"github.com/enboxorg/meshnet/wgengine/router"
)

type darwinRouter struct {
	logf    logger.Logf
	tunName string
	cmd     func(name string, args ...string) error

	addrs  []netip.Prefix
	routes map[netip.Prefix]bool
}

func newOSRouter(logf logger.Logf, tunName string) router.Router {
	return &darwinRouter{
		logf:    logf,
		tunName: tunName,
		cmd:     darwinExecCommand,
	}
}

func (r *darwinRouter) Up() error {
	if err := r.run("ifconfig", r.tunName, "up"); err != nil {
		return fmt.Errorf("bringing up %s: %w", r.tunName, err)
	}
	r.logf("darwinRouter: %s is up", r.tunName)
	return nil
}

func (r *darwinRouter) Set(cfg *router.Config) error {
	if cfg == nil {
		return r.cleanup()
	}

	r.logf("darwinRouter: Set: %d addrs, %d routes", len(cfg.LocalAddrs), len(cfg.Routes))

	if err := r.syncAddrsAndRoutes(cfg.LocalAddrs, tunnelRoutes(cfg.Routes, cfg.LocalRoutes)); err != nil {
		return err
	}
	return nil
}

func (r *darwinRouter) Close() error {
	if err := r.cleanup(); err != nil {
		return err
	}
	_ = r.run("ifconfig", r.tunName, "down")
	r.logf("darwinRouter: closed")
	return nil
}

func (r *darwinRouter) cleanup() error {
	var firstErr error
	for rt := range r.routes {
		if err := r.run(darwinRouteDeleteArgs(r.tunName, rt)...); err != nil {
			if commandAlreadyGone(err) {
				continue
			}
			r.logf("darwinRouter: warning: failed to remove route %s: %v", rt, err)
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	for _, addr := range r.addrs {
		if err := r.run(darwinAddrDeleteArgs(r.tunName, addr)...); err != nil {
			if commandAlreadyGone(err) {
				continue
			}
			r.logf("darwinRouter: warning: failed to remove addr %s: %v", addr, err)
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	if firstErr == nil {
		r.addrs = nil
		r.routes = nil
	}
	return firstErr
}

func (r *darwinRouter) syncAddrsAndRoutes(wantAddrs []netip.Prefix, wantRoutes []netip.Prefix) error {
	var firstErr error
	setErr := func(err error) {
		if firstErr == nil {
			firstErr = err
		}
	}

	addrsToRemove := diffPrefixes(r.addrs, wantAddrs)
	resetRoutes := len(r.addrs) > 0 && len(addrsToRemove) == len(r.addrs)

	for _, addr := range addrsToRemove {
		if err := r.run(darwinAddrDeleteArgs(r.tunName, addr)...); err != nil {
			if commandAlreadyGone(err) {
				continue
			}
			r.logf("darwinRouter: addr delete failed for %s: %v", addr, err)
			setErr(err)
		}
	}
	for _, addr := range diffPrefixes(wantAddrs, r.addrs) {
		if err := r.run(darwinAddrAddArgs(r.tunName, addr)...); err != nil {
			if !commandAlreadyExists(err) {
				r.logf("darwinRouter: addr add failed for %s: %v", addr, err)
				setErr(err)
			}
		}
	}

	newRoutes := make(map[netip.Prefix]bool, len(wantRoutes))
	for _, route := range wantRoutes {
		newRoutes[route] = true
	}

	for route := range r.routes {
		if resetRoutes || !newRoutes[route] {
			if err := r.run(darwinRouteDeleteArgs(r.tunName, route)...); err != nil {
				if commandAlreadyGone(err) {
					continue
				}
				r.logf("darwinRouter: route delete failed for %s: %v", route, err)
				setErr(err)
			}
		}
	}
	for route := range newRoutes {
		if resetRoutes || !r.routes[route] {
			if err := r.run(darwinRouteAddArgs(r.tunName, route)...); err != nil {
				if !commandAlreadyExists(err) {
					r.logf("darwinRouter: route add failed for %s: %v", route, err)
					setErr(err)
				}
			}
		}
	}

	if firstErr == nil {
		r.addrs = append([]netip.Prefix(nil), wantAddrs...)
		r.routes = newRoutes
	}
	return firstErr
}

func (r *darwinRouter) run(argv ...string) error {
	if len(argv) == 0 {
		return fmt.Errorf("empty command")
	}
	cmd := r.cmd
	if cmd == nil {
		cmd = darwinExecCommand
	}
	return cmd(argv[0], argv[1:]...)
}

func diffPrefixes(have []netip.Prefix, want []netip.Prefix) []netip.Prefix {
	wantSet := make(map[netip.Prefix]bool, len(want))
	for _, p := range want {
		wantSet[p] = true
	}

	var out []netip.Prefix
	for _, p := range have {
		if !wantSet[p] {
			out = append(out, p)
		}
	}
	return out
}

func darwinExecCommand(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w (%s)", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
