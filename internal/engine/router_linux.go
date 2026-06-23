// Linux-specific router implementation for meshd.
//
// This provides a minimal router.Router that configures IP addresses and
// routes on the TUN device using the `ip` command. It handles the subset
// of router.Config that meshd needs: LocalAddrs (addresses on the TUN)
// and Routes (routes to mesh peers through the TUN).
//
// Advanced features (netfilter, SNAT, stateful filtering) are not
// implemented — meshd relies on the default allow-all packet filter.

//go:build linux

package engine

import (
	"fmt"
	"net/netip"
	"os/exec"
	"strings"

	"github.com/enboxorg/meshnet/types/logger"
	"github.com/enboxorg/meshnet/wgengine/router"
)

// linuxRouter configures the OS network stack for a real TUN device on Linux.
// It uses the `ip` command to manage addresses and routes.
type linuxRouter struct {
	logf    logger.Logf
	tunName string

	// Track current state to compute deltas on Set().
	addrs  []netip.Prefix
	routes []netip.Prefix
}

// newOSRouter creates a new router for the given TUN device.
func newOSRouter(logf logger.Logf, tunName string) router.Router {
	return &linuxRouter{logf: logf, tunName: tunName}
}

func (r *linuxRouter) Up() error {
	// Bring the TUN interface up.
	if err := r.cmd("ip", "link", "set", "dev", r.tunName, "up"); err != nil {
		return fmt.Errorf("bringing up %s: %w", r.tunName, err)
	}
	r.logf("linuxRouter: %s is up", r.tunName)
	return nil
}

func (r *linuxRouter) Set(cfg *router.Config) error {
	if cfg == nil {
		return r.cleanup()
	}

	r.logf("linuxRouter: Set: %d addrs, %d routes", len(cfg.LocalAddrs), len(cfg.Routes))

	// Sync addresses: add new ones, remove stale ones.
	if err := r.syncAddrs(cfg.LocalAddrs); err != nil {
		return fmt.Errorf("syncing addresses: %w", err)
	}

	if err := r.syncRoutes(tunnelRoutes(cfg.Routes, cfg.LocalRoutes)); err != nil {
		return fmt.Errorf("syncing routes: %w", err)
	}

	return nil
}

func (r *linuxRouter) Close() error {
	if err := r.cleanup(); err != nil {
		return err
	}
	// Bring the interface down. Ignore errors — the device may already
	// be gone if the engine closed it first.
	_ = r.cmd("ip", "link", "set", "dev", r.tunName, "down")
	r.logf("linuxRouter: closed")
	return nil
}

// cleanup removes all managed addresses and routes from the TUN device.
func (r *linuxRouter) cleanup() error {
	for _, addr := range r.addrs {
		_ = r.cmd("ip", "addr", "del", addr.String(), "dev", r.tunName)
	}
	for _, rt := range r.routes {
		_ = r.cmd("ip", "route", "del", rt.String(), "dev", r.tunName)
	}
	r.addrs = nil
	r.routes = nil
	return nil
}

// syncAddrs reconciles the desired addresses with the current state.
func (r *linuxRouter) syncAddrs(want []netip.Prefix) error {
	wantSet := make(map[netip.Prefix]bool, len(want))
	for _, a := range want {
		wantSet[a] = true
	}

	// Remove addresses we no longer want.
	var kept []netip.Prefix
	for _, a := range r.addrs {
		if wantSet[a] {
			kept = append(kept, a)
			continue
		}
		if err := r.cmd("ip", "addr", "del", a.String(), "dev", r.tunName); err != nil {
			r.logf("linuxRouter: warning: failed to remove addr %s: %v", a, err)
		}
	}

	// Add addresses we don't have yet.
	haveSet := make(map[netip.Prefix]bool, len(r.addrs))
	for _, a := range r.addrs {
		haveSet[a] = true
	}
	for _, a := range want {
		if haveSet[a] {
			continue
		}
		if err := r.cmd("ip", "addr", "add", a.String(), "dev", r.tunName); err != nil {
			// EEXIST is fine — the address is already present.
			if !strings.Contains(err.Error(), "RTNETLINK answers: File exists") {
				return fmt.Errorf("adding addr %s: %w", a, err)
			}
		}
		kept = append(kept, a)
	}

	r.addrs = kept
	return nil
}

// syncRoutes reconciles the desired routes with the current state.
func (r *linuxRouter) syncRoutes(want []netip.Prefix) error {
	wantSet := make(map[netip.Prefix]bool, len(want))
	for _, rt := range want {
		wantSet[rt] = true
	}

	// Remove routes we no longer want.
	var kept []netip.Prefix
	for _, rt := range r.routes {
		if wantSet[rt] {
			kept = append(kept, rt)
			continue
		}
		if err := r.cmd("ip", "route", "del", rt.String(), "dev", r.tunName); err != nil {
			r.logf("linuxRouter: warning: failed to remove route %s: %v", rt, err)
		}
	}

	// Add routes we don't have yet.
	haveSet := make(map[netip.Prefix]bool, len(r.routes))
	for _, rt := range r.routes {
		haveSet[rt] = true
	}
	for _, rt := range want {
		if haveSet[rt] {
			continue
		}
		if err := r.cmd("ip", "route", "add", rt.String(), "dev", r.tunName); err != nil {
			if !strings.Contains(err.Error(), "RTNETLINK answers: File exists") {
				return fmt.Errorf("adding route %s: %w", rt, err)
			}
		}
		kept = append(kept, rt)
	}

	r.routes = kept
	return nil
}

// cmd runs an ip command and returns any error.
func (r *linuxRouter) cmd(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w (%s)", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
