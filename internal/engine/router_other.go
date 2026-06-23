// Stub router for platforms without a real OS router.
//
// Real TUN routing is only supported on selected platforms. Elsewhere,
// meshd operates in userspace-only mode (fake TUN + netstack).

//go:build !linux && !darwin

package engine

import (
	"github.com/enboxorg/meshnet/types/logger"
	"github.com/enboxorg/meshnet/wgengine/router"
)

// newOSRouter is a stub on unsupported platforms. It returns nil,
// signaling that the caller should fall back to the fake router.
func newOSRouter(_ logger.Logf, _ string) router.Router {
	return nil
}
