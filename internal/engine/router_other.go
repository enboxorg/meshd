// Stub router for non-Linux platforms.
//
// Real TUN routing is only supported on Linux. On other platforms,
// meshd operates in userspace-only mode (fake TUN + netstack).

//go:build !linux

package engine

import (
	"github.com/enboxorg/meshnet/types/logger"
	"github.com/enboxorg/meshnet/wgengine/router"
)

// newLinuxRouter is a stub on non-Linux platforms. It returns nil,
// signaling that the caller should fall back to the fake router.
func newLinuxRouter(_ logger.Logf, _ string) router.Router {
	return nil
}
