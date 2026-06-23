package mesh

import (
	"net/netip"

	"github.com/enboxorg/meshd/internal/meshaddr"
)

// AllocateMeshIP deterministically allocates a mesh IP address from a CIDR
// based on the node's DID URI.
//
// The allocation uses SHA-256(DID) to pick a host address within the CIDR,
// avoiding the network address (.0), broadcast address, and the meshnet
// service IP (10.200.0.1) which is reserved by the networking engine.
//
// For the default 10.200.0.0/16 CIDR this gives 65533 possible addresses
// (10.200.0.2 through 10.200.255.254, excluding .0.1).
//
// Collisions are theoretically possible but extremely unlikely given the
// 16-bit host space and SHA-256 distribution. For production use, the
// network creator should maintain a registry.
func AllocateMeshIP(cidr string, didURI string) (netip.Addr, error) {
	return meshaddr.AllocateMeshIP(cidr, didURI)
}
