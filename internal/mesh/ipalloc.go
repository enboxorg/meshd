package mesh

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net/netip"
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
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("parsing CIDR %q: %w", cidr, err)
	}
	prefix = prefix.Masked() // Canonicalize: zero host bits in the base address.

	if !prefix.Addr().Is4() {
		return netip.Addr{}, fmt.Errorf("only IPv4 CIDRs are supported, got %s", cidr)
	}

	// Calculate host space size.
	bits := prefix.Bits()
	hostBits := 32 - bits
	if hostBits < 2 {
		return netip.Addr{}, fmt.Errorf("CIDR %s has too few host bits (%d)", cidr, hostBits)
	}

	// Number of usable addresses: 2^hostBits - 3 (exclude network, broadcast, and service IP).
	maxHosts := uint32(1<<hostBits) - 3

	// Hash the DID to get a deterministic host offset.
	hash := sha256.Sum256([]byte(didURI))
	hostOffset := binary.BigEndian.Uint32(hash[:4]) % maxHosts

	// Host offset is 0-based, but we start from .2 (skip network address and service IP).
	hostNum := hostOffset + 2

	// Add the host number to the network base address.
	base := prefix.Addr().As4()
	baseInt := binary.BigEndian.Uint32(base[:])
	allocatedInt := baseInt + hostNum

	var result [4]byte
	binary.BigEndian.PutUint32(result[:], allocatedInt)

	return netip.AddrFrom4(result), nil
}
