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
// avoiding the network address (.0) and broadcast address (.255 for /24,
// or the last address in the range).
//
// For the default 10.200.0.0/16 CIDR this gives 65534 possible addresses
// (10.200.0.1 through 10.200.255.254).
//
// Collisions are theoretically possible but extremely unlikely given the
// 16-bit host space and SHA-256 distribution. For production use, the
// network creator should maintain a registry.
func AllocateMeshIP(cidr string, didURI string) (netip.Addr, error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("parsing CIDR %q: %w", cidr, err)
	}

	if !prefix.Addr().Is4() {
		return netip.Addr{}, fmt.Errorf("only IPv4 CIDRs are supported, got %s", cidr)
	}

	// Calculate host space size.
	bits := prefix.Bits()
	hostBits := 32 - bits
	if hostBits < 2 {
		return netip.Addr{}, fmt.Errorf("CIDR %s has too few host bits (%d)", cidr, hostBits)
	}

	// Number of usable addresses: 2^hostBits - 2 (exclude network and broadcast).
	maxHosts := uint32(1<<hostBits) - 2

	// Hash the DID to get a deterministic host offset.
	hash := sha256.Sum256([]byte(didURI))
	hostOffset := binary.BigEndian.Uint32(hash[:4]) % maxHosts

	// Host offset is 0-based, but we start from .1 (skip network address).
	hostNum := hostOffset + 1

	// Add the host number to the network base address.
	base := prefix.Addr().As4()
	baseInt := binary.BigEndian.Uint32(base[:])
	allocatedInt := baseInt + hostNum

	var result [4]byte
	binary.BigEndian.PutUint32(result[:], allocatedInt)

	return netip.AddrFrom4(result), nil
}
