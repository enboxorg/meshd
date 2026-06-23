// Package meshaddr contains address allocation helpers shared by the mesh
// orchestration and DWN control layers.
package meshaddr

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
func AllocateMeshIP(cidr string, didURI string) (netip.Addr, error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("parsing CIDR %q: %w", cidr, err)
	}
	prefix = prefix.Masked()

	if !prefix.Addr().Is4() {
		return netip.Addr{}, fmt.Errorf("only IPv4 CIDRs are supported, got %s", cidr)
	}

	bits := prefix.Bits()
	hostBits := 32 - bits
	if hostBits < 2 {
		return netip.Addr{}, fmt.Errorf("CIDR %s has too few host bits (%d)", cidr, hostBits)
	}

	maxHosts := uint32(1<<hostBits) - 3
	hash := sha256.Sum256([]byte(didURI))
	hostOffset := binary.BigEndian.Uint32(hash[:4]) % maxHosts
	hostNum := hostOffset + 2

	base := prefix.Addr().As4()
	baseInt := binary.BigEndian.Uint32(base[:])
	allocatedInt := baseInt + hostNum

	var result [4]byte
	binary.BigEndian.PutUint32(result[:], allocatedInt)

	return netip.AddrFrom4(result), nil
}
