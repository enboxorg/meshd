// Package control defines the interface between the DWN coordination layer
// and the networking engine (meshnet).
//
// The key abstraction is MapResponse — a snapshot of the mesh network state
// that the WireGuard engine consumes. These types are mapped to meshnet's
// tailcfg.MapResponse and related types by the engine/Converter.
//
// The control client watches DWN records (via subscriptions) and produces
// updated MapResponse snapshots whenever the mesh state changes.
package control

import (
	"net/netip"
	"time"
)

// Node represents a peer in the mesh network.
// Maps to tailcfg.Node in meshnet.
type Node struct {
	// ID is a unique identifier for this node (derived from record ID).
	ID int64

	// Name is the hostname or label for this node.
	Name string

	// DID is the node's DID URI.
	DID string

	// Key is the WireGuard public key (Curve25519, base64).
	// Derived from the node's did:jwk identity (Ed25519 → X25519 birational map),
	// not read from a record field.
	Key string

	// DiscoKey is the disco public key (base64) for DERP relay and
	// direct connection upgrade. Exchanged via DWN node/endpoint records.
	DiscoKey string

	// Endpoints are the node's reachable ip:port pairs.
	Endpoints []string

	// MeshIP is the node's IP within the mesh CIDR.
	MeshIP netip.Addr

	// AllowedIPs are the CIDRs this node is allowed to route.
	AllowedIPs []netip.Prefix

	// PreferredDERP is the ID of the preferred DERP region.
	PreferredDERP int

	// Online indicates whether the node is currently reachable.
	// Determined by whether the most recent endpoint record update
	// is within the staleness threshold (DefaultPeerStaleThreshold).
	Online bool

	// LastSeen is the time of the most recent endpoint record update.
	// Zero value means no endpoint data is available.
	LastSeen time.Time

	// OS is the operating system.
	OS string

	// Capabilities advertised by this node.
	Capabilities []string
}

// DERPRegion represents a DERP relay region.
// Maps to tailcfg.DERPRegion in meshnet.
type DERPRegion struct {
	// RegionID is a unique numeric identifier.
	RegionID int

	// RegionCode is a short string code (e.g. "us-east").
	RegionCode string

	// RegionName is a human-readable name.
	RegionName string

	// Nodes are the DERP servers in this region.
	Nodes []DERPNode
}

// DERPNode represents a single DERP relay server.
// Maps to tailcfg.DERPNode in meshnet.
type DERPNode struct {
	// Name is a unique identifier for this DERP node.
	Name string

	// RegionID is the parent region.
	RegionID int

	// HostName is the DERP server's hostname.
	HostName string

	// IPv4 is the DERP server's IPv4 address (optional).
	IPv4 string

	// DERPPort is the DERP HTTPS port (typically 443).
	DERPPort int

	// STUNPort is the STUN UDP port (typically 3478).
	STUNPort int

	// STUNOnly indicates this node only provides STUN, not DERP.
	STUNOnly bool

	// InsecureForTests disables TLS verification (for local test DERP servers).
	InsecureForTests bool
}

// DERPMap is the full set of DERP regions.
// Maps to tailcfg.DERPMap in meshnet.
type DERPMap struct {
	Regions map[int]*DERPRegion
}

// FilterRule represents a packet filter rule.
// Maps to tailcfg.FilterRule in meshnet.
type FilterRule struct {
	// SrcIPs are source IP ranges that this rule matches.
	SrcIPs []string

	// DstPorts are destination ip:port ranges.
	DstPorts []NetPortRange
}

// NetPortRange is an IP + port range for filter rules.
type NetPortRange struct {
	IP    string
	Ports PortRange
}

// PortRange is a range of ports.
type PortRange struct {
	First uint16
	Last  uint16
}

// DNSConfig holds mesh DNS configuration.
// Maps to tailcfg.DNSConfig in meshnet.
type DNSConfig struct {
	// Resolvers are DNS server addresses.
	Resolvers []string

	// MagicDNSSuffix is the suffix for mesh-local name resolution.
	MagicDNSSuffix string
}

// MapResponse is a complete snapshot of the mesh network state.
// This is the primary data structure passed to the networking engine.
// Maps to tailcfg.MapResponse in meshnet.
type MapResponse struct {
	// Node is this node's own configuration.
	Node *Node

	// Peers are all other nodes in the mesh.
	Peers []*Node

	// DERPMap is the relay server map.
	DERPMap *DERPMap

	// PacketFilter is the set of ACL rules.
	PacketFilter []FilterRule

	// DNSConfig is the mesh DNS configuration.
	DNSConfig *DNSConfig
}
