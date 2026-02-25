// Package engine bridges meshd's control layer to the meshnet networking
// engine. It converts meshd's [control.MapResponse] into meshnet's
// [netmap.NetworkMap] and provides the [MapResponseFunc] callback that
// meshnet's DWNControl polls.
package engine

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/netip"
	"sort"

	"github.com/enboxorg/meshd/internal/control"

	"github.com/enboxorg/meshnet/tailcfg"
	"github.com/enboxorg/meshnet/types/dnstype"
	"github.com/enboxorg/meshnet/types/key"
	"github.com/enboxorg/meshnet/types/netmap"
	"github.com/enboxorg/meshnet/types/views"
	"github.com/enboxorg/meshnet/wgengine/filter"
	"go4.org/mem"
)

// Converter holds config for converting meshd types to meshnet types.
type Converter struct {
	// Domain is the mesh domain name (e.g. "my-mesh").
	Domain string

	// MagicDNSSuffix is the suffix for mesh-local DNS (e.g. "mesh.local").
	MagicDNSSuffix string

	logger *slog.Logger
}

// ConverterOption configures a Converter.
type ConverterOption func(*Converter)

// WithConverterLogger sets the logger for the converter.
func WithConverterLogger(l *slog.Logger) ConverterOption {
	return func(c *Converter) {
		c.logger = l
	}
}

// NewConverter creates a new Converter with the given options.
func NewConverter(domain string, opts ...ConverterOption) *Converter {
	c := &Converter{
		Domain:         domain,
		MagicDNSSuffix: "mesh.local",
		logger:         slog.Default(),
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Convert transforms a meshd MapResponse into a meshnet NetworkMap.
//
// The returned NetworkMap has all the fields meshnet's LocalBackend needs
// to configure WireGuard peers, DERP relays, DNS, and packet filters.
func (c *Converter) Convert(resp *control.MapResponse) (*netmap.NetworkMap, error) {
	if resp == nil {
		return nil, fmt.Errorf("nil MapResponse")
	}

	nm := &netmap.NetworkMap{
		Domain: c.Domain,
	}

	// Convert self node.
	if resp.Node != nil {
		if resp.Node.Key == "" {
			return nil, fmt.Errorf("self node has empty WireGuard key (DID=%s)", resp.Node.DID)
		}
		selfNode, err := c.convertNode(resp.Node)
		if err != nil {
			return nil, fmt.Errorf("converting self node: %w", err)
		}
		nm.SelfNode = selfNode.View()
	}

	// Convert peers, sorted by Node.ID.
	// Skip peers with empty WireGuard keys — these are typically stale
	// records that couldn't be decrypted (e.g., old Protocol Path
	// encrypted records before a context encryption re-registration).
	peers := make([]*tailcfg.Node, 0, len(resp.Peers))
	for _, p := range resp.Peers {
		if p.Key == "" {
			c.logger.Warn("skipping peer with empty WireGuard key",
				slog.String("did", p.DID),
				slog.String("name", p.Name),
			)
			continue
		}
		peerNode, err := c.convertNode(p)
		if err != nil {
			c.logger.Warn("skipping peer conversion",
				slog.String("did", p.DID),
				slog.Any("error", err),
			)
			continue
		}
		peers = append(peers, peerNode)
	}
	sort.Slice(peers, func(i, j int) bool {
		return peers[i].ID < peers[j].ID
	})

	peerViews := make([]tailcfg.NodeView, len(peers))
	for i, p := range peers {
		peerViews[i] = p.View()
	}
	nm.Peers = peerViews

	// Convert DERP map.
	if resp.DERPMap != nil {
		nm.DERPMap = c.convertDERPMap(resp.DERPMap)
	}

	// Convert DNS config.
	if resp.DNSConfig != nil {
		nm.DNS = c.convertDNSConfig(resp.DNSConfig)
	}

	// Convert packet filter rules.
	// We must set BOTH PacketFilterRules (raw tailcfg.FilterRule) AND
	// PacketFilter (compiled filtertype.Match). The LocalBackend's
	// updateFilterLocked reads PacketFilter (not PacketFilterRules) to
	// build the actual packet filter. In upstream Tailscale, the mapSession
	// compiles rules via MatchesFromFilterRules; since we bypass mapSession,
	// we must compile them ourselves.
	if len(resp.PacketFilter) > 0 {
		rules := c.convertFilterRules(resp.PacketFilter)
		nm.PacketFilterRules = views.SliceOf(rules)

		matches, err := filter.MatchesFromFilterRules(rules)
		if err != nil {
			c.logger.Warn("compiling packet filter rules",
				slog.Any("error", err),
				slog.Int("rules", len(rules)),
			)
		}
		nm.PacketFilter = matches
	}

	return nm, nil
}

// convertNode converts a meshd Node to a meshnet tailcfg.Node.
func (c *Converter) convertNode(n *control.Node) (*tailcfg.Node, error) {
	node := &tailcfg.Node{
		ID:       tailcfg.NodeID(n.ID),
		StableID: tailcfg.StableNodeID(fmt.Sprintf("dwn-%d", n.ID)),
		Name:     c.fqdn(n.Name),
		HomeDERP: n.PreferredDERP,
		Hostinfo: (&tailcfg.Hostinfo{
			Hostname: n.Name,
			OS:       n.OS,
		}).View(),
		MachineAuthorized: true,
	}

	online := n.Online
	node.Online = &online

	if !n.LastSeen.IsZero() {
		lastSeen := n.LastSeen
		node.LastSeen = &lastSeen
	}

	// Parse WireGuard public key. The key is stored as base64 in DWN records.
	if n.Key != "" {
		nodeKey, err := parseWireGuardKey(n.Key)
		if err != nil {
			return nil, fmt.Errorf("parsing WireGuard key for %q: %w", n.Name, err)
		}
		node.Key = nodeKey
	}

	// Parse disco public key. The disco key enables DERP relay and direct
	// connection upgrades between peers. It is exchanged via DWN
	// nodeInfo/endpoint records as base64.
	if n.DiscoKey != "" {
		dk, err := parseDiscoKey(n.DiscoKey)
		if err != nil {
			c.logger.Debug("skipping invalid disco key",
				slog.String("node", n.Name),
				slog.Any("error", err),
			)
		} else {
			node.DiscoKey = dk
		}
	}

	// Convert addresses (mesh IP as /32 or /128 prefix).
	if n.MeshIP.IsValid() {
		prefix := netip.PrefixFrom(n.MeshIP, n.MeshIP.BitLen())
		node.Addresses = []netip.Prefix{prefix}
	}

	// Convert AllowedIPs.
	if len(n.AllowedIPs) > 0 {
		node.AllowedIPs = make([]netip.Prefix, len(n.AllowedIPs))
		copy(node.AllowedIPs, n.AllowedIPs)
	} else if n.MeshIP.IsValid() {
		// Default: only the node's own IP.
		node.AllowedIPs = []netip.Prefix{
			netip.PrefixFrom(n.MeshIP, n.MeshIP.BitLen()),
		}
	}

	// Convert endpoints from string "ip:port" to netip.AddrPort.
	for _, epStr := range n.Endpoints {
		ap, err := netip.ParseAddrPort(epStr)
		if err != nil {
			c.logger.Debug("skipping unparseable endpoint",
				slog.String("endpoint", epStr),
				slog.Any("error", err),
			)
			continue
		}
		node.Endpoints = append(node.Endpoints, ap)
	}

	return node, nil
}

// parseWireGuardKey parses a base64-encoded WireGuard public key (32 bytes)
// into a meshnet key.NodePublic.
func parseWireGuardKey(b64Key string) (key.NodePublic, error) {
	raw, err := base64.StdEncoding.DecodeString(b64Key)
	if err != nil {
		// Try raw (no padding) base64.
		raw, err = base64.RawStdEncoding.DecodeString(b64Key)
		if err != nil {
			return key.NodePublic{}, fmt.Errorf("base64 decode: %w", err)
		}
	}
	if len(raw) != 32 {
		return key.NodePublic{}, fmt.Errorf("WireGuard key must be 32 bytes, got %d", len(raw))
	}
	return key.NodePublicFromRaw32(mem.B(raw)), nil
}

// parseDiscoKey parses a base64-encoded disco public key (32 bytes)
// into a meshnet key.DiscoPublic.
func parseDiscoKey(b64Key string) (key.DiscoPublic, error) {
	raw, err := base64.StdEncoding.DecodeString(b64Key)
	if err != nil {
		// Try raw (no padding) base64.
		raw, err = base64.RawStdEncoding.DecodeString(b64Key)
		if err != nil {
			return key.DiscoPublic{}, fmt.Errorf("base64 decode: %w", err)
		}
	}
	if len(raw) != 32 {
		return key.DiscoPublic{}, fmt.Errorf("disco key must be 32 bytes, got %d", len(raw))
	}
	return key.DiscoPublicFromRaw32(mem.B(raw)), nil
}

// fqdn converts a hostname to an FQDN with trailing dot, as meshnet expects.
func (c *Converter) fqdn(hostname string) string {
	if hostname == "" {
		return ""
	}
	suffix := c.MagicDNSSuffix
	if suffix == "" {
		suffix = "mesh.local"
	}
	return hostname + "." + suffix + "."
}

// convertDERPMap converts a meshd DERPMap to a meshnet tailcfg.DERPMap.
func (c *Converter) convertDERPMap(dm *control.DERPMap) *tailcfg.DERPMap {
	result := &tailcfg.DERPMap{
		Regions:            make(map[int]*tailcfg.DERPRegion, len(dm.Regions)),
		OmitDefaultRegions: true, // Don't use Tailscale's built-in DERP servers.
	}

	for id, region := range dm.Regions {
		r := &tailcfg.DERPRegion{
			RegionID:   region.RegionID,
			RegionCode: region.RegionCode,
			RegionName: region.RegionName,
		}

		for _, dn := range region.Nodes {
			r.Nodes = append(r.Nodes, &tailcfg.DERPNode{
				Name:             dn.Name,
				RegionID:         dn.RegionID,
				HostName:         dn.HostName,
				IPv4:             dn.IPv4,
				DERPPort:         dn.DERPPort,
				STUNPort:         dn.STUNPort,
				STUNOnly:         dn.STUNOnly,
				InsecureForTests: dn.InsecureForTests,
			})
		}

		result.Regions[id] = r
	}

	return result
}

// convertDNSConfig converts a meshd DNSConfig to a meshnet tailcfg.DNSConfig.
func (c *Converter) convertDNSConfig(dns *control.DNSConfig) tailcfg.DNSConfig {
	cfg := tailcfg.DNSConfig{
		Proxied: true, // Enable MagicDNS.
	}

	if dns.MagicDNSSuffix != "" {
		cfg.Domains = []string{dns.MagicDNSSuffix}
	}

	for _, addr := range dns.Resolvers {
		cfg.Resolvers = append(cfg.Resolvers, &dnstype.Resolver{
			Addr: addr,
		})
	}

	for _, domain := range dns.Domains {
		cfg.Domains = append(cfg.Domains, domain)
	}

	return cfg
}

// convertFilterRules converts meshd filter rules to meshnet tailcfg.FilterRule.
func (c *Converter) convertFilterRules(rules []control.FilterRule) []tailcfg.FilterRule {
	result := make([]tailcfg.FilterRule, 0, len(rules))
	for _, r := range rules {
		tr := tailcfg.FilterRule{
			SrcIPs: r.SrcIPs,
		}
		for _, dp := range r.DstPorts {
			tr.DstPorts = append(tr.DstPorts, tailcfg.NetPortRange{
				IP: dp.IP,
				Ports: tailcfg.PortRange{
					First: dp.Ports.First,
					Last:  dp.Ports.Last,
				},
			})
		}
		result = append(result, tr)
	}
	return result
}

// MapResponseFunc creates a meshnet-compatible MapResponseFunc that reads
// mesh state from DWN and converts it to a NetworkMap.
//
// This function is the bridge between meshd's DWN control client and
// meshnet's DWNControl polling loop. It is passed to DWNControlConfig.MapResponseFunc.
//
// If autoDelivery is non-nil, it is triggered after each successful state
// load to deliver context keys to any new members.
func MapResponseFunc(client *control.DWNClient, converter *Converter, autoDelivery *AutoKeyDelivery) func(context.Context) (*netmap.NetworkMap, error) {
	return func(ctx context.Context) (*netmap.NetworkMap, error) {
		resp, err := client.LoadState(ctx)
		if err != nil {
			return nil, fmt.Errorf("loading DWN state: %w", err)
		}

		// If auto key delivery is active, extract member DIDs from
		// the response and deliver context keys to any new members.
		if autoDelivery != nil && resp != nil {
			var memberDIDs []string
			if resp.Node != nil {
				memberDIDs = append(memberDIDs, resp.Node.DID)
			}
			for _, p := range resp.Peers {
				memberDIDs = append(memberDIDs, p.DID)
			}
			autoDelivery.OnMembersUpdated(ctx, memberDIDs)
		}

		return converter.Convert(resp)
	}
}
