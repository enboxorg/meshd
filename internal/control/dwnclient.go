package control

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"

	"github.com/enboxorg/dwn-mesh/internal/dwn"
)

// Protocol URIs used by dwn-mesh.
const (
	ProtocolMesh = "https://enbox.org/protocols/wireguard-mesh"
	ProtocolNode = "https://enbox.org/protocols/wireguard-node"
)

// Sentinel errors.
var (
	ErrNoNetwork = errors.New("network record not found")
	ErrNoEntry   = errors.New("no data found in entry")
)

// UpdateFunc is called whenever the mesh state changes.
type UpdateFunc func(*MapResponse)

// dwnClientOptions holds configuration for the DWN control client.
type dwnClientOptions struct {
	logger   *slog.Logger
	onUpdate UpdateFunc
	resolver Resolver
}

// Option configures a DWNClient.
type Option func(*dwnClientOptions)

// WithLogger sets the logger for the control client.
func WithLogger(l *slog.Logger) Option {
	return func(o *dwnClientOptions) {
		o.logger = l
	}
}

// WithUpdateHandler sets the callback invoked on mesh state changes.
func WithUpdateHandler(fn UpdateFunc) Option {
	return func(o *dwnClientOptions) {
		o.onUpdate = fn
	}
}

// WithResolver sets the DID resolver used to discover peer DWN endpoints.
// If not set, peer DWN endpoints cannot be resolved from their DIDs.
func WithResolver(r Resolver) Option {
	return func(o *dwnClientOptions) {
		o.resolver = r
	}
}

// DWNClient reads mesh state from DWN records and produces MapResponse
// snapshots for the networking engine.
type DWNClient struct {
	anchorDWN       *dwn.Client
	anchorTenant    string
	networkRecordID string
	selfDID         string
	signer          *dwn.Signer
	logger          *slog.Logger
	onUpdate        UpdateFunc
	resolver        Resolver

	mu      sync.RWMutex
	network *NetworkConfig
	members map[string]*MemberInfo
	nodes   map[string]*NodeInfoData
	relays  []*RelayData
	acl     *ACLPolicyData

	// peerEndpoints caches resolved DID → DWN endpoint mappings.
	peerEndpoints map[string]*PeerEndpointInfo
}

// NewDWNClient creates a new DWN-based control client.
func NewDWNClient(
	anchorEndpoint string,
	anchorTenant string,
	networkRecordID string,
	selfDID string,
	signer *dwn.Signer,
	opts ...Option,
) *DWNClient {
	options := &dwnClientOptions{
		logger: slog.Default(),
	}
	for _, opt := range opts {
		opt(options)
	}

	return &DWNClient{
		anchorDWN:       dwn.NewClient(anchorEndpoint, signer),
		anchorTenant:    anchorTenant,
		networkRecordID: networkRecordID,
		selfDID:         selfDID,
		signer:          signer,
		logger:          options.logger,
		onUpdate:        options.onUpdate,
		resolver:        options.resolver,
		members:         make(map[string]*MemberInfo),
		nodes:           make(map[string]*NodeInfoData),
		peerEndpoints:   make(map[string]*PeerEndpointInfo),
	}
}

// LoadState reads the current mesh state from the anchor DWN and builds
// an initial MapResponse.
func (c *DWNClient) LoadState(ctx context.Context) (*MapResponse, error) {
	// 1. Read network config.
	c.logger.DebugContext(ctx, "reading network record",
		slog.String("recordId", c.networkRecordID),
	)

	netResp, err := c.anchorDWN.RecordsRead(ctx, c.anchorTenant, dwn.RecordsFilter{
		RecordID: c.networkRecordID,
	}, "network/member")
	if err != nil {
		return nil, fmt.Errorf("reading network: %w", err)
	}
	if netResp.Reply == nil || netResp.Reply.Status.Code != 200 {
		code, detail := 0, "nil reply"
		if netResp.Reply != nil {
			code = netResp.Reply.Status.Code
			detail = netResp.Reply.Status.Detail
		}
		return nil, fmt.Errorf("%w: %d %s", ErrNoNetwork, code, detail)
	}

	var network NetworkConfig
	if err := parseEntryData(netResp.Reply.Entry, &network); err != nil {
		return nil, fmt.Errorf("parsing network: %w", err)
	}

	c.mu.Lock()
	c.network = &network
	c.mu.Unlock()

	// 2. Query members.
	c.logger.DebugContext(ctx, "querying members")

	membersResp, err := c.anchorDWN.RecordsQuery(ctx, c.anchorTenant, dwn.RecordsFilter{
		Protocol:     ProtocolMesh,
		ProtocolPath: "network/member",
	}, "createdAscending", nil, "network/member")
	if err != nil {
		return nil, fmt.Errorf("querying members: %w", err)
	}

	entries, err := dwn.QueryResult(membersResp)
	if err != nil {
		return nil, fmt.Errorf("parsing members: %w", err)
	}

	c.mu.Lock()
	for _, entry := range entries {
		var member MemberInfo
		if err := json.Unmarshal(entry, &member); err != nil {
			c.logger.WarnContext(ctx, "parsing member entry", slog.Any("error", err))
			continue
		}
		c.members[member.DID] = &member
	}
	c.mu.Unlock()

	c.logger.DebugContext(ctx, "loaded members", slog.Int("count", len(entries)))

	// 3. Query nodeInfo records.
	nodesResp, err := c.anchorDWN.RecordsQuery(ctx, c.anchorTenant, dwn.RecordsFilter{
		Protocol:     ProtocolMesh,
		ProtocolPath: "network/nodeInfo",
	}, "createdAscending", nil, "network/member")
	if err != nil {
		return nil, fmt.Errorf("querying nodes: %w", err)
	}

	nodeEntries, err := dwn.QueryResult(nodesResp)
	if err != nil {
		return nil, fmt.Errorf("parsing nodes: %w", err)
	}

	c.mu.Lock()
	for _, entry := range nodeEntries {
		var node NodeInfoData
		if err := json.Unmarshal(entry, &node); err != nil {
			c.logger.WarnContext(ctx, "parsing node entry", slog.Any("error", err))
			continue
		}
		c.nodes[node.DID] = &node
	}
	c.mu.Unlock()

	c.logger.DebugContext(ctx, "loaded nodes", slog.Int("count", len(nodeEntries)))

	// 4. Query relay records.
	relayResp, err := c.anchorDWN.RecordsQuery(ctx, c.anchorTenant, dwn.RecordsFilter{
		Protocol:     ProtocolMesh,
		ProtocolPath: "network/relay",
	}, "createdAscending", nil, "network/member")
	if err != nil {
		return nil, fmt.Errorf("querying relays: %w", err)
	}

	relayEntries, err := dwn.QueryResult(relayResp)
	if err != nil {
		return nil, fmt.Errorf("parsing relays: %w", err)
	}

	c.mu.Lock()
	for _, entry := range relayEntries {
		var relay RelayData
		if err := json.Unmarshal(entry, &relay); err != nil {
			c.logger.WarnContext(ctx, "parsing relay entry", slog.Any("error", err))
			continue
		}
		c.relays = append(c.relays, &relay)
	}
	c.mu.Unlock()

	c.logger.InfoContext(ctx, "mesh state loaded",
		slog.String("network", network.Name),
		slog.Int("members", len(c.members)),
		slog.Int("nodes", len(c.nodes)),
		slog.Int("relays", len(c.relays)),
	)

	return c.buildMapResponse(), nil
}

// BuildStaticMapResponse creates a MapResponse from explicitly provided
// data, without querying any DWN. Useful for testing and bootstrapping.
func BuildStaticMapResponse(selfNode *Node, peers []*Node, derpMap *DERPMap) *MapResponse {
	if derpMap == nil {
		derpMap = &DERPMap{Regions: make(map[int]*DERPRegion)}
	}
	return &MapResponse{
		Node:         selfNode,
		Peers:        peers,
		DERPMap:      derpMap,
		PacketFilter: defaultFilterRules(),
		DNSConfig:    &DNSConfig{MagicDNSSuffix: "mesh.local"},
	}
}

// ResolvePeerDID resolves a peer's DID and caches the result. Returns the
// cached result on subsequent calls for the same DID. If no resolver is
// configured, returns nil without error.
func (c *DWNClient) ResolvePeerDID(ctx context.Context, peerDID string) (*PeerEndpointInfo, error) {
	if c.resolver == nil {
		return nil, nil
	}

	c.mu.RLock()
	cached, ok := c.peerEndpoints[peerDID]
	c.mu.RUnlock()
	if ok {
		return cached, nil
	}

	info, err := ResolvePeerEndpoints(ctx, c.resolver, peerDID, c.logger)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	c.peerEndpoints[peerDID] = info
	c.mu.Unlock()

	return info, nil
}

// buildMapResponse constructs a MapResponse from the current cached state.
func (c *DWNClient) buildMapResponse() *MapResponse {
	c.mu.RLock()
	defer c.mu.RUnlock()

	resp := &MapResponse{
		Peers:     make([]*Node, 0),
		DERPMap:   c.buildDERPMap(),
		DNSConfig: c.buildDNSConfig(),
	}

	var nodeID int64 = 1
	for did, nodeInfo := range c.nodes {
		node := nodeInfoToNode(nodeID, did, nodeInfo)
		nodeID++

		if did == c.selfDID {
			resp.Node = node
		} else {
			resp.Peers = append(resp.Peers, node)
		}
	}

	if c.acl != nil {
		resp.PacketFilter = c.buildFilterRules()
	} else {
		resp.PacketFilter = defaultFilterRules()
	}

	return resp
}

func nodeInfoToNode(id int64, did string, info *NodeInfoData) *Node {
	node := &Node{
		ID:           id,
		Name:         info.Hostname,
		DID:          did,
		Key:          info.WireGuardPublicKey,
		OS:           info.OS,
		Capabilities: info.Capabilities,
		Online:       true,
	}

	if ip, err := netip.ParseAddr(info.MeshIP); err == nil {
		node.MeshIP = ip
		node.AllowedIPs = []netip.Prefix{netip.PrefixFrom(ip, ip.BitLen())}
	}

	for _, cidr := range info.AllowedIPs {
		if prefix, err := netip.ParsePrefix(cidr); err == nil {
			node.AllowedIPs = append(node.AllowedIPs, prefix)
		}
	}

	for _, ep := range info.Endpoints {
		for _, pub := range ep.PublicEndpoints {
			node.Endpoints = append(node.Endpoints, fmt.Sprintf("%s:%d", pub.Address, pub.Port))
		}
		node.Endpoints = append(node.Endpoints, ep.LocalEndpoints...)
		if ep.PreferredDERP != 0 {
			node.PreferredDERP = ep.PreferredDERP
		}
	}

	return node
}

func (c *DWNClient) buildDERPMap() *DERPMap {
	dm := &DERPMap{Regions: make(map[int]*DERPRegion)}

	for i, relay := range c.relays {
		regionID := i + 1
		dm.Regions[regionID] = &DERPRegion{
			RegionID:   regionID,
			RegionCode: relay.Region,
			RegionName: relay.Region,
			Nodes: []DERPNode{
				{
					Name:     fmt.Sprintf("relay-%d", regionID),
					RegionID: regionID,
					HostName: relay.URL,
					DERPPort: 443,
					STUNPort: relay.STUNPort,
				},
			},
		}
	}

	return dm
}

func (c *DWNClient) buildDNSConfig() *DNSConfig {
	if c.network == nil {
		return nil
	}
	suffix := c.network.MagicDNSSuffix
	if suffix == "" {
		suffix = "mesh.local"
	}
	return &DNSConfig{
		MagicDNSSuffix: suffix,
		Resolvers:      c.network.DNSServers,
	}
}

func (c *DWNClient) buildFilterRules() []FilterRule {
	if c.acl == nil {
		return defaultFilterRules()
	}

	var rules []FilterRule
	for _, r := range c.acl.Rules {
		if r.Action != "accept" {
			continue
		}
		rule := FilterRule{SrcIPs: r.Src}
		for _, dst := range r.Dst {
			rule.DstPorts = append(rule.DstPorts, NetPortRange{
				IP:    dst,
				Ports: PortRange{First: 0, Last: 65535},
			})
		}
		rules = append(rules, rule)
	}
	return rules
}

func defaultFilterRules() []FilterRule {
	return []FilterRule{
		{
			SrcIPs: []string{"*"},
			DstPorts: []NetPortRange{
				{IP: "*", Ports: PortRange{First: 0, Last: 65535}},
			},
		},
	}
}

// parseEntryData extracts the data from a DWN read response entry.
func parseEntryData(entry json.RawMessage, dst any) error {
	if entry == nil {
		return ErrNoEntry
	}

	// First try wrapped entry (RecordsRead response format).
	var wrapped struct {
		RecordsWrite struct {
			EncodedData string `json:"encodedData"`
		} `json:"recordsWrite"`
	}
	if err := json.Unmarshal(entry, &wrapped); err == nil && wrapped.RecordsWrite.EncodedData != "" {
		data, err := base64.RawURLEncoding.DecodeString(wrapped.RecordsWrite.EncodedData)
		if err != nil {
			return fmt.Errorf("decoding data: %w", err)
		}
		return json.Unmarshal(data, dst)
	}

	// Fall back to direct unmarshal.
	return json.Unmarshal(entry, dst)
}
