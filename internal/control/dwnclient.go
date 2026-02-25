package control

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sort"
	"sync"

	"github.com/enboxorg/dwn-mesh/internal/dwn"
	dwncrypto "github.com/enboxorg/dwn-mesh/internal/dwn/crypto"
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
	logger     *slog.Logger
	onUpdate   UpdateFunc
	resolver   Resolver
	encManager *dwncrypto.EncryptionKeyManager
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

// WithEncryptionKeyManager sets the encryption key manager used to decrypt
// encrypted protocol records. If not set, encrypted records cannot be read.
func WithEncryptionKeyManager(mgr *dwncrypto.EncryptionKeyManager) Option {
	return func(o *dwnClientOptions) {
		o.encManager = mgr
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
	encManager      *dwncrypto.EncryptionKeyManager

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
		encManager:      options.encManager,
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
	// Network record is NOT encrypted (publicly readable anchor).
	if err := parseEntryData(netResp.Reply.Entry, &network, nil); err != nil {
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
		ContextID:    c.networkRecordID,
	}, "createdAscending", nil, "network/member")
	if err != nil {
		return nil, fmt.Errorf("querying members: %w", err)
	}

	entries, err := dwn.QueryResult(membersResp)
	if err != nil {
		return nil, fmt.Errorf("parsing members: %w", err)
	}

	memberDecryptor := c.makeDecryptor("network/member")
	c.mu.Lock()
	for _, entry := range entries {
		// Extract DID from descriptor metadata (not encrypted).
		meta := extractEntryMetadata(entry)
		memberDID := meta.Recipient // member records use recipient as the member DID

		var member MemberInfo
		if err := parseEntryData(entry, &member, memberDecryptor); err != nil {
			c.logger.WarnContext(ctx, "parsing member entry",
				slog.Any("error", err),
				slog.String("memberDID", memberDID),
			)
			// Even if we can't decrypt the data, we can still track the member
			// by DID from the unencrypted descriptor fields.
			if memberDID != "" {
				member.DID = memberDID
				member.RecordID = meta.RecordID
				c.members[memberDID] = &member
			}
			continue
		}
		member.DID = memberDID
		member.RecordID = meta.RecordID
		if memberDID != "" {
			c.members[memberDID] = &member
		}
	}
	c.mu.Unlock()

	c.logger.DebugContext(ctx, "loaded members", slog.Int("count", len(entries)))

	// 3. Query nodeInfo records.
	nodesResp, err := c.anchorDWN.RecordsQuery(ctx, c.anchorTenant, dwn.RecordsFilter{
		Protocol:     ProtocolMesh,
		ProtocolPath: "network/nodeInfo",
		ContextID:    c.networkRecordID,
	}, "createdAscending", nil, "network/member")
	if err != nil {
		return nil, fmt.Errorf("querying nodes: %w", err)
	}

	nodeEntries, err := dwn.QueryResult(nodesResp)
	if err != nil {
		return nil, fmt.Errorf("parsing nodes: %w", err)
	}

	nodeDecryptor := c.makeDecryptor("network/nodeInfo")
	c.mu.Lock()
	for _, entry := range nodeEntries {
		// Extract DID from descriptor tags (not encrypted).
		meta := extractEntryMetadata(entry)
		nodeDID := ""
		if did, ok := meta.Tags["did"].(string); ok {
			nodeDID = did
		}

		var node NodeInfoData
		if err := parseEntryData(entry, &node, nodeDecryptor); err != nil {
			c.logger.WarnContext(ctx, "parsing node entry",
				slog.Any("error", err),
				slog.String("nodeDID", nodeDID),
			)
			// Even if we can't decrypt the data payload, track the node DID
			// from the unencrypted tags. This allows peer discovery and auto
			// key delivery to work even before context key exchange completes.
			if nodeDID != "" {
				node.DID = nodeDID
				node.RecordID = meta.RecordID
				c.nodes[nodeDID] = &node
			}
			continue
		}
		node.DID = nodeDID
		node.RecordID = meta.RecordID
		if nodeDID != "" {
			c.nodes[nodeDID] = &node
		}
	}
	c.mu.Unlock()

	c.logger.DebugContext(ctx, "loaded nodes", slog.Int("count", len(nodeEntries)))

	// 4. Query relay records.
	relayResp, err := c.anchorDWN.RecordsQuery(ctx, c.anchorTenant, dwn.RecordsFilter{
		Protocol:     ProtocolMesh,
		ProtocolPath: "network/relay",
		ContextID:    c.networkRecordID,
	}, "createdAscending", nil, "network/member")
	if err != nil {
		return nil, fmt.Errorf("querying relays: %w", err)
	}

	relayEntries, err := dwn.QueryResult(relayResp)
	if err != nil {
		return nil, fmt.Errorf("parsing relays: %w", err)
	}

	relayDecryptor := c.makeDecryptor("network/relay")
	c.mu.Lock()
	for _, entry := range relayEntries {
		var relay RelayData
		if err := parseEntryData(entry, &relay, relayDecryptor); err != nil {
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

	// Sort DIDs for deterministic NodeID assignment. Go map iteration
	// order is random, and magicsock panics if the same public key
	// appears under different NodeIDs across successive polls.
	dids := make([]string, 0, len(c.nodes))
	for did := range c.nodes {
		dids = append(dids, did)
	}
	sort.Strings(dids)

	var nodeID int64 = 1
	for _, did := range dids {
		nodeInfo := c.nodes[did]
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

	// Default to DERP region 1 if no endpoint provided a preference.
	// Without a HomeDERP, magicsock removes the DERP relay address for
	// the peer, making packet relay impossible until a real endpoint
	// update is written with STUN-discovered DERP info.
	if node.PreferredDERP == 0 {
		node.PreferredDERP = 1
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

	// If no custom relays are configured, inject bootstrap DERP regions
	// so peers behind NAT have a relay path. These use Tailscale's public
	// DERP servers which speak the same protocol meshnet expects.
	if len(dm.Regions) == 0 {
		dm.Regions = defaultDERPRegions()
	}

	return dm
}

// defaultDERPRegions returns a set of bootstrap DERP relay regions.
// These are Tailscale's publicly available DERP servers which use the
// same protocol as meshnet. They provide relay connectivity (for NAT
// traversal) and STUN (for endpoint discovery) out of the box.
//
// Operators can override these by registering custom relay records
// on the anchor DWN. Once any relay record exists, these defaults
// are not used.
func defaultDERPRegions() map[int]*DERPRegion {
	return map[int]*DERPRegion{
		1: {
			RegionID:   1,
			RegionCode: "nyc",
			RegionName: "New York City",
			Nodes: []DERPNode{
				{Name: "1a", RegionID: 1, HostName: "derp1.tailscale.com", DERPPort: 443, STUNPort: 3478},
			},
		},
		2: {
			RegionID:   2,
			RegionCode: "sfo",
			RegionName: "San Francisco",
			Nodes: []DERPNode{
				{Name: "2a", RegionID: 2, HostName: "derp2.tailscale.com", DERPPort: 443, STUNPort: 3478},
			},
		},
		3: {
			RegionID:   3,
			RegionCode: "sin",
			RegionName: "Singapore",
			Nodes: []DERPNode{
				{Name: "3a", RegionID: 3, HostName: "derp3.tailscale.com", DERPPort: 443, STUNPort: 3478},
			},
		},
		4: {
			RegionID:   4,
			RegionCode: "fra",
			RegionName: "Frankfurt",
			Nodes: []DERPNode{
				{Name: "4a", RegionID: 4, HostName: "derp4.tailscale.com", DERPPort: 443, STUNPort: 3478},
			},
		},
	}
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

// entryMetadata holds descriptor-level fields extracted from a DWN record
// entry. These fields are NOT encrypted and are always accessible.
type entryMetadata struct {
	RecordID  string         `json:"recordId"`
	Recipient string         `json:"recipient"`
	Tags      map[string]any `json:"tags"`
}

// extractEntryMetadata extracts non-encrypted descriptor metadata from
// a DWN record entry. This works even when the data payload is encrypted
// and cannot be decrypted.
//
// The function inspects both wrapped format (recordsWrite.descriptor)
// and flat format (descriptor) entries.
func extractEntryMetadata(entry json.RawMessage) entryMetadata {
	var meta entryMetadata

	// Try wrapped format: {"recordsWrite": {"descriptor": {...}}}
	var wrapped struct {
		RecordsWrite struct {
			RecordID   string `json:"recordId"`
			Descriptor struct {
				Recipient string         `json:"recipient"`
				Tags      map[string]any `json:"tags"`
			} `json:"descriptor"`
		} `json:"recordsWrite"`
	}
	if err := json.Unmarshal(entry, &wrapped); err == nil {
		meta.RecordID = wrapped.RecordsWrite.RecordID
		meta.Recipient = wrapped.RecordsWrite.Descriptor.Recipient
		meta.Tags = wrapped.RecordsWrite.Descriptor.Tags
		if meta.RecordID != "" || meta.Recipient != "" {
			return meta
		}
	}

	// Try flat format: {"recordId": "...", "descriptor": {...}}
	var flat struct {
		RecordID   string `json:"recordId"`
		Descriptor struct {
			Recipient string         `json:"recipient"`
			Tags      map[string]any `json:"tags"`
		} `json:"descriptor"`
	}
	if err := json.Unmarshal(entry, &flat); err == nil {
		meta.RecordID = flat.RecordID
		meta.Recipient = flat.Descriptor.Recipient
		meta.Tags = flat.Descriptor.Tags
	}

	return meta
}

// parseEntryData extracts the data from a DWN read response entry.
// If the entry contains encryption metadata and a decryptor is provided,
// the data is decrypted before unmarshaling.
func parseEntryData(entry json.RawMessage, dst any, decryptor entryDecryptor) error {
	if entry == nil {
		return ErrNoEntry
	}

	// First try wrapped entry (RecordsRead response format).
	var wrapped struct {
		RecordsWrite struct {
			EncodedData string               `json:"encodedData"`
			Encryption  *dwncrypto.Encryption `json:"encryption"`
		} `json:"recordsWrite"`
	}
	if err := json.Unmarshal(entry, &wrapped); err == nil && wrapped.RecordsWrite.EncodedData != "" {
		data, err := base64.RawURLEncoding.DecodeString(wrapped.RecordsWrite.EncodedData)
		if err != nil {
			return fmt.Errorf("decoding data: %w", err)
		}

		// If encrypted and we have a decryptor, decrypt.
		if wrapped.RecordsWrite.Encryption != nil && decryptor != nil {
			data, err = decryptor(data, wrapped.RecordsWrite.Encryption)
			if err != nil {
				return fmt.Errorf("decrypting data: %w", err)
			}
		}

		return json.Unmarshal(data, dst)
	}

	// Try flat entry format (query results).
	var flat struct {
		EncodedData string               `json:"encodedData"`
		Encryption  *dwncrypto.Encryption `json:"encryption"`
	}
	if err := json.Unmarshal(entry, &flat); err == nil && flat.EncodedData != "" {
		data, err := base64.RawURLEncoding.DecodeString(flat.EncodedData)
		if err != nil {
			return fmt.Errorf("decoding data: %w", err)
		}

		// If encrypted and we have a decryptor, decrypt.
		if flat.Encryption != nil && decryptor != nil {
			data, err = decryptor(data, flat.Encryption)
			if err != nil {
				return fmt.Errorf("decrypting data: %w", err)
			}
		}

		return json.Unmarshal(data, dst)
	}

	// Fall back to direct unmarshal.
	return json.Unmarshal(entry, dst)
}

// entryDecryptor is a function that decrypts ciphertext using the JWE metadata.
type entryDecryptor func(ciphertext []byte, enc *dwncrypto.Encryption) ([]byte, error)

// makeDecryptor creates a decryptor function from an EncryptionKeyManager
// and a protocol path. Returns nil if no key manager is available.
//
// The decryptor inspects the JWE recipient entries to determine the derivation
// scheme used and applies the correct decryption strategy:
//   - protocolPath: derives the key from root via HKDF at the given path
//   - protocolContext: uses a delivered context key (or derives from root if owner)
func (c *DWNClient) makeDecryptor(protocolPath string) entryDecryptor {
	if c.encManager == nil {
		return nil
	}

	return func(ciphertext []byte, enc *dwncrypto.Encryption) ([]byte, error) {
		// Inspect the JWE to determine which derivation scheme was used.
		scheme := detectDerivationScheme(enc)

		switch scheme {
		case dwncrypto.DerivationSchemeProtocolContext:
			// Protocol Context: use delivered context key or derive from root.
			// We need the contextID, which we can get from the network record ID
			// stored on the DWNClient.
			contextKey, err := c.encManager.DeriveContextDecryptionKey(c.networkRecordID)
			if err != nil {
				// Fall back to Protocol Path if context key isn't available.
				c.logger.Debug("context key not available, falling back to protocolPath",
					slog.String("protocolPath", protocolPath),
					slog.Any("error", err),
				)
				return c.decryptWithProtocolPath(ciphertext, enc, protocolPath)
			}
			return dwncrypto.DecryptDataWithScheme(ciphertext, enc, contextKey, dwncrypto.DerivationSchemeProtocolContext)

		default:
			// Protocol Path (default): derive from root HKDF.
			return c.decryptWithProtocolPath(ciphertext, enc, protocolPath)
		}
	}
}

// decryptWithProtocolPath decrypts using the Protocol Path derivation scheme.
func (c *DWNClient) decryptWithProtocolPath(ciphertext []byte, enc *dwncrypto.Encryption, protocolPath string) ([]byte, error) {
	privKey, err := c.encManager.DeriveDecryptionKey(protocolPath)
	if err != nil {
		return nil, fmt.Errorf("deriving decryption key for %s: %w", protocolPath, err)
	}
	return dwncrypto.DecryptData(ciphertext, enc, privKey, c.encManager.RootKeyID)
}

// detectDerivationScheme examines the JWE recipients to determine which
// key derivation scheme was used for encryption.
func detectDerivationScheme(enc *dwncrypto.Encryption) string {
	if enc == nil {
		return ""
	}
	for _, r := range enc.Recipients {
		if r.Header.DerivationScheme != "" {
			return r.Header.DerivationScheme
		}
	}
	return dwncrypto.DerivationSchemeProtocolPath // default
}
