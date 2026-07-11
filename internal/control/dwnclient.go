package control

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/enboxorg/meshd/internal/dwn"
	dwncrypto "github.com/enboxorg/meshd/internal/dwn/crypto"
	"github.com/enboxorg/meshd/internal/meshaddr"
	"github.com/enboxorg/meshd/pkg/dids/didjwk"
	"github.com/enboxorg/meshd/protocols"
)

// DefaultPeerStaleThreshold is the duration after which a peer is considered
// offline if no endpoint record update has been received. This is roughly
// 10x the default poll interval (30s), giving ample time for normal
// endpoint refreshes to arrive even with network jitter.
const DefaultPeerStaleThreshold = 5 * time.Minute

// Sentinel errors.
var (
	ErrNoNetwork = errors.New("network record not found")
	ErrNoEntry   = errors.New("no data found in entry")
)

// dwnClientOptions holds configuration for the DWN control client.
type dwnClientOptions struct {
	logger         *slog.Logger
	resolver       Resolver
	encManager     *dwncrypto.EncryptionKeyManager
	protocolRole   string
	grantID        string
	delegatedGrant json.RawMessage
	grantKeys      *GrantKeySet
	audienceSource *SealedAudienceSource
}

// Option configures a DWNClient.
type Option func(*dwnClientOptions)

// WithLogger sets the logger for the control client.
func WithLogger(l *slog.Logger) Option {
	return func(o *dwnClientOptions) {
		o.logger = l
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

// WithProtocolRole sets the DWN protocol role used for read queries.
// The anchor (network owner) should leave this empty (reads as author).
// Non-anchor nodes default to "network/node" when no explicit role is set.
func WithProtocolRole(role string) Option {
	return func(o *dwnClientOptions) {
		o.protocolRole = role
	}
}

// WithPermissionGrantID sets the DWN permission grant used for read queries.
func WithPermissionGrantID(grantID string) Option {
	return func(o *dwnClientOptions) {
		o.grantID = grantID
	}
}

// WithDelegatedGrant sets the delegated grant (full grant RecordsWrite
// message) invoked for read queries. Takes precedence over a plain
// permission grant ID.
func WithDelegatedGrant(grant json.RawMessage) Option {
	return func(o *dwnClientOptions) {
		o.delegatedGrant = grant
	}
}

// WithGrantKeys sets the delegate's grant-key subtree decrypters, used to
// decrypt any record whose protocol path is covered by a delivered grant key.
func WithGrantKeys(keys *GrantKeySet) Option {
	return func(o *dwnClientOptions) {
		o.grantKeys = keys
	}
}

// WithAudienceSource sets the sealed audience source used to recover
// role-audience private keys (via seal) when decrypting role-readable
// records.
func WithAudienceSource(src *SealedAudienceSource) Option {
	return func(o *dwnClientOptions) {
		o.audienceSource = src
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
	resolver        Resolver
	encManager      *dwncrypto.EncryptionKeyManager

	// protocolRole is the DWN protocol role used for read queries.
	// The anchor (network author) leaves this empty (reads as author).
	// Non-anchor nodes default to "network/node" unless explicitly set.
	protocolRole string

	// grantID is an optional DWN permission grant invoked for read queries.
	grantID string

	// delegatedGrant is an optional delegated grant message invoked for read
	// queries. Takes precedence over grantID.
	delegatedGrant json.RawMessage

	// grantKeys holds the delegate's grant-key subtree decrypters.
	grantKeys *GrantKeySet

	// audienceSource recovers role-audience private keys via seal unsealing.
	audienceSource *SealedAudienceSource

	mu      sync.RWMutex
	network *NetworkConfig
	members map[string]*MemberRecord
	nodes   map[string]*NodeRecord
	relays  []*RelayData
	acl     *ACLPolicyData

	// peerEndpoints caches resolved DID → DWN endpoint mappings.
	peerEndpoints map[string]*PeerEndpointInfo

	// undecryptablePeers counts (cumulatively, across all state loads) node
	// records whose data payload could not be decrypted — the visible symptom
	// of a missing role-audience key delivery (issue #187). Tracked separately
	// from droppedPeers because a record can fail to decrypt yet still surface a
	// mesh IP via fallback, or decrypt yet lack a usable IP.
	undecryptablePeers atomic.Int64

	// droppedPeers counts (cumulatively) peers omitted from the network map
	// because no mesh IP could be read or derived for them.
	droppedPeers atomic.Int64
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

	// Non-anchor nodes default to role-based reads — unless a delegated
	// grant authorizes the queries (the delegated author is the owner, not
	// a role holder, and a message cannot invoke both).
	protocolRole := options.protocolRole
	if protocolRole == "" && len(options.delegatedGrant) == 0 &&
		anchorTenant != "" && selfDID != "" && anchorTenant != selfDID {
		protocolRole = "network/node"
	}

	return &DWNClient{
		anchorDWN:       dwn.NewClient(anchorEndpoint, signer),
		anchorTenant:    anchorTenant,
		networkRecordID: networkRecordID,
		selfDID:         selfDID,
		signer:          signer,
		logger:          options.logger,
		resolver:        options.resolver,
		encManager:      options.encManager,
		protocolRole:    protocolRole,
		grantID:         options.grantID,
		delegatedGrant:  options.delegatedGrant,
		grantKeys:       options.grantKeys,
		audienceSource:  options.audienceSource,
		members:         make(map[string]*MemberRecord),
		nodes:           make(map[string]*NodeRecord),
		peerEndpoints:   make(map[string]*PeerEndpointInfo),
	}
}

// UndecryptablePeerCount returns the cumulative number of node records this
// client has failed to decrypt since it was created. A non-zero, growing value
// means role-audience keys are not reaching this node (issue #187): its peers
// exist in the DWN but cannot be read, so they never enter the mesh map.
func (c *DWNClient) UndecryptablePeerCount() int64 {
	return c.undecryptablePeers.Load()
}

// DroppedPeerCount returns the cumulative number of peers omitted from the
// network map because no mesh IP could be read or derived for them.
func (c *DWNClient) DroppedPeerCount() int64 {
	return c.droppedPeers.Load()
}

// readAuth builds the message auth for read queries at the given role. A
// delegated grant takes precedence over a plain permission grant.
func (c *DWNClient) readAuth(role string) dwn.MessageAuth {
	if len(c.delegatedGrant) > 0 {
		return dwn.MessageAuth{ProtocolRole: role, DelegatedGrant: c.delegatedGrant}
	}
	return dwn.MessageAuth{ProtocolRole: role, PermissionGrantID: c.grantID}
}

// LoadState reads the current mesh state from the anchor DWN and builds
// an initial MapResponse.
//
// The new protocol has two node paths:
//   - network/node — owner-provisioned devices
//   - network/member/node — member-associated devices
//
// Both paths have nodeInfo and endpoint child records. LoadState queries
// all paths and merges them into a unified node map keyed by DID.
func (c *DWNClient) LoadState(ctx context.Context) (*MapResponse, error) {
	// Determine the protocol role for queries. The anchor (network owner)
	// can read as author without a role. Non-anchor nodes use their node
	// role. Both network/node and network/member roles grant read access
	// to all record types, so we use network/node universally for
	// non-anchor reads.
	role := c.protocolRole

	// 1. Read network config.
	c.logger.DebugContext(ctx, "reading network record",
		slog.String("recordId", c.networkRecordID),
	)

	netResp, err := c.anchorDWN.RecordsReadWithAuth(ctx, c.anchorTenant, dwn.RecordsFilter{
		RecordID: c.networkRecordID,
	}, c.readAuth(role))
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
	if err := ParseEntryData(netResp.Reply.Entry, &network, nil); err != nil {
		return nil, fmt.Errorf("parsing network: %w", err)
	}

	c.mu.Lock()
	c.network = &network
	c.mu.Unlock()

	// 2. Query owner-provisioned node records (network/node).
	c.logger.DebugContext(ctx, "querying owner-provisioned nodes")

	nodesResp, err := c.anchorDWN.RecordsQueryWithAuth(ctx, c.anchorTenant, dwn.RecordsFilter{
		Protocol:     protocols.MeshProtocolURI,
		ProtocolPath: "network/node",
		ContextID:    c.networkRecordID,
	}, "createdAscending", nil, c.readAuth(role))
	if err != nil {
		return nil, fmt.Errorf("querying nodes: %w", err)
	}

	nodeEntries, err := dwn.QueryResult(nodesResp)
	if err != nil {
		return nil, fmt.Errorf("parsing nodes: %w", err)
	}

	nodeDecryptor := c.makeDecryptor(ctx, "network/node")
	c.mu.Lock()
	clear(c.nodes) // Clear stale nodes before repopulating.
	for _, entry := range nodeEntries {
		c.loadNodeEntry(ctx, entry, nodeDecryptor, "")
	}
	c.mu.Unlock()

	c.logger.DebugContext(ctx, "loaded owner-provisioned nodes", slog.Int("count", len(nodeEntries)))

	// 3. Query member records (network/member) to discover members.
	c.logger.DebugContext(ctx, "querying members")

	membersResp, err := c.anchorDWN.RecordsQueryWithAuth(ctx, c.anchorTenant, dwn.RecordsFilter{
		Protocol:     protocols.MeshProtocolURI,
		ProtocolPath: "network/member",
		ContextID:    c.networkRecordID,
	}, "createdAscending", nil, c.readAuth(role))
	if err != nil {
		// Non-fatal: members are optional (a simple personal mesh may have none).
		c.logger.DebugContext(ctx, "querying members failed", slog.Any("error", err))
	} else {
		memberEntries, err := dwn.QueryResult(membersResp)
		if err != nil {
			c.logger.DebugContext(ctx, "parsing member results", slog.Any("error", err))
		} else {
			memberDecryptor := c.makeDecryptor(ctx, "network/member")
			c.mu.Lock()
			clear(c.members) // Clear stale members before repopulating.
			for _, entry := range memberEntries {
				meta := extractEntryMetadata(entry)
				memberDID := meta.Recipient

				var member MemberRecord
				if err := ParseEntryData(entry, &member, memberDecryptor); err != nil {
					c.logger.DebugContext(ctx, "parsing member entry",
						slog.Any("error", err),
						slog.String("memberDID", memberDID),
					)
					// Track the member even if we can't decrypt.
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

			c.logger.DebugContext(ctx, "loaded members", slog.Int("count", len(memberEntries)))
		}
	}

	// 4. Query member-associated node records (network/member/node).
	c.logger.DebugContext(ctx, "querying member nodes")

	memberNodeCount := 0
	for _, query := range c.memberNodeParentQueries() {
		memberNodesResp, err := c.anchorDWN.RecordsQueryWithAuth(ctx, c.anchorTenant, dwn.RecordsFilter{
			Protocol:     protocols.MeshProtocolURI,
			ProtocolPath: "network/member/node",
			ContextID:    query.ParentContextID,
		}, "createdAscending", nil, c.readAuth(role))
		if err != nil {
			// Non-fatal: member nodes are optional.
			c.logger.DebugContext(ctx, "querying member nodes failed",
				slog.String("memberRecordId", query.MemberRecordID),
				slog.Any("error", err),
			)
			continue
		}

		memberNodeEntries, err := dwn.QueryResult(memberNodesResp)
		if err != nil {
			c.logger.DebugContext(ctx, "parsing member node results",
				slog.String("memberRecordId", query.MemberRecordID),
				slog.Any("error", err),
			)
			continue
		}

		memberNodeDecryptor := c.makeDecryptor(ctx, "network/member/node")
		c.mu.Lock()
		for _, entry := range memberNodeEntries {
			c.loadNodeEntry(ctx, entry, memberNodeDecryptor, query.MemberRecordID)
		}
		c.mu.Unlock()
		memberNodeCount += len(memberNodeEntries)
	}
	c.logger.DebugContext(ctx, "loaded member nodes", slog.Int("count", memberNodeCount))

	// 5. Query relay records.
	relayResp, err := c.anchorDWN.RecordsQueryWithAuth(ctx, c.anchorTenant, dwn.RecordsFilter{
		Protocol:     protocols.MeshProtocolURI,
		ProtocolPath: "network/relay",
		ContextID:    c.networkRecordID,
	}, "createdAscending", nil, c.readAuth(role))
	if err != nil {
		return nil, fmt.Errorf("querying relays: %w", err)
	}

	relayEntries, err := dwn.QueryResult(relayResp)
	if err != nil {
		return nil, fmt.Errorf("parsing relays: %w", err)
	}

	relayDecryptor := c.makeDecryptor(ctx, "network/relay")
	c.mu.Lock()
	c.relays = nil // Clear stale relays before repopulating.
	for _, entry := range relayEntries {
		var relay RelayData
		if err := ParseEntryData(entry, &relay, relayDecryptor); err != nil {
			c.logger.DebugContext(ctx, "parsing relay entry", slog.Any("error", err))
			continue
		}
		c.relays = append(c.relays, &relay)
	}
	c.mu.Unlock()

	// 6. Query ACL policy record.
	aclResp, err := c.anchorDWN.RecordsQueryWithAuth(ctx, c.anchorTenant, dwn.RecordsFilter{
		Protocol:     protocols.MeshProtocolURI,
		ProtocolPath: "network/aclPolicy",
		ContextID:    c.networkRecordID,
	}, "createdDescending", nil, c.readAuth(role))
	if err != nil {
		// Non-fatal: ACL policy is optional. Default to allow-all.
		c.logger.DebugContext(ctx, "querying ACL policy failed", slog.Any("error", err))
	} else {
		aclEntries, err := dwn.QueryResult(aclResp)
		if err != nil {
			c.logger.DebugContext(ctx, "parsing ACL policy results", slog.Any("error", err))
		} else if len(aclEntries) > 0 {
			// ACL policies are squashed snapshots; take the newest visible entry.
			aclDecryptor := c.makeDecryptor(ctx, "network/aclPolicy")
			var policy ACLPolicyData
			if err := ParseEntryData(aclEntries[0], &policy, aclDecryptor); err != nil {
				c.logger.DebugContext(ctx, "parsing ACL policy entry", slog.Any("error", err))
			} else {
				c.mu.Lock()
				c.acl = &policy
				c.mu.Unlock()
				c.logger.DebugContext(ctx, "loaded ACL policy",
					slog.Int("version", policy.Version),
					slog.Int("rules", len(policy.Rules)),
				)
			}
		}
	}

	// 7. Query nodeInfo records under each node's direct parent context.
	c.loadNodeChildRecords(ctx, "nodeInfo", role, c.loadNodeInfoEntry)

	// 8. Query endpoint records under each node's direct parent context.
	c.loadNodeChildRecords(ctx, "endpoint", role, c.loadEndpointEntry)

	hasACL := c.acl != nil
	c.logger.DebugContext(ctx, "mesh state loaded",
		slog.String("network", network.Name),
		slog.Int("nodes", len(c.nodes)),
		slog.Int("members", len(c.members)),
		slog.Int("relays", len(c.relays)),
		slog.Bool("aclPolicy", hasACL),
	)

	resp := c.buildMapResponse()
	if resp == nil {
		return nil, fmt.Errorf("self DID %q not found in network node records", c.selfDID)
	}
	return resp, nil
}

type memberNodeParentQuery struct {
	MemberRecordID  string
	ParentContextID string
}

func (c *DWNClient) memberNodeParentQueries() []memberNodeParentQuery {
	c.mu.RLock()
	defer c.mu.RUnlock()

	queries := make([]memberNodeParentQuery, 0, len(c.members))
	for _, member := range c.members {
		if member.RecordID == "" {
			continue
		}
		queries = append(queries, memberNodeParentQuery{
			MemberRecordID:  member.RecordID,
			ParentContextID: c.networkRecordID + "/" + member.RecordID,
		})
	}
	sort.Slice(queries, func(i, j int) bool {
		return queries[i].ParentContextID < queries[j].ParentContextID
	})
	return queries
}

// loadNodeEntry parses a node record entry and adds it to the nodes map.
// memberRecordID is the parent member record ID (empty for owner-provisioned nodes).
// Caller must hold c.mu.
func (c *DWNClient) loadNodeEntry(ctx context.Context, entry json.RawMessage, decryptor EntryDecryptor, memberRecordID string) {
	meta := extractEntryMetadata(entry)
	nodeDID := meta.Recipient

	var node NodeRecord
	if err := ParseEntryData(entry, &node, decryptor); err != nil {
		// An undecryptable peer node record is the visible symptom of a
		// missing role-audience key delivery (issue #187): the record exists
		// but this node was never handed the key to read it. Surface it at
		// Warn (not Debug) and count it so operators can see peers silently
		// dropping out of the mesh.
		c.undecryptablePeers.Add(1)
		c.logger.WarnContext(ctx, "node record could not be decrypted; peer will be invisible until a role-audience key is delivered",
			slog.Any("error", err),
			slog.String("nodeDID", nodeDID),
			slog.String("memberRecordId", memberRecordID),
		)
		// Even if we can't decrypt the data payload, track the node DID
		// from the unencrypted recipient field. This allows peer discovery
		// and auto key delivery to work even before context key exchange.
		if nodeDID != "" {
			node.DID = nodeDID
			node.RecordID = meta.RecordID
			node.MemberRecordID = memberRecordID
			c.nodes[nodeDID] = &node
		}
		return
	}
	node.NormalizeOwnerDID()
	node.DID = nodeDID
	node.RecordID = meta.RecordID
	node.MemberRecordID = memberRecordID
	if nodeDID != "" {
		c.nodes[nodeDID] = &node
	}
}

type nodeChildRecordQuery struct {
	ProtocolPath    string
	ParentContextID string
}

func (c *DWNClient) nodeChildRecordQueries(childType string) []nodeChildRecordQuery {
	c.mu.RLock()
	defer c.mu.RUnlock()

	queries := make([]nodeChildRecordQuery, 0, len(c.nodes))
	for _, node := range c.nodes {
		if node.RecordID == "" {
			continue
		}

		if node.MemberRecordID != "" {
			queries = append(queries, nodeChildRecordQuery{
				ProtocolPath:    "network/member/node/" + childType,
				ParentContextID: c.networkRecordID + "/" + node.MemberRecordID + "/" + node.RecordID,
			})
			continue
		}

		queries = append(queries, nodeChildRecordQuery{
			ProtocolPath:    "network/node/" + childType,
			ParentContextID: c.networkRecordID + "/" + node.RecordID,
		})
	}
	sort.Slice(queries, func(i, j int) bool {
		if queries[i].ParentContextID == queries[j].ParentContextID {
			return queries[i].ProtocolPath < queries[j].ProtocolPath
		}
		return queries[i].ParentContextID < queries[j].ParentContextID
	})
	return queries
}

func (c *DWNClient) loadNodeChildRecords(ctx context.Context, childType string, role string, handler func(ctx context.Context, entry json.RawMessage, decryptor EntryDecryptor)) {
	total := 0
	for _, query := range c.nodeChildRecordQueries(childType) {
		total += c.loadChildRecords(ctx, query.ProtocolPath, query.ParentContextID, role, handler)
	}
	c.logger.DebugContext(ctx, "loaded node child records",
		slog.String("type", childType),
		slog.Int("count", total),
	)
}

// loadChildRecords queries child records at the given protocol path under a
// direct parent context and processes each entry with the provided handler.
func (c *DWNClient) loadChildRecords(ctx context.Context, protocolPath string, parentContextID string, role string, handler func(ctx context.Context, entry json.RawMessage, decryptor EntryDecryptor)) int {
	resp, err := c.anchorDWN.RecordsQueryWithAuth(ctx, c.anchorTenant, dwn.RecordsFilter{
		Protocol:     protocols.MeshProtocolURI,
		ProtocolPath: protocolPath,
		ContextID:    parentContextID,
	}, "createdDescending", nil, c.readAuth(role))
	if err != nil {
		c.logger.DebugContext(ctx, "querying child records failed",
			slog.String("path", protocolPath),
			slog.String("parentContextId", parentContextID),
			slog.Any("error", err),
		)
		return 0
	}

	entries, err := dwn.QueryResult(resp)
	if err != nil {
		c.logger.DebugContext(ctx, "parsing child record results",
			slog.String("path", protocolPath),
			slog.String("parentContextId", parentContextID),
			slog.Any("error", err),
		)
		return 0
	}

	decryptor := c.makeDecryptor(ctx, protocolPath)
	c.mu.Lock()
	for _, entry := range entries {
		handler(ctx, entry, decryptor)
	}
	c.mu.Unlock()

	c.logger.DebugContext(ctx, "loaded child records",
		slog.String("path", protocolPath),
		slog.String("parentContextId", parentContextID),
		slog.Int("count", len(entries)),
	)
	return len(entries)
}

// loadNodeInfoEntry parses a nodeInfo entry and attaches it to the parent node.
// Caller must hold c.mu.
func (c *DWNClient) loadNodeInfoEntry(ctx context.Context, entry json.RawMessage, decryptor EntryDecryptor) {
	meta := extractEntryMetadata(entry)
	var info NodeInfoData
	if err := ParseEntryData(entry, &info, decryptor); err != nil {
		c.logger.DebugContext(ctx, "parsing nodeInfo entry", slog.Any("error", err))
		return
	}

	// Attach to parent node by matching parentId to a node's recordID.
	parentID := meta.ParentID
	for _, node := range c.nodes {
		if node.RecordID != "" && node.RecordID == parentID {
			node.Info = &info
			break
		}
	}
}

// loadEndpointEntry parses an endpoint entry and attaches it to the parent node.
// Caller must hold c.mu.
func (c *DWNClient) loadEndpointEntry(ctx context.Context, entry json.RawMessage, decryptor EntryDecryptor) {
	meta := extractEntryMetadata(entry)
	var ep EndpointData
	if err := ParseEntryData(entry, &ep, decryptor); err != nil {
		c.logger.DebugContext(ctx, "parsing endpoint entry", slog.Any("error", err))
		return
	}

	// Attach to parent node by matching parentId to a node's recordID.
	parentID := meta.ParentID
	for _, node := range c.nodes {
		if node.RecordID != "" && node.RecordID == parentID {
			node.Endpoints = append(node.Endpoints, ep)
			break
		}
	}
}

// ACLPolicy returns the loaded ACL policy, or nil if none is configured.
func (c *DWNClient) ACLPolicy() *ACLPolicyData {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.acl
}

// Members returns the loaded member records, keyed by member DID.
func (c *DWNClient) Members() map[string]*MemberRecord {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.members
}

// Nodes returns the loaded node records, keyed by node DID.
func (c *DWNClient) Nodes() map[string]*NodeRecord {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.nodes
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

	// Keep response ordering deterministic for logs, status output, and tests.
	// Node IDs themselves are derived from each DID below; assigning IDs from
	// this sorted position would renumber existing WireGuard keys whenever a
	// peer joins or leaves, which magicsock explicitly rejects.
	dids := make([]string, 0, len(c.nodes))
	for did := range c.nodes {
		dids = append(dids, did)
	}
	sort.Strings(dids)

	now := time.Now().UTC()
	for _, did := range dids {
		rec := c.nodes[did]
		if nodeRecordExpired(rec, now) {
			if did == c.selfDID {
				c.logger.Debug("self node membership is expired",
					slog.String("did", did),
					slog.String("expiresAt", rec.ExpiresAt),
				)
				return nil
			}
			c.logger.Debug("skipping expired peer in network map",
				slog.String("did", did),
				slog.String("expiresAt", rec.ExpiresAt),
			)
			continue
		}
		nodeID, stableID := nodeIdentityForDID(c.networkRecordID, did)
		node := nodeRecordToNode(nodeID, did, rec)
		node.StableID = stableID
		c.applyFallbackMeshIP(node)

		// Skip peers whose mesh IP cannot be read or derived. These
		// "ghost" nodes are still tracked in c.nodes for auto key delivery
		// purposes, but should not be injected into the network map. A peer
		// reaching here typically failed to decrypt (issue #187), so surface
		// it at Warn and count it rather than swallowing at Debug.
		if did != c.selfDID && !node.MeshIP.IsValid() {
			c.droppedPeers.Add(1)
			c.logger.Warn("dropping peer from network map: no mesh IP (record likely undecryptable — missing role-audience key)",
				slog.String("did", did),
			)
			continue
		}

		if did == c.selfDID {
			resp.Node = node
		} else {
			resp.Peers = append(resp.Peers, node)
		}
	}

	if resp.Node == nil {
		// Self DID not found in nodes map. This can happen if our node
		// record hasn't been written yet or was removed by the anchor.
		return nil
	}

	if c.acl != nil {
		resp.PacketFilter = c.buildFilterRules()
	} else {
		resp.PacketFilter = defaultFilterRules()
	}

	return resp
}

// nodeIdentityForDID returns meshnet identifiers that remain stable as the
// membership set changes. The versioned input includes the immutable network
// record ID so independent control planes have separate identity domains.
// The NodeID is constrained to the positive 53-bit integer range so it remains
// exactly representable anywhere it crosses a JSON/JavaScript boundary.
// StableID uses a longer digest for diagnostics and identity lookups. A zero
// truncated NodeID is reserved by meshnet, so map it to 1.
func nodeIdentityForDID(networkRecordID, did string) (int64, string) {
	digest := sha256.Sum256([]byte("meshd node identity v1\x00" + networkRecordID + "\x00" + did))
	const maxExactInteger = uint64(1<<53) - 1
	id := int64(binary.BigEndian.Uint64(digest[:8]) & maxExactInteger)
	if id == 0 {
		id = 1
	}
	return id, "dwn-" + hex.EncodeToString(digest[:16])
}

func nodeRecordExpired(rec *NodeRecord, now time.Time) bool {
	if rec == nil || rec.ExpiresAt == "" {
		return false
	}
	expiresAt, err := time.Parse(time.RFC3339, rec.ExpiresAt)
	if err != nil {
		return false
	}
	return now.After(expiresAt)
}

func (c *DWNClient) applyFallbackMeshIP(node *Node) {
	if node == nil || node.MeshIP.IsValid() || c.network == nil || c.network.MeshCIDR == "" {
		return
	}
	ip, err := meshaddr.AllocateMeshIP(c.network.MeshCIDR, node.DID)
	if err != nil {
		c.logger.Debug("fallback mesh IP allocation failed",
			slog.String("did", node.DID),
			slog.String("cidr", c.network.MeshCIDR),
			slog.Any("error", err),
		)
		return
	}
	node.MeshIP = ip
	if len(node.AllowedIPs) == 0 {
		node.AllowedIPs = []netip.Prefix{netip.PrefixFrom(ip, ip.BitLen())}
	}
	c.logger.Debug("using deterministic fallback mesh IP",
		slog.String("did", node.DID),
		slog.String("ip", ip.String()),
	)
}

func nodeRecordToNode(id int64, did string, rec *NodeRecord) *Node {
	return nodeRecordToNodeWithThreshold(id, did, rec, DefaultPeerStaleThreshold, time.Now())
}

// nodeRecordToNodeWithThreshold converts a NodeRecord to a Node, using the
// given staleness threshold and reference time. The reference time is passed
// as a parameter (instead of calling time.Now()) to make the function
// deterministically testable.
//
// The WireGuard public key is derived from the node's did:jwk identity
// (Ed25519 → X25519 birational map). If derivation fails (e.g., non-jwk DID),
// the Key field is left empty and logged.
func nodeRecordToNodeWithThreshold(id int64, nodeDID string, rec *NodeRecord, staleThreshold time.Duration, now time.Time) *Node {
	node := &Node{
		ID:             id,
		DID:            nodeDID,
		MemberDID:      rec.EffectiveOwnerDID(),
		MemberRecordID: rec.MemberRecordID,
		ExpiresAt:      rec.ExpiresAt,
		Label:          rec.Label,
	}

	// Populate operational fields from the nodeInfo child record if available.
	if rec.Info != nil {
		node.Name = rec.Info.Hostname
		node.OS = rec.Info.OS
		node.Capabilities = rec.Info.Capabilities
	}

	// Fall back to node label if no hostname from nodeInfo.
	if node.Name == "" && rec.Label != "" {
		node.Name = rec.Label
	}

	// Derive WireGuard public key from did:jwk.
	if x25519Pub, err := didjwk.DeriveX25519PublicKey(nodeDID); err == nil {
		node.Key = base64.StdEncoding.EncodeToString(x25519Pub)
	}

	if ip, err := netip.ParseAddr(rec.MeshIP); err == nil {
		node.MeshIP = ip
		node.AllowedIPs = []netip.Prefix{netip.PrefixFrom(ip, ip.BitLen())}
	}

	for _, cidr := range rec.AllowedIPs {
		if prefix, err := netip.ParsePrefix(cidr); err == nil {
			node.AllowedIPs = append(node.AllowedIPs, prefix)
		}
	}

	// Track the most recent endpoint update time to determine online status.
	var lastSeen time.Time

	for _, ep := range rec.Endpoints {
		for _, pub := range ep.PublicEndpoints {
			node.Endpoints = append(node.Endpoints, fmt.Sprintf("%s:%d", pub.Address, pub.Port))
		}
		node.Endpoints = append(node.Endpoints, ep.LocalEndpoints...)
		if ep.PreferredDERP != 0 {
			node.PreferredDERP = ep.PreferredDERP
		}
		// Endpoint records may carry a disco key. Use the latest non-empty one.
		if ep.DiscoKey != "" {
			node.DiscoKey = ep.DiscoKey
		}
		// Track the most recent endpoint update.
		if ep.UpdatedAt != "" {
			if t, err := time.Parse(time.RFC3339, ep.UpdatedAt); err == nil {
				if t.After(lastSeen) {
					lastSeen = t
				}
			}
		}
	}

	node.LastSeen = lastSeen

	// Determine online status from the most recent endpoint update.
	// A peer is online if it has endpoint data updated within the
	// staleness threshold. Peers with no endpoint data are considered
	// offline (they registered but never started the engine).
	if !lastSeen.IsZero() && now.Sub(lastSeen) <= staleThreshold {
		node.Online = true
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

	// Build DID → mesh IP lookup from the current node map.
	didToIP := make(map[string]string, len(c.nodes))
	for did, node := range c.nodes {
		ip := node.MeshIP
		if ip == "" && c.network != nil && c.network.MeshCIDR != "" {
			if fallbackIP, err := meshaddr.AllocateMeshIP(c.network.MeshCIDR, did); err == nil {
				ip = fallbackIP.String()
			}
		}
		if ip != "" {
			didToIP[did] = ip
		}
	}

	var rules []FilterRule
	for _, r := range c.acl.Rules {
		if r.Action != "accept" {
			continue
		}

		// Resolve source matchers to IPs.
		srcIPs := c.resolveMatchers(r.Src, didToIP)
		if len(srcIPs) == 0 {
			continue
		}

		// Resolve destination matchers to IPs.
		dstIPs := c.resolveMatchers(r.Dst, didToIP)
		if len(dstIPs) == 0 {
			continue
		}

		// Parse destination port ranges. If none specified, allow all ports.
		dstPorts := parsePortRanges(r.DstPorts)
		if len(dstPorts) == 0 {
			dstPorts = []PortRange{{First: 0, Last: 65535}}
		}

		// Map protocol string to IP protocol numbers.
		ipProto := protoToIPProto(r.Proto)

		// Build filter rule: each dst IP × each port range.
		rule := FilterRule{
			SrcIPs:  srcIPs,
			IPProto: ipProto,
		}
		for _, ip := range dstIPs {
			for _, pr := range dstPorts {
				rule.DstPorts = append(rule.DstPorts, NetPortRange{
					IP:    ip,
					Ports: pr,
				})
			}
		}
		rules = append(rules, rule)
	}

	// If no accept rules were produced but defaultAction is "accept",
	// fall through to allow-all.
	if len(rules) == 0 && c.acl.DefaultAction == "accept" {
		return defaultFilterRules()
	}

	return rules
}

// protoToIPProto maps an ACL rule's proto string to IP protocol numbers.
// Returns nil for empty or "*" (meaning all protocols — TCP, UDP, ICMP).
//
// IANA protocol numbers: ICMPv4=1, TCP=6, UDP=17, ICMPv6=58.
func protoToIPProto(proto string) []int {
	switch proto {
	case "tcp":
		return []int{6} // TCP
	case "udp":
		return []int{17} // UDP
	case "icmp":
		return []int{1, 58} // ICMPv4 + ICMPv6
	default:
		// Empty or "*": nil means all protocols (meshnet default).
		return nil
	}
}

// resolveMatchers expands ACL source/destination matchers into IP strings
// that the packet filter engine understands. Supported matchers:
//   - "*"          → "*" (wildcard)
//   - "group:name" → expanded to node DIDs, then resolved to mesh IPs
//   - "did:..."    → resolved to mesh IP
//   - "10.x.y.z"  → passed through as-is (direct IP)
//   - "10.x.y.z/n"→ passed through as-is (CIDR)
func (c *DWNClient) resolveMatchers(matchers []string, didToIP map[string]string) []string {
	var result []string
	for _, m := range matchers {
		switch {
		case m == "*":
			return []string{"*"}
		case len(m) > 6 && m[:6] == "group:":
			groupName := m[6:]
			if c.acl != nil && c.acl.Groups != nil {
				for _, did := range c.acl.Groups[groupName] {
					if ip, ok := didToIP[did]; ok {
						result = append(result, ip)
					}
				}
			}
		case len(m) > 4 && m[:4] == "did:":
			if ip, ok := didToIP[m]; ok {
				result = append(result, ip)
			}
		default:
			// Assume IP or CIDR — pass through.
			result = append(result, m)
		}
	}
	return result
}

// parsePortRanges parses port range strings like "22", "80", "8000-9000"
// into PortRange structs. Invalid entries are silently skipped.
func parsePortRanges(ports []string) []PortRange {
	var result []PortRange
	for _, p := range ports {
		pr, ok := parsePortRange(p)
		if ok {
			result = append(result, pr)
		}
	}
	return result
}

// parsePortRange parses a single port or port range string.
// Returns the parsed range and true, or zero value and false on error.
func parsePortRange(s string) (PortRange, bool) {
	// Try "first-last" format.
	for i := 0; i < len(s); i++ {
		if s[i] == '-' {
			first, ok1 := parsePort(s[:i])
			last, ok2 := parsePort(s[i+1:])
			if ok1 && ok2 && first <= last {
				return PortRange{First: first, Last: last}, true
			}
			return PortRange{}, false
		}
	}
	// Single port.
	port, ok := parsePort(s)
	if ok {
		return PortRange{First: port, Last: port}, true
	}
	return PortRange{}, false
}

// parsePort parses a decimal port number string (0-65535).
func parsePort(s string) (uint16, bool) {
	if len(s) == 0 || len(s) > 5 {
		return 0, false
	}
	var n uint32
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + uint32(c-'0')
	}
	if n > 65535 {
		return 0, false
	}
	return uint16(n), true
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
	RecordID  string `json:"recordId"`
	ParentID  string `json:"parentId"`
	Recipient string `json:"recipient"`
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
				ParentID  string `json:"parentId"`
				Recipient string `json:"recipient"`
			} `json:"descriptor"`
		} `json:"recordsWrite"`
	}
	if err := json.Unmarshal(entry, &wrapped); err == nil {
		meta.RecordID = wrapped.RecordsWrite.RecordID
		meta.ParentID = wrapped.RecordsWrite.Descriptor.ParentID
		meta.Recipient = wrapped.RecordsWrite.Descriptor.Recipient
		if meta.RecordID != "" || meta.Recipient != "" {
			return meta
		}
	}

	// Try flat format: {"recordId": "...", "descriptor": {...}}
	var flat struct {
		RecordID   string `json:"recordId"`
		Descriptor struct {
			ParentID  string `json:"parentId"`
			Recipient string `json:"recipient"`
		} `json:"descriptor"`
	}
	if err := json.Unmarshal(entry, &flat); err == nil {
		meta.RecordID = flat.RecordID
		meta.ParentID = flat.Descriptor.ParentID
		meta.Recipient = flat.Descriptor.Recipient
	}

	return meta
}

// ParseEntryData extracts the data from a DWN read response entry.
// If the entry contains encryption metadata and a decryptor is provided,
// the data is decrypted before unmarshaling.
func ParseEntryData(entry json.RawMessage, dst any, decryptor EntryDecryptor) error {
	if entry == nil {
		return ErrNoEntry
	}

	// First try wrapped entry (RecordsRead response format).
	var wrapped struct {
		RecordsWrite struct {
			EncodedData string                `json:"encodedData"`
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
		EncodedData string                `json:"encodedData"`
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

// EntryDecryptor is a function that decrypts ciphertext using the JWE metadata.
type EntryDecryptor func(ciphertext []byte, enc *dwncrypto.Encryption) ([]byte, error)

// makeDecryptor creates an encryption-v1 decryptor for records read at the
// given protocolPath. Returns nil if no key material is available.
//
// Decryption chain (first applicable wins):
//  1. Network owner: derive the protocolPath leaf key from the encryption
//     root and unwrap the record's protocolPath keyEncryption entry.
//  2. Delegate grant keys: a delivered grant-key subtree covering the path
//     decrypts the protocolPath entry directly.
//  3. Role audience: recover the audience private key — by unsealing the
//     `$encryption/audience` record (owner or grant-key seal coverage), or
//     from a `$encryption/delivery` record addressed to this node — and
//     unwrap the record's roleAudience entry.
//  4. Fallback: protocolPath via this node's own root (records the reader
//     authored on paths keyed to its own definition).
func (c *DWNClient) makeDecryptor(ctx context.Context, protocolPath string) EntryDecryptor {
	if c.encManager == nil && c.grantKeys.Empty() && c.audienceSource == nil {
		return nil
	}

	return func(ciphertext []byte, enc *dwncrypto.Encryption) ([]byte, error) {
		if c.isNetworkOwner() && c.encManager != nil {
			return c.decryptWithProtocolPath(ciphertext, enc, protocolPath)
		}
		if dec := c.grantKeys.DecrypterFor(protocols.MeshProtocolURI, protocolPath); dec != nil {
			plaintext, err := dec.Decrypt(ciphertext, enc, protocols.MeshProtocolURI, protocolPath)
			if err == nil {
				return plaintext, nil
			}
			c.logger.Debug("grant-key decrypt failed, trying role audience",
				slog.String("path", protocolPath), slog.Any("error", err))
		}
		var roleAudienceErr error
		if infos := dwncrypto.RoleAudienceEntryInfos(enc); len(infos) > 0 {
			plaintext, err := c.decryptRoleAudience(ctx, ciphertext, enc, infos)
			if err == nil {
				return plaintext, nil
			}
			roleAudienceErr = err
			c.logger.Debug("role-audience decrypt failed",
				slog.String("path", protocolPath), slog.Any("error", err))
			if c.encManager == nil {
				return nil, err
			}
		}
		if c.encManager == nil {
			return nil, fmt.Errorf("no key material decrypts record at %s", protocolPath)
		}
		// protocolPath fallback: only succeeds for records this reader authored and
		// can re-derive. For an owner-authored roleAudience record a non-owner derives
		// the wrong KEK and fails with a misleading "AES Key Unwrap integrity check
		// failed" — so when the record carried roleAudience entries, surface that real
		// (missing role-audience key) failure instead of masking it with the fallback.
		plaintext, err := c.decryptWithProtocolPath(ciphertext, enc, protocolPath)
		if err != nil && roleAudienceErr != nil {
			return nil, roleAudienceErr
		}
		return plaintext, err
	}
}

// isNetworkOwner reports whether this client reads as the network author, who
// can derive every protocolPath key from its encryption root.
func (c *DWNClient) isNetworkOwner() bool {
	return c.selfDID == "" || c.selfDID == c.anchorTenant
}

// decryptWithProtocolPath decrypts using the protocolPath derivation scheme.
func (c *DWNClient) decryptWithProtocolPath(ciphertext []byte, enc *dwncrypto.Encryption, protocolPath string) ([]byte, error) {
	privKey, err := c.encManager.DeriveDecryptionKey(protocolPath)
	if err != nil {
		return nil, fmt.Errorf("deriving decryption key for %s: %w", protocolPath, err)
	}
	defer clear(privKey)
	return dwncrypto.DecryptData(ciphertext, enc, privKey)
}

// decryptRoleAudience decrypts a role-readable record via the roleAudience
// scheme. A record carries one roleAudience entry per reading role; entries
// matching this reader's own role are tried first. Per entry, the audience
// PRIVATE key for (protocol, rolePath, keyId) is recovered two ways:
//
//  1. Seal: the `$encryption/audience` record's sealedPrivateKey, unsealed
//     with a role-path seal key this reader can derive (owner root or a
//     covering grant-key subtree) via the audience source.
//  2. Delivery: a `$encryption/delivery` record addressed to this node,
//     decrypted with this node's own role-path key.
func (c *DWNClient) decryptRoleAudience(ctx context.Context, ciphertext []byte, enc *dwncrypto.Encryption, infos []*dwncrypto.RoleAudienceInfo) ([]byte, error) {
	// Prefer the entry for this reader's own role: seal/delivery lookups for
	// other roles' tuples cannot succeed for a pure role holder.
	if c.protocolRole != "" {
		preferred := make([]*dwncrypto.RoleAudienceInfo, 0, len(infos))
		var rest []*dwncrypto.RoleAudienceInfo
		for _, info := range infos {
			if info.RolePath == c.protocolRole {
				preferred = append(preferred, info)
			} else {
				rest = append(rest, info)
			}
		}
		infos = append(preferred, rest...)
	}

	var errs []error
	for _, info := range infos {
		if c.audienceSource != nil {
			audiencePriv, err := c.audienceSource.AudiencePrivateKeyByKeyID(ctx, info.Protocol, info.RolePath, info.KeyID)
			if err == nil {
				dec, err := dwncrypto.NewRoleAudienceDecrypter(audiencePriv)
				clear(audiencePriv)
				if err != nil {
					return nil, err
				}
				plaintext, err := dec.Decrypt(ciphertext, enc)
				dec.Close()
				if err == nil {
					return plaintext, nil
				}
				errs = append(errs, fmt.Errorf("%s seal decrypt: %w", info.RolePath, err))
			} else {
				errs = append(errs, fmt.Errorf("%s seal: %w", info.RolePath, err))
			}
		}

		plaintext, err := c.decryptViaDelivery(ctx, ciphertext, enc, info)
		if err == nil {
			return plaintext, nil
		}
		errs = append(errs, fmt.Errorf("%s delivery: %w", info.RolePath, err))
	}
	return nil, fmt.Errorf("role audience key unavailable: %w", errors.Join(errs...))
}

// decryptViaDelivery recovers the audience key from a `$encryption/delivery`
// record addressed to this node and unwraps the record's roleAudience entry.
// The delivery record is encrypted to this node's OWN role-path key, derived
// from its encryption root.
func (c *DWNClient) decryptViaDelivery(ctx context.Context, ciphertext []byte, enc *dwncrypto.Encryption, info *dwncrypto.RoleAudienceInfo) ([]byte, error) {
	if c.encManager == nil {
		return nil, fmt.Errorf("no encryption root available for delivery records")
	}
	reply, err := c.anchorDWN.RecordsQueryWithAuth(ctx, c.anchorTenant, dwn.RecordsFilter{
		Protocol:     info.Protocol,
		ProtocolPath: dwncrypto.EncryptionControlDeliveryPath,
		Recipient:    c.selfDID,
		Tags: map[string]any{
			"protocol": info.Protocol,
			"rolePath": info.RolePath,
			"keyId":    info.KeyID,
		},
	}, "createdDescending", nil, dwn.MessageAuth{}) // recipient-readable, plain query
	if err != nil {
		return nil, fmt.Errorf("querying delivery records: %w", err)
	}
	entries, err := dwn.QueryEntries(reply)
	if err != nil {
		return nil, fmt.Errorf("parsing delivery query: %w", err)
	}
	for _, entry := range entries {
		deliveryEnc, deliveryData, ok := entryEncryptionAndData(entry)
		if !ok || deliveryEnc == nil {
			continue
		}
		payload, err := dwncrypto.DecryptDeliveryRecord(c.encManager.RootPrivateKey, info.Protocol, info.RolePath, deliveryEnc, deliveryData)
		if err != nil {
			c.logger.Debug("delivery record decrypt failed", slog.Any("error", err))
			continue
		}
		if payload.KeyID != info.KeyID {
			continue
		}
		audiencePriv, err := base64.RawURLEncoding.DecodeString(payload.KeyMaterial.PrivateKeyJwk.D)
		if err != nil {
			continue
		}
		dec, err := dwncrypto.NewRoleAudienceDecrypter(audiencePriv)
		clear(audiencePriv)
		if err != nil {
			continue
		}
		plaintext, err := dec.Decrypt(ciphertext, enc)
		dec.Close()
		if err == nil {
			return plaintext, nil
		}
	}
	return nil, fmt.Errorf("no delivery record for keyId %s at %s", info.KeyID, info.RolePath)
}

// entryEncryptionAndData extracts the encryption envelope and decoded data
// from a query entry (wrapped or flat form).
func entryEncryptionAndData(entry json.RawMessage) (*dwncrypto.Encryption, []byte, bool) {
	type record struct {
		EncodedData string                `json:"encodedData"`
		Encryption  *dwncrypto.Encryption `json:"encryption"`
	}

	rec := record{}
	var wrapped struct {
		RecordsWrite record `json:"recordsWrite"`
	}
	if err := json.Unmarshal(entry, &wrapped); err == nil &&
		(wrapped.RecordsWrite.EncodedData != "" || wrapped.RecordsWrite.Encryption != nil) {
		rec = wrapped.RecordsWrite
	} else if err := json.Unmarshal(entry, &rec); err != nil {
		return nil, nil, false
	}

	if rec.EncodedData == "" {
		return nil, nil, false
	}
	data, err := base64.RawURLEncoding.DecodeString(rec.EncodedData)
	if err != nil {
		return nil, nil, false
	}
	return rec.Encryption, data, true
}
