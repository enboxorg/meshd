package control

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"sort"
	"strings"
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
	ErrNoNetwork              = errors.New("network record not found")
	ErrNoEntry                = errors.New("no data found in entry")
	errRawCaptureReadNotFound = errors.New("RecordsRead entry not found")
)

func shouldAbortStateLoad(ctx context.Context, err error) bool {
	return ctx.Err() != nil ||
		errors.Is(err, dwn.ErrRateLimited) ||
		errors.Is(err, dwn.ErrTransport) ||
		errors.Is(err, context.Canceled) ||
		errors.Is(err, context.DeadlineExceeded)
}

func endpointFailureClass(err error) string {
	switch {
	case errors.Is(err, dwn.ErrRateLimited):
		return "rate-limit"
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return "context"
	case errors.Is(err, dwn.ErrTransport):
		return "transport"
	case errors.Is(err, errAudienceKeyDeliveryAbsent):
		return "key-unavailable"
	}
	message := strings.ToLower(err.Error())
	if strings.Contains(message, "no delivery record") ||
		strings.Contains(message, "role audience key unavailable") ||
		strings.Contains(message, "no key material") {
		return "key-unavailable"
	}
	return "parse"
}

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

	// deliveredAudienceKeys caches successfully unwrapped delivery keys and
	// coalesces concurrent lookups. It has its own lock because record parsing
	// can run while c.mu is held.
	deliveredAudienceKeys audienceKeyCache
	// roleAudienceKeys memoizes the combined seal-or-delivery resolution per
	// tuple, preventing one absent audience query per encrypted record.
	roleAudienceKeys audienceKeyCache

	// loadMu serializes complete state refreshes and blocks snapshot readers
	// until a refresh either commits or rolls back.
	loadMu sync.Mutex

	// deltaMu protects the last-good raw snapshot and staged topology events.
	deltaMu              sync.Mutex
	rawBaseline          *rawMeshRecordSet
	pendingTopology      []pendingTopologyEvent
	pendingTopologyBytes int
	topologySequence     uint64
	repairSequence       uint64
	fullReconciliation   bool
	mu                   sync.RWMutex
	rawParsedGeneration  uint64
	rawParsedOutcomes    map[rawParsedOutcomeKey]rawParsedOutcome

	network *NetworkConfig
	members map[string]*MemberRecord
	nodes   map[string]*NodeRecord
	relays  []*RelayData
	acl     *ACLPolicyData

	// peerEndpoints caches resolved DID → DWN endpoint mappings.
	peerEndpoints map[string]*PeerEndpointInfo

	// undecryptablePeers counts distinct node failure episodes/classes.
	// nodeFailures suppresses repeated projection warnings for unchanged opaque
	// records until the record recovers or the failure class changes. The map is
	// protected by mu because node parsing already runs under that lock.
	undecryptablePeers atomic.Int64
	nodeFailures       map[string]string

	// unreadableEndpoints counts endpoint records that could not be parsed or
	// decrypted. endpointFailures suppresses repeated warnings until recovery;
	// both are protected independently (atomic and c.mu, respectively).
	unreadableEndpoints atomic.Int64
	endpointFailures    map[string]string

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
		anchorDWN:        dwn.NewClient(anchorEndpoint, signer),
		anchorTenant:     anchorTenant,
		networkRecordID:  networkRecordID,
		selfDID:          selfDID,
		signer:           signer,
		logger:           options.logger,
		resolver:         options.resolver,
		encManager:       options.encManager,
		protocolRole:     protocolRole,
		grantID:          options.grantID,
		delegatedGrant:   options.delegatedGrant,
		grantKeys:        options.grantKeys,
		audienceSource:   options.audienceSource,
		members:          make(map[string]*MemberRecord),
		nodes:            make(map[string]*NodeRecord),
		peerEndpoints:    make(map[string]*PeerEndpointInfo),
		nodeFailures:     make(map[string]string),
		endpointFailures: make(map[string]string),
	}
}

// UndecryptablePeerCount returns the number of distinct node failure episodes
// or failure-class transitions since this client was created. A non-zero,
// growing value means records remain unreadable or are failing in new ways.
func (c *DWNClient) UndecryptablePeerCount() int64 {
	return c.undecryptablePeers.Load()
}

// UnreadableEndpointCount returns the cumulative number of endpoint records
// that could not be parsed or decrypted. A growing value can explain peers
// that are listed but have no usable direct or relay path.
func (c *DWNClient) UnreadableEndpointCount() int64 {
	return c.unreadableEndpoints.Load()
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

type dwnClientStateSnapshot struct {
	network *NetworkConfig
	members map[string]*MemberRecord
	nodes   map[string]*NodeRecord
	relays  []*RelayData
	acl     *ACLPolicyData
}

func cloneRecordMap[T any](source map[string]*T) map[string]*T {
	if source == nil {
		return nil
	}
	clone := make(map[string]*T, len(source))
	for key, value := range source {
		clone[key] = value
	}
	return clone
}

func (c *DWNClient) stateSnapshot() dwnClientStateSnapshot {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return dwnClientStateSnapshot{
		network: c.network,
		members: cloneRecordMap(c.members),
		nodes:   cloneRecordMap(c.nodes),
		relays:  append([]*RelayData(nil), c.relays...),
		acl:     c.acl,
	}
}

func (c *DWNClient) restoreState(snapshot dwnClientStateSnapshot) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.network = snapshot.network
	c.members = snapshot.members
	c.nodes = snapshot.nodes
	c.relays = snapshot.relays
	c.acl = snapshot.acl
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
	return c.LoadStateValidated(ctx, nil)
}

// LoadStateValidated reads a complete remote snapshot and validates its
// projected response before making the parsed state, raw baseline, or covered
// topology-event prefix durable. The validator runs while loadMu is held and
// must not call methods that acquire loadMu.
func (c *DWNClient) LoadStateValidated(ctx context.Context, validate PendingStateValidator) (*MapResponse, error) {
	if ctx == nil {
		return nil, fmt.Errorf("loading full state: nil context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	c.loadMu.Lock()
	defer c.loadMu.Unlock()
	c.invalidateRawParsedOutcomes()
	c.deliveredAudienceKeys.invalidateFailures()
	c.roleAudienceKeys.invalidateFailures()

	through := c.beginFullReconciliation()
	budget := &fullStateFetchBudget{}
	role := c.protocolRole
	fetchStarted := time.Now()
	loadCommitted := false
	logger := c.logger
	if logger == nil {
		logger = slog.Default()
	}
	defer func() {
		requests, records, retainedBytes := budget.snapshot()
		logger.DebugContext(ctx, "full state reconciliation finished",
			slog.Bool("committed", loadCommitted),
			slog.Int("requests", requests),
			slog.Int("records", records),
			slog.Int("retainedBytes", retainedBytes),
			slog.Duration("duration", time.Since(fetchStarted)),
		)
	}()
	if err := budget.takeRequest(); err != nil {
		return nil, err
	}
	networkResult, err := c.anchorDWN.RecordsReadWithAuth(ctx, c.anchorTenant, dwn.RecordsFilter{
		RecordID: c.networkRecordID,
	}, c.readAuth(role))
	if err != nil {
		return nil, fmt.Errorf("reading network: %w", err)
	}
	if networkResult != nil && networkResult.Reply != nil && networkResult.Reply.Status.Code == http.StatusNotFound {
		return nil, fmt.Errorf("%w: %d %s", ErrNoNetwork, networkResult.Reply.Status.Code, networkResult.Reply.Status.Detail)
	}
	if statusErr := rawCaptureReadStatusError(networkResult); statusErr != nil {
		if errors.Is(statusErr, dwn.ErrRateLimited) {
			return nil, fmt.Errorf("reading network: %w", statusErr)
		}
		return nil, fmt.Errorf("reading network: %w", errors.Join(dwn.ErrTransport, statusErr))
	}
	networkEntry, err := rawMeshRecordReadEntry(networkResult)
	if err != nil {
		return nil, fmt.Errorf("reading network entry: %w", err)
	}
	if err := budget.retain([]json.RawMessage{networkEntry}, nil); err != nil {
		return nil, fmt.Errorf("retaining network entry: %w", err)
	}
	candidate, err := newRawMeshRecordSet([]json.RawMessage{networkEntry}, "network")
	if err != nil {
		return nil, fmt.Errorf("normalizing network entry: %w", err)
	}

	queryPath := func(protocolPath, contextID, dateSort string) error {
		entries, err := c.queryAllRawMeshRecords(ctx, dwn.RecordsFilter{
			Protocol:     protocols.MeshProtocolURI,
			ProtocolPath: protocolPath,
			ContextID:    contextID,
		}, dateSort, role, budget)
		if err != nil {
			return fmt.Errorf("querying %s under %s: %w", protocolPath, contextID, err)
		}
		if _, err := candidate.addEntries(entries, protocolPath); err != nil {
			return fmt.Errorf("normalizing %s under %s: %w", protocolPath, contextID, err)
		}
		return nil
	}
	queryGroup := func(specs []fullStateQuerySpec) error {
		batches, err := c.queryRawMeshRecordGroup(ctx, specs, role, budget)
		if err != nil {
			return err
		}
		for i, entries := range batches {
			spec := specs[i]
			if _, err := candidate.addEntries(entries, spec.protocolPath); err != nil {
				return fmt.Errorf("normalizing %s under %s: %w", spec.protocolPath, spec.contextID, err)
			}
		}
		return nil
	}

	if err := queryPath("network/node", c.networkRecordID, "createdAscending"); err != nil {
		return nil, err
	}
	if err := queryPath("network/member", c.networkRecordID, "createdAscending"); err != nil {
		return nil, err
	}
	memberContexts := fullStateMemberContexts(candidate, c.networkRecordID)
	memberQueries := make([]fullStateQuerySpec, len(memberContexts))
	for i, memberContext := range memberContexts {
		memberQueries[i] = fullStateQuerySpec{
			protocolPath: "network/member/node", contextID: memberContext, dateSort: "createdAscending",
		}
	}
	if err := queryGroup(memberQueries); err != nil {
		return nil, err
	}
	if err := queryPath("network/relay", c.networkRecordID, "createdAscending"); err != nil {
		return nil, err
	}
	if err := queryPath("network/aclPolicy", c.networkRecordID, "createdDescending"); err != nil {
		return nil, err
	}
	nodeContexts := fullStateNodeContexts(candidate, c.networkRecordID)
	nodeQueries := make([]fullStateQuerySpec, 0, 2*len(nodeContexts))
	for _, node := range nodeContexts {
		nodeQueries = append(nodeQueries,
			fullStateQuerySpec{protocolPath: node.infoPath, contextID: node.contextID, dateSort: "createdDescending"},
			fullStateQuerySpec{protocolPath: node.endpointPath, contextID: node.contextID, dateSort: "createdDescending"},
		)
	}
	if err := queryGroup(nodeQueries); err != nil {
		return nil, err
	}

	projection, err := c.projectRawMeshRecordSetWithDecryptors(ctx, candidate, c.makeDecryptor)
	if err != nil {
		return nil, fmt.Errorf("projecting full state: %w", err)
	}
	if validate != nil {
		if err := validate(projection.response); err != nil {
			return projection.response, err
		}
	}
	if err := c.completeFullReconciliation(ctx, candidate, projection, through); err != nil {
		return projection.response, err
	}
	loadCommitted = true
	return projection.response, nil
}

const (
	fullStateQueryPageSize = 256
	fullStateQueryWorkers  = 8
	fullStateMaxQueryPages = 64
	fullStateMaxRecords    = 10_000
	fullStateMaxBytes      = 64 << 20
	fullStateMaxRequests   = 25_000
)

type fullStateFetchBudget struct {
	mu       sync.Mutex
	requests int
	records  int
	bytes    int
}

func (b *fullStateFetchBudget) takeRequest() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.requests >= fullStateMaxRequests {
		return fmt.Errorf("full-state request limit exceeded: %d", fullStateMaxRequests)
	}
	b.requests++
	return nil
}

func (b *fullStateFetchBudget) retain(entries []json.RawMessage, cursor json.RawMessage) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(entries) > fullStateMaxRecords-b.records {
		return fmt.Errorf("full-state record limit exceeded: %d", fullStateMaxRecords)
	}
	retainedBytes := len(cursor)
	for _, entry := range entries {
		if len(entry) > fullStateMaxBytes-retainedBytes {
			return fmt.Errorf("full-state byte limit exceeded: %d", fullStateMaxBytes)
		}
		retainedBytes += len(entry)
	}
	if retainedBytes > fullStateMaxBytes-b.bytes {
		return fmt.Errorf("full-state byte limit exceeded: %d", fullStateMaxBytes)
	}
	b.records += len(entries)
	b.bytes += retainedBytes
	return nil
}

func (b *fullStateFetchBudget) snapshot() (requests, records, retainedBytes int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.requests, b.records, b.bytes
}

func canonicalFullStateCursor(raw json.RawMessage) (json.RawMessage, string, error) {
	if len(raw) == 0 {
		return nil, "", nil
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, raw); err != nil {
		return nil, "", fmt.Errorf("decoding pagination cursor: %w", err)
	}
	canonical := cloneRawJSON(compact.Bytes())
	if bytes.Equal(canonical, []byte("null")) {
		return nil, "", nil
	}
	return canonical, string(canonical), nil
}

func fullStateMemberContexts(set *rawMeshRecordSet, networkRecordID string) []string {
	seen := make(map[string]struct{})
	for _, record := range set.all() {
		if record.protocol != protocols.MeshProtocolURI || record.protocolPath != "network/member" ||
			!rawRecordIsDirectChild(record, networkRecordID) {
			continue
		}
		seen[record.contextID] = struct{}{}
	}
	contexts := make([]string, 0, len(seen))
	for contextID := range seen {
		contexts = append(contexts, contextID)
	}
	sort.Strings(contexts)
	return contexts
}

type fullStateNodeContext struct {
	contextID    string
	infoPath     string
	endpointPath string
}

func fullStateNodeContexts(set *rawMeshRecordSet, networkRecordID string) []fullStateNodeContext {
	memberContexts := make(map[string]struct{})
	for _, contextID := range fullStateMemberContexts(set, networkRecordID) {
		memberContexts[contextID] = struct{}{}
	}
	seen := make(map[string]fullStateNodeContext)
	for _, record := range set.all() {
		if record.protocol != protocols.MeshProtocolURI {
			continue
		}
		var node fullStateNodeContext
		switch record.protocolPath {
		case "network/node":
			if !rawRecordIsDirectChild(record, networkRecordID) {
				continue
			}
			node = fullStateNodeContext{
				contextID: record.contextID, infoPath: "network/node/nodeInfo", endpointPath: "network/node/endpoint",
			}
		case "network/member/node":
			if _, ok := memberContexts[record.parentContextID]; !ok || !rawRecordIsDirectChild(record, record.parentContextID) {
				continue
			}
			node = fullStateNodeContext{
				contextID: record.contextID, infoPath: "network/member/node/nodeInfo", endpointPath: "network/member/node/endpoint",
			}
		default:
			continue
		}
		seen[node.infoPath+"\x00"+node.contextID] = node
	}
	nodes := make([]fullStateNodeContext, 0, len(seen))
	for _, node := range seen {
		nodes = append(nodes, node)
	}
	sort.Slice(nodes, func(i, j int) bool {
		if nodes[i].infoPath != nodes[j].infoPath {
			return nodes[i].infoPath < nodes[j].infoPath
		}
		return nodes[i].contextID < nodes[j].contextID
	})
	return nodes
}

type fullStatePageQuery func(context.Context, *dwn.Pagination) (*dwn.DwnReply, error)

func (c *DWNClient) queryAllRawMeshRecords(
	ctx context.Context,
	filter dwn.RecordsFilter,
	dateSort string,
	role string,
	budget *fullStateFetchBudget,
) ([]json.RawMessage, error) {
	return c.queryAllRawMeshRecordsWith(ctx, filter, role, budget, func(ctx context.Context, pagination *dwn.Pagination) (*dwn.DwnReply, error) {
		return c.anchorDWN.RecordsQueryWithAuth(
			ctx, c.anchorTenant, filter, dateSort, pagination, c.readAuth(role),
		)
	})
}

func (c *DWNClient) queryAllRawMeshRecordsWith(
	ctx context.Context,
	filter dwn.RecordsFilter,
	role string,
	budget *fullStateFetchBudget,
	query fullStatePageQuery,
) ([]json.RawMessage, error) {
	var entries []json.RawMessage
	var cursor json.RawMessage
	seenCursors := make(map[string]struct{})
	for page := 0; page < fullStateMaxQueryPages; page++ {
		if err := budget.takeRequest(); err != nil {
			return nil, err
		}
		reply, err := query(ctx, &dwn.Pagination{Limit: fullStateQueryPageSize, Cursor: cloneRawJSON(cursor)})
		if err != nil {
			return nil, fmt.Errorf("requesting page %d: %w", page+1, err)
		}
		pageEntries, err := dwn.QueryEntries(reply)
		if err != nil {
			if errors.Is(err, dwn.ErrRateLimited) {
				return nil, fmt.Errorf("reading page %d: %w", page+1, err)
			}
			if reply == nil || reply.Status.Code != http.StatusOK {
				err = errors.Join(dwn.ErrTransport, err)
			}
			return nil, fmt.Errorf("reading page %d: %w", page+1, err)
		}
		hydrated, err := c.hydrateRawCaptureEntries(ctx, pageEntries, filter.ProtocolPath, filter.ContextID, role, budget)
		if err != nil {
			return nil, fmt.Errorf("hydrating page %d: %w", page+1, err)
		}
		nextCursor, cursorKey, err := canonicalFullStateCursor(reply.Cursor)
		if err != nil {
			return nil, fmt.Errorf("page %d: %w", page+1, err)
		}
		if err := budget.retain(hydrated, nextCursor); err != nil {
			return nil, fmt.Errorf("page %d: %w", page+1, err)
		}
		entries = append(entries, hydrated...)
		if cursorKey == "" {
			return entries, nil
		}
		if _, duplicate := seenCursors[cursorKey]; duplicate {
			return nil, fmt.Errorf("page %d repeated pagination cursor", page+1)
		}
		seenCursors[cursorKey] = struct{}{}
		cursor = nextCursor
	}
	return nil, fmt.Errorf("query page limit exceeded: %d", fullStateMaxQueryPages)
}

type fullStateQuerySpec struct {
	protocolPath string
	contextID    string
	dateSort     string
}

func (c *DWNClient) queryRawMeshRecordGroup(
	ctx context.Context,
	specs []fullStateQuerySpec,
	role string,
	budget *fullStateFetchBudget,
) ([][]json.RawMessage, error) {
	if len(specs) == 0 {
		return nil, nil
	}
	groupCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make([][]json.RawMessage, len(specs))
	jobs := make(chan int, len(specs))
	for i := range specs {
		jobs <- i
	}
	close(jobs)

	workerCount := min(fullStateQueryWorkers, len(specs))
	var workers sync.WaitGroup
	var firstErr error
	var errorOnce sync.Once
	for range workerCount {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for index := range jobs {
				if groupCtx.Err() != nil {
					return
				}
				spec := specs[index]
				entries, err := c.queryAllRawMeshRecords(groupCtx, dwn.RecordsFilter{
					Protocol: protocols.MeshProtocolURI, ProtocolPath: spec.protocolPath, ContextID: spec.contextID,
				}, spec.dateSort, role, budget)
				if err != nil {
					errorOnce.Do(func() {
						firstErr = fmt.Errorf("querying %s under %s: %w", spec.protocolPath, spec.contextID, err)
						cancel()
					})
					return
				}
				results[index] = entries
			}
		}()
	}
	workers.Wait()
	if firstErr != nil {
		return nil, firstErr
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return results, nil
}

func rawMeshRecordReadEntry(result *dwn.RecordsReadResult) (json.RawMessage, error) {
	if err := rawCaptureReadStatusError(result); err != nil {
		return nil, err
	}
	entry, err := dwn.ReadEntry(result.Reply)
	if err != nil {
		return nil, err
	}
	encodedData := ""
	if len(result.Data) != 0 && !rawRecordHasEncodedData(entry) {
		encodedData = base64.RawURLEncoding.EncodeToString(result.Data)
	}
	entry, err = injectSubscriptionEncodedData(entry, encodedData)
	if err != nil {
		return nil, err
	}
	if !rawRecordHasEncodedData(entry) {
		return nil, fmt.Errorf("RecordsRead result has no encoded data")
	}
	return entry, nil
}

type rawCaptureRecordIdentity struct {
	recordID         string
	protocol         string
	protocolPath     string
	contextID        string
	parentContextID  string
	parentID         string
	recipient        string
	dateCreated      string
	messageTimestamp string
	revision         time.Time
	messageCID       string
}

// hydrateRawCaptureEntries fills query entries whose data was omitted because
// it exceeded the DWN inline-data limit. The targeted read is authenticated in
// exactly the same way as the query. Hydration is all-or-nothing: callers keep
// the original query slice when any read or validation fails.
func (c *DWNClient) hydrateRawCaptureEntries(ctx context.Context, entries []json.RawMessage, pathHint, contextID, role string, budget *fullStateFetchBudget) ([]json.RawMessage, error) {
	var hydrated []json.RawMessage
	for i, entry := range entries {
		if rawRecordHasEncodedData(entry) {
			continue
		}

		expected, err := rawCaptureIdentity(entry)
		if err != nil {
			return nil, fmt.Errorf("identifying %s query entry %d: %w", pathHint, i, err)
		}
		if expected.protocol != protocols.MeshProtocolURI || expected.protocolPath != pathHint || expected.parentContextID != contextID {
			return nil, fmt.Errorf("query entry %s does not match requested protocol/path %s %s", expected.recordID, protocols.MeshProtocolURI, pathHint)
		}

		if err := budget.takeRequest(); err != nil {
			return nil, err
		}
		result, err := c.anchorDWN.RecordsReadWithAuth(ctx, c.anchorTenant, dwn.RecordsFilter{
			RecordID: expected.recordID,
		}, c.readAuth(role))
		if err != nil {
			return nil, fmt.Errorf("hydrating %s record %s: %w", pathHint, expected.recordID, err)
		}
		if err := rawCaptureReadStatusError(result); err != nil {
			if !errors.Is(err, dwn.ErrRateLimited) && !errors.Is(err, dwn.ErrTransport) &&
				!errors.Is(err, errRawCaptureReadNotFound) {
				err = errors.Join(dwn.ErrTransport, err)
			}
			return nil, fmt.Errorf("hydrating %s record %s: %w", pathHint, expected.recordID, err)
		}
		readEntry, err := rawMeshRecordReadEntry(result)
		if err != nil {
			return nil, fmt.Errorf("hydrating %s record %s: %w", pathHint, expected.recordID, err)
		}
		actual, err := rawCaptureIdentity(readEntry)
		if err != nil {
			return nil, fmt.Errorf("validating hydrated %s record %s: %w", pathHint, expected.recordID, err)
		}
		if !sameRawCaptureSlot(actual, expected) {
			return nil, fmt.Errorf("hydrated %s record %s moved to a different immutable slot", pathHint, expected.recordID)
		}
		if compareRawCaptureRevision(actual, expected) < 0 {
			return nil, fmt.Errorf("hydrated %s record %s is older than the queried revision", pathHint, expected.recordID)
		}

		if hydrated == nil {
			hydrated = append([]json.RawMessage(nil), entries...)
		}
		hydrated[i] = readEntry
	}
	if hydrated == nil {
		return entries, nil
	}
	return hydrated, nil
}

func rawCaptureReadStatusError(result *dwn.RecordsReadResult) error {
	if result == nil || result.Reply == nil {
		return fmt.Errorf("%w: empty RecordsRead result", dwn.ErrTransport)
	}
	status := result.Reply.Status
	if status.Code == http.StatusTooManyRequests {
		return &dwn.RateLimitError{RetryAfter: rawCaptureRetryAfter(status.Detail), Detail: status.Detail}
	}
	if status.Code == http.StatusNotFound {
		return fmt.Errorf("%w: %d %s", errRawCaptureReadNotFound, status.Code, status.Detail)
	}
	if status.Code != http.StatusOK {
		return fmt.Errorf("%w: read failed: %d %s", dwn.ErrTransport, status.Code, status.Detail)
	}
	return nil
}

func sameRawCaptureSlot(a, b rawCaptureRecordIdentity) bool {
	return a.recordID == b.recordID &&
		a.protocol == b.protocol &&
		a.protocolPath == b.protocolPath &&
		a.contextID == b.contextID &&
		a.parentContextID == b.parentContextID &&
		a.parentID == b.parentID &&
		a.recipient == b.recipient &&
		a.dateCreated == b.dateCreated
}

func compareRawCaptureRevision(a, b rawCaptureRecordIdentity) int {
	if a.revision.Before(b.revision) {
		return -1
	}
	if a.revision.After(b.revision) {
		return 1
	}
	return strings.Compare(a.messageCID, b.messageCID)
}

func rawCaptureRetryAfter(detail string) time.Duration {
	const marker = "retry after "
	lower := strings.ToLower(detail)
	index := strings.LastIndex(lower, marker)
	if index < 0 {
		return time.Second
	}
	fields := strings.Fields(strings.TrimSpace(detail[index+len(marker):]))
	if len(fields) == 0 {
		return time.Second
	}
	delay, err := time.ParseDuration(strings.TrimRight(fields[0], ".,;"))
	if err != nil || delay < 0 {
		return time.Second
	}
	return delay
}

func rawCaptureIdentity(entry json.RawMessage) (rawCaptureRecordIdentity, error) {
	record, err := normalizeRawMeshRecordIdentity(entry, "")
	if err != nil {
		return rawCaptureRecordIdentity{}, err
	}
	return rawCaptureRecordIdentity{
		recordID:         record.recordID,
		protocol:         record.protocol,
		protocolPath:     record.protocolPath,
		contextID:        record.contextID,
		parentContextID:  record.parentContextID,
		parentID:         record.parentID,
		recipient:        record.recipient,
		dateCreated:      record.dateCreated,
		messageTimestamp: record.messageTimestamp,
		revision:         record.revision,
		messageCID:       record.messageCID,
	}, nil
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
func (c *DWNClient) loadNodeEntry(ctx context.Context, entry json.RawMessage, decryptor EntryDecryptor, memberRecordID string) error {
	meta := extractEntryMetadata(entry)
	nodeDID := meta.Recipient

	failureKey := meta.RecordID
	if failureKey == "" {
		failureKey = nodeDID
	}

	var node NodeRecord
	if err := ParseEntryData(entry, &node, decryptor); err != nil {
		if c.nodeFailures == nil {
			c.nodeFailures = make(map[string]string)
		}
		failureClass := endpointFailureClass(err)
		if previous, warned := c.nodeFailures[failureKey]; !warned || previous != failureClass {
			c.undecryptablePeers.Add(1)
			c.logger.WarnContext(ctx, "node record could not be loaded; peer will be invisible until key delivery or record recovery",
				slog.Any("error", err),
				slog.String("failureClass", failureClass),
				slog.String("nodeDID", nodeDID),
				slog.String("recordId", meta.RecordID),
				slog.String("memberRecordId", memberRecordID),
			)
		}
		c.nodeFailures[failureKey] = failureClass
		// Even if we can't decrypt the data payload, track the node DID
		// from the unencrypted recipient field. This allows peer discovery
		// and auto key delivery to work even before context key exchange.
		if nodeDID != "" {
			node.DID = nodeDID
			node.RecordID = meta.RecordID
			node.MemberRecordID = memberRecordID
			node.Opaque = true
			c.nodes[nodeDID] = &node
		}
		return err
	}
	node.NormalizeOwnerDID()
	node.DID = nodeDID
	node.RecordID = meta.RecordID
	node.MemberRecordID = memberRecordID
	if nodeDID != "" {
		c.nodes[nodeDID] = &node
	}
	if _, recovering := c.nodeFailures[failureKey]; recovering {
		delete(c.nodeFailures, failureKey)
		c.logger.InfoContext(ctx, "node record is readable again",
			slog.String("nodeDID", nodeDID),
			slog.String("recordId", meta.RecordID),
			slog.String("memberRecordId", memberRecordID),
		)
	}
	return nil
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

type nodeChildRecordHandler func(ctx context.Context, entry json.RawMessage, decryptor EntryDecryptor) error

type nodeChildRecordCapture func(protocolPath string, entries []json.RawMessage, err error) error

func (c *DWNClient) loadNodeChildRecords(ctx context.Context, childType string, role string, handler nodeChildRecordHandler) error {
	return c.loadNodeChildRecordsWithCapture(ctx, childType, role, handler, nil)
}

func (c *DWNClient) loadNodeChildRecordsWithCapture(ctx context.Context, childType string, role string, handler nodeChildRecordHandler, capture nodeChildRecordCapture) error {
	total := 0
	for _, query := range c.nodeChildRecordQueries(childType) {
		count, err := c.loadChildRecordsWithCapture(ctx, query.ProtocolPath, query.ParentContextID, role, handler, capture)
		if err != nil {
			return fmt.Errorf("%s under %s: %w", query.ProtocolPath, query.ParentContextID, err)
		}
		total += count
	}
	c.logger.DebugContext(ctx, "loaded node child records",
		slog.String("type", childType),
		slog.Int("count", total),
	)
	return nil
}

// loadChildRecords queries child records at the given protocol path under a
// direct parent context and processes each entry with the provided handler.
func (c *DWNClient) loadChildRecords(ctx context.Context, protocolPath string, parentContextID string, role string, handler nodeChildRecordHandler) (int, error) {
	return c.loadChildRecordsWithCapture(ctx, protocolPath, parentContextID, role, handler, nil)
}

func (c *DWNClient) loadChildRecordsWithCapture(ctx context.Context, protocolPath string, parentContextID string, role string, handler nodeChildRecordHandler, capture nodeChildRecordCapture) (int, error) {
	resp, err := c.anchorDWN.RecordsQueryWithAuth(ctx, c.anchorTenant, dwn.RecordsFilter{
		Protocol:     protocols.MeshProtocolURI,
		ProtocolPath: protocolPath,
		ContextID:    parentContextID,
	}, "createdDescending", nil, c.readAuth(role))
	if err != nil {
		if shouldAbortStateLoad(ctx, err) {
			return 0, fmt.Errorf("querying child records: %w", err)
		}
		if capture != nil {
			if captureErr := capture(protocolPath, nil, err); captureErr != nil {
				return 0, captureErr
			}
		}
		c.logger.DebugContext(ctx, "querying child records failed",
			slog.String("path", protocolPath),
			slog.String("parentContextId", parentContextID),
			slog.Any("error", err),
		)
		return 0, nil
	}

	entries, err := dwn.QueryResult(resp)
	if err != nil {
		if shouldAbortStateLoad(ctx, err) {
			return 0, fmt.Errorf("parsing child record results: %w", err)
		}
		if capture != nil {
			if captureErr := capture(protocolPath, nil, err); captureErr != nil {
				return 0, captureErr
			}
		}
		c.logger.DebugContext(ctx, "parsing child record results",
			slog.String("path", protocolPath),
			slog.String("parentContextId", parentContextID),
			slog.Any("error", err),
		)
		return 0, nil
	}

	if capture != nil {
		if captureErr := capture(protocolPath, entries, nil); captureErr != nil {
			return 0, captureErr
		}
	}

	decryptor := c.makeDecryptor(ctx, protocolPath)
	var loadErr error
	c.mu.Lock()
	for _, entry := range entries {
		if err := handler(ctx, entry, decryptor); shouldAbortStateLoad(ctx, err) {
			loadErr = err
			break
		}
	}
	c.mu.Unlock()
	if loadErr != nil {
		return 0, loadErr
	}

	c.logger.DebugContext(ctx, "loaded child records",
		slog.String("path", protocolPath),
		slog.String("parentContextId", parentContextID),
		slog.Int("count", len(entries)),
	)
	return len(entries), nil
}

// loadNodeInfoEntry parses a nodeInfo entry and attaches it to the parent node.
// Caller must hold c.mu.
func (c *DWNClient) loadNodeInfoEntry(ctx context.Context, entry json.RawMessage, decryptor EntryDecryptor) error {
	meta := extractEntryMetadata(entry)
	var info NodeInfoData
	if err := ParseEntryData(entry, &info, decryptor); err != nil {
		c.logger.DebugContext(ctx, "parsing nodeInfo entry", slog.Any("error", err))
		return err
	}

	// Attach to parent node by matching parentId to a node's recordID.
	parentID := meta.ParentID
	for _, node := range c.nodes {
		if node.RecordID != "" && node.RecordID == parentID {
			node.Info = &info
			break
		}
	}
	return nil
}

// loadEndpointEntry parses an endpoint entry and attaches it to the parent node.
// Caller must hold c.mu.
func (c *DWNClient) loadEndpointEntry(ctx context.Context, entry json.RawMessage, decryptor EntryDecryptor) error {
	meta := extractEntryMetadata(entry)
	failureKey := meta.ParentID
	if failureKey == "" {
		failureKey = meta.RecordID
	}

	var parentNode *NodeRecord
	for _, node := range c.nodes {
		if node.RecordID != "" && node.RecordID == meta.ParentID {
			parentNode = node
			break
		}
	}

	var ep EndpointData
	if err := ParseEntryData(entry, &ep, decryptor); err != nil {
		c.unreadableEndpoints.Add(1)
		if c.endpointFailures == nil {
			c.endpointFailures = make(map[string]string)
		}
		failureClass := endpointFailureClass(err)
		if previous, warned := c.endpointFailures[failureKey]; !warned || previous != failureClass {
			nodeDID := meta.Recipient
			if parentNode != nil && parentNode.DID != "" {
				nodeDID = parentNode.DID
			}
			c.logger.WarnContext(ctx, "endpoint record could not be loaded; peer connectivity may be degraded",
				slog.Any("error", err),
				slog.String("failureClass", failureClass),
				slog.String("nodeDID", nodeDID),
				slog.String("recordId", meta.RecordID),
				slog.String("parentId", meta.ParentID),
			)
		}
		c.endpointFailures[failureKey] = failureClass
		return err
	}

	if _, recovering := c.endpointFailures[failureKey]; recovering {
		delete(c.endpointFailures, failureKey)
		c.logger.InfoContext(ctx, "endpoint record is readable again",
			slog.String("recordId", meta.RecordID),
			slog.String("parentId", meta.ParentID),
		)
	}
	if parentNode != nil {
		parentNode.Endpoints = append(parentNode.Endpoints, ep)
	}
	return nil
}

// ACLPolicy returns the loaded ACL policy, or nil if none is configured.
func (c *DWNClient) ACLPolicy() *ACLPolicyData {
	c.loadMu.Lock()
	defer c.loadMu.Unlock()
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.acl
}

// Members returns the loaded member records, keyed by member DID.
func (c *DWNClient) Members() map[string]*MemberRecord {
	c.loadMu.Lock()
	defer c.loadMu.Unlock()
	c.mu.RLock()
	defer c.mu.RUnlock()
	return cloneRecordMap(c.members)
}

// Nodes returns the loaded node records, keyed by node DID.
func (c *DWNClient) Nodes() map[string]*NodeRecord {
	c.loadMu.Lock()
	defer c.loadMu.Unlock()
	c.mu.RLock()
	defer c.mu.RUnlock()
	return cloneRecordMap(c.nodes)
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
	if c.acl != nil {
		resp.PacketFilter = c.buildFilterRules()
	} else {
		resp.PacketFilter = defaultFilterRules()
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
		if rec == nil {
			continue
		}
		if rec.Opaque {
			if did == c.selfDID {
				c.logger.Warn("self node record is opaque; refusing descriptor-only network identity",
					slog.String("did", did), slog.String("recordId", rec.RecordID))
				return nil
			}
			c.droppedPeers.Add(1)
			c.logger.Warn("dropping opaque peer before fallback identity derivation",
				slog.String("did", did), slog.String("recordId", rec.RecordID))
			continue
		}
		expired := nodeRecordExpired(rec, now)
		if did == c.selfDID && (rec.Revoked || expired) {
			c.logger.Debug("self node membership is inactive",
				slog.String("did", did),
				slog.String("expiresAt", rec.ExpiresAt),
				slog.Bool("revoked", rec.Revoked),
			)
			nodeID, stableID := nodeIdentityForDID(c.networkRecordID, did)
			node := nodeRecordToNode(nodeID, did, rec)
			node.StableID = stableID
			c.applyFallbackMeshIP(node)
			resp.Node = node
			resp.Peers = nil
			return resp
		}
		if expired || rec.Revoked {
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
	return !now.Before(expiresAt)
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
		node.Capabilities = append([]string(nil), rec.Info.Capabilities...)
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
		Resolvers:      append([]string(nil), c.network.DNSServers...),
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
		privateKey, err := c.roleAudiencePrivateKey(ctx, info)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s audience key: %w", info.RolePath, err))
			continue
		}
		dec, err := dwncrypto.NewRoleAudienceDecrypter(privateKey)
		clear(privateKey)
		if err != nil {
			return nil, err
		}
		plaintext, err := dec.Decrypt(ciphertext, enc)
		dec.Close()
		if err == nil {
			return plaintext, nil
		}
		errs = append(errs, fmt.Errorf("%s audience decrypt: %w", info.RolePath, err))
	}
	return nil, fmt.Errorf("role audience key unavailable: %w", errors.Join(errs...))
}

func stableRoleAudienceRouteFailure(err error) bool {
	return errors.Is(err, errAudienceRecordAbsent) ||
		errors.Is(err, errAudienceSealUnavailable) ||
		errors.Is(err, errAudienceDeliveryUnavailable) ||
		errors.Is(err, errAudienceKeyDeliveryAbsent)
}

func (c *DWNClient) roleAudiencePrivateKey(ctx context.Context, info *dwncrypto.RoleAudienceInfo) ([]byte, error) {
	key := audienceKeyCacheKey{protocol: info.Protocol, rolePath: info.RolePath, keyID: info.KeyID}
	return c.roleAudienceKeys.get(ctx, key, func(ctx context.Context) ([]byte, error) {
		var errs []error
		allRoutesStable := true
		if c.audienceSource != nil {
			privateKey, err := c.audienceSource.AudiencePrivateKeyByKeyID(ctx, info.Protocol, info.RolePath, info.KeyID)
			if err == nil {
				return privateKey, nil
			}
			errs = append(errs, fmt.Errorf("seal: %w", err))
			allRoutesStable = allRoutesStable && stableRoleAudienceRouteFailure(err)
		}
		privateKey, err := c.deliveryAudiencePrivateKey(ctx, info)
		if err == nil {
			return privateKey, nil
		}
		errs = append(errs, fmt.Errorf("delivery: %w", err))
		allRoutesStable = allRoutesStable && stableRoleAudienceRouteFailure(err)
		joined := errors.Join(errs...)
		if allRoutesStable {
			return nil, fmt.Errorf("%w: role audience key unavailable: %w", errAudienceKeyDeliveryAbsent, joined)
		}
		return nil, fmt.Errorf("role audience key unavailable: %w", joined)
	})
}

// decryptViaDelivery recovers the audience key from a `$encryption/delivery`
// record addressed to this node and unwraps the record's roleAudience entry.
// The delivery record is encrypted to this node's OWN role-path key, derived
// from its encryption root.
func (c *DWNClient) decryptViaDelivery(ctx context.Context, ciphertext []byte, enc *dwncrypto.Encryption, info *dwncrypto.RoleAudienceInfo) ([]byte, error) {
	privateKey, err := c.deliveryAudiencePrivateKey(ctx, info)
	if err != nil {
		return nil, err
	}
	defer clear(privateKey)

	dec, err := dwncrypto.NewRoleAudienceDecrypter(privateKey)
	if err != nil {
		return nil, fmt.Errorf("using delivered audience key: %w", err)
	}
	defer dec.Close()
	return dec.Decrypt(ciphertext, enc)
}

func (c *DWNClient) deliveryAudiencePrivateKey(ctx context.Context, info *dwncrypto.RoleAudienceInfo) ([]byte, error) {
	return c.deliveredAudienceKeys.get(ctx, audienceKeyCacheKey{
		protocol: info.Protocol,
		rolePath: info.RolePath,
		keyID:    info.KeyID,
	}, func(ctx context.Context) ([]byte, error) {
		return c.queryDeliveryAudiencePrivateKey(ctx, info)
	})
}

func (c *DWNClient) queryDeliveryAudiencePrivateKey(ctx context.Context, info *dwncrypto.RoleAudienceInfo) ([]byte, error) {
	if c.encManager == nil {
		return nil, fmt.Errorf("%w: no encryption root available for delivery records", errAudienceDeliveryUnavailable)
	}
	reply, err := c.queryDeliveryRecordsWithRetry(ctx, info)
	if err != nil {
		return nil, fmt.Errorf("querying delivery records: %w", err)
	}
	entries, err := dwn.QueryEntries(reply)
	if err != nil {
		if !errors.Is(err, dwn.ErrRateLimited) {
			err = errors.Join(dwn.ErrTransport, err)
		}
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
		privateKey, err := base64.RawURLEncoding.DecodeString(payload.KeyMaterial.PrivateKeyJwk.D)
		if err != nil {
			continue
		}
		return privateKey, nil
	}
	return nil, fmt.Errorf("%w: no delivery record for keyId %s at %s", errAudienceKeyDeliveryAbsent, info.KeyID, info.RolePath)
}

// queryDeliveryRecordsWithRetry makes at most one bounded retry of this
// read-only query. The outer control poll remains the long-lived retry path.
func (c *DWNClient) queryDeliveryRecordsWithRetry(ctx context.Context, info *dwncrypto.RoleAudienceInfo) (*dwn.DwnReply, error) {
	query := func() (*dwn.DwnReply, error) {
		return c.anchorDWN.RecordsQueryWithAuth(ctx, c.anchorTenant, dwn.RecordsFilter{
			Protocol:     info.Protocol,
			ProtocolPath: dwncrypto.EncryptionControlDeliveryPath,
			Recipient:    c.selfDID,
			Tags: map[string]any{
				"protocol": info.Protocol,
				"rolePath": info.RolePath,
				"keyId":    info.KeyID,
			},
		}, "createdDescending", nil, dwn.MessageAuth{})
	}

	reply, err := query()
	if err == nil || !errors.Is(err, dwn.ErrRateLimited) {
		return reply, err
	}

	delay := time.Second
	var rateLimitErr *dwn.RateLimitError
	if errors.As(err, &rateLimitErr) {
		delay = rateLimitErr.RetryAfter
	}
	if delay < 250*time.Millisecond {
		delay = 250 * time.Millisecond
	}
	if delay > 5*time.Second {
		return nil, err
	}

	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timer.C:
	}
	return query()
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
