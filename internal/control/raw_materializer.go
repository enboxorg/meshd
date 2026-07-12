package control

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/enboxorg/meshd/internal/dwn"
	"github.com/enboxorg/meshd/protocols"
)

type rawParsedOutcomeKind uint8

const (
	rawParsedNetwork rawParsedOutcomeKind = iota + 1
	rawParsedMember
	rawParsedNode
	rawParsedRelay
	rawParsedACL
	rawParsedNodeInfo
	rawParsedEndpoint
)

// rawParsedOutcomeKey is the authoritative identity of one parsed contribution.
// The canonical message CID changes for every meaningful RecordsWrite change;
// context/path and the decrypt generation fence parent/key-context changes.
type rawParsedOutcomeKey struct {
	kind            rawParsedOutcomeKind
	recordID        string
	messageCID      string
	protocolPath    string
	contextID       string
	parentContextID string
	recipient       string
	revision        time.Time
	generation      uint64
}

type rawParsedLogicalSlot struct {
	kind            rawParsedOutcomeKind
	recordID        string
	protocolPath    string
	parentContextID string
	recipient       string
}

type rawParsedSlotOutcome struct {
	key     rawParsedOutcomeKey
	outcome rawParsedOutcome
}

// rawParsedOutcome owns immutable typed data. opaque means parsing reached a
// stable, non-transient failure and the record contributes only its documented
// ghost/skip/last-good behavior until delivery or full-load invalidation.
type rawParsedOutcome struct {
	opaque   bool
	network  *NetworkConfig
	member   *MemberRecord
	node     *NodeRecord
	relay    *RelayData
	acl      *ACLPolicyData
	nodeInfo *NodeInfoData
	endpoint *EndpointData
}

type rawParsedProjection struct {
	generation    uint64
	previous      map[rawParsedOutcomeKey]rawParsedOutcome
	previousSlots map[rawParsedLogicalSlot]rawParsedSlotOutcome
	currentSlots  map[rawParsedLogicalSlot]rawParsedSlotOutcome
	next          map[rawParsedOutcomeKey]rawParsedOutcome
}

const revokedSelfExpiry = "1970-01-01T00:00:00Z"

func (c *DWNClient) beginRawParsedProjection() *rawParsedProjection {
	c.mu.RLock()
	defer c.mu.RUnlock()
	previous := make(map[rawParsedOutcomeKey]rawParsedOutcome, len(c.rawParsedOutcomes))
	for key, outcome := range c.rawParsedOutcomes {
		previous[key] = outcome
	}
	projection := &rawParsedProjection{
		generation:    c.rawParsedGeneration,
		previous:      previous,
		previousSlots: make(map[rawParsedLogicalSlot]rawParsedSlotOutcome, len(previous)),
		currentSlots:  make(map[rawParsedLogicalSlot]rawParsedSlotOutcome, len(previous)),
		next:          make(map[rawParsedOutcomeKey]rawParsedOutcome, len(previous)),
	}
	for key, outcome := range previous {
		stageRawParsedSlot(projection.previousSlots, key, outcome)
	}
	return projection
}

func (c *DWNClient) invalidateRawParsedOutcomes() {
	c.mu.Lock()
	c.rawParsedGeneration++
	refreshed := make(map[rawParsedOutcomeKey]rawParsedOutcome, len(c.rawParsedOutcomes))
	for key, outcome := range c.rawParsedOutcomes {
		if !outcome.opaque {
			key.generation = c.rawParsedGeneration
		}
		refreshed[key] = outcome
	}
	c.rawParsedOutcomes = refreshed
	c.mu.Unlock()
}

func (p *rawParsedProjection) key(record rawMeshRecord, kind rawParsedOutcomeKind) rawParsedOutcomeKey {
	return rawParsedOutcomeKey{
		kind:            kind,
		recordID:        record.recordID,
		messageCID:      record.messageCID,
		protocolPath:    record.protocolPath,
		contextID:       record.contextID,
		parentContextID: record.parentContextID,
		recipient:       record.recipient,
		revision:        record.revision,
		generation:      p.generation,
	}
}

func (p *rawParsedProjection) lastGood(record rawMeshRecord, kind rawParsedOutcomeKind) (rawParsedOutcome, bool) {
	slot := rawParsedSlot(record, kind)
	if staged, ok := p.currentSlots[slot]; ok {
		return cloneRawParsedOutcome(staged.outcome), true
	}
	previous, ok := p.previousSlots[slot]
	return cloneRawParsedOutcome(previous.outcome), ok
}

func (p *rawParsedProjection) lastGoodNodeForRecipient(recipient string) (*NodeRecord, bool) {
	var newest rawParsedSlotOutcome
	found := false
	consider := func(slots map[rawParsedLogicalSlot]rawParsedSlotOutcome) {
		for slot, candidate := range slots {
			if slot.kind != rawParsedNode || slot.recipient != recipient || candidate.outcome.node == nil {
				continue
			}
			if !found || rawParsedOutcomeKeyIsNewer(candidate.key, newest.key) {
				newest = candidate
				found = true
			}
		}
	}
	consider(p.previousSlots)
	consider(p.currentSlots)
	if !found {
		return nil, false
	}
	return cloneNodeRecord(newest.outcome.node), true
}

func rawParsedSlot(record rawMeshRecord, kind rawParsedOutcomeKind) rawParsedLogicalSlot {
	return newRawParsedLogicalSlot(kind, record.recordID, record.recipient, record.protocolPath, record.parentContextID)
}

func rawParsedSlotFromKey(key rawParsedOutcomeKey) rawParsedLogicalSlot {
	return newRawParsedLogicalSlot(key.kind, key.recordID, key.recipient, key.protocolPath, key.parentContextID)
}

func newRawParsedLogicalSlot(
	kind rawParsedOutcomeKind,
	recordID string,
	recipient string,
	protocolPath string,
	parentContextID string,
) rawParsedLogicalSlot {
	slot := rawParsedLogicalSlot{
		kind: kind, recordID: recordID, protocolPath: protocolPath, parentContextID: parentContextID,
	}
	switch kind {
	case rawParsedMember, rawParsedNode:
		if recipient != "" {
			slot.recordID = ""
			slot.recipient = recipient
		}
	case rawParsedACL, rawParsedNodeInfo, rawParsedEndpoint:
		slot.recordID = ""
	}
	return slot
}

func stageRawParsedSlot(
	slots map[rawParsedLogicalSlot]rawParsedSlotOutcome,
	key rawParsedOutcomeKey,
	outcome rawParsedOutcome,
) {
	if !rawParsedOutcomeHasContribution(key.kind, outcome) {
		return
	}
	slot := rawParsedSlotFromKey(key)
	current, ok := slots[slot]
	if !ok || rawParsedOutcomeKeyIsNewer(key, current.key) {
		slots[slot] = rawParsedSlotOutcome{key: key, outcome: outcome}
	}
}

func rawParsedOutcomeHasContribution(kind rawParsedOutcomeKind, outcome rawParsedOutcome) bool {
	switch kind {
	case rawParsedNetwork:
		return outcome.network != nil
	case rawParsedMember:
		return outcome.member != nil
	case rawParsedNode:
		return outcome.node != nil
	case rawParsedRelay:
		return outcome.relay != nil
	case rawParsedACL:
		return outcome.acl != nil
	case rawParsedNodeInfo:
		return outcome.nodeInfo != nil
	case rawParsedEndpoint:
		return outcome.endpoint != nil
	default:
		return false
	}
}

func rawParsedOutcomeKeyIsNewer(candidate, current rawParsedOutcomeKey) bool {
	if candidate.revision.Before(current.revision) {
		return false
	}
	if candidate.revision.After(current.revision) {
		return true
	}
	return candidate.messageCID > current.messageCID
}

func (p *rawParsedProjection) lookup(record rawMeshRecord, kind rawParsedOutcomeKind) (rawParsedOutcome, bool) {
	key := p.key(record, kind)
	outcome, ok := p.previous[key]
	if !ok {
		return rawParsedOutcome{}, false
	}
	p.next[key] = outcome
	stageRawParsedSlot(p.currentSlots, key, outcome)
	return cloneRawParsedOutcome(outcome), true
}

func (p *rawParsedProjection) store(record rawMeshRecord, kind rawParsedOutcomeKind, outcome rawParsedOutcome) {
	key := p.key(record, kind)
	owned := cloneRawParsedOutcome(outcome)
	p.next[key] = owned
	stageRawParsedSlot(p.currentSlots, key, owned)
}

// materializeRawMeshRecordSet projects a complete raw record snapshot into a
// new parsed control-plane state. The caller must serialize calls with loadMu.
// No state reachable from c is mutated until a usable MapResponse has been
// built, so a failed, canceled, or rate-limited projection leaves the previous
// state (including its pointer identity) untouched.
func (c *DWNClient) materializeRawMeshRecordSet(ctx context.Context, set *rawMeshRecordSet) (*MapResponse, error) {
	projection, err := c.projectRawMeshRecordSetWithDecryptors(ctx, set, c.makeDecryptor)
	if err != nil {
		return nil, err
	}
	c.commitRawMeshMaterialization(projection)
	return projection.response, nil
}

// materializeRawMeshRecordSetWithDecryptors is split out to make abort and
// rollback behavior deterministic in tests. Production callers use
// materializeRawMeshRecordSet, which supplies the client's normal decryptors.
func (c *DWNClient) materializeRawMeshRecordSetWithDecryptors(
	ctx context.Context,
	set *rawMeshRecordSet,
	decryptorFor func(context.Context, string) EntryDecryptor,
) (*MapResponse, error) {
	projection, err := c.projectRawMeshRecordSetWithDecryptors(ctx, set, decryptorFor)
	if err != nil {
		return nil, err
	}
	c.commitRawMeshMaterialization(projection)
	return projection.response, nil
}

type rawMeshMaterialization struct {
	builder          *DWNClient
	response         *MapResponse
	parsedGeneration uint64
	parsedOutcomes   map[rawParsedOutcomeKey]rawParsedOutcome
}

func (c *DWNClient) projectRawMeshRecordSetWithDecryptors(
	ctx context.Context,
	set *rawMeshRecordSet,
	decryptorFor func(context.Context, string) EntryDecryptor,
) (*rawMeshMaterialization, error) {
	if c == nil {
		return nil, fmt.Errorf("materializing raw mesh state: nil DWN client")
	}
	if ctx == nil {
		return nil, fmt.Errorf("materializing raw mesh state: nil context")
	}
	if set == nil {
		return nil, fmt.Errorf("materializing raw mesh state: nil record set")
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("materializing raw mesh state: %w", err)
	}

	groups := groupRawMeshMapRecords(set.all(), c.networkRecordID)
	if groups.network == nil {
		return nil, fmt.Errorf("%w: record %q is absent from local state", ErrNoNetwork, c.networkRecordID)
	}
	parsed := c.beginRawParsedProjection()

	logger := c.logger
	if logger == nil {
		logger = slog.Default()
	}
	endpointFailures := c.cloneEndpointFailures()
	nodeFailures := c.cloneNodeFailures()
	previousACL := c.cloneACLPolicy()
	builder := &DWNClient{
		networkRecordID:  c.networkRecordID,
		selfDID:          c.selfDID,
		logger:           logger,
		members:          make(map[string]*MemberRecord),
		nodes:            make(map[string]*NodeRecord),
		endpointFailures: endpointFailures,
		nodeFailures:     nodeFailures,
	}

	if err := requireRawMaterializationData(*groups.network); err != nil {
		return nil, err
	}
	if outcome, ok := parsed.lookup(*groups.network, rawParsedNetwork); ok && !outcome.opaque && outcome.network != nil {
		builder.network = outcome.network
	} else {
		var network NetworkConfig
		if err := ParseEntryData(groups.network.raw, &network, nil); err != nil {
			return nil, fmt.Errorf("parsing materialized network: %w", err)
		}
		builder.network = &network
		parsed.store(*groups.network, rawParsedNetwork, rawParsedOutcome{network: &network})
	}

	decryptors := make(map[string]EntryDecryptor)
	decryptor := func(path string) EntryDecryptor {
		if dec, ok := decryptors[path]; ok {
			return dec
		}
		var dec EntryDecryptor
		if decryptorFor != nil {
			dec = decryptorFor(ctx, path)
		}
		decryptors[path] = dec
		return dec
	}

	// Members must be materialized before member-associated nodes because the
	// member record ID defines each node's direct parent context.
	sortRawRecordsOldestFirst(groups.members)
	for _, record := range groups.members {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("materializing members: %w", err)
		}
		if err := requireRawMaterializationData(record); err != nil {
			return nil, err
		}
		var member MemberRecord
		if outcome, ok := parsed.lookup(record, rawParsedMember); ok {
			if outcome.member != nil {
				member = *outcome.member
			}
			member.DID = record.recipient
			member.RecordID = record.recordID
			if member.DID != "" {
				builder.members[member.DID] = &member
			}
			continue
		}
		if err := ParseEntryData(record.raw, &member, decryptor(record.protocolPath)); err != nil {
			logger.DebugContext(ctx, "parsing materialized member entry",
				slog.Any("error", err), slog.String("memberDID", record.recipient))
			if shouldAbortRawMaterialization(ctx, err) {
				return nil, fmt.Errorf("parsing materialized member %s: %w", record.recordID, err)
			}
			// Match LoadState: public descriptor metadata keeps an opaque member
			// addressable until its audience key arrives.
			outcome := rawParsedOutcome{opaque: true}
			if errors.Is(err, errAudienceKeyDeliveryAbsent) {
				if previous, ok := parsed.lastGood(record, rawParsedMember); ok && previous.member != nil {
					member = *previous.member
					outcome.member = &member
				}
			}
			member.DID = record.recipient
			member.RecordID = record.recordID
			if outcome.member != nil {
				outcome.member = &member
			}
			parsed.store(record, rawParsedMember, outcome)
			if member.DID != "" {
				builder.members[member.DID] = &member
			}
			continue
		}
		member.DID = record.recipient
		member.RecordID = record.recordID
		parsed.store(record, rawParsedMember, rawParsedOutcome{member: &member})
		if member.DID != "" {
			builder.members[member.DID] = &member
		}
	}

	memberRecordIDs := make(map[string]struct{}, len(builder.members))
	for _, member := range builder.members {
		if member.RecordID != "" {
			memberRecordIDs[member.RecordID] = struct{}{}
		}
	}

	currentNodeFailures := make(map[string]struct{}, len(groups.ownerNodes)+len(groups.memberNodes))

	// Preserve full-load precedence: owner nodes are loaded first and a
	// member-associated record for the same DID wins afterward.
	sortRawRecordsOldestFirst(groups.ownerNodes)
	for _, record := range groups.ownerNodes {
		currentNodeFailures[record.recordID] = struct{}{}
		if err := materializeNodeRecord(ctx, builder, parsed, record, "", decryptor(record.protocolPath)); err != nil {
			return nil, err
		}
	}
	sortRawRecordsOldestFirst(groups.memberNodes)
	for _, record := range groups.memberNodes {
		if _, ok := memberRecordIDs[record.parentID]; !ok {
			continue
		}
		parentContext := c.networkRecordID + "/" + record.parentID
		if !rawRecordIsDirectChild(record, parentContext) {
			continue
		}
		currentNodeFailures[record.recordID] = struct{}{}
		if err := materializeNodeRecord(ctx, builder, parsed, record, record.parentID, decryptor(record.protocolPath)); err != nil {
			return nil, err
		}
	}

	for failureKey := range builder.nodeFailures {
		if _, current := currentNodeFailures[failureKey]; !current {
			delete(builder.nodeFailures, failureKey)
		}
	}
	self := builder.nodes[builder.selfDID]
	if self == nil {
		if builder.selfDID == "" {
			return nil, fmt.Errorf("materializing raw mesh state: self DID is empty")
		}
		installRevokedSelfNode(builder, parsed)
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("materializing raw mesh state: %w", err)
		}
		return finishRawMeshMaterialization(c, builder, parsed)
	}
	if self.Opaque {
		return nil, fmt.Errorf("materializing self node %s: descriptor-only node is not authorized", self.RecordID)
	}
	if self.Revoked || nodeRecordExpired(self, time.Now().UTC()) {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("materializing raw mesh state: %w", err)
		}
		return finishRawMeshMaterialization(c, builder, parsed)
	}

	sortRawRelaysOldestFirst(groups.relays)
	for _, record := range groups.relays {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("materializing relays: %w", err)
		}
		if err := requireRawMaterializationData(record); err != nil {
			return nil, err
		}
		if outcome, ok := parsed.lookup(record, rawParsedRelay); ok {
			if outcome.relay == nil {
				return nil, fmt.Errorf("materialized relay %s is unreadable and no last-good relay is available", record.recordID)
			}
			builder.relays = append(builder.relays, outcome.relay)
			continue
		}
		var relay RelayData
		if err := ParseEntryData(record.raw, &relay, decryptor(record.protocolPath)); err != nil {
			logger.DebugContext(ctx, "parsing materialized relay entry", slog.Any("error", err))
			if shouldAbortRawMaterialization(ctx, err) {
				return nil, fmt.Errorf("parsing materialized relay %s: %w", record.recordID, err)
			}
			previous, ok := parsed.lastGood(record, rawParsedRelay)
			if !ok || previous.relay == nil {
				return nil, fmt.Errorf("parsing materialized relay %s without a last-good relay: %w", record.recordID, err)
			}
			parsed.store(record, rawParsedRelay, rawParsedOutcome{opaque: true, relay: previous.relay})
			builder.relays = append(builder.relays, previous.relay)
			continue
		}
		parsed.store(record, rawParsedRelay, rawParsedOutcome{relay: &relay})
		builder.relays = append(builder.relays, &relay)
	}

	if groups.acl != nil {
		if err := requireRawMaterializationData(*groups.acl); err != nil {
			return nil, err
		}
		if outcome, ok := parsed.lookup(*groups.acl, rawParsedACL); ok {
			if outcome.opaque {
				if previousACL == nil {
					return nil, fmt.Errorf("materialized ACL %s is unreadable and no last-good policy is available", groups.acl.recordID)
				}
				builder.acl = previousACL
			} else {
				builder.acl = outcome.acl
			}
		} else {
			var policy ACLPolicyData
			if err := ParseEntryData(groups.acl.raw, &policy, decryptor(groups.acl.protocolPath)); err != nil {
				logger.DebugContext(ctx, "parsing materialized ACL policy", slog.Any("error", err))
				if shouldAbortRawMaterialization(ctx, err) {
					return nil, fmt.Errorf("parsing materialized ACL policy: %w", err)
				}
				if previousACL == nil {
					return nil, fmt.Errorf("parsing materialized ACL policy without a last-good policy: %w", err)
				}
				// Keep the prior parsed ACL until the opaque replacement becomes
				// decryptable, matching legacy LoadState's last-good policy behavior.
				builder.acl = previousACL
				parsed.store(*groups.acl, rawParsedACL, rawParsedOutcome{opaque: true})
			} else {
				builder.acl = &policy
				parsed.store(*groups.acl, rawParsedACL, rawParsedOutcome{acl: &policy})
			}
		}
	}

	nodeParents := materializedNodeParents(c.networkRecordID, builder.nodes)
	sortRawRecordsNewestFirst(groups.nodeInfo)
	seenNodeInfo := make(map[string]struct{}, len(nodeParents))
	for _, record := range groups.nodeInfo {
		parent, ok := nodeParents[record.parentID]
		if !ok || record.protocolPath != parent.infoPath || !rawRecordIsDirectChild(record, parent.contextID) {
			continue
		}
		if _, seen := seenNodeInfo[record.parentID]; seen {
			continue
		}
		seenNodeInfo[record.parentID] = struct{}{}
		if err := requireRawMaterializationData(record); err != nil {
			return nil, err
		}
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("materializing node info: %w", err)
		}
		if outcome, ok := parsed.lookup(record, rawParsedNodeInfo); ok {
			if outcome.nodeInfo != nil {
				parent.node.Info = outcome.nodeInfo
			}
			continue
		}
		var info NodeInfoData
		if err := ParseEntryData(record.raw, &info, decryptor(record.protocolPath)); err != nil {
			logger.DebugContext(ctx, "parsing materialized nodeInfo entry", slog.Any("error", err))
			if shouldAbortRawMaterialization(ctx, err) {
				return nil, fmt.Errorf("decrypting materialized node info %s: %w", record.recordID, err)
			}
			outcome := rawParsedOutcome{opaque: true}
			if errors.Is(err, errAudienceKeyDeliveryAbsent) {
				if previous, ok := parsed.lastGood(record, rawParsedNodeInfo); ok {
					outcome.nodeInfo = previous.nodeInfo
					if previous.nodeInfo != nil {
						parent.node.Info = previous.nodeInfo
					}
				}
			}
			parsed.store(record, rawParsedNodeInfo, outcome)
			continue
		}
		parent.node.Info = &info
		parsed.store(record, rawParsedNodeInfo, rawParsedOutcome{nodeInfo: &info})
	}

	currentEndpointFailures := make(map[string]struct{}, len(groups.endpoints))
	sortRawRecordsNewestFirst(groups.endpoints)
	seenEndpoints := make(map[string]struct{}, len(nodeParents))
	for _, record := range groups.endpoints {
		parent, ok := nodeParents[record.parentID]
		if !ok || record.protocolPath != parent.endpointPath || !rawRecordIsDirectChild(record, parent.contextID) {
			continue
		}
		if _, seen := seenEndpoints[record.parentID]; seen {
			continue
		}
		seenEndpoints[record.parentID] = struct{}{}
		failureKey := record.parentID
		if failureKey == "" {
			failureKey = record.recordID
		}
		currentEndpointFailures[failureKey] = struct{}{}
		if err := requireRawMaterializationData(record); err != nil {
			return nil, err
		}
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("materializing endpoints: %w", err)
		}
		if outcome, ok := parsed.lookup(record, rawParsedEndpoint); ok {
			if outcome.endpoint != nil {
				parent.node.Endpoints = append(parent.node.Endpoints, *outcome.endpoint)
			}
			continue
		}
		endpoint, err := materializeEndpointRecord(ctx, builder, parent.node, record, decryptor(record.protocolPath))
		if err != nil {
			if shouldAbortRawMaterialization(ctx, err) {
				return nil, fmt.Errorf("decrypting materialized endpoint %s: %w", record.recordID, err)
			}
			outcome := rawParsedOutcome{opaque: true}
			if errors.Is(err, errAudienceKeyDeliveryAbsent) {
				if previous, ok := parsed.lastGood(record, rawParsedEndpoint); ok {
					outcome.endpoint = previous.endpoint
					if previous.endpoint != nil {
						parent.node.Endpoints = append(parent.node.Endpoints, *previous.endpoint)
					}
				}
			}
			parsed.store(record, rawParsedEndpoint, outcome)
			continue
		}
		parsed.store(record, rawParsedEndpoint, rawParsedOutcome{endpoint: endpoint})
	}
	for failureKey := range builder.endpointFailures {
		if _, current := currentEndpointFailures[failureKey]; !current {
			delete(builder.endpointFailures, failureKey)
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("materializing raw mesh state: %w", err)
	}
	return finishRawMeshMaterialization(c, builder, parsed)
}

func installRevokedSelfNode(builder *DWNClient, parsed *rawParsedProjection) {
	revoked, ok := parsed.lastGoodNodeForRecipient(builder.selfDID)
	if !ok {
		revoked = &NodeRecord{DID: builder.selfDID}
	}
	revoked.DID = builder.selfDID
	revoked.Opaque = false
	revoked.Revoked = true
	revoked.ExpiresAt = revokedSelfExpiry
	builder.nodes[builder.selfDID] = revoked
}

func finishRawMeshMaterialization(
	c *DWNClient,
	builder *DWNClient,
	parsed *rawParsedProjection,
) (*rawMeshMaterialization, error) {
	response := builder.buildMapResponse()
	if response == nil {
		return nil, fmt.Errorf("self DID %q not found in materialized network node records", c.selfDID)
	}

	return &rawMeshMaterialization{
		builder:          builder,
		response:         response,
		parsedGeneration: parsed.generation,
		parsedOutcomes:   parsed.next,
	}, nil
}

func (c *DWNClient) commitRawMeshMaterialization(projection *rawMeshMaterialization) {
	c.mu.Lock()
	c.commitRawMeshMaterializationLocked(projection)
	c.mu.Unlock()
	c.commitRawMeshMaterializationCounters(projection)
}

func (c *DWNClient) commitRawMeshMaterializationLocked(projection *rawMeshMaterialization) {
	builder := projection.builder
	c.network = builder.network
	c.members = builder.members
	c.nodes = builder.nodes
	c.relays = builder.relays
	c.acl = builder.acl
	c.nodeFailures = builder.nodeFailures
	c.endpointFailures = builder.endpointFailures
	if c.rawParsedGeneration == projection.parsedGeneration {
		c.rawParsedOutcomes = projection.parsedOutcomes
	}
}

func (c *DWNClient) commitRawMeshMaterializationCounters(projection *rawMeshMaterialization) {
	builder := projection.builder
	c.undecryptablePeers.Add(builder.undecryptablePeers.Load())
	c.unreadableEndpoints.Add(builder.unreadableEndpoints.Load())
	c.droppedPeers.Add(builder.droppedPeers.Load())
}

type rawMeshMapRecordGroups struct {
	network     *rawMeshRecord
	members     []rawMeshRecord
	ownerNodes  []rawMeshRecord
	memberNodes []rawMeshRecord
	relays      []rawMeshRecord
	acl         *rawMeshRecord
	nodeInfo    []rawMeshRecord
	endpoints   []rawMeshRecord
}

func groupRawMeshMapRecords(records []rawMeshRecord, networkRecordID string) rawMeshMapRecordGroups {
	var groups rawMeshMapRecordGroups
	for i := range records {
		record := records[i]
		if record.protocol != protocols.MeshProtocolURI {
			continue
		}
		switch record.protocolPath {
		case "network":
			if record.recordID == networkRecordID && (record.contextID == "" || record.contextID == record.recordID) {
				copy := record
				groups.network = &copy
			}
		case "network/member":
			if rawRecordIsDirectChild(record, networkRecordID) {
				groups.members = append(groups.members, record)
			}
		case "network/node":
			if rawRecordIsDirectChild(record, networkRecordID) {
				groups.ownerNodes = append(groups.ownerNodes, record)
			}
		case "network/member/node":
			groups.memberNodes = append(groups.memberNodes, record)
		case "network/relay":
			if rawRecordIsDirectChild(record, networkRecordID) {
				groups.relays = append(groups.relays, record)
			}
		case "network/aclPolicy":
			if rawRecordIsDirectChild(record, networkRecordID) && rawRecordIsNewer(record, groups.acl) {
				copy := record
				groups.acl = &copy
			}
		case "network/node/nodeInfo", "network/member/node/nodeInfo":
			groups.nodeInfo = append(groups.nodeInfo, record)
		case "network/node/endpoint", "network/member/node/endpoint":
			groups.endpoints = append(groups.endpoints, record)
		}
	}
	return groups
}

func rawRecordIsNewer(candidate rawMeshRecord, current *rawMeshRecord) bool {
	return current == nil || compareRawMeshRecordRevision(candidate.head(), current.head()) > 0
}

func rawRecordIsDirectChild(record rawMeshRecord, parentContextID string) bool {
	parentID := parentContextID
	if separator := strings.LastIndexByte(parentID, '/'); separator >= 0 {
		parentID = parentID[separator+1:]
	}
	if record.parentID != parentID {
		return false
	}
	return record.contextID == parentContextID+"/"+record.recordID
}

func sortRawRecordsOldestFirst(records []rawMeshRecord) {
	sort.Slice(records, func(i, j int) bool {
		if comparison := compareRawMeshRecordRevision(records[i].head(), records[j].head()); comparison != 0 {
			return comparison < 0
		}
		return records[i].recordID < records[j].recordID
	})
}

func sortRawRecordsNewestFirst(records []rawMeshRecord) {
	sort.Slice(records, func(i, j int) bool {
		if comparison := compareRawMeshRecordRevision(records[i].head(), records[j].head()); comparison != 0 {
			return comparison > 0
		}
		return records[i].recordID > records[j].recordID
	})
}

// Relay region IDs are positional, so updates must preserve RecordsQuery's
// createdAscending order rather than reordering a relay by update timestamp.
func sortRawRelaysOldestFirst(records []rawMeshRecord) {
	sort.Slice(records, func(i, j int) bool {
		if records[i].dateCreatedTime.Before(records[j].dateCreatedTime) {
			return true
		}
		if records[i].dateCreatedTime.After(records[j].dateCreatedTime) {
			return false
		}
		if comparison := compareRawMeshRecordRevision(records[i].head(), records[j].head()); comparison != 0 {
			return comparison < 0
		}
		return records[i].recordID < records[j].recordID
	})
}

func requireRawMaterializationData(record rawMeshRecord) error {
	if !rawRecordHasEncodedData(record.raw) {
		return fmt.Errorf("materializing %s record %s: %w", record.protocolPath, record.recordID, errRawMeshRecordDataUnavailable)
	}
	return nil
}

func materializeNodeRecord(
	ctx context.Context,
	builder *DWNClient,
	parsed *rawParsedProjection,
	record rawMeshRecord,
	memberRecordID string,
	decryptor EntryDecryptor,
) error {
	if err := requireRawMaterializationData(record); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("materializing nodes: %w", err)
	}
	if outcome, ok := parsed.lookup(record, rawParsedNode); ok {
		if outcome.node != nil {
			outcome.node.DID = record.recipient
			outcome.node.RecordID = record.recordID
			outcome.node.MemberRecordID = memberRecordID
			outcome.node.Opaque = false
			outcome.node.Revoked = false
			if record.recipient != "" {
				builder.nodes[record.recipient] = outcome.node
			}
			return nil
		}
		if outcome.opaque {
			if record.recipient == builder.selfDID {
				return fmt.Errorf("materializing self node %s: unreadable without a recipient-matched last-good node", record.recordID)
			}
			if record.recipient != "" {
				builder.nodes[record.recipient] = &NodeRecord{
					DID: record.recipient, RecordID: record.recordID, MemberRecordID: memberRecordID, Opaque: true,
				}
			}
			return nil
		}
		return nil
	}
	if err := builder.loadNodeEntry(ctx, record.raw, decryptor, memberRecordID); err != nil {
		if shouldAbortRawMaterialization(ctx, err) {
			return fmt.Errorf("decrypting materialized node %s: %w", record.recordID, err)
		}
		outcome := rawParsedOutcome{opaque: true}
		if errors.Is(err, errAudienceKeyDeliveryAbsent) {
			if previous, ok := parsed.lastGood(record, rawParsedNode); ok && previous.node != nil {
				outcome.node = previous.node
				outcome.node.DID = record.recipient
				outcome.node.RecordID = record.recordID
				outcome.node.MemberRecordID = memberRecordID
				outcome.node.Opaque = false
				outcome.node.Revoked = false
				if record.recipient != "" {
					builder.nodes[record.recipient] = outcome.node
				}
			}
		}
		if record.recipient == builder.selfDID && outcome.node == nil {
			return fmt.Errorf("materializing self node %s: unreadable without a recipient-matched last-good node: %w", record.recordID, err)
		}
		parsed.store(record, rawParsedNode, outcome)
		return nil
	}
	if node := builder.nodes[record.recipient]; node != nil && node.RecordID == record.recordID {
		parsed.store(record, rawParsedNode, rawParsedOutcome{node: node})
	} else {
		// A successfully decoded node without a public recipient contributes
		// nothing; cache the stable skip so unrelated deltas do not reparse it.
		parsed.store(record, rawParsedNode, rawParsedOutcome{opaque: true})
	}

	return nil
}

func materializeEndpointRecord(
	ctx context.Context,
	builder *DWNClient,
	parentNode *NodeRecord,
	record rawMeshRecord,
	decryptor EntryDecryptor,
) (*EndpointData, error) {
	failureKey := record.parentID
	if failureKey == "" {
		failureKey = record.recordID
	}
	var endpoint EndpointData
	if err := ParseEntryData(record.raw, &endpoint, decryptor); err != nil {
		builder.unreadableEndpoints.Add(1)
		if builder.endpointFailures == nil {
			builder.endpointFailures = make(map[string]string)
		}
		failureClass := endpointFailureClass(err)
		if previous, warned := builder.endpointFailures[failureKey]; !warned || previous != failureClass {
			builder.logger.WarnContext(ctx, "endpoint record could not be loaded; peer connectivity may be degraded",
				slog.Any("error", err),
				slog.String("failureClass", failureClass),
				slog.String("nodeDID", parentNode.DID),
				slog.String("recordId", record.recordID),
				slog.String("parentId", record.parentID),
			)
		}
		builder.endpointFailures[failureKey] = failureClass
		return nil, err
	}
	if _, recovering := builder.endpointFailures[failureKey]; recovering {
		delete(builder.endpointFailures, failureKey)
		builder.logger.InfoContext(ctx, "endpoint record is readable again",
			slog.String("recordId", record.recordID),
			slog.String("parentId", record.parentID),
		)
	}
	parentNode.Endpoints = append(parentNode.Endpoints, endpoint)
	return &endpoint, nil
}

type materializedNodeParent struct {
	node         *NodeRecord
	contextID    string
	infoPath     string
	endpointPath string
}

func materializedNodeParents(networkRecordID string, nodes map[string]*NodeRecord) map[string]materializedNodeParent {
	parents := make(map[string]materializedNodeParent, len(nodes))
	for _, node := range nodes {
		if node == nil || node.RecordID == "" {
			continue
		}
		if node.MemberRecordID != "" {
			parents[node.RecordID] = materializedNodeParent{
				node:         node,
				contextID:    networkRecordID + "/" + node.MemberRecordID + "/" + node.RecordID,
				infoPath:     "network/member/node/nodeInfo",
				endpointPath: "network/member/node/endpoint",
			}
			continue
		}
		parents[node.RecordID] = materializedNodeParent{
			node:         node,
			contextID:    networkRecordID + "/" + node.RecordID,
			infoPath:     "network/node/nodeInfo",
			endpointPath: "network/node/endpoint",
		}
	}
	return parents
}

func (c *DWNClient) cloneEndpointFailures() map[string]string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	cloned := make(map[string]string, len(c.endpointFailures))
	for key, class := range c.endpointFailures {
		cloned[key] = class
	}
	return cloned
}

func (c *DWNClient) cloneNodeFailures() map[string]string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	cloned := make(map[string]string, len(c.nodeFailures))
	for key, class := range c.nodeFailures {
		cloned[key] = class
	}
	return cloned
}

func shouldAbortRawMaterialization(ctx context.Context, err error) bool {
	return shouldAbortStateLoad(ctx, err) || errors.Is(err, dwn.ErrTransport)
}

func (c *DWNClient) cloneACLPolicy() *ACLPolicyData {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return cloneACLPolicyData(c.acl)
}

func cloneRawParsedOutcome(outcome rawParsedOutcome) rawParsedOutcome {
	outcome.network = cloneNetworkConfig(outcome.network)
	outcome.member = cloneMemberRecord(outcome.member)
	outcome.node = cloneNodeRecord(outcome.node)
	outcome.relay = cloneRelayData(outcome.relay)
	outcome.acl = cloneACLPolicyData(outcome.acl)
	outcome.nodeInfo = cloneNodeInfoData(outcome.nodeInfo)
	outcome.endpoint = cloneEndpointData(outcome.endpoint)
	return outcome
}

func cloneNetworkConfig(source *NetworkConfig) *NetworkConfig {
	if source == nil {
		return nil
	}
	cloned := *source
	cloned.DNSServers = append([]string(nil), source.DNSServers...)
	return &cloned
}

func cloneMemberRecord(source *MemberRecord) *MemberRecord {
	if source == nil {
		return nil
	}
	cloned := *source
	return &cloned
}

func cloneNodeRecord(source *NodeRecord) *NodeRecord {
	if source == nil {
		return nil
	}
	cloned := *source
	cloned.AllowedIPs = append([]string(nil), source.AllowedIPs...)
	cloned.Info = cloneNodeInfoData(source.Info)
	if source.Endpoints != nil {
		cloned.Endpoints = make([]EndpointData, len(source.Endpoints))
		for i := range source.Endpoints {
			cloned.Endpoints[i] = *cloneEndpointData(&source.Endpoints[i])
		}
	}
	return &cloned
}

func cloneRelayData(source *RelayData) *RelayData {
	if source == nil {
		return nil
	}
	cloned := *source
	return &cloned
}

func cloneACLPolicyData(source *ACLPolicyData) *ACLPolicyData {
	if source == nil {
		return nil
	}
	cloned := *source
	if source.Groups != nil {
		cloned.Groups = make(map[string][]string, len(source.Groups))
		for name, members := range source.Groups {
			cloned.Groups[name] = append([]string(nil), members...)
		}
	}
	if source.Rules != nil {
		cloned.Rules = make([]ACLRule, len(source.Rules))
		for i, rule := range source.Rules {
			cloned.Rules[i] = rule
			cloned.Rules[i].Src = append([]string(nil), rule.Src...)
			cloned.Rules[i].Dst = append([]string(nil), rule.Dst...)
			cloned.Rules[i].SrcPorts = append([]string(nil), rule.SrcPorts...)
			cloned.Rules[i].DstPorts = append([]string(nil), rule.DstPorts...)
		}
	}
	return &cloned
}

func cloneNodeInfoData(source *NodeInfoData) *NodeInfoData {
	if source == nil {
		return nil
	}
	cloned := *source
	cloned.Capabilities = append([]string(nil), source.Capabilities...)
	return &cloned
}

func cloneEndpointData(source *EndpointData) *EndpointData {
	if source == nil {
		return nil
	}
	cloned := *source
	cloned.PublicEndpoints = append([]PublicEndpoint(nil), source.PublicEndpoints...)
	cloned.LocalEndpoints = append([]string(nil), source.LocalEndpoints...)
	return &cloned
}
