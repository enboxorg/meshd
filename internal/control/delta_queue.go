package control

import (
	"context"
	"errors"
	"fmt"

	"github.com/enboxorg/meshd/internal/dwn"
	dwncrypto "github.com/enboxorg/meshd/internal/dwn/crypto"
	"github.com/enboxorg/meshd/protocols"
)

const (
	maxPendingTopologyEvents  = 4096
	maxPendingTopologyBytes   = 8 << 20
	pendingTopologyFixedBytes = 64
)

// ErrFullReconciliationRequired means the local raw cache cannot prove that
// it has a complete topology history and must be replaced by a full snapshot.
var ErrFullReconciliationRequired = errors.New("full reconciliation required")

// PendingStateValidator validates a fully projected local state before its
// raw/parsed state and captured event prefix are committed. The callback runs
// while the client's load transaction is serialized and must not call back
// into methods that acquire loadMu.
type PendingStateValidator func(*MapResponse) error

type pendingTopologyEvent struct {
	sequence      uint64
	message       *dwn.SubscriptionMessage
	retainedBytes int
}

// beginFullReconciliation captures the topology sequence immediately before a
// remote snapshot begins. installRawBaseline uses it as a cut: events staged
// after this sequence survive the baseline installation.
func (c *DWNClient) beginFullReconciliation() uint64 {
	c.deltaMu.Lock()
	defer c.deltaMu.Unlock()
	return c.topologySequence
}

// installRawBaseline installs an independently owned complete raw snapshot and
// removes only events and repair markers covered by that snapshot. The caller
// serializes complete loads through loadMu.
func (c *DWNClient) installRawBaseline(set *rawMeshRecordSet, through uint64) {
	c.deltaMu.Lock()
	defer c.deltaMu.Unlock()
	if set == nil {
		c.rawBaseline = nil
		c.clearPendingTopologyLocked()
		c.markFullReconciliationLocked()
		return
	}

	c.rawBaseline = set.clone()
	c.trimPendingTopologyPrefixLocked(through)
	if c.fullReconciliation && c.repairSequence <= through {
		c.fullReconciliation = false
		c.repairSequence = 0
	}
}

// completeFullReconciliation atomically publishes one validated full snapshot.
// A repair marker newer than the fetch cut invalidates the candidate, while
// ordinary post-cut events remain queued for the next incremental refresh.
func (c *DWNClient) completeFullReconciliation(
	ctx context.Context,
	candidate *rawMeshRecordSet,
	projection *rawMeshMaterialization,
	through uint64,
) error {
	if candidate == nil || projection == nil {
		return fmt.Errorf("completing full reconciliation: nil candidate or projection")
	}
	installed := candidate.clone()
	c.deltaMu.Lock()
	if err := ctx.Err(); err != nil {
		c.deltaMu.Unlock()
		return errors.Join(ErrFullReconciliationRequired, err)
	}
	if c.fullReconciliation && c.repairSequence > through {
		c.deltaMu.Unlock()
		return ErrFullReconciliationRequired
	}

	c.mu.Lock()
	if err := ctx.Err(); err != nil {
		c.mu.Unlock()
		c.deltaMu.Unlock()
		return errors.Join(ErrFullReconciliationRequired, err)
	}
	c.commitRawMeshMaterializationLocked(projection)
	c.rawBaseline = installed
	c.trimPendingTopologyPrefixLocked(through)
	if c.fullReconciliation && c.repairSequence <= through {
		c.fullReconciliation = false
		c.repairSequence = 0
	}
	c.mu.Unlock()
	c.deltaMu.Unlock()
	c.commitRawMeshMaterializationCounters(projection)
	return nil
}

// StageTopologyEvent retains a deep copy of one map-affecting event. Poison or
// ambiguous frames are ACKed but mark the cache for repair so they cannot cause
// an infinite reconnect loop. The bounded queue remains safe under a stalled
// consumer.
func (c *DWNClient) StageTopologyEvent(message *dwn.SubscriptionMessage) error {
	if rawTopologyEventAffectsDecryptContext(message) {
		c.invalidateRawParsedOutcomes()
		c.deliveredAudienceKeys.invalidateFailures()
		c.roleAudienceKeys.invalidateFailures()
		c.RequireFullReconciliation()
		return nil
	}
	relevant, certain := rawTopologyEventAffectsMap(message)
	if !certain {
		c.deltaMu.Lock()
		c.clearPendingTopologyLocked()
		c.markFullReconciliationLocked()
		c.deltaMu.Unlock()
		return nil
	}
	if !relevant {
		return nil
	}
	eventBytes := pendingTopologyMessageBytes(message)
	if eventBytes > maxPendingTopologyBytes {
		c.deltaMu.Lock()
		c.clearPendingTopologyLocked()
		c.markFullReconciliationLocked()
		c.deltaMu.Unlock()
		return nil
	}
	cloned, err := clonePendingTopologyMessage(message)
	if err != nil {
		c.deltaMu.Lock()
		c.clearPendingTopologyLocked()
		c.markFullReconciliationLocked()
		c.deltaMu.Unlock()
		return nil
	}

	c.deltaMu.Lock()
	defer c.deltaMu.Unlock()
	// Account the retained clone, not the caller-owned message. Rechecking also
	// keeps the bound exact if a caller mutated its message between sizing and
	// cloning (concurrent mutation remains outside the API contract).
	eventBytes = pendingTopologyMessageBytes(cloned)
	if len(c.pendingTopology) >= maxPendingTopologyEvents ||
		eventBytes > maxPendingTopologyBytes || c.pendingTopologyBytes > maxPendingTopologyBytes-eventBytes {
		c.clearPendingTopologyLocked()
		c.markFullReconciliationLocked()
		return nil
	}
	c.topologySequence++
	c.pendingTopology = append(c.pendingTopology, pendingTopologyEvent{
		sequence:      c.topologySequence,
		message:       cloned,
		retainedBytes: eventBytes,
	})
	c.pendingTopologyBytes += eventBytes
	return nil
}

func rawTopologyEventAffectsDecryptContext(message *dwn.SubscriptionMessage) bool {
	if message == nil || message.Type != dwn.SubscriptionEventType || message.Event == nil || len(message.Event.Message) == 0 {
		return false
	}
	method, err := classifyRawRecordMessage(message.Event.Message)
	if err != nil {
		return false
	}
	var protocol, path string
	if method == "Write" {
		write, _, err := unwrapRawRecordMessage(message.Event.Message, "recordsWrite")
		if err != nil || write.Descriptor == nil {
			return false
		}
		protocol, path = write.Descriptor.Protocol, write.Descriptor.ProtocolPath
	} else {
		if len(message.Event.InitialWrite) == 0 {
			return false
		}
		initial, _, err := unwrapRawRecordMessage(message.Event.InitialWrite, "recordsWrite")
		if err != nil || initial.Descriptor == nil {
			return false
		}
		protocol, path = initial.Descriptor.Protocol, initial.Descriptor.ProtocolPath
	}
	return (protocol == protocols.MeshProtocolURI &&
		(path == dwncrypto.EncryptionControlAudiencePath || path == dwncrypto.EncryptionControlDeliveryPath)) ||
		(protocol == dwncrypto.EncryptionProtocolURI && path == dwncrypto.GrantKeyProtocolPath)
}

// RequireFullReconciliation invalidates delta continuity after a subscription
// gap or another condition that a local replay cannot repair.
func (c *DWNClient) RequireFullReconciliation() {
	c.deltaMu.Lock()
	c.clearPendingTopologyLocked()
	c.markFullReconciliationLocked()
	c.deltaMu.Unlock()
}

func (c *DWNClient) markFullReconciliationLocked() {
	c.topologySequence++
	c.repairSequence = c.topologySequence
	c.fullReconciliation = true
}

// beginPendingTopology snapshots a baseline and deeply copied queue prefix.
// The returned sequence fences precisely which events a successful apply may
// remove while later concurrently staged events remain queued.
func (c *DWNClient) beginPendingTopology() (*rawMeshRecordSet, []pendingTopologyEvent, uint64, error) {
	c.deltaMu.Lock()
	defer c.deltaMu.Unlock()
	if c.fullReconciliation || c.rawBaseline == nil {
		return nil, nil, 0, ErrFullReconciliationRequired
	}
	baseline := c.rawBaseline.clone()
	events := make([]pendingTopologyEvent, len(c.pendingTopology))
	var through uint64
	for i, event := range c.pendingTopology {
		message, err := clonePendingTopologyMessage(event.message)
		if err != nil {
			c.clearPendingTopologyLocked()
			c.markFullReconciliationLocked()
			return nil, nil, 0, ErrFullReconciliationRequired
		}
		events[i] = pendingTopologyEvent{
			sequence:      event.sequence,
			message:       message,
			retainedBytes: event.retainedBytes,
		}
		through = event.sequence
	}
	return baseline, events, through, nil
}

func (c *DWNClient) completePendingTopology(ctx context.Context, candidate *rawMeshRecordSet, projection *rawMeshMaterialization, through uint64) error {
	c.deltaMu.Lock()
	defer c.deltaMu.Unlock()
	if c.fullReconciliation || c.rawBaseline == nil {
		return ErrFullReconciliationRequired
	}
	if err := ctx.Err(); err != nil {
		c.clearPendingTopologyLocked()
		c.markFullReconciliationLocked()
		return errors.Join(ErrFullReconciliationRequired, err)
	}
	if through == 0 {
		return nil
	}
	prefix := 0
	for prefix < len(c.pendingTopology) && c.pendingTopology[prefix].sequence <= through {
		prefix++
	}
	if prefix == 0 || c.pendingTopology[prefix-1].sequence != through {
		c.clearPendingTopologyLocked()
		c.markFullReconciliationLocked()
		return ErrFullReconciliationRequired
	}
	c.mu.Lock()
	c.commitRawMeshMaterializationLocked(projection)
	c.rawBaseline = candidate
	c.trimPendingTopologyPrefixLocked(through)
	c.mu.Unlock()
	c.commitRawMeshMaterializationCounters(projection)
	return nil
}

// ApplyPendingState builds and commits the current map from local state.
// Callers that must validate a derived representation before commit should use
// ApplyPendingStateValidated.
func (c *DWNClient) ApplyPendingState(ctx context.Context) (*MapResponse, error) {
	return c.ApplyPendingStateValidated(ctx, nil)
}

// ApplyPendingStateValidated builds the current map from local state,
// hydrating only a write whose subscription frame omitted its data. The
// validator runs after complete projection but before the raw baseline, parsed
// state, counters, or captured queue prefix are committed. A validation error
// leaves the complete candidate pending for a later retry.
func (c *DWNClient) ApplyPendingStateValidated(ctx context.Context, validate PendingStateValidator) (*MapResponse, error) {
	if ctx == nil {
		return nil, fmt.Errorf("applying pending topology: nil context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	c.loadMu.Lock()
	defer c.loadMu.Unlock()

	candidate, events, through, err := c.beginPendingTopology()
	if err != nil {
		return nil, err
	}
	if len(events) == 0 {
		response := c.buildMapResponse()
		if response == nil {
			c.RequireFullReconciliation()
			return nil, ErrFullReconciliationRequired
		}
		if validate != nil {
			if err := validate(response); err != nil {
				return response, err
			}
		}
		// Fence publication against repair or cancellation racing validation.
		if err := c.completePendingTopology(ctx, candidate, nil, 0); err != nil {
			return nil, err
		}
		return response, nil
	}

	for _, event := range events {
		if err := c.applyPendingTopologyEvent(ctx, candidate, event.message); err != nil {
			c.RequireFullReconciliation()
			return nil, errors.Join(ErrFullReconciliationRequired, err)
		}
	}
	projection, err := c.projectRawMeshRecordSetWithDecryptors(ctx, candidate, c.makeDecryptor)
	if err != nil {
		c.RequireFullReconciliation()
		return nil, errors.Join(ErrFullReconciliationRequired, err)
	}
	if validate != nil {
		if err := validate(projection.response); err != nil {
			return projection.response, err
		}
	}
	if err := c.completePendingTopology(ctx, candidate, projection, through); err != nil {
		return nil, err
	}
	return projection.response, nil
}

func (c *DWNClient) applyPendingTopologyEvent(ctx context.Context, candidate *rawMeshRecordSet, message *dwn.SubscriptionMessage) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := candidate.applySubscriptionMessage(message, ""); err == nil {
		return nil
	} else if !errors.Is(err, errRawMeshRecordDataUnavailable) {
		return err
	}
	return c.hydrateAndApplyTopologyWrite(ctx, candidate, message)
}

func (c *DWNClient) hydrateAndApplyTopologyWrite(ctx context.Context, candidate *rawMeshRecordSet, message *dwn.SubscriptionMessage) error {
	recordID, err := topologyWriteRecordID(message)
	if err != nil {
		return err
	}
	if c.anchorDWN == nil {
		return fmt.Errorf("hydrating topology record %s: no anchor DWN client", recordID)
	}
	result, err := c.anchorDWN.RecordsReadWithAuth(
		ctx,
		c.anchorTenant,
		dwn.RecordsFilter{RecordID: recordID},
		c.readAuth(c.protocolRole),
	)
	if err != nil {
		return fmt.Errorf("hydrating topology record %s: %w", recordID, err)
	}
	raw, err := rawMeshRecordReadEntry(result)
	if err != nil {
		return fmt.Errorf("hydrating topology record %s: %w", recordID, err)
	}
	original, err := normalizeRawMeshRecordIdentity(message.Event.Message, "")
	if err != nil {
		return fmt.Errorf("hydrating topology record %s: invalid original write: %w", recordID, err)
	}
	record, err := normalizeRawMeshRecord(raw, "")
	if err != nil {
		return fmt.Errorf("hydrating topology record %s: %w", recordID, err)
	}
	if record.recordID != original.recordID || record.protocol != original.protocol ||
		record.protocolPath != original.protocolPath || record.contextID != original.contextID ||
		record.parentID != original.parentID || record.recipient != original.recipient ||
		record.dateCreated != original.dateCreated {
		return fmt.Errorf("hydrating topology record %s: read returned a different immutable record slot", recordID)
	}
	if compareRawMeshRecordRevision(record.head(), original.head()) < 0 {
		return fmt.Errorf("hydrating topology record %s: read returned stale head %s before event %s",
			recordID, record.messageCID, original.messageCID)
	}

	// Apply the read head by its own canonical identity. Replaying it with the
	// subscription frame would compare a newer head against the original cursor CID.
	candidate.mu.Lock()
	candidate.initLocked(1)
	candidate.applyWriteLocked(record)
	candidate.mu.Unlock()
	return nil
}

func rawTopologyEventAffectsMap(message *dwn.SubscriptionMessage) (relevant, certain bool) {
	if message != nil && message.IsLatestBaseState != nil && !*message.IsLatestBaseState {
		return false, true
	}
	if message == nil || message.Type != dwn.SubscriptionEventType || message.Event == nil || len(message.Event.Message) == 0 {
		return false, false
	}
	method, err := classifyRawRecordMessage(message.Event.Message)
	if err != nil {
		return false, false
	}
	if method == "Delete" {
		if len(message.Event.InitialWrite) == 0 {
			return true, true
		}
		deletion, err := normalizeRawMeshRecordDelete(message.Event.Message)
		if err != nil {
			return false, false
		}
		initial, err := normalizeRawMeshRecordIdentity(message.Event.InitialWrite, "")
		if err != nil || initial.recordID != deletion.recordID {
			return false, false
		}
		if initial.protocol != protocols.MeshProtocolURI {
			return false, true
		}
		return rawMeshMapProtocolPath(initial.protocolPath), true
	}
	write, _, err := unwrapRawRecordMessage(message.Event.Message, "recordsWrite")
	if err != nil || write.Descriptor == nil || write.Descriptor.Protocol == "" || write.Descriptor.ProtocolPath == "" {
		return false, false
	}
	if write.Descriptor.Protocol != protocols.MeshProtocolURI {
		return false, true
	}
	return rawMeshMapProtocolPath(write.Descriptor.ProtocolPath), true
}

func rawMeshMapProtocolPath(path string) bool {
	switch path {
	case "network", "network/member", "network/node", "network/member/node",
		"network/relay", "network/aclPolicy", "network/node/nodeInfo",
		"network/member/node/nodeInfo", "network/node/endpoint",
		"network/member/node/endpoint":
		return true
	default:
		return false
	}
}

func topologyWriteRecordID(message *dwn.SubscriptionMessage) (string, error) {
	if message == nil || message.Event == nil {
		return "", fmt.Errorf("topology write is missing its event")
	}
	write, _, err := unwrapRawRecordMessage(message.Event.Message, "recordsWrite")
	if err != nil {
		return "", err
	}
	if write.RecordID == "" {
		return "", fmt.Errorf("topology write is missing recordId")
	}
	return write.RecordID, nil
}

func pendingTopologyMessageBytes(message *dwn.SubscriptionMessage) int {
	if message == nil {
		return 0
	}
	size := pendingTopologyFixedBytes + len(message.Type) + len(message.Seq) +
		len(message.MessageCID) + len(message.Protocol) + len(message.EncodedData)
	if message.Cursor != nil {
		size += len(message.Cursor.StreamID) + len(message.Cursor.Epoch) +
			len(message.Cursor.Position) + len(message.Cursor.MessageCID)
	}
	if message.Event != nil {
		size += len(message.Event.Message) + len(message.Event.InitialWrite)
	}
	if message.Error != nil {
		size += len(message.Error.Code) + len(message.Error.Detail)
	}
	return size
}

func pendingTopologyEventsBytes(events []pendingTopologyEvent) int {
	total := 0
	for _, event := range events {
		total += pendingTopologyMessageBytes(event.message)
	}
	return total
}

func (c *DWNClient) trimPendingTopologyPrefixLocked(through uint64) {
	first := 0
	removedBytes := 0
	for first < len(c.pendingTopology) && c.pendingTopology[first].sequence <= through {
		removedBytes += c.pendingTopology[first].retainedBytes
		first++
	}
	if first == 0 {
		return
	}
	remaining := append([]pendingTopologyEvent(nil), c.pendingTopology[first:]...)
	clear(c.pendingTopology)
	c.pendingTopology = remaining
	c.pendingTopologyBytes -= removedBytes
}

func (c *DWNClient) clearPendingTopologyLocked() {
	clear(c.pendingTopology)
	c.pendingTopology = nil
	c.pendingTopologyBytes = 0
}

func clonePendingTopologyMessage(message *dwn.SubscriptionMessage) (*dwn.SubscriptionMessage, error) {
	if message == nil || message.Type != dwn.SubscriptionEventType || message.Event == nil || len(message.Event.Message) == 0 {
		return nil, fmt.Errorf("invalid topology event")
	}
	cloned := *message
	if message.Cursor != nil {
		cursor := *message.Cursor
		cloned.Cursor = &cursor
	}
	event := *message.Event
	event.Message = cloneRawJSON(message.Event.Message)
	event.InitialWrite = cloneRawJSON(message.Event.InitialWrite)
	cloned.Event = &event
	if message.Error != nil {
		wireError := *message.Error
		cloned.Error = &wireError
	}
	if message.IsLatestBaseState != nil {
		latest := *message.IsLatestBaseState
		cloned.IsLatestBaseState = &latest
	}
	return &cloned, nil
}
