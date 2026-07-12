package control

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/enboxorg/meshd/internal/dwn"
)

var (
	errMalformedRawMeshRecord        = errors.New("malformed raw mesh record")
	errRawMeshRecordDataUnavailable  = errors.New("raw mesh record data unavailable")
	errUnsupportedRawMeshRecordEvent = errors.New("unsupported raw mesh record event")
)

// rawMeshRecordMethod and rawMeshRecordRevision mirror the DWN base-state
// lattice. messageCID is the canonical tie-breaker for equal timestamps.
type rawMeshRecordMethod uint8

const (
	rawMeshRecordWrite rawMeshRecordMethod = iota + 1
	rawMeshRecordDelete
)

type rawMeshSquashSlot struct {
	protocol        string
	protocolPath    string
	parentContextID string
}

type rawMeshRecordRevision struct {
	method           rawMeshRecordMethod
	messageTimestamp string
	revision         time.Time
	messageCID       string
	prune            bool
	slot             rawMeshSquashSlot
}

// rawMeshRecord is the lossless local representation of one RecordsWrite.
// The descriptor fields are duplicated here so callers can route records
// without repeatedly decoding raw. raw and all values returned from this type
// are deep copies; a caller never receives storage owned by the record set.
type rawMeshRecord struct {
	raw              json.RawMessage
	recordID         string
	protocol         string
	protocolPath     string
	contextID        string
	parentContextID  string
	parentID         string
	recipient        string
	dateCreated      string
	dateCreatedTime  time.Time
	messageTimestamp string
	revision         time.Time
	messageCID       string
	squash           bool
}

func (r rawMeshRecord) clone() rawMeshRecord {
	r.raw = cloneRawJSON(r.raw)
	return r
}

func (r rawMeshRecord) slot() rawMeshSquashSlot {
	return rawMeshSquashSlot{
		protocol:        r.protocol,
		protocolPath:    r.protocolPath,
		parentContextID: r.parentContextID,
	}
}

func (r rawMeshRecord) head() rawMeshRecordRevision {
	return rawMeshRecordRevision{
		method:           rawMeshRecordWrite,
		messageTimestamp: r.messageTimestamp,
		revision:         r.revision,
		messageCID:       r.messageCID,
		slot:             r.slot(),
	}
}

type rawMeshRecordDeleteData struct {
	recordID string
	rawMeshRecordRevision
}

// rawMeshRecordSet indexes the latest RecordsWrite by record ID. heads also
// retains delete tombstones, whose delete-wins lattice permanently prevents a
// delayed RecordsWrite from resurrecting the record. Squash indexes mirror the
// DWN server's (protocol, protocolPath, parent-context) scope.
type rawMeshRecordSet struct {
	mu           sync.RWMutex
	records      map[string]rawMeshRecord
	heads        map[string]rawMeshRecordRevision
	slotRecords  map[rawMeshSquashSlot]map[string]struct{}
	squashFloors map[rawMeshSquashSlot]time.Time
}

func (s *rawMeshRecordSet) initLocked(capacity int) {
	if s.records == nil {
		s.records = make(map[string]rawMeshRecord, capacity)
	}
	if s.heads == nil {
		s.heads = make(map[string]rawMeshRecordRevision, capacity)
	}
	if s.slotRecords == nil {
		s.slotRecords = make(map[rawMeshSquashSlot]map[string]struct{})
	}
	if s.squashFloors == nil {
		s.squashFloors = make(map[rawMeshSquashSlot]time.Time)
	}
}

func newRawMeshRecordSet(entries []json.RawMessage, pathHint string) (*rawMeshRecordSet, error) {
	set := &rawMeshRecordSet{}
	set.initLocked(len(entries))
	if _, err := set.addEntries(entries, pathHint); err != nil {
		return nil, err
	}
	return set, nil
}

// addEntries atomically normalizes RecordsWrite query entries before merging
// them. Sorting by the DWN revision order makes reconstruction deterministic
// and lets a visible squash record rebuild its slot floor.
func (s *rawMeshRecordSet) addEntries(entries []json.RawMessage, pathHint string) (changed bool, err error) {
	if s == nil {
		return false, fmt.Errorf("%w: nil record set", errMalformedRawMeshRecord)
	}
	records := make([]rawMeshRecord, 0, len(entries))
	for i, entry := range entries {
		record, err := normalizeRawMeshRecord(entry, pathHint)
		if err != nil {
			return false, fmt.Errorf("entry %d: %w", i, err)
		}
		records = append(records, record)
	}
	sort.SliceStable(records, func(i, j int) bool {
		if comparison := compareRawMeshRecordRevision(records[i].head(), records[j].head()); comparison != 0 {
			return comparison < 0
		}
		return records[i].recordID < records[j].recordID
	})

	s.mu.Lock()
	defer s.mu.Unlock()
	s.initLocked(len(records))

	// A RecordsQuery batch is an already-visible snapshot. Floors that predate
	// this batch still fence stale data, but squash writes within the batch are
	// resolved together so equal-timestamp siblings deliberately retained by
	// the server are not made order-dependent.
	floorsBefore := make(map[rawMeshSquashSlot]time.Time, len(s.squashFloors))
	for slot, floor := range s.squashFloors {
		floorsBefore[slot] = floor
	}
	var squashes []rawMeshRecord
	for _, record := range records {
		if floor, ok := floorsBefore[record.slot()]; ok && !record.revision.After(floor) {
			if current, exists := s.heads[record.recordID]; !exists || compareRawMeshRecordRevision(record.head(), current) != 0 {
				continue
			}
		}
		if !s.writeCouldApplyLocked(record) {
			continue
		}
		s.storeWriteLocked(record)
		changed = true
		if record.squash {
			squashes = append(squashes, record)
		}
	}
	for _, squash := range squashes {
		current, ok := s.heads[squash.recordID]
		if !ok || current.method != rawMeshRecordWrite || current.messageCID != squash.messageCID {
			continue
		}
		changed = s.applySquashLocked(squash) || changed
	}
	return changed, nil
}

func (s *rawMeshRecordSet) clone() *rawMeshRecordSet {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	cloned := &rawMeshRecordSet{}
	cloned.initLocked(len(s.records))
	for id, record := range s.records {
		cloned.records[id] = record.clone()
	}
	for id, head := range s.heads {
		cloned.heads[id] = head
	}
	for slot, ids := range s.slotRecords {
		clonedIDs := make(map[string]struct{}, len(ids))
		for id := range ids {
			clonedIDs[id] = struct{}{}
		}
		cloned.slotRecords[slot] = clonedIDs
	}
	for slot, floor := range s.squashFloors {
		cloned.squashFloors[slot] = floor
	}
	return cloned
}

func (s *rawMeshRecordSet) len() int {
	if s == nil {
		return 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.records)
}

func (s *rawMeshRecordSet) get(recordID string) (rawMeshRecord, bool) {
	if s == nil {
		return rawMeshRecord{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	record, ok := s.records[recordID]
	return record.clone(), ok
}

// all returns a deterministic, deeply cloned snapshot ordered by record ID.
func (s *rawMeshRecordSet) all() []rawMeshRecord {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	ids := make([]string, 0, len(s.records))
	for id := range s.records {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	records := make([]rawMeshRecord, 0, len(ids))
	for _, id := range ids {
		records = append(records, s.records[id].clone())
	}
	return records
}

// applySubscriptionMessage applies one Records Write/Delete event. An explicit
// non-latest row is ignorable, but every accepted event is still fenced by the
// canonical DWN revision and delete-wins lattice because replay can overlap a
// newer full-reconciliation baseline.
func (s *rawMeshRecordSet) applySubscriptionMessage(message *dwn.SubscriptionMessage, pathHint string) (changed bool, err error) {
	if s == nil {
		return false, fmt.Errorf("%w: nil record set", errMalformedRawMeshRecord)
	}
	if message != nil && message.IsLatestBaseState != nil && !*message.IsLatestBaseState {
		return false, nil
	}
	if message == nil {
		return false, fmt.Errorf("%w: nil subscription message", errMalformedRawMeshRecord)
	}
	if message.Type != dwn.SubscriptionEventType {
		return false, fmt.Errorf("%w: subscription message type %q", errUnsupportedRawMeshRecordEvent, message.Type)
	}
	if message.Event == nil || len(message.Event.Message) == 0 {
		return false, fmt.Errorf("%w: subscription event is missing event.message", errMalformedRawMeshRecord)
	}

	computedCID, err := validateSubscriptionRecordMessageCID(message)
	if err != nil {
		return false, err
	}
	messageType, err := classifyRawRecordMessage(message.Event.Message)
	if err != nil {
		return false, err
	}
	switch messageType {
	case "Write":
		identity, err := normalizeRawMeshRecordIdentity(message.Event.Message, pathHint)
		if err != nil {
			return false, err
		}
		if identity.messageCID != computedCID {
			return false, fmt.Errorf("%w: RecordsWrite CID changed while normalizing", errMalformedRawMeshRecord)
		}
		s.mu.RLock()
		couldApply := s.writeCouldApplyLocked(identity)
		s.mu.RUnlock()
		if !couldApply {
			return false, nil
		}

		raw, err := injectSubscriptionEncodedData(message.Event.Message, message.EncodedData)
		if err != nil {
			return false, err
		}
		if !rawRecordHasEncodedData(raw) {
			return false, fmt.Errorf("%w: RecordsWrite event is missing encoded data", errRawMeshRecordDataUnavailable)
		}
		record, err := normalizeRawMeshRecord(raw, pathHint)
		if err != nil {
			return false, err
		}
		if record.messageCID != computedCID {
			return false, fmt.Errorf("%w: RecordsWrite CID changed while attaching data", errMalformedRawMeshRecord)
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		s.initLocked(1)
		return s.applyWriteLocked(record), nil
	case "Delete":
		deletion, err := normalizeRawMeshRecordDelete(message.Event.Message)
		if err != nil {
			return false, err
		}
		if deletion.messageCID != computedCID {
			return false, fmt.Errorf("%w: RecordsDelete CID changed while normalizing", errMalformedRawMeshRecord)
		}
		if len(message.Event.InitialWrite) != 0 {
			identity, identityErr := normalizeRawMeshRecordIdentity(message.Event.InitialWrite, pathHint)
			if identityErr != nil {
				return false, fmt.Errorf("%w: invalid delete initialWrite: %v", errMalformedRawMeshRecord, identityErr)
			}
			if identity.recordID != deletion.recordID {
				return false, fmt.Errorf("%w: delete recordId %q does not match initialWrite %q", errMalformedRawMeshRecord, deletion.recordID, identity.recordID)
			}
			deletion.slot = identity.slot()
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		s.initLocked(1)
		return s.applyDeleteLocked(deletion), nil
	default:
		return false, fmt.Errorf("%w: Records method %q", errUnsupportedRawMeshRecordEvent, messageType)
	}
}

func (s *rawMeshRecordSet) writeCouldApplyLocked(record rawMeshRecord) bool {
	incoming := record.head()
	if current, ok := s.heads[record.recordID]; ok {
		if current.method == rawMeshRecordDelete {
			return false
		}
		if compareRawMeshRecordRevision(incoming, current) <= 0 {
			return false
		}
	}
	if floor, ok := s.squashFloors[record.slot()]; ok && !record.revision.After(floor) {
		return false
	}
	return true
}

func (s *rawMeshRecordSet) storeWriteLocked(record rawMeshRecord) {
	slot := record.slot()
	if previous, ok := s.heads[record.recordID]; ok && previous.slot != slot {
		s.removeSlotRecordLocked(previous.slot, record.recordID)
	}
	s.records[record.recordID] = record.clone()
	s.heads[record.recordID] = record.head()
	s.addSlotRecordLocked(slot, record.recordID)
}

func (s *rawMeshRecordSet) applyWriteLocked(record rawMeshRecord) bool {
	if !s.writeCouldApplyLocked(record) {
		return false
	}
	s.storeWriteLocked(record)
	changed := true
	if record.squash {
		changed = s.applySquashLocked(record) || changed
	}
	return changed
}

func (s *rawMeshRecordSet) applySquashLocked(record rawMeshRecord) bool {
	slot := record.slot()
	changed := false
	for siblingID := range s.slotRecords[slot] {
		if siblingID == record.recordID {
			continue
		}
		sibling, ok := s.heads[siblingID]
		if ok && sibling.method == rawMeshRecordWrite && sibling.revision.Before(record.revision) {
			s.removeHeadLocked(siblingID)
			changed = true
		}
	}
	if floor, ok := s.squashFloors[slot]; !ok || record.revision.After(floor) {
		s.squashFloors[slot] = record.revision
	}
	return changed
}

func (s *rawMeshRecordSet) applyDeleteLocked(incoming rawMeshRecordDeleteData) bool {
	current, exists := s.heads[incoming.recordID]
	if exists {
		switch current.method {
		case rawMeshRecordWrite:
			// A stale replay delete must not remove a newer live base state.
			if compareRawMeshRecordRevision(incoming.rawMeshRecordRevision, current) <= 0 {
				return false
			}
		case rawMeshRecordDelete:
			// Delete is terminal. The sole legal transition is a strictly newer
			// prune replacing a plain tombstone.
			if current.prune || !incoming.prune ||
				compareRawMeshRecordRevision(incoming.rawMeshRecordRevision, current) <= 0 {
				return false
			}
		}
	}

	if exists {
		incoming.slot = current.slot
	}
	_, visible := s.records[incoming.recordID]
	delete(s.records, incoming.recordID)
	if exists && current.slot != incoming.slot {
		s.removeSlotRecordLocked(current.slot, incoming.recordID)
	}
	s.heads[incoming.recordID] = incoming.rawMeshRecordRevision
	s.addSlotRecordLocked(incoming.slot, incoming.recordID)
	return visible
}

func (s *rawMeshRecordSet) addSlotRecordLocked(slot rawMeshSquashSlot, recordID string) {
	if slot == (rawMeshSquashSlot{}) {
		return
	}
	ids := s.slotRecords[slot]
	if ids == nil {
		ids = make(map[string]struct{})
		s.slotRecords[slot] = ids
	}
	ids[recordID] = struct{}{}
}

func (s *rawMeshRecordSet) removeSlotRecordLocked(slot rawMeshSquashSlot, recordID string) {
	ids := s.slotRecords[slot]
	delete(ids, recordID)
	if len(ids) == 0 {
		delete(s.slotRecords, slot)
	}
}

func (s *rawMeshRecordSet) removeHeadLocked(recordID string) {
	if head, ok := s.heads[recordID]; ok {
		s.removeSlotRecordLocked(head.slot, recordID)
	}
	delete(s.records, recordID)
	delete(s.heads, recordID)
}

type rawMeshRecordDescriptor struct {
	Interface        string `json:"interface"`
	Method           string `json:"method"`
	Protocol         string `json:"protocol"`
	ProtocolPath     string `json:"protocolPath"`
	ParentID         string `json:"parentId"`
	Recipient        string `json:"recipient"`
	RecordID         string `json:"recordId"`
	DateCreated      string `json:"dateCreated"`
	MessageTimestamp string `json:"messageTimestamp"`
	Squash           bool   `json:"squash"`
	Prune            bool   `json:"prune"`
}

type rawMeshRecordMessage struct {
	RecordID    string                   `json:"recordId"`
	ContextID   string                   `json:"contextId"`
	Descriptor  *rawMeshRecordDescriptor `json:"descriptor"`
	EncodedData *json.RawMessage         `json:"encodedData"`
}

func normalizeRawMeshRecord(entry json.RawMessage, pathHint string) (rawMeshRecord, error) {
	record, err := normalizeRawMeshRecordIdentity(entry, pathHint)
	if err != nil {
		return rawMeshRecord{}, err
	}
	if !rawRecordHasEncodedData(entry) {
		return rawMeshRecord{}, fmt.Errorf("%w: RecordsWrite is missing encoded data", errRawMeshRecordDataUnavailable)
	}
	record.raw = cloneRawJSON(entry)
	return record, nil
}

func normalizeRawMeshRecordIdentity(entry json.RawMessage, pathHint string) (rawMeshRecord, error) {
	message, _, err := unwrapRawRecordMessage(entry, "recordsWrite")
	if err != nil {
		return rawMeshRecord{}, err
	}
	if message.Descriptor == nil {
		return rawMeshRecord{}, fmt.Errorf("%w: RecordsWrite is missing descriptor", errMalformedRawMeshRecord)
	}
	descriptor := message.Descriptor
	if descriptor.Interface != "Records" || descriptor.Method != "Write" {
		return rawMeshRecord{}, fmt.Errorf("%w: expected RecordsWrite, got %s%s", errMalformedRawMeshRecord, descriptor.Interface, descriptor.Method)
	}
	if message.RecordID == "" || descriptor.Protocol == "" {
		return rawMeshRecord{}, fmt.Errorf("%w: RecordsWrite is missing recordId or protocol", errMalformedRawMeshRecord)
	}
	protocolPath := descriptor.ProtocolPath
	if protocolPath == "" {
		protocolPath = pathHint
	}
	if protocolPath == "" {
		return rawMeshRecord{}, fmt.Errorf("%w: RecordsWrite is missing protocolPath", errMalformedRawMeshRecord)
	}
	parentContextID, err := validateRawMeshRecordContext(message.RecordID, message.ContextID, descriptor.ParentID)
	if err != nil {
		return rawMeshRecord{}, err
	}
	revision, err := parseRawMeshRecordRevision(descriptor.MessageTimestamp)
	if err != nil {
		return rawMeshRecord{}, err
	}
	dateCreated, err := parseRawMeshRecordDateCreated(descriptor.DateCreated)
	if err != nil {
		return rawMeshRecord{}, err
	}
	messageCID, err := computeRawRecordMessageCID(entry)
	if err != nil {
		return rawMeshRecord{}, err
	}
	return rawMeshRecord{
		raw:              cloneRawJSON(entry),
		recordID:         message.RecordID,
		protocol:         descriptor.Protocol,
		protocolPath:     protocolPath,
		contextID:        message.ContextID,
		parentContextID:  parentContextID,
		parentID:         descriptor.ParentID,
		recipient:        descriptor.Recipient,
		dateCreated:      descriptor.DateCreated,
		dateCreatedTime:  dateCreated,
		messageTimestamp: descriptor.MessageTimestamp,
		revision:         revision,
		messageCID:       messageCID,
		squash:           descriptor.Squash,
	}, nil
}

func normalizeRawMeshRecordDelete(entry json.RawMessage) (rawMeshRecordDeleteData, error) {
	message, _, err := unwrapRawRecordMessage(entry, "recordsDelete")
	if err != nil {
		return rawMeshRecordDeleteData{}, err
	}
	if message.Descriptor == nil {
		return rawMeshRecordDeleteData{}, fmt.Errorf("%w: RecordsDelete is missing descriptor", errMalformedRawMeshRecord)
	}
	descriptor := message.Descriptor
	if descriptor.Interface != "Records" || descriptor.Method != "Delete" {
		return rawMeshRecordDeleteData{}, fmt.Errorf("%w: expected RecordsDelete, got %s%s", errMalformedRawMeshRecord, descriptor.Interface, descriptor.Method)
	}
	if descriptor.RecordID == "" {
		return rawMeshRecordDeleteData{}, fmt.Errorf("%w: RecordsDelete descriptor is missing recordId", errMalformedRawMeshRecord)
	}
	revision, err := parseRawMeshRecordRevision(descriptor.MessageTimestamp)
	if err != nil {
		return rawMeshRecordDeleteData{}, err
	}
	messageCID, err := computeRawRecordMessageCID(entry)
	if err != nil {
		return rawMeshRecordDeleteData{}, err
	}
	return rawMeshRecordDeleteData{
		recordID: descriptor.RecordID,
		rawMeshRecordRevision: rawMeshRecordRevision{
			method:           rawMeshRecordDelete,
			messageTimestamp: descriptor.MessageTimestamp,
			revision:         revision,
			messageCID:       messageCID,
			prune:            descriptor.Prune,
		},
	}, nil
}

func compareRawMeshRecordRevision(a, b rawMeshRecordRevision) int {
	if a.revision.Before(b.revision) {
		return -1
	}
	if a.revision.After(b.revision) {
		return 1
	}
	return strings.Compare(a.messageCID, b.messageCID)
}

func validateRawMeshRecordContext(recordID, contextID, parentID string) (string, error) {
	if contextID == "" {
		return "", fmt.Errorf("%w: RecordsWrite is missing contextId", errMalformedRawMeshRecord)
	}
	if contextID == recordID {
		if parentID != "" {
			return "", fmt.Errorf("%w: root RecordsWrite has parentId %q", errMalformedRawMeshRecord, parentID)
		}
		return "", nil
	}
	suffix := "/" + recordID
	if !strings.HasSuffix(contextID, suffix) {
		return "", fmt.Errorf("%w: contextId %q does not end in recordId %q", errMalformedRawMeshRecord, contextID, recordID)
	}
	parentContextID := strings.TrimSuffix(contextID, suffix)
	if parentContextID == "" || strings.HasSuffix(parentContextID, "/") {
		return "", fmt.Errorf("%w: invalid parent context %q", errMalformedRawMeshRecord, parentContextID)
	}
	lastSlash := strings.LastIndexByte(parentContextID, '/')
	expectedParentID := parentContextID[lastSlash+1:]
	if parentID == "" || parentID != expectedParentID {
		return "", fmt.Errorf("%w: parentId %q does not match context parent %q", errMalformedRawMeshRecord, parentID, expectedParentID)
	}
	return parentContextID, nil
}

func computeRawRecordMessageCID(entry json.RawMessage) (string, error) {
	raw, _, err := unwrapRawRecordMessageJSON(entry, "")
	if err != nil {
		return "", err
	}
	var canonical map[string]any
	if err := json.Unmarshal(raw, &canonical); err != nil || canonical == nil {
		return "", fmt.Errorf("%w: decoding canonical record message", errMalformedRawMeshRecord)
	}
	delete(canonical, "encodedData")
	delete(canonical, "initialWrite")
	delete(canonical, "messageCid")
	cid, err := dwn.ComputeCID(canonical)
	if err != nil {
		return "", fmt.Errorf("%w: computing record message CID: %v", errMalformedRawMeshRecord, err)
	}
	return cid, nil
}

func validateSubscriptionRecordMessageCID(message *dwn.SubscriptionMessage) (string, error) {
	computed, err := computeRawRecordMessageCID(message.Event.Message)
	if err != nil {
		return "", err
	}
	topLevel := message.MessageCID
	cursor := ""
	if message.Cursor != nil {
		cursor = message.Cursor.MessageCID
	}
	if topLevel != "" && cursor != "" && topLevel != cursor {
		return "", fmt.Errorf("%w: subscription messageCid %q disagrees with cursor %q", errMalformedRawMeshRecord, topLevel, cursor)
	}
	provided := topLevel
	if provided == "" {
		provided = cursor
	}
	if provided != "" && provided != computed {
		return "", fmt.Errorf("%w: subscription messageCid %q does not match computed %q", errMalformedRawMeshRecord, provided, computed)
	}
	return computed, nil
}

func classifyRawRecordMessage(entry json.RawMessage) (string, error) {
	message, wrapper, err := unwrapRawRecordMessage(entry, "")
	if err != nil {
		return "", err
	}
	if message.Descriptor == nil {
		return "", fmt.Errorf("%w: event message is missing descriptor", errMalformedRawMeshRecord)
	}
	descriptor := message.Descriptor
	if descriptor.Interface == "" || descriptor.Method == "" {
		return "", fmt.Errorf("%w: event descriptor is missing interface or method", errMalformedRawMeshRecord)
	}
	if descriptor.Interface != "Records" {
		return "", fmt.Errorf("%w: interface %q", errUnsupportedRawMeshRecordEvent, descriptor.Interface)
	}
	if wrapper != "" {
		expected := "records" + descriptor.Method
		if wrapper != expected {
			return "", fmt.Errorf("%w: wrapper %q contains Records%s", errMalformedRawMeshRecord, wrapper, descriptor.Method)
		}
	}
	if descriptor.Method != "Write" && descriptor.Method != "Delete" {
		return "", fmt.Errorf("%w: Records method %q", errUnsupportedRawMeshRecordEvent, descriptor.Method)
	}
	return descriptor.Method, nil
}

func unwrapRawRecordMessageJSON(entry json.RawMessage, requestedWrapper string) (json.RawMessage, string, error) {
	var object map[string]json.RawMessage
	if len(entry) == 0 || json.Unmarshal(entry, &object) != nil || object == nil {
		return nil, "", fmt.Errorf("%w: record message is not a JSON object", errMalformedRawMeshRecord)
	}

	wrapper := requestedWrapper
	if wrapper == "" {
		if _, ok := object["recordsWrite"]; ok {
			wrapper = "recordsWrite"
		} else if _, ok := object["recordsDelete"]; ok {
			wrapper = "recordsDelete"
		}
	}
	raw := entry
	if wrapper != "" {
		wrapped, ok := object[wrapper]
		if !ok || len(wrapped) == 0 || string(wrapped) == "null" {
			if requestedWrapper == "" {
				return nil, "", fmt.Errorf("%w: %s wrapper is empty", errMalformedRawMeshRecord, wrapper)
			}
			wrapper = ""
		} else {
			raw = wrapped
		}
	}
	return raw, wrapper, nil
}

// unwrapRawRecordMessage accepts both flat messages and query/read-style
// {"recordsWrite": {...}} / {"recordsDelete": {...}} wrappers.
func unwrapRawRecordMessage(entry json.RawMessage, requestedWrapper string) (rawMeshRecordMessage, string, error) {
	raw, wrapper, err := unwrapRawRecordMessageJSON(entry, requestedWrapper)
	if err != nil {
		return rawMeshRecordMessage{}, "", err
	}
	var message rawMeshRecordMessage
	if err := json.Unmarshal(raw, &message); err != nil {
		return rawMeshRecordMessage{}, "", fmt.Errorf("%w: decoding record message: %v", errMalformedRawMeshRecord, err)
	}
	return message, wrapper, nil
}

func injectSubscriptionEncodedData(entry json.RawMessage, encodedData string) (json.RawMessage, error) {
	cloned := cloneRawJSON(entry)
	if encodedData == "" || rawRecordHasEncodedData(cloned) {
		return cloned, nil
	}

	var object map[string]json.RawMessage
	if err := json.Unmarshal(cloned, &object); err != nil || object == nil {
		return nil, fmt.Errorf("%w: RecordsWrite is not a JSON object", errMalformedRawMeshRecord)
	}
	encoded, err := json.Marshal(encodedData)
	if err != nil {
		return nil, fmt.Errorf("%w: encoding subscription data: %v", errMalformedRawMeshRecord, err)
	}
	if wrapped, ok := object["recordsWrite"]; ok {
		var write map[string]json.RawMessage
		if err := json.Unmarshal(wrapped, &write); err != nil || write == nil {
			return nil, fmt.Errorf("%w: recordsWrite wrapper is not a JSON object", errMalformedRawMeshRecord)
		}
		write["encodedData"] = encoded
		object["recordsWrite"], err = json.Marshal(write)
		if err != nil {
			return nil, fmt.Errorf("%w: encoding recordsWrite wrapper: %v", errMalformedRawMeshRecord, err)
		}
	} else {
		object["encodedData"] = encoded
	}
	result, err := json.Marshal(object)
	if err != nil {
		return nil, fmt.Errorf("%w: encoding RecordsWrite: %v", errMalformedRawMeshRecord, err)
	}
	return result, nil
}

func rawRecordHasEncodedData(entry json.RawMessage) bool {
	message, _, err := unwrapRawRecordMessage(entry, "recordsWrite")
	if err != nil || message.EncodedData == nil {
		return false
	}
	var encoded string
	return json.Unmarshal(*message.EncodedData, &encoded) == nil && encoded != ""
}

func parseRawMeshRecordRevision(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, fmt.Errorf("%w: record is missing messageTimestamp", errMalformedRawMeshRecord)
	}
	revision, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: invalid messageTimestamp %q: %v", errMalformedRawMeshRecord, value, err)
	}
	return revision, nil
}

func parseRawMeshRecordDateCreated(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, fmt.Errorf("%w: record is missing dateCreated", errMalformedRawMeshRecord)
	}
	created, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: invalid dateCreated %q: %v", errMalformedRawMeshRecord, value, err)
	}
	return created, nil
}

func cloneRawJSON(raw json.RawMessage) json.RawMessage {
	if raw == nil {
		return nil
	}
	return append(json.RawMessage(nil), raw...)
}
