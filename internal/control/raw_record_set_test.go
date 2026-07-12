package control

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/enboxorg/meshd/internal/dwn"
)

const rawRecordTestProtocol = "https://example.com/protocol"

func TestNewRawMeshRecordSetNormalizesEntriesAndKeepsLatestRevision(t *testing.T) {
	older := rawRecordTestWrite(t, "record-a", "", "2026-07-11T12:00:00Z", "old")
	newer := rawRecordTestWrite(t, "record-a", "", "2026-07-11T12:00:02.123456Z", "new")
	wrapped := rawRecordTestWrappedWrite(t, "record-b", "network/member", "2026-07-11T12:00:01Z", "wrapped")

	set, err := newRawMeshRecordSet([]json.RawMessage{newer, older, wrapped}, "network/node")
	if err != nil {
		t.Fatalf("newRawMeshRecordSet: %v", err)
	}
	if got := set.len(); got != 2 {
		t.Fatalf("len = %d, want 2", got)
	}

	recordA, ok := set.get("record-a")
	if !ok {
		t.Fatal("record-a missing")
	}
	if recordA.protocol != rawRecordTestProtocol || recordA.protocolPath != "network/node" {
		t.Fatalf("record-a protocol/path = %q/%q", recordA.protocol, recordA.protocolPath)
	}
	if recordA.contextID != "parent-record-a/record-a" || recordA.parentID != "parent-record-a" || recordA.recipient != "did:example:record-a" {
		t.Fatalf("record-a metadata = %+v", recordA)
	}
	if recordA.messageTimestamp != "2026-07-11T12:00:02.123456Z" {
		t.Fatalf("record-a timestamp = %q", recordA.messageTimestamp)
	}
	if got := rawRecordEncodedData(t, recordA.raw); got != "new" {
		t.Fatalf("record-a encodedData = %q, want new", got)
	}

	recordB, ok := set.get("record-b")
	if !ok {
		t.Fatal("record-b missing")
	}
	if recordB.protocolPath != "network/member" {
		t.Fatalf("wrapped path = %q", recordB.protocolPath)
	}
	if got := rawRecordEncodedData(t, recordB.raw); got != "wrapped" {
		t.Fatalf("wrapped encodedData = %q", got)
	}

	all := set.all()
	if len(all) != 2 || all[0].recordID != "record-a" || all[1].recordID != "record-b" {
		t.Fatalf("all order = %#v", all)
	}
}

func TestRawMeshRecordSetAddEntriesIsAtomic(t *testing.T) {
	set, err := newRawMeshRecordSet([]json.RawMessage{
		rawRecordTestWrite(t, "record-a", "network/node", "2026-07-11T12:00:00Z", "initial"),
	}, "")
	if err != nil {
		t.Fatal(err)
	}

	valid := rawRecordTestWrite(t, "record-b", "network/member", "2026-07-11T12:00:01Z", "valid")
	malformed := json.RawMessage(`{"descriptor":{"interface":"Records","method":"Write"}}`)
	changed, err := set.addEntries([]json.RawMessage{valid, malformed}, "")
	if changed || !errors.Is(err, errMalformedRawMeshRecord) {
		t.Fatalf("failed batch changed=%v err=%v", changed, err)
	}
	if set.len() != 1 {
		t.Fatalf("failed batch partially mutated set: len=%d", set.len())
	}
	if _, ok := set.get("record-b"); ok {
		t.Fatal("valid prefix of failed batch was applied")
	}

	changed, err = set.addEntries([]json.RawMessage{valid}, "")
	if err != nil || !changed || set.len() != 2 {
		t.Fatalf("valid batch changed=%v len=%d err=%v", changed, set.len(), err)
	}
	changed, err = set.addEntries([]json.RawMessage{valid}, "")
	if err != nil || changed {
		t.Fatalf("idempotent batch changed=%v err=%v", changed, err)
	}
}

func TestRawMeshRecordSetAppliesWriteUpdateAndDelete(t *testing.T) {
	set, err := newRawMeshRecordSet(nil, "")
	if err != nil {
		t.Fatalf("newRawMeshRecordSet: %v", err)
	}

	createRaw := rawRecordTestWrite(t, "record-a", "network/node", "2026-07-11T12:00:00Z", "")
	create := rawRecordTestSubscription(createRaw, "created")
	changed, err := set.applySubscriptionMessage(create, "unused/path")
	if err != nil {
		t.Fatalf("apply create: %v", err)
	}
	if !changed {
		t.Fatal("create did not report a change")
	}
	record, ok := set.get("record-a")
	if !ok {
		t.Fatal("created record missing")
	}
	if got := rawRecordEncodedData(t, record.raw); got != "created" {
		t.Fatalf("injected encodedData = %q", got)
	}

	updateRaw := rawRecordTestWrite(t, "record-a", "network/node", "2026-07-11T12:00:01Z", "in-message")
	changed, err = set.applySubscriptionMessage(rawRecordTestSubscription(updateRaw, "top-level"), "")
	if err != nil {
		t.Fatalf("apply update: %v", err)
	}
	if !changed {
		t.Fatal("update did not report a change")
	}
	record, _ = set.get("record-a")
	if got := rawRecordEncodedData(t, record.raw); got != "in-message" {
		t.Fatalf("existing encodedData was overwritten: %q", got)
	}

	deleteRaw := rawRecordTestDelete(t, "record-a", "2026-07-11T12:00:02Z")
	changed, err = set.applySubscriptionMessage(rawRecordTestSubscription(deleteRaw, ""), "")
	if err != nil {
		t.Fatalf("apply delete: %v", err)
	}
	if !changed || set.len() != 0 {
		t.Fatalf("delete changed=%v len=%d", changed, set.len())
	}

	changed, err = set.applySubscriptionMessage(rawRecordTestSubscription(deleteRaw, ""), "")
	if err != nil {
		t.Fatalf("replay delete: %v", err)
	}
	if changed {
		t.Fatal("idempotent delete reported a change")
	}
}

func TestRawMeshRecordSetAppliesWrappedWriteEvent(t *testing.T) {
	set, _ := newRawMeshRecordSet(nil, "")
	event := rawRecordTestSubscription(
		rawRecordTestWrappedWrite(t, "record-a", "network/node", "2026-07-11T12:00:00Z", ""),
		"from-subscription",
	)
	changed, err := set.applySubscriptionMessage(event, "")
	if err != nil {
		t.Fatalf("apply wrapped write: %v", err)
	}
	if !changed {
		t.Fatal("wrapped write did not report a change")
	}
	record, _ := set.get("record-a")
	if got := rawRecordEncodedData(t, record.raw); got != "from-subscription" {
		t.Fatalf("wrapped encodedData = %q", got)
	}
}

func TestRawMeshRecordSetRejectsStaleWritesAndNeverResurrectsTombstone(t *testing.T) {
	set, err := newRawMeshRecordSet([]json.RawMessage{
		rawRecordTestWrite(t, "record-a", "network/node", "2026-07-11T12:00:02Z", "current"),
	}, "")
	if err != nil {
		t.Fatal(err)
	}

	staleWrite := rawRecordTestSubscription(
		rawRecordTestWrite(t, "record-a", "network/node", "2026-07-11T12:00:01Z", "stale"),
		"",
	)
	if changed, err := set.applySubscriptionMessage(staleWrite, ""); err != nil || changed {
		t.Fatalf("stale write changed=%v err=%v", changed, err)
	}

	// A stale replay delete cannot remove a newer live base state when the
	// optional isLatestBaseState hint is absent.
	olderDelete := rawRecordTestSubscription(rawRecordTestDelete(t, "record-a", "2026-07-11T12:00:01Z"), "")
	if changed, err := set.applySubscriptionMessage(olderDelete, ""); err != nil || changed {
		t.Fatalf("stale delete changed=%v err=%v", changed, err)
	}
	if record, ok := set.get("record-a"); !ok || rawRecordEncodedData(t, record.raw) != "current" {
		t.Fatalf("stale delete removed current write: record=%#v ok=%v", record, ok)
	}

	newerDelete := rawRecordTestSubscription(rawRecordTestDelete(t, "record-a", "2026-07-11T12:00:03Z"), "")
	if changed, err := set.applySubscriptionMessage(newerDelete, ""); err != nil || !changed {
		t.Fatalf("newer delete changed=%v err=%v", changed, err)
	}
	if set.len() != 0 {
		t.Fatalf("newer delete retained record: len=%d", set.len())
	}

	for _, write := range []*dwn.SubscriptionMessage{
		staleWrite,
		rawRecordTestSubscription(rawRecordTestWrite(t, "record-a", "network/node", "2026-07-11T12:00:04Z", "later"), ""),
	} {
		if changed, err := set.applySubscriptionMessage(write, ""); err != nil || changed || set.len() != 0 {
			t.Fatalf("write resurrected tombstone changed=%v len=%d err=%v", changed, set.len(), err)
		}
	}
}

func TestRawMeshRecordSetDeleteAndPruneTransitionsFollowBaseStateOrder(t *testing.T) {
	set, err := newRawMeshRecordSet([]json.RawMessage{
		rawRecordTestWrite(t, "record-a", "network/node", "2026-07-11T12:00:01Z", "current"),
	}, "")
	if err != nil {
		t.Fatal(err)
	}

	plain := rawRecordTestSubscription(rawRecordTestDelete(t, "record-a", "2026-07-11T12:00:02Z"), "")
	if changed, err := set.applySubscriptionMessage(plain, ""); err != nil || !changed {
		t.Fatalf("plain delete changed=%v err=%v", changed, err)
	}

	newerPlain := rawRecordTestSubscription(rawRecordTestDelete(t, "record-a", "2026-07-11T12:00:03Z"), "")
	if changed, err := set.applySubscriptionMessage(newerPlain, ""); err != nil || changed {
		t.Fatalf("second plain delete changed=%v err=%v", changed, err)
	}
	olderPrune := rawRecordTestDeleteWith(t, "record-a", "2026-07-11T12:00:01Z", true, "")
	if changed, err := set.applySubscriptionMessage(rawRecordTestSubscription(olderPrune, ""), ""); err != nil || changed {
		t.Fatalf("older prune changed=%v err=%v", changed, err)
	}

	newerPrune := rawRecordTestDeleteWith(t, "record-a", "2026-07-11T12:00:04Z", true, "")
	if changed, err := set.applySubscriptionMessage(rawRecordTestSubscription(newerPrune, ""), ""); err != nil || changed {
		// The visible record was already deleted, so accepting the stronger
		// tombstone does not change the visible projection.
		t.Fatalf("newer prune visible change=%v err=%v", changed, err)
	}
	head := set.heads["record-a"]
	if !head.prune || head.messageTimestamp != "2026-07-11T12:00:04Z" {
		t.Fatalf("head after prune = %#v", head)
	}

	terminalPrune := rawRecordTestDeleteWith(t, "record-a", "2026-07-11T12:00:05Z", true, "")
	if changed, err := set.applySubscriptionMessage(rawRecordTestSubscription(terminalPrune, ""), ""); err != nil || changed {
		t.Fatalf("second prune changed=%v err=%v", changed, err)
	}
	if got := set.heads["record-a"].messageTimestamp; got != "2026-07-11T12:00:04Z" {
		t.Fatalf("terminal prune was replaced: %s", got)
	}
}

func TestRawMeshRecordSetIgnoresNonLatestBaseState(t *testing.T) {
	set, _ := newRawMeshRecordSet(nil, "")
	latest := false
	changed, err := set.applySubscriptionMessage(&dwn.SubscriptionMessage{
		Type:              "not-an-event",
		IsLatestBaseState: &latest,
	}, "")
	if err != nil || changed || set.len() != 0 {
		t.Fatalf("ignored event changed=%v len=%d err=%v", changed, set.len(), err)
	}
}

func TestRawMeshRecordSetMissingWriteDataIsMalformedAndDoesNotMutate(t *testing.T) {
	missingData := rawRecordTestWrite(t, "record-a", "network/node", "2026-07-11T12:00:00Z", "")
	if _, err := newRawMeshRecordSet([]json.RawMessage{missingData}, ""); !errors.Is(err, errRawMeshRecordDataUnavailable) {
		t.Fatalf("initial missing-data error = %v", err)
	}

	set, _ := newRawMeshRecordSet(nil, "")
	event := rawRecordTestSubscription(missingData, "")
	changed, err := set.applySubscriptionMessage(event, "")
	if changed || !errors.Is(err, errRawMeshRecordDataUnavailable) {
		t.Fatalf("missing data changed=%v err=%v", changed, err)
	}
	if errors.Is(err, errMalformedRawMeshRecord) {
		t.Fatalf("missing data was classified as malformed: %v", err)
	}
	if set.len() != 0 {
		t.Fatalf("missing-data event mutated set: len=%d", set.len())
	}
}

func TestRawMeshRecordSetDeepCopiesInputsOutputsAndClones(t *testing.T) {
	source := rawRecordTestWrite(t, "record-a", "network/node", "2026-07-11T12:00:00Z", "original")
	set, err := newRawMeshRecordSet([]json.RawMessage{source}, "")
	if err != nil {
		t.Fatal(err)
	}
	for i := range source {
		source[i] = 'x'
	}
	record, _ := set.get("record-a")
	if got := rawRecordEncodedData(t, record.raw); got != "original" {
		t.Fatalf("input mutation reached set: %q", got)
	}

	record.raw[0] = 'x'
	all := set.all()
	all[0].raw[0] = 'x'
	record, _ = set.get("record-a")
	if got := rawRecordEncodedData(t, record.raw); got != "original" {
		t.Fatalf("output mutation reached set: %q", got)
	}

	cloned := set.clone()
	update := rawRecordTestSubscription(
		rawRecordTestWrite(t, "record-a", "network/node", "2026-07-11T12:00:01Z", "clone-only"),
		"",
	)
	if changed, err := cloned.applySubscriptionMessage(update, ""); err != nil || !changed {
		t.Fatalf("update clone changed=%v err=%v", changed, err)
	}
	originalRecord, _ := set.get("record-a")
	cloneRecord, _ := cloned.get("record-a")
	if rawRecordEncodedData(t, originalRecord.raw) != "original" || rawRecordEncodedData(t, cloneRecord.raw) != "clone-only" {
		t.Fatal("clone and original share record storage")
	}

	eventRaw := rawRecordTestWrite(t, "record-b", "network/node", "2026-07-11T12:00:02Z", "event")
	event := rawRecordTestSubscription(eventRaw, "")
	if _, err := set.applySubscriptionMessage(event, ""); err != nil {
		t.Fatal(err)
	}
	for i := range eventRaw {
		eventRaw[i] = 'x'
	}
	eventRecord, _ := set.get("record-b")
	if got := rawRecordEncodedData(t, eventRecord.raw); got != "event" {
		t.Fatalf("event mutation reached set: %q", got)
	}
}

func TestRawMeshRecordSetClassifiesMalformedAndUnsupportedEvents(t *testing.T) {
	set, _ := newRawMeshRecordSet(nil, "")
	tests := []struct {
		name string
		msg  *dwn.SubscriptionMessage
		want error
	}{
		{name: "nil", msg: nil, want: errMalformedRawMeshRecord},
		{name: "eose", msg: &dwn.SubscriptionMessage{Type: dwn.SubscriptionEOSEType}, want: errUnsupportedRawMeshRecordEvent},
		{name: "missing event", msg: &dwn.SubscriptionMessage{Type: dwn.SubscriptionEventType}, want: errMalformedRawMeshRecord},
		{name: "invalid json", msg: rawRecordTestSubscription(json.RawMessage(`{`), "data"), want: errMalformedRawMeshRecord},
		{
			name: "unsupported interface",
			msg:  rawRecordTestSubscription(json.RawMessage(`{"descriptor":{"interface":"Protocols","method":"Configure"}}`), "data"),
			want: errUnsupportedRawMeshRecordEvent,
		},
		{
			name: "unsupported records method",
			msg:  rawRecordTestSubscription(json.RawMessage(`{"descriptor":{"interface":"Records","method":"Read"}}`), "data"),
			want: errUnsupportedRawMeshRecordEvent,
		},
		{
			name: "delete missing descriptor record ID",
			msg:  rawRecordTestSubscription(json.RawMessage(`{"recordId":"wrong-location","descriptor":{"interface":"Records","method":"Delete","messageTimestamp":"2026-07-11T12:00:00Z"}}`), ""),
			want: errMalformedRawMeshRecord,
		},
		{
			name: "write missing record ID",
			msg:  rawRecordTestSubscription(json.RawMessage(`{"descriptor":{"interface":"Records","method":"Write","protocol":"https://example.com/protocol","protocolPath":"network/node","messageTimestamp":"2026-07-11T12:00:00Z"}}`), "data"),
			want: errMalformedRawMeshRecord,
		},
		{
			name: "invalid timestamp",
			msg:  rawRecordTestSubscription(rawRecordTestWrite(t, "record-a", "network/node", "not-time", "data"), ""),
			want: errMalformedRawMeshRecord,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed, err := set.applySubscriptionMessage(test.msg, "")
			if changed || !errors.Is(err, test.want) {
				t.Fatalf("changed=%v err=%v, want errors.Is(..., %v)", changed, err, test.want)
			}
		})
	}
}

func TestNewRawMeshRecordSetRejectsMalformedEntries(t *testing.T) {
	tests := []json.RawMessage{
		json.RawMessage(`not-json`),
		json.RawMessage(`{"descriptor":{"interface":"Records","method":"Write","protocol":"https://example.com/protocol","protocolPath":"network/node","messageTimestamp":"2026-07-11T12:00:00Z"}}`),
		rawRecordTestWrite(t, "record-a", "", "2026-07-11T12:00:00Z", "data"),
	}
	for i, entry := range tests {
		_, err := newRawMeshRecordSet([]json.RawMessage{entry}, "")
		if !errors.Is(err, errMalformedRawMeshRecord) {
			t.Fatalf("case %d: err=%v", i, err)
		}
	}
}

func TestRawMeshRecordSetConcurrentCloneReadAndApply(t *testing.T) {
	set, err := newRawMeshRecordSet([]json.RawMessage{
		rawRecordTestWrite(t, "record-a", "network/node", "2026-07-11T12:00:00Z", "initial"),
	}, "")
	if err != nil {
		t.Fatal(err)
	}

	const iterations = 50
	var wg sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				_, _ = set.get("record-a")
				_ = set.all()
				_ = set.clone()
			}
		}()
	}
	for worker := 0; worker < 2; worker++ {
		worker := worker
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				timestamp := time.Date(2026, 7, 11, 12, 1, worker*iterations+i, 0, time.UTC).Format(time.RFC3339Nano)
				raw := rawRecordTestWrite(t, "record-a", "network/node", timestamp, fmt.Sprintf("%d-%d", worker, i))
				_, _ = set.applySubscriptionMessage(rawRecordTestSubscription(raw, ""), "")
			}
		}()
	}
	wg.Wait()
	if set.len() != 1 {
		t.Fatalf("len after concurrent updates = %d", set.len())
	}
}

func rawRecordTestWrite(t *testing.T, recordID, protocolPath, timestamp, encodedData string) json.RawMessage {
	t.Helper()
	parentContext := "parent-" + recordID
	message := map[string]any{
		"recordId":  recordID,
		"contextId": parentContext + "/" + recordID,
		"descriptor": map[string]any{
			"interface":        "Records",
			"method":           "Write",
			"protocol":         rawRecordTestProtocol,
			"protocolPath":     protocolPath,
			"parentId":         parentContext,
			"recipient":        "did:example:" + recordID,
			"dateCreated":      timestamp,
			"messageTimestamp": timestamp,
			"dataCid":          "data-" + encodedData,
		},
	}
	if encodedData != "" {
		message["encodedData"] = encodedData
	}
	return rawRecordTestJSON(t, message)
}

func rawRecordTestWrappedWrite(t *testing.T, recordID, protocolPath, timestamp, encodedData string) json.RawMessage {
	t.Helper()
	var write any
	if err := json.Unmarshal(rawRecordTestWrite(t, recordID, protocolPath, timestamp, encodedData), &write); err != nil {
		t.Fatal(err)
	}
	return rawRecordTestJSON(t, map[string]any{"recordsWrite": write})
}

func rawRecordTestDelete(t *testing.T, recordID, timestamp string) json.RawMessage {
	t.Helper()
	return rawRecordTestJSON(t, map[string]any{
		"descriptor": map[string]any{
			"interface":        "Records",
			"method":           "Delete",
			"recordId":         recordID,
			"messageTimestamp": timestamp,
		},
	})
}

func rawRecordTestSubscription(raw json.RawMessage, encodedData string) *dwn.SubscriptionMessage {
	latest := true
	return &dwn.SubscriptionMessage{
		Type:              dwn.SubscriptionEventType,
		IsLatestBaseState: &latest,
		EncodedData:       encodedData,
		Event:             &dwn.RecordEvent{Message: raw},
	}
}

func rawRecordEncodedData(t *testing.T, raw json.RawMessage) string {
	t.Helper()
	message, _, err := unwrapRawRecordMessage(raw, "recordsWrite")
	if err != nil {
		t.Fatalf("unwrap record: %v", err)
	}
	if message.EncodedData == nil {
		return ""
	}
	var value string
	if err := json.Unmarshal(*message.EncodedData, &value); err != nil {
		t.Fatalf("decode encodedData: %v", err)
	}
	return value
}

func rawRecordTestJSON(t *testing.T, value any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestRawMeshRecordSetCanonicalCIDAndSubscriptionAgreement(t *testing.T) {
	raw := rawRecordTestWrite(t, "record-cid", "network/node", "2026-07-11T12:00:00Z", "data")
	cid, err := computeRawRecordMessageCID(raw)
	if err != nil {
		t.Fatal(err)
	}
	event := rawRecordTestSubscription(raw, "")
	event.MessageCID = cid
	event.Cursor = &dwn.ProgressToken{StreamID: "stream", Epoch: "epoch", Position: "1", MessageCID: cid}
	set, _ := newRawMeshRecordSet(nil, "")
	if changed, err := set.applySubscriptionMessage(event, ""); err != nil || !changed {
		t.Fatalf("matching CID changed=%v err=%v", changed, err)
	}

	mismatch := rawRecordTestSubscription(rawRecordTestWrite(t, "other", "network/node", "2026-07-11T12:00:01Z", "data"), "")
	mismatch.MessageCID = "bafy-wrong"
	mismatch.Cursor = &dwn.ProgressToken{StreamID: "stream", Epoch: "epoch", Position: "2", MessageCID: "bafy-other"}
	if changed, err := set.applySubscriptionMessage(mismatch, ""); changed || !errors.Is(err, errMalformedRawMeshRecord) {
		t.Fatalf("mismatched CIDs changed=%v err=%v", changed, err)
	}

	agreedWrong := rawRecordTestSubscription(rawRecordTestWrite(t, "agreed-wrong", "network/node", "2026-07-11T12:00:02Z", "data"), "")
	agreedWrong.MessageCID = "bafy-agreed-but-wrong"
	agreedWrong.Cursor = &dwn.ProgressToken{StreamID: "stream", Epoch: "epoch", Position: "3", MessageCID: agreedWrong.MessageCID}
	if changed, err := set.applySubscriptionMessage(agreedWrong, ""); changed || !errors.Is(err, errMalformedRawMeshRecord) {
		t.Fatalf("agreed noncanonical CID changed=%v err=%v", changed, err)
	}
}

func TestComputeRawRecordMessageCIDCanonicalBoundary(t *testing.T) {
	var canonical map[string]any
	if err := json.Unmarshal(rawRecordTestWrite(t, "record-boundary", "network/node", "2026-07-11T12:00:00Z", "payload"), &canonical); err != nil {
		t.Fatal(err)
	}
	canonical["authorization"] = map[string]any{"signature": "authorization-a"}
	canonical["encryption"] = map[string]any{"algorithm": "encryption-a"}
	canonical["attestation"] = map[string]any{"signature": "attestation-a"}
	base := rawRecordTestJSON(t, canonical)
	baseCID, err := computeRawRecordMessageCID(base)
	if err != nil {
		t.Fatal(err)
	}

	decorated := mapsCloneForRawRecordTest(t, canonical)
	decorated["encodedData"] = "different-reply-data"
	decorated["initialWrite"] = map[string]any{"descriptor": map[string]any{"messageTimestamp": "1999-01-01T00:00:00Z"}}
	decorated["messageCid"] = "bafy-reply-decoration"
	decoratedCID, err := computeRawRecordMessageCID(rawRecordTestJSON(t, decorated))
	if err != nil {
		t.Fatal(err)
	}
	if decoratedCID != baseCID {
		t.Fatalf("reply decorations changed canonical CID: got %q, want %q", decoratedCID, baseCID)
	}

	for _, field := range []string{"authorization", "encryption", "attestation"} {
		t.Run(field, func(t *testing.T) {
			changed := mapsCloneForRawRecordTest(t, canonical)
			changed[field] = map[string]any{"changed": field + "-b"}
			changedCID, err := computeRawRecordMessageCID(rawRecordTestJSON(t, changed))
			if err != nil {
				t.Fatal(err)
			}
			if changedCID == baseCID {
				t.Fatalf("changing canonical %s did not change CID %q", field, baseCID)
			}
		})
	}
}

func mapsCloneForRawRecordTest(t *testing.T, value map[string]any) map[string]any {
	t.Helper()
	var cloned map[string]any
	if err := json.Unmarshal(rawRecordTestJSON(t, value), &cloned); err != nil {
		t.Fatal(err)
	}
	return cloned
}

func TestRawMeshRecordSetEqualTimestampUsesCanonicalCID(t *testing.T) {
	a := rawRecordTestWrite(t, "record-tie", "network/node", "2026-07-11T12:00:00Z", "alpha")
	b := rawRecordTestWrite(t, "record-tie", "network/node", "2026-07-11T12:00:00Z", "beta")
	aCID, _ := computeRawRecordMessageCID(a)
	bCID, _ := computeRawRecordMessageCID(b)
	lowRaw, highRaw := a, b
	lowCID, highCID := aCID, bCID
	if lowCID > highCID {
		lowRaw, highRaw = highRaw, lowRaw
		lowCID, highCID = highCID, lowCID
	}
	if lowCID == highCID {
		t.Fatal("fixture did not produce distinct canonical CIDs")
	}

	set, err := newRawMeshRecordSet([]json.RawMessage{lowRaw}, "")
	if err != nil {
		t.Fatal(err)
	}
	if changed, err := set.applySubscriptionMessage(rawRecordTestSubscription(highRaw, ""), ""); err != nil || !changed {
		t.Fatalf("higher CID changed=%v err=%v", changed, err)
	}
	if got, _ := set.get("record-tie"); got.messageCID != highCID {
		t.Fatalf("winning CID = %q, want %q", got.messageCID, highCID)
	}
	if changed, err := set.applySubscriptionMessage(rawRecordTestSubscription(lowRaw, ""), ""); err != nil || changed {
		t.Fatalf("lower CID replay changed=%v err=%v", changed, err)
	}
}

func TestRawMeshRecordSetDeleteToPruneUsesCanonicalBaseStateOrder(t *testing.T) {
	set, err := newRawMeshRecordSet([]json.RawMessage{
		rawRecordTestWrite(t, "record-delete", "network/node", "2026-07-11T12:00:00Z", "visible"),
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	const tieTimestamp = "2026-07-11T12:00:01Z"
	plain := rawRecordTestDeleteWith(t, "record-delete", tieTimestamp, false, "plain")
	if changed, err := set.applySubscriptionMessage(rawRecordTestSubscription(plain, ""), ""); err != nil || !changed {
		t.Fatalf("plain delete changed=%v err=%v", changed, err)
	}
	plainCID, err := computeRawRecordMessageCID(plain)
	if err != nil {
		t.Fatal(err)
	}

	tiedPrune := rawRecordTestDeleteWith(t, "record-delete", tieTimestamp, true, "prune-tie")
	tiedPruneCID, err := computeRawRecordMessageCID(tiedPrune)
	if err != nil {
		t.Fatal(err)
	}
	if changed, err := set.applySubscriptionMessage(rawRecordTestSubscription(tiedPrune, ""), ""); err != nil || changed {
		t.Fatalf("tied prune visible change=%v err=%v", changed, err)
	}
	head := set.heads["record-delete"]
	if wantPrune := tiedPruneCID > plainCID; head.prune != wantPrune {
		t.Fatalf("equal-time prune=%v, want %v from CID order plain=%q prune=%q", head.prune, wantPrune, plainCID, tiedPruneCID)
	}
	if !head.prune {
		newerPrune := rawRecordTestDeleteWith(t, "record-delete", "2026-07-11T12:00:02Z", true, "prune-newer")
		if changed, err := set.applySubscriptionMessage(rawRecordTestSubscription(newerPrune, ""), ""); err != nil || changed {
			t.Fatalf("newer prune visible change=%v err=%v", changed, err)
		}
		head = set.heads["record-delete"]
		if !head.prune {
			t.Fatal("strictly newer prune did not replace plain tombstone")
		}
	}

	terminal := head
	laterPrune := rawRecordTestDeleteWith(t, "record-delete", "2026-07-11T13:00:00Z", true, "prune-terminal")
	if changed, err := set.applySubscriptionMessage(rawRecordTestSubscription(laterPrune, ""), ""); err != nil || changed {
		t.Fatalf("terminal prune visible change=%v err=%v", changed, err)
	}
	if got := set.heads["record-delete"]; got.messageCID != terminal.messageCID || !got.prune {
		t.Fatalf("terminal prune was replaced: got=%#v want=%#v", got, terminal)
	}
}

func TestRawMeshRecordSetSquashSnapshotFloorAndContextIsolation(t *testing.T) {
	const timestamp = "2026-07-11T12:01:00Z"
	old := rawRecordTestWriteAt(t, "old", "network/node/endpoint", "network/node-a", "2026-07-11T12:00:00Z", "old", false)
	equal := rawRecordTestWriteAt(t, "equal", "network/node/endpoint", "network/node-a", timestamp, "equal", false)
	squash := rawRecordTestWriteAt(t, "squash", "network/node/endpoint", "network/node-a", timestamp, "new", true)
	isolated := rawRecordTestWriteAt(t, "isolated", "network/node/endpoint", "network/node-b", "2026-07-11T11:00:00Z", "isolated", false)

	// Query snapshot ingest must retain equal-time siblings regardless of CID/order.
	set, err := newRawMeshRecordSet([]json.RawMessage{squash, old, isolated, equal}, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := set.get("old"); ok {
		t.Fatal("squash retained strictly older sibling")
	}
	for _, id := range []string{"equal", "squash", "isolated"} {
		if _, ok := set.get(id); !ok {
			t.Fatalf("snapshot lost retained record %q", id)
		}
	}

	delayedEqual := rawRecordTestWriteAt(t, "delayed", "network/node/endpoint", "network/node-a", timestamp, "delayed", false)
	if changed, err := set.applySubscriptionMessage(rawRecordTestSubscription(delayedEqual, ""), ""); err != nil || changed {
		t.Fatalf("floor-equal delayed write changed=%v err=%v", changed, err)
	}
	newer := rawRecordTestWriteAt(t, "newer", "network/node/endpoint", "network/node-a", "2026-07-11T12:02:00Z", "newer", false)
	if changed, err := set.applySubscriptionMessage(rawRecordTestSubscription(newer, ""), ""); err != nil || !changed {
		t.Fatalf("above-floor write changed=%v err=%v", changed, err)
	}
}

func TestRawMeshRecordSetSquashDoesNotDiscardDeleteTombstone(t *testing.T) {
	const parent = "network/node-a"
	set, err := newRawMeshRecordSet([]json.RawMessage{
		rawRecordTestWriteAt(t, "deleted-sibling", "network/node/endpoint", parent, "2026-07-11T12:00:00Z", "old", false),
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	if changed, err := set.applySubscriptionMessage(rawRecordTestSubscription(
		rawRecordTestDelete(t, "deleted-sibling", "2026-07-11T12:01:00Z"), "",
	), ""); err != nil || !changed {
		t.Fatalf("delete sibling changed=%v err=%v", changed, err)
	}
	squash := rawRecordTestWriteAt(t, "replacement", "network/node/endpoint", parent, "2026-07-11T12:02:00Z", "new", true)
	if changed, err := set.applySubscriptionMessage(rawRecordTestSubscription(squash, ""), ""); err != nil || !changed {
		t.Fatalf("squash changed=%v err=%v", changed, err)
	}
	if head, ok := set.heads["deleted-sibling"]; !ok || head.method != rawMeshRecordDelete {
		t.Fatalf("squash discarded delete tombstone: %#v, present=%v", head, ok)
	}
	resurrection := rawRecordTestWriteAt(t, "deleted-sibling", "network/node/endpoint", parent, "2026-07-11T12:03:00Z", "", false)
	if changed, err := set.applySubscriptionMessage(rawRecordTestSubscription(resurrection, ""), ""); err != nil || changed {
		t.Fatalf("post-squash resurrection changed=%v err=%v", changed, err)
	}
}

func TestRawMeshRecordSetStaleDataLessWriteNeedsNoHydration(t *testing.T) {
	set, err := newRawMeshRecordSet([]json.RawMessage{
		rawRecordTestWrite(t, "record-no-read", "network/node", "2026-07-11T12:02:00Z", "current"),
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	stale := rawRecordTestWrite(t, "record-no-read", "network/node", "2026-07-11T12:01:00Z", "")
	if changed, err := set.applySubscriptionMessage(rawRecordTestSubscription(stale, ""), ""); err != nil || changed {
		t.Fatalf("stale data-less write changed=%v err=%v", changed, err)
	}

	if changed, err := set.applySubscriptionMessage(rawRecordTestSubscription(
		rawRecordTestDelete(t, "record-no-read", "2026-07-11T12:03:00Z"), "",
	), ""); err != nil || !changed {
		t.Fatalf("newer delete changed=%v err=%v", changed, err)
	}
	futureButForbidden := rawRecordTestWrite(t, "record-no-read", "network/node", "2026-07-11T13:00:00Z", "")
	if changed, err := set.applySubscriptionMessage(rawRecordTestSubscription(futureButForbidden, ""), ""); err != nil || changed {
		t.Fatalf("tombstoned data-less write changed=%v err=%v", changed, err)
	}
}

func rawRecordTestWriteAt(t *testing.T, recordID, protocolPath, parentContext, timestamp, encodedData string, squash bool) json.RawMessage {
	t.Helper()
	var message map[string]any
	if err := json.Unmarshal(rawRecordTestWrite(t, recordID, protocolPath, timestamp, encodedData), &message); err != nil {
		t.Fatal(err)
	}
	message["contextId"] = parentContext + "/" + recordID
	descriptor := message["descriptor"].(map[string]any)
	segments := strings.Split(parentContext, "/")
	descriptor["parentId"] = segments[len(segments)-1]
	if squash {
		descriptor["squash"] = true
	}
	return rawRecordTestJSON(t, message)
}

func rawRecordTestDeleteWith(t *testing.T, recordID, timestamp string, prune bool, permissionGrantID string) json.RawMessage {
	t.Helper()
	var message map[string]any
	if err := json.Unmarshal(rawRecordTestDelete(t, recordID, timestamp), &message); err != nil {
		t.Fatal(err)
	}
	descriptor := message["descriptor"].(map[string]any)
	if prune {
		descriptor["prune"] = true
	}
	if permissionGrantID != "" {
		descriptor["permissionGrantId"] = permissionGrantID
	}
	return rawRecordTestJSON(t, message)
}
