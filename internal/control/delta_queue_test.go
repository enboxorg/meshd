package control

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/enboxorg/meshd/internal/dwn"
	"github.com/enboxorg/meshd/protocols"
)

func TestApplyPendingStateWriteDeleteUsesNoRemoteRequest(t *testing.T) {
	client := newMaterializerTestClient()
	set := installDeltaTestBaseline(t, client, materializerBaseRecords(t))

	peerWrite := materializerRecord(t, materializerRecordSpec{
		id: "peer-node", path: "network/node", parentContext: materializerNetworkID,
		recipient: materializerPeerDID, data: NodeRecord{MeshIP: "10.200.1.2", Label: "peer"},
		timestamp: "2026-07-11T12:01:00Z",
	})
	event := rawRecordTestSubscription(peerWrite, "")
	event.Cursor = &dwn.ProgressToken{StreamID: "topology", Epoch: "epoch", Position: "1"}
	if err := client.StageTopologyEvent(event); err != nil {
		t.Fatal(err)
	}
	for i := range event.Event.Message {
		event.Event.Message[i] = 'x'
	}
	event.Cursor.Position = "mutated"
	*event.IsLatestBaseState = false

	response, err := client.ApplyPendingState(context.Background())
	if err != nil {
		t.Fatalf("apply write: %v", err)
	}
	if len(response.Peers) != 1 || response.Peers[0].DID != materializerPeerDID {
		t.Fatalf("write peers = %#v", response.Peers)
	}
	if _, ok := client.rawBaseline.get("peer-node"); !ok {
		t.Fatal("committed raw baseline is missing peer write")
	}

	deleteEvent := rawRecordTestSubscription(
		rawRecordTestDelete(t, "peer-node", "2026-07-11T12:02:00Z"),
		"",
	)
	if err := client.StageTopologyEvent(deleteEvent); err != nil {
		t.Fatal(err)
	}
	response, err = client.ApplyPendingState(context.Background())
	if err != nil {
		t.Fatalf("apply delete: %v", err)
	}
	if len(response.Peers) != 0 {
		t.Fatalf("delete peers = %#v", response.Peers)
	}
	if _, ok := client.rawBaseline.get("peer-node"); ok {
		t.Fatal("committed raw baseline retained deleted peer")
	}
	if response, err = client.ApplyPendingState(context.Background()); err != nil || response.Node == nil {
		t.Fatalf("no-pending local response = %#v, %v", response, err)
	}
	if client.anchorDWN != nil {
		t.Fatal("zero-remote test unexpectedly configured an anchor client")
	}

	// Keep the initially returned set demonstrably independent from the cache.
	externalPeerWrite := materializerRecord(t, materializerRecordSpec{
		id: "peer-node", path: "network/node", parentContext: materializerNetworkID,
		recipient: materializerPeerDID, data: NodeRecord{MeshIP: "10.200.1.2", Label: "external"},
		timestamp: "2026-07-11T12:04:00Z",
	})
	if _, err := set.addEntries([]json.RawMessage{externalPeerWrite}, ""); err != nil {
		t.Fatal(err)
	}
	if _, ok := client.rawBaseline.get("peer-node"); ok {
		t.Fatal("external baseline mutation reached the installed cache")
	}
}

func TestApplyPendingStateHydratesNewerHeadWithOriginalCursorCID(t *testing.T) {
	owner, signer, _, _ := sealedTestOwner(t)
	endpointData, err := json.Marshal(EndpointData{
		LocalEndpoints: []string{"192.0.2.55:4242"},
		DiscoKey:       "hydrated-disco",
		UpdatedAt:      "2026-07-11T12:04:00Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	dateCreated := "2026-07-11T12:03:00Z"
	originalEntry := deltaRecordWithoutEncodedData(t, materializerRecord(t, materializerRecordSpec{
		id: "self-endpoint", path: "network/node/endpoint",
		parentContext: materializerNetworkID + "/self-node",
		data:          EndpointData{}, timestamp: dateCreated,
	}))
	readEntry := deltaRecordWithoutEncodedData(t, materializerRecord(t, materializerRecordSpec{
		id: "self-endpoint", path: "network/node/endpoint",
		parentContext: materializerNetworkID + "/self-node",
		data:          EndpointData{}, dateCreated: dateCreated, timestamp: "2026-07-11T12:04:00Z",
	}))
	originalCID, err := computeRawRecordMessageCID(originalEntry)
	if err != nil {
		t.Fatal(err)
	}
	readCID, err := computeRawRecordMessageCID(readEntry)
	if err != nil {
		t.Fatal(err)
	}
	if readCID == originalCID {
		t.Fatal("newer RecordsRead head reused the original event CID")
	}

	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		var request dwn.JsonRpcRequest
		if err := json.Unmarshal([]byte(r.Header.Get("dwn-request")), &request); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		response := &dwn.JsonRpcResponse{
			JSONRPC: "2.0",
			ID:      request.ID,
			Result: &dwn.JsonRpcResult{
				Reply: &dwn.DwnReply{
					Status: dwn.Status{Code: http.StatusOK, Detail: "OK"},
					Entry:  readEntry,
				},
			},
		}
		wire, err := json.Marshal(response)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("dwn-response", string(wire))
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(endpointData)
	}))
	defer server.Close()

	client := NewDWNClient(
		server.URL,
		owner.URI,
		materializerNetworkID,
		materializerSelfDID,
		signer,
	)
	installDeltaTestBaseline(t, client, materializerBaseRecords(t))
	event := rawRecordTestSubscription(originalEntry, "")
	event.MessageCID = originalCID
	event.Cursor = &dwn.ProgressToken{
		StreamID: "topology", Epoch: "epoch", Position: "1", MessageCID: originalCID,
	}
	if err := client.StageTopologyEvent(event); err != nil {
		t.Fatal(err)
	}

	response, err := client.ApplyPendingState(context.Background())
	if err != nil {
		t.Fatalf("ApplyPendingState: %v", err)
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("RecordsRead requests = %d, want exactly 1", got)
	}
	if len(response.Node.Endpoints) != 1 || response.Node.Endpoints[0] != "192.0.2.55:4242" {
		t.Fatalf("hydrated endpoints = %#v", response.Node.Endpoints)
	}
	if response.Node.DiscoKey != "hydrated-disco" {
		t.Fatalf("hydrated disco key = %q", response.Node.DiscoKey)
	}
	committed, ok := client.rawBaseline.get("self-endpoint")
	if !ok || committed.messageCID != readCID || committed.messageTimestamp != "2026-07-11T12:04:00Z" {
		t.Fatalf("committed hydrated head = %#v, want newer CID %q", committed, readCID)
	}
	if _, err := client.ApplyPendingState(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("no-pending apply made another request: %d", got)
	}
}

func TestApplyPendingStateHydrationHTTP500DefersFullRebuild(t *testing.T) {
	owner, signer, _, _ := sealedTestOwner(t)
	entry := deltaRecordWithoutEncodedData(t, materializerRecord(t, materializerRecordSpec{
		id: "self-endpoint-500", path: "network/node/endpoint",
		parentContext: materializerNetworkID + "/self-node", data: EndpointData{},
		timestamp: "2026-07-11T12:05:00Z",
	}))
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		var request dwn.JsonRpcRequest
		if err := json.Unmarshal([]byte(r.Header.Get("dwn-request")), &request); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(dwn.JsonRpcResponse{
			JSONRPC: "2.0", ID: request.ID, Result: &dwn.JsonRpcResult{Reply: &dwn.DwnReply{
				Status: dwn.Status{Code: http.StatusInternalServerError, Detail: "forced failure"},
			}},
		})
	}))
	defer server.Close()
	client := NewDWNClient(server.URL, owner.URI, materializerNetworkID, materializerSelfDID, signer)
	installDeltaTestBaseline(t, client, materializerBaseRecords(t))
	oldRaw := client.rawBaseline
	if err := client.StageTopologyEvent(rawRecordTestSubscription(entry, "")); err != nil {
		t.Fatal(err)
	}

	_, err := client.ApplyPendingState(context.Background())
	if !errors.Is(err, ErrFullReconciliationRequired) || !errors.Is(err, dwn.ErrTransport) {
		t.Fatalf("hydration error = %v, want full-repair + transport", err)
	}
	if requests.Load() != 1 || client.rawBaseline != oldRaw {
		t.Fatalf("hydration failure requests=%d raw=%p/old=%p", requests.Load(), client.rawBaseline, oldRaw)
	}
}

func TestDeltaQueueOverflowMalformedAndIrrelevantFrames(t *testing.T) {
	client := newMaterializerTestClient()
	installDeltaTestBaseline(t, client, materializerBaseRecords(t))

	irrelevant := materializerRecord(t, materializerRecordSpec{
		id: "invite", path: "network/invite", parentContext: materializerNetworkID,
		data: json.RawMessage("not-json"), timestamp: "2026-07-11T12:00:00Z",
	})
	beforeSequence := client.topologySequence
	if err := client.StageTopologyEvent(rawRecordTestSubscription(irrelevant, "")); err != nil {
		t.Fatal(err)
	}
	if len(client.pendingTopology) != 0 || client.topologySequence != beforeSequence {
		t.Fatalf("irrelevant frame queued: len=%d sequence=%d", len(client.pendingTopology), client.topologySequence)
	}

	counted := rawRecordTestSubscription(
		rawRecordTestDelete(t, "counted", "2026-07-11T12:00:00Z"), "",
	)
	for i := 0; i < maxPendingTopologyEvents; i++ {
		if err := client.StageTopologyEvent(counted); err != nil {
			t.Fatal(err)
		}
	}
	if got := len(client.pendingTopology); got != maxPendingTopologyEvents {
		t.Fatalf("queue length = %d", got)
	}
	if err := client.StageTopologyEvent(rawRecordTestSubscription(
		rawRecordTestDelete(t, "overflow", "2026-07-11T13:00:00Z"), "",
	)); err != nil {
		t.Fatal(err)
	}
	if !client.fullReconciliation || len(client.pendingTopology) != 0 || client.pendingTopologyBytes != 0 {
		t.Fatalf("overflow repair=%v queue=%d bytes=%d", client.fullReconciliation, len(client.pendingTopology), client.pendingTopologyBytes)
	}
	if _, err := client.ApplyPendingState(context.Background()); !errors.Is(err, ErrFullReconciliationRequired) {
		t.Fatalf("overflow apply error = %v", err)
	}

	through := client.beginFullReconciliation()
	client.installRawBaseline(newDeltaTestRawSet(t, materializerBaseRecords(t)), through)
	if client.fullReconciliation {
		t.Fatal("covered overflow repair marker survived baseline")
	}
	if err := client.StageTopologyEvent(&dwn.SubscriptionMessage{Type: dwn.SubscriptionEventType}); err != nil {
		t.Fatal(err)
	}
	if !client.fullReconciliation {
		t.Fatal("malformed poison frame did not request full reconciliation")
	}
}

func TestDeltaQueueIgnoresIrrelevantDeleteInitialWrite(t *testing.T) {
	client := newMaterializerTestClient()
	timestamp := "2026-07-11T12:00:00Z"
	initialWrite := rawRecordTestJSON(t, map[string]any{
		"recordId":  "invite-delete",
		"contextId": materializerNetworkID + "/invite-delete",
		"descriptor": map[string]any{
			"interface":        "Records",
			"method":           "Write",
			"protocol":         protocols.MeshProtocolURI,
			"protocolPath":     "network/invite",
			"parentId":         materializerNetworkID,
			"dateCreated":      timestamp,
			"messageTimestamp": timestamp,
		},
	})
	event := rawRecordTestSubscription(rawRecordTestDelete(t, "invite-delete", "2026-07-11T12:01:00Z"), "")
	event.Event.InitialWrite = initialWrite
	beforeSequence := client.topologySequence

	if err := client.StageTopologyEvent(event); err != nil {
		t.Fatal(err)
	}
	if client.fullReconciliation || len(client.pendingTopology) != 0 || client.topologySequence != beforeSequence {
		t.Fatalf("irrelevant delete queued: repair=%v queue=%d sequence=%d", client.fullReconciliation, len(client.pendingTopology), client.topologySequence)
	}
}

func TestDeltaSequenceAndBaselineCutPreserveNewerEvents(t *testing.T) {
	client := newMaterializerTestClient()
	set := installDeltaTestBaseline(t, client, materializerBaseRecords(t))

	if err := client.StageTopologyEvent(rawRecordTestSubscription(
		rawRecordTestDelete(t, "first", "2026-07-11T12:01:00Z"), "",
	)); err != nil {
		t.Fatal(err)
	}
	firstSequence := client.pendingTopology[0].sequence
	if _, err := client.ApplyPendingState(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(client.pendingTopology) != 0 {
		t.Fatal("applied prefix remained queued")
	}
	assertPendingTopologyByteInvariant(t, client)

	if err := client.StageTopologyEvent(rawRecordTestSubscription(
		rawRecordTestDelete(t, "covered", "2026-07-11T12:02:00Z"), "",
	)); err != nil {
		t.Fatal(err)
	}
	secondSequence := client.pendingTopology[0].sequence
	if secondSequence <= firstSequence {
		t.Fatalf("sequence reset across drained batches: first=%d second=%d", firstSequence, secondSequence)
	}
	through := client.beginFullReconciliation()
	if err := client.StageTopologyEvent(rawRecordTestSubscription(
		rawRecordTestDelete(t, "after-cut", "2026-07-11T12:03:00Z"), "",
	)); err != nil {
		t.Fatal(err)
	}
	afterCutSequence := client.pendingTopology[1].sequence
	afterCutBytes := pendingTopologyMessageBytes(client.pendingTopology[1].message)
	client.installRawBaseline(set, through)
	if len(client.pendingTopology) != 1 || client.pendingTopology[0].sequence != afterCutSequence {
		t.Fatalf("baseline cut lost concurrent tail: %#v", client.pendingTopology)
	}
	if got := pendingTopologyEventsBytes(client.pendingTopology); got != afterCutBytes {
		t.Fatalf("baseline cut bytes = %d, want tail %d", got, afterCutBytes)
	}
	if _, err := client.ApplyPendingState(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := pendingTopologyEventsBytes(client.pendingTopology); got != 0 {
		t.Fatalf("applied prefix bytes = %d, want 0", got)
	}
	assertPendingTopologyByteInvariant(t, client)
}

func TestApplyPendingStateRequiredRecordFailureRollsBack(t *testing.T) {
	client := newMaterializerTestClient()
	installDeltaTestBaseline(t, client, materializerBaseRecords(t))
	oldNetwork := client.network
	oldNode := client.nodes[materializerSelfDID]
	oldACL := client.acl
	oldBaseline := client.rawBaseline
	oldUnreadable := client.UnreadableEndpointCount()
	oldDropped := client.DroppedPeerCount()

	invalidNetwork := materializerRecord(t, materializerRecordSpec{
		id: materializerNetworkID, path: "network", data: json.RawMessage("not-json"),
		timestamp: "2026-07-11T12:02:00Z",
	})
	if err := client.StageTopologyEvent(rawRecordTestSubscription(invalidNetwork, "")); err != nil {
		t.Fatal(err)
	}
	if _, err := client.ApplyPendingState(context.Background()); !errors.Is(err, ErrFullReconciliationRequired) {
		t.Fatalf("ApplyPendingState error = %v", err)
	}
	if !client.fullReconciliation {
		t.Fatal("required-record projection failure did not request repair")
	}
	if client.network != oldNetwork || client.nodes[materializerSelfDID] != oldNode ||
		client.acl != oldACL || client.rawBaseline != oldBaseline {
		t.Fatal("required-record projection failure replaced last-good pointers")
	}
	if client.UnreadableEndpointCount() != oldUnreadable || client.DroppedPeerCount() != oldDropped {
		t.Fatal("required-record projection failure transferred observability counters")
	}
}

func TestApplyPendingStateSelectedRecordFailureUsesLastGoodPolicy(t *testing.T) {
	t.Run("ACL retains prior policy", func(t *testing.T) {
		client := newMaterializerTestClient()
		records := append(materializerBaseRecords(t), materializerRecord(t, materializerRecordSpec{
			id: "acl", path: "network/aclPolicy", parentContext: materializerNetworkID,
			data: ACLPolicyData{Version: 1, DefaultAction: "accept"}, timestamp: "2026-07-11T12:01:00Z",
		}))
		installDeltaTestBaseline(t, client, records)
		oldBaseline := client.rawBaseline
		oldACL := client.acl
		update := materializerRecord(t, materializerRecordSpec{
			id: "acl", path: "network/aclPolicy", parentContext: materializerNetworkID,
			data: json.RawMessage("not-json"), timestamp: "2026-07-11T12:02:00Z",
		})
		if err := client.StageTopologyEvent(rawRecordTestSubscription(update, "")); err != nil {
			t.Fatal(err)
		}
		if _, err := client.ApplyPendingState(context.Background()); err != nil {
			t.Fatalf("ApplyPendingState: %v", err)
		}
		if client.fullReconciliation || len(client.pendingTopology) != 0 {
			t.Fatalf("ACL replacement caused repair=%v queue=%d", client.fullReconciliation, len(client.pendingTopology))
		}
		if client.rawBaseline == oldBaseline {
			t.Fatal("ACL replacement did not advance the raw baseline")
		}
		if oldACL == nil || client.acl == nil || oldACL.Version != 1 || client.acl.Version != 1 ||
			oldACL.DefaultAction != "accept" || client.acl.DefaultAction != "accept" {
			t.Fatalf("last-good ACL was not preserved: old=%#v current=%#v", oldACL, client.acl)
		}
	})

	t.Run("endpoint is skipped", func(t *testing.T) {
		client := newMaterializerTestClient()
		records := append(materializerBaseRecords(t), materializerRecord(t, materializerRecordSpec{
			id: "endpoint", path: "network/node/endpoint", parentContext: materializerNetworkID + "/self-node",
			data: EndpointData{LocalEndpoints: []string{"old-endpoint"}}, timestamp: "2026-07-11T12:01:00Z",
		}))
		installDeltaTestBaseline(t, client, records)
		oldBaseline := client.rawBaseline
		oldNode := client.nodes[materializerSelfDID]
		oldUnreadable := client.UnreadableEndpointCount()
		update := materializerRecord(t, materializerRecordSpec{
			id: "endpoint", path: "network/node/endpoint", parentContext: materializerNetworkID + "/self-node",
			data: json.RawMessage("not-json"), timestamp: "2026-07-11T12:02:00Z",
		})
		if err := client.StageTopologyEvent(rawRecordTestSubscription(update, "")); err != nil {
			t.Fatal(err)
		}
		response, err := client.ApplyPendingState(context.Background())
		if err != nil {
			t.Fatalf("ApplyPendingState: %v", err)
		}
		if client.fullReconciliation || len(client.pendingTopology) != 0 {
			t.Fatalf("endpoint replacement caused repair=%v queue=%d", client.fullReconciliation, len(client.pendingTopology))
		}
		if client.rawBaseline == oldBaseline {
			t.Fatal("endpoint replacement did not advance the raw baseline")
		}
		if response == nil || response.Node == nil || len(response.Node.Endpoints) != 0 ||
			len(client.nodes[materializerSelfDID].Endpoints) != 0 {
			t.Fatalf("malformed endpoint was not skipped: response=%#v node=%#v", response, client.nodes[materializerSelfDID])
		}
		if oldNode == nil || len(oldNode.Endpoints) != 1 || len(oldNode.Endpoints[0].LocalEndpoints) != 1 ||
			oldNode.Endpoints[0].LocalEndpoints[0] != "old-endpoint" {
			t.Fatalf("projection mutated the prior node: %#v", oldNode)
		}
		if client.UnreadableEndpointCount() <= oldUnreadable {
			t.Fatal("skipped endpoint did not increment unreadable endpoint count")
		}
	})
}

func TestPendingCommitFencePreservesLastGoodOnRepairAndCancellation(t *testing.T) {
	t.Run("repair between projection and commit", func(t *testing.T) {
		client, candidate, projection, through, oldNode, oldBaseline := prepareBlockedDeltaCommit(t)
		oldDropped := client.DroppedPeerCount()

		release := make(chan struct{})
		repaired := make(chan struct{})
		go func() {
			<-release
			client.RequireFullReconciliation()
			close(repaired)
		}()
		close(release)
		<-repaired

		err := client.completePendingTopology(context.Background(), candidate, projection, through)
		if !errors.Is(err, ErrFullReconciliationRequired) {
			t.Fatalf("complete error = %v", err)
		}
		if client.nodes[materializerSelfDID] != oldNode || client.rawBaseline != oldBaseline {
			t.Fatal("repair fence committed projected state")
		}
		if client.DroppedPeerCount() != oldDropped {
			t.Fatal("repair fence transferred projected counters")
		}
	})

	t.Run("context canceled at commit fence", func(t *testing.T) {
		client, candidate, projection, through, oldNode, oldBaseline := prepareBlockedDeltaCommit(t)
		oldDropped := client.DroppedPeerCount()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		err := client.completePendingTopology(ctx, candidate, projection, through)
		if !errors.Is(err, context.Canceled) || !errors.Is(err, ErrFullReconciliationRequired) {
			t.Fatalf("complete error = %v", err)
		}
		if client.nodes[materializerSelfDID] != oldNode || client.rawBaseline != oldBaseline {
			t.Fatal("canceled fence committed projected state")
		}
		if client.DroppedPeerCount() != oldDropped {
			t.Fatal("canceled fence transferred projected counters")
		}
	})
}

func prepareBlockedDeltaCommit(t *testing.T) (
	*DWNClient,
	*rawMeshRecordSet,
	*rawMeshMaterialization,
	uint64,
	*NodeRecord,
	*rawMeshRecordSet,
) {
	t.Helper()
	client := newMaterializerTestClient()
	records := []json.RawMessage{
		materializerRecord(t, materializerRecordSpec{
			id: materializerNetworkID, path: "network",
			data: NetworkConfig{Name: "no-fallback"}, timestamp: "2026-07-11T12:00:00Z",
		}),
		materializerRecord(t, materializerRecordSpec{
			id: "self-node", path: "network/node", parentContext: materializerNetworkID,
			recipient: materializerSelfDID, data: NodeRecord{MeshIP: "10.200.1.1"},
			timestamp: "2026-07-11T12:00:01Z",
		}),
	}
	installDeltaTestBaseline(t, client, records)
	oldNode := client.nodes[materializerSelfDID]
	oldBaseline := client.rawBaseline

	peer := materializerRecord(t, materializerRecordSpec{
		id: "peer-node", path: "network/node", parentContext: materializerNetworkID,
		recipient: materializerPeerDID, data: NodeRecord{Label: "no-ip"},
		timestamp: "2026-07-11T12:01:00Z",
	})
	if err := client.StageTopologyEvent(rawRecordTestSubscription(peer, "")); err != nil {
		t.Fatal(err)
	}
	candidate, events, through, err := client.beginPendingTopology()
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range events {
		if err := client.applyPendingTopologyEvent(context.Background(), candidate, event.message); err != nil {
			t.Fatal(err)
		}
	}
	projection, err := client.projectRawMeshRecordSetWithDecryptors(context.Background(), candidate, client.makeDecryptor)
	if err != nil {
		t.Fatal(err)
	}
	if projection.builder.DroppedPeerCount() == 0 {
		t.Fatal("fixture did not produce a projected counter delta")
	}
	return client, candidate, projection, through, oldNode, oldBaseline
}

func TestApplyPendingStateValidatedCommitsOnlyAfterValidation(t *testing.T) {
	client := newMaterializerTestClient()
	installDeltaTestBaseline(t, client, materializerBaseRecords(t))
	oldBaseline := client.rawBaseline
	oldNode := client.nodes[materializerSelfDID]

	peerWrite := materializerRecord(t, materializerRecordSpec{
		id: "validated-peer", path: "network/node", parentContext: materializerNetworkID,
		recipient: materializerPeerDID, data: NodeRecord{MeshIP: "10.200.1.2"},
		timestamp: "2026-07-11T12:05:00Z",
	})
	if err := client.StageTopologyEvent(rawRecordTestSubscription(peerWrite, "")); err != nil {
		t.Fatal(err)
	}
	validationErr := errors.New("network map rejected")
	response, err := client.ApplyPendingStateValidated(context.Background(), func(candidate *MapResponse) error {
		if len(candidate.Peers) != 1 {
			t.Fatalf("candidate peers = %#v", candidate.Peers)
		}
		return validationErr
	})
	if !errors.Is(err, validationErr) || response == nil {
		t.Fatalf("validated apply = (%#v, %v)", response, err)
	}
	if client.rawBaseline != oldBaseline || client.nodes[materializerSelfDID] != oldNode || len(client.pendingTopology) != 1 {
		t.Fatal("validation failure advanced last-good state or queue")
	}
	if _, err := client.ApplyPendingStateValidated(context.Background(), func(*MapResponse) error { return nil }); err != nil {
		t.Fatalf("validated retry: %v", err)
	}
	if client.rawBaseline == oldBaseline || len(client.pendingTopology) != 0 {
		t.Fatal("successful validation did not commit the captured prefix")
	}
}

func TestApplyPendingStateValidatedPreservesConcurrentTail(t *testing.T) {
	client := newMaterializerTestClient()
	installDeltaTestBaseline(t, client, materializerBaseRecords(t))
	first := rawRecordTestSubscription(rawRecordTestDelete(t, "first-tail", "2026-07-11T12:05:00Z"), "")
	second := rawRecordTestSubscription(rawRecordTestDelete(t, "second-tail", "2026-07-11T12:06:00Z"), "")
	if err := client.StageTopologyEvent(first); err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, err := client.ApplyPendingStateValidated(context.Background(), func(*MapResponse) error {
			close(entered)
			<-release
			return nil
		})
		done <- err
	}()
	<-entered
	if err := client.StageTopologyEvent(second); err != nil {
		t.Fatal(err)
	}
	secondSequence := client.pendingTopology[len(client.pendingTopology)-1].sequence
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if len(client.pendingTopology) != 1 || client.pendingTopology[0].sequence != secondSequence {
		t.Fatalf("concurrent tail = %#v", client.pendingTopology)
	}
	assertPendingTopologyByteInvariant(t, client)
}

func TestApplyPendingStateValidatedRepairAndCancellationFence(t *testing.T) {
	for _, test := range []struct {
		name  string
		fence func(*DWNClient, context.CancelFunc)
		want  error
	}{
		{name: "repair", fence: func(client *DWNClient, _ context.CancelFunc) { client.RequireFullReconciliation() }, want: ErrFullReconciliationRequired},
		{name: "cancel", fence: func(_ *DWNClient, cancel context.CancelFunc) { cancel() }, want: context.Canceled},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := newMaterializerTestClient()
			installDeltaTestBaseline(t, client, materializerBaseRecords(t))
			oldBaseline := client.rawBaseline
			if err := client.StageTopologyEvent(rawRecordTestSubscription(rawRecordTestDelete(t, "fenced", "2026-07-11T12:05:00Z"), "")); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			entered := make(chan struct{})
			release := make(chan struct{})
			done := make(chan error, 1)
			go func() {
				_, err := client.ApplyPendingStateValidated(ctx, func(*MapResponse) error {
					close(entered)
					<-release
					return nil
				})
				done <- err
			}()
			<-entered
			test.fence(client, cancel)
			close(release)
			err := <-done
			if !errors.Is(err, test.want) || !errors.Is(err, ErrFullReconciliationRequired) {
				t.Fatalf("fenced apply error = %v", err)
			}
			if client.rawBaseline != oldBaseline {
				t.Fatal("fenced validation committed raw state")
			}
		})
	}
}

func TestApplyPendingStateValidatedNoPendingRepairFence(t *testing.T) {
	client := newMaterializerTestClient()
	installDeltaTestBaseline(t, client, materializerBaseRecords(t))
	oldBaseline := client.rawBaseline
	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, err := client.ApplyPendingStateValidated(context.Background(), func(*MapResponse) error {
			close(entered)
			<-release
			return nil
		})
		done <- err
	}()
	<-entered
	client.RequireFullReconciliation()
	close(release)
	if err := <-done; !errors.Is(err, ErrFullReconciliationRequired) {
		t.Fatalf("no-pending fenced apply error = %v", err)
	}
	if client.rawBaseline != oldBaseline {
		t.Fatal("no-pending fence changed baseline")
	}
}

func TestTopologyQueueByteBudgetBoundaryAndAccounting(t *testing.T) {
	client := newMaterializerTestClient()
	installDeltaTestBaseline(t, client, materializerBaseRecords(t))
	event := rawRecordTestSubscription(rawRecordTestDelete(t, "byte-budget", "2026-07-11T12:05:00Z"), "")
	baseBytes := pendingTopologyMessageBytes(event)
	event.EncodedData = strings.Repeat("x", maxPendingTopologyBytes-baseBytes)
	if got := pendingTopologyMessageBytes(event); got != maxPendingTopologyBytes {
		t.Fatalf("boundary event bytes = %d", got)
	}
	if err := client.StageTopologyEvent(event); err != nil {
		t.Fatal(err)
	}
	if got := pendingTopologyEventsBytes(client.pendingTopology); got != maxPendingTopologyBytes || client.fullReconciliation {
		t.Fatalf("boundary queue bytes=%d repair=%v", got, client.fullReconciliation)
	}
	assertPendingTopologyByteInvariant(t, client)
	if err := client.StageTopologyEvent(rawRecordTestSubscription(rawRecordTestDelete(t, "overflow-byte", "2026-07-11T12:06:00Z"), "")); err != nil {
		t.Fatal(err)
	}
	if !client.fullReconciliation || len(client.pendingTopology) != 0 || pendingTopologyEventsBytes(client.pendingTopology) != 0 {
		t.Fatal("byte overflow did not clear queue and request repair")
	}
	assertPendingTopologyByteInvariant(t, client)

	through := client.beginFullReconciliation()
	client.installRawBaseline(newDeltaTestRawSet(t, materializerBaseRecords(t)), through)
	if err := client.StageTopologyEvent(rawRecordTestSubscription(rawRecordTestDelete(t, "before-oversized", "2026-07-11T12:06:30Z"), "")); err != nil {
		t.Fatal(err)
	}
	oversized := rawRecordTestSubscription(rawRecordTestDelete(t, "oversized-byte", "2026-07-11T12:07:00Z"), "")
	oversized.EncodedData = strings.Repeat("y", maxPendingTopologyBytes-pendingTopologyMessageBytes(oversized)+1)
	if err := client.StageTopologyEvent(oversized); err != nil {
		t.Fatal(err)
	}
	if !client.fullReconciliation || len(client.pendingTopology) != 0 || client.pendingTopologyBytes != 0 {
		t.Fatal("oversized single event was retained")
	}
	assertPendingTopologyByteInvariant(t, client)

	through = client.beginFullReconciliation()
	client.installRawBaseline(newDeltaTestRawSet(t, materializerBaseRecords(t)), through)
	metadataHeavy := rawRecordTestSubscription(rawRecordTestDelete(t, "metadata-budget", "2026-07-11T12:08:00Z"), "")
	metadataHeavy.Seq = strings.Repeat("s", 4096)
	metadataHeavy.MessageCID = strings.Repeat("m", 4096)
	metadataHeavy.Protocol = strings.Repeat("p", 512<<10)
	metadataHeavy.Cursor = &dwn.ProgressToken{
		StreamID: strings.Repeat("i", 512<<10),
		Epoch:    strings.Repeat("e", 512<<10),
		Position: strings.Repeat("9", 512<<10),
	}
	metadataHeavy.Error = &dwn.SubscriptionError{
		Code:   strings.Repeat("c", 4096),
		Detail: strings.Repeat("d", 512<<10),
	}
	metadataBytes := pendingTopologyFixedBytes + len(metadataHeavy.Type) + len(metadataHeavy.Seq) +
		len(metadataHeavy.MessageCID) + len(metadataHeavy.Protocol) + len(metadataHeavy.EncodedData) +
		len(metadataHeavy.Cursor.StreamID) + len(metadataHeavy.Cursor.Epoch) +
		len(metadataHeavy.Cursor.Position) + len(metadataHeavy.Cursor.MessageCID) +
		len(metadataHeavy.Event.Message) + len(metadataHeavy.Event.InitialWrite) +
		len(metadataHeavy.Error.Code) + len(metadataHeavy.Error.Detail)
	if got := pendingTopologyMessageBytes(metadataHeavy); got != metadataBytes {
		t.Fatalf("metadata event bytes = %d, want exact retained size %d", got, metadataBytes)
	}
	if metadataBytes >= maxPendingTopologyBytes {
		t.Fatalf("metadata fixture already exceeds budget: %d", metadataBytes)
	}
	metadataHeavy.Cursor.MessageCID = strings.Repeat("r", maxPendingTopologyBytes-metadataBytes)
	if got := pendingTopologyMessageBytes(metadataHeavy); got != maxPendingTopologyBytes {
		t.Fatalf("metadata boundary bytes = %d", got)
	}
	if err := client.StageTopologyEvent(metadataHeavy); err != nil {
		t.Fatal(err)
	}
	metadataHeavy.Cursor.MessageCID = "mutated after staging"
	if got := pendingTopologyEventsBytes(client.pendingTopology); got != maxPendingTopologyBytes || client.fullReconciliation {
		t.Fatalf("metadata boundary queue bytes=%d repair=%v", got, client.fullReconciliation)
	}
	assertPendingTopologyByteInvariant(t, client)
	if err := client.StageTopologyEvent(rawRecordTestSubscription(rawRecordTestDelete(t, "metadata-overflow", "2026-07-11T12:09:00Z"), "")); err != nil {
		t.Fatal(err)
	}
	if !client.fullReconciliation || len(client.pendingTopology) != 0 || client.pendingTopologyBytes != 0 {
		t.Fatal("metadata byte overflow did not clear queue and request repair")
	}
	assertPendingTopologyByteInvariant(t, client)
}

func TestDeltaQueueByteAccountingClearPaths(t *testing.T) {
	client := newMaterializerTestClient()
	installDeltaTestBaseline(t, client, materializerBaseRecords(t))
	event := rawRecordTestSubscription(
		rawRecordTestDelete(t, "accounting-clear", "2026-07-11T12:10:00Z"), "",
	)

	if err := client.StageTopologyEvent(event); err != nil {
		t.Fatal(err)
	}
	assertPendingTopologyByteInvariant(t, client)
	client.RequireFullReconciliation()
	assertPendingTopologyByteInvariant(t, client)
	if !client.fullReconciliation {
		t.Fatal("explicit repair did not set the repair marker")
	}

	through := client.beginFullReconciliation()
	client.installRawBaseline(newDeltaTestRawSet(t, materializerBaseRecords(t)), through)
	if err := client.StageTopologyEvent(event); err != nil {
		t.Fatal(err)
	}
	assertPendingTopologyByteInvariant(t, client)
	client.deltaMu.Lock()
	client.pendingTopology[0].message.Event = nil
	client.deltaMu.Unlock()
	if _, _, _, err := client.beginPendingTopology(); !errors.Is(err, ErrFullReconciliationRequired) {
		t.Fatalf("clone failure = %v, want full repair", err)
	}
	assertPendingTopologyByteInvariant(t, client)

	through = client.beginFullReconciliation()
	client.installRawBaseline(newDeltaTestRawSet(t, materializerBaseRecords(t)), through)
	if err := client.StageTopologyEvent(event); err != nil {
		t.Fatal(err)
	}
	candidate, _, pendingThrough, err := client.beginPendingTopology()
	if err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := client.completePendingTopology(canceled, candidate, nil, pendingThrough); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled completion = %v", err)
	}
	assertPendingTopologyByteInvariant(t, client)

	through = client.beginFullReconciliation()
	client.installRawBaseline(newDeltaTestRawSet(t, materializerBaseRecords(t)), through)
	if err := client.StageTopologyEvent(event); err != nil {
		t.Fatal(err)
	}
	client.installRawBaseline(nil, client.beginFullReconciliation())
	assertPendingTopologyByteInvariant(t, client)
}

func TestFullReconciliationByteAccountingPreservesConcurrentTail(t *testing.T) {
	client := newMaterializerTestClient()
	set := installDeltaTestBaseline(t, client, materializerBaseRecords(t))
	covered := rawRecordTestSubscription(
		rawRecordTestDelete(t, "covered-accounting", "2026-07-11T12:11:00Z"), "",
	)
	if err := client.StageTopologyEvent(covered); err != nil {
		t.Fatal(err)
	}
	through := client.beginFullReconciliation()
	tail := rawRecordTestSubscription(
		rawRecordTestDelete(t, "concurrent-accounting-tail", "2026-07-11T12:12:00Z"), "",
	)

	const workers = 8
	const perWorker = 32
	start := make(chan struct{})
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for range perWorker {
				if err := client.StageTopologyEvent(tail); err != nil {
					errs <- err
					return
				}
			}
		}()
	}
	close(start)
	client.installRawBaseline(set, through)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	assertPendingTopologyByteInvariant(t, client)
	client.deltaMu.Lock()
	if got, want := len(client.pendingTopology), workers*perWorker; got != want {
		client.deltaMu.Unlock()
		t.Fatalf("post-cut tail count = %d, want %d", got, want)
	}
	if got, want := client.pendingTopologyBytes, workers*perWorker*pendingTopologyMessageBytes(tail); got != want {
		client.deltaMu.Unlock()
		t.Fatalf("post-cut tail bytes = %d, want %d", got, want)
	}
	client.deltaMu.Unlock()

	commitThrough := client.beginFullReconciliation()
	postCommit := rawRecordTestSubscription(
		rawRecordTestDelete(t, "post-commit-accounting", "2026-07-11T12:13:00Z"), "",
	)
	if err := client.StageTopologyEvent(postCommit); err != nil {
		t.Fatal(err)
	}
	candidate := newDeltaTestRawSet(t, materializerBaseRecords(t))
	projection, err := client.projectRawMeshRecordSetWithDecryptors(context.Background(), candidate, client.makeDecryptor)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.completeFullReconciliation(context.Background(), candidate, projection, commitThrough); err != nil {
		t.Fatal(err)
	}
	assertPendingTopologyByteInvariant(t, client)
	client.deltaMu.Lock()
	if got := len(client.pendingTopology); got != 1 {
		client.deltaMu.Unlock()
		t.Fatalf("full commit tail count = %d, want 1", got)
	}
	if got, want := client.pendingTopologyBytes, pendingTopologyMessageBytes(postCommit); got != want {
		client.deltaMu.Unlock()
		t.Fatalf("full commit tail bytes = %d, want %d", got, want)
	}
	client.deltaMu.Unlock()
}

func assertPendingTopologyByteInvariant(t *testing.T, client *DWNClient) {
	t.Helper()
	client.deltaMu.Lock()
	defer client.deltaMu.Unlock()
	want := 0
	for i, event := range client.pendingTopology {
		eventBytes := pendingTopologyMessageBytes(event.message)
		if event.retainedBytes != eventBytes {
			t.Fatalf("event %d retained bytes = %d, want %d", i, event.retainedBytes, eventBytes)
		}
		want += eventBytes
	}
	if client.pendingTopologyBytes != want {
		t.Fatalf("pending topology bytes = %d, want %d", client.pendingTopologyBytes, want)
	}
	if client.pendingTopologyBytes < 0 || client.pendingTopologyBytes > maxPendingTopologyBytes {
		t.Fatalf("pending topology byte bound = %d", client.pendingTopologyBytes)
	}
}

func installDeltaTestBaseline(t *testing.T, client *DWNClient, records []json.RawMessage) *rawMeshRecordSet {
	t.Helper()
	set := newDeltaTestRawSet(t, records)
	if _, err := client.materializeRawMeshRecordSet(context.Background(), set); err != nil {
		t.Fatalf("materialize baseline: %v", err)
	}
	through := client.beginFullReconciliation()
	client.installRawBaseline(set, through)
	return set
}

func newDeltaTestRawSet(t *testing.T, records []json.RawMessage) *rawMeshRecordSet {
	t.Helper()
	set, err := newRawMeshRecordSet(records, "")
	if err != nil {
		t.Fatalf("newRawMeshRecordSet: %v", err)
	}
	return set
}

func deltaRecordWithoutEncodedData(t *testing.T, raw json.RawMessage) json.RawMessage {
	t.Helper()
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		t.Fatal(err)
	}
	delete(object, "encodedData")
	stripped, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	return stripped
}
