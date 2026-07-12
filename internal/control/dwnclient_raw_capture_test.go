package control

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/enboxorg/meshd/internal/dwn"
	"github.com/enboxorg/meshd/protocols"
)

type rawCaptureServerControl struct {
	failNetwork          atomic.Bool
	networkStarted       chan struct{}
	releaseNetwork       chan struct{}
	startOnce            sync.Once
	requests             atomic.Int64
	targetedReads        atomic.Int64
	targetedRateLimit    atomic.Bool
	queryRateLimitPath   string
	queryRateLimitDetail string
	queryDelay           time.Duration
	activeQueries        atomic.Int32
	maxConcurrentQueries atomic.Int32
	targetedReadEntry    map[string]json.RawMessage
	targetedReadBodies   map[string][]byte
}

func newRawCaptureLoadClient(
	t *testing.T,
	network json.RawMessage,
	entriesByPath map[string][]json.RawMessage,
	control *rawCaptureServerControl,
) *DWNClient {
	t.Helper()
	if control == nil {
		control = &rawCaptureServerControl{}
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		control.requests.Add(1)
		var request dwn.JsonRpcRequest
		if err := json.Unmarshal([]byte(r.Header.Get("dwn-request")), &request); err != nil || request.Params == nil || request.Params.Message == nil {
			http.Error(w, "invalid DWN request", http.StatusBadRequest)
			return
		}
		message := request.Params.Message
		method, _ := message.Descriptor["method"].(string)
		reply := &dwn.DwnReply{Status: dwn.Status{Code: http.StatusOK, Detail: "OK"}}
		if method == "Read" {
			filter, _ := message.Descriptor["filter"].(map[string]any)
			recordID, _ := filter["recordId"].(string)
			if recordID != materializerNetworkID {
				control.targetedReads.Add(1)
				if control.targetedRateLimit.Load() {
					reply.Status = dwn.Status{Code: http.StatusTooManyRequests, Detail: "RateLimitExceeded: retry after 2s"}
				} else if entry, ok := control.targetedReadEntry[recordID]; ok {
					reply.Entry = entry
					if body, ok := control.targetedReadBodies[recordID]; ok {
						response, err := json.Marshal(dwn.JsonRpcResponse{
							JSONRPC: "2.0", ID: request.ID,
							Result: &dwn.JsonRpcResult{Reply: reply},
						})
						if err != nil {
							http.Error(w, err.Error(), http.StatusInternalServerError)
							return
						}
						w.Header().Set("dwn-response", string(response))
						w.Header().Set("Content-Type", "application/octet-stream")
						_, _ = w.Write(body)
						return
					}
				} else {
					reply.Status = dwn.Status{Code: http.StatusNotFound, Detail: "targeted fixture missing"}
				}
			} else {
				if control.networkStarted != nil {
					control.startOnce.Do(func() { close(control.networkStarted) })
				}
				if control.releaseNetwork != nil {
					<-control.releaseNetwork
				}
				if control.failNetwork.Load() {
					reply.Status = dwn.Status{Code: http.StatusInternalServerError, Detail: "forced failure"}
				} else {
					reply.Entry = network
				}
			}
		} else {
			filter, _ := message.Descriptor["filter"].(map[string]any)
			path, _ := filter["protocolPath"].(string)
			contextID, _ := filter["contextId"].(string)
			active := control.activeQueries.Add(1)
			for {
				maximum := control.maxConcurrentQueries.Load()
				if active <= maximum || control.maxConcurrentQueries.CompareAndSwap(maximum, active) {
					break
				}
			}
			defer control.activeQueries.Add(-1)
			if control.queryDelay > 0 {
				select {
				case <-time.After(control.queryDelay):
				case <-r.Context().Done():
					return
				}
			}
			if path == control.queryRateLimitPath {
				detail := control.queryRateLimitDetail
				if detail == "" {
					detail = "RateLimitExceeded: retry after 1s"
				}
				reply.Status = dwn.Status{Code: http.StatusTooManyRequests, Detail: detail}
			} else {
				var selected []json.RawMessage
				for _, entry := range entriesByPath[path] {
					identity, identityErr := rawCaptureIdentity(entry)
					if identityErr != nil || identity.parentContextID == contextID {
						selected = append(selected, entry)
					}
				}
				reply.Entries, _ = json.Marshal(selected)
			}
		}
		_ = json.NewEncoder(w).Encode(dwn.JsonRpcResponse{
			JSONRPC: "2.0",
			ID:      request.ID,
			Result:  &dwn.JsonRpcResult{Reply: reply},
		})
	}))
	t.Cleanup(server.Close)
	_, signer, _, _ := sealedTestOwner(t)
	return NewDWNClient(server.URL, materializerSelfDID, materializerNetworkID, materializerSelfDID, signer)
}

func rawCaptureLoadFixture(t *testing.T) (json.RawMessage, map[string][]json.RawMessage) {
	t.Helper()
	record := func(id, path, parent, recipient, timestamp string, data any) json.RawMessage {
		raw := materializerRecord(t, materializerRecordSpec{id: id, path: path, parentContext: parent, recipient: recipient, data: data, timestamp: timestamp})
		var message map[string]any
		if err := json.Unmarshal(raw, &message); err != nil {
			t.Fatal(err)
		}
		message["descriptor"].(map[string]any)["dateCreated"] = timestamp
		raw, err := json.Marshal(message)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	network := record(materializerNetworkID, "network", "", "", "2026-07-11T12:00:00Z", NetworkConfig{Name: "capture", MeshCIDR: "10.200.0.0/16"})
	entries := map[string][]json.RawMessage{
		"network/node":                 {record("self-node", "network/node", materializerNetworkID, materializerSelfDID, "2026-07-11T12:00:01Z", NodeRecord{MeshIP: "10.200.1.1", Label: "self"})},
		"network/member":               {record("member-record", "network/member", materializerNetworkID, "did:jwk:member", "2026-07-11T12:00:02Z", MemberRecord{Label: "member", AddedAt: "2026-07-11T12:00:02Z"})},
		"network/member/node":          {record("peer-node", "network/member/node", materializerNetworkID+"/member-record", materializerPeerDID, "2026-07-11T12:00:03Z", NodeRecord{MeshIP: "10.200.1.2", Label: "peer"})},
		"network/relay":                {record("relay-record", "network/relay", materializerNetworkID, "", "2026-07-11T12:00:04Z", RelayData{URL: "relay.example.com", Region: "test", STUNPort: 3478})},
		"network/aclPolicy":            {record("acl-record", "network/aclPolicy", materializerNetworkID, "", "2026-07-11T12:00:05Z", ACLPolicyData{Version: 1, DefaultAction: "accept"})},
		"network/node/nodeInfo":        {record("self-info", "network/node/nodeInfo", materializerNetworkID+"/self-node", "", "2026-07-11T12:00:06Z", NodeInfoData{Hostname: "self-host"})},
		"network/member/node/nodeInfo": {record("peer-info", "network/member/node/nodeInfo", materializerNetworkID+"/member-record/peer-node", "", "2026-07-11T12:00:07Z", NodeInfoData{Hostname: "peer-host"})},
		"network/node/endpoint":        {record("self-endpoint", "network/node/endpoint", materializerNetworkID+"/self-node", "", "2026-07-11T12:00:08Z", EndpointData{LocalEndpoints: []string{"192.0.2.1:1111"}})},
		"network/member/node/endpoint": {record("peer-endpoint", "network/member/node/endpoint", materializerNetworkID+"/member-record/peer-node", "", "2026-07-11T12:00:09Z", EndpointData{LocalEndpoints: []string{"192.0.2.2:2222"}})},
	}
	return network, entries
}

func TestRawCaptureReadStatusAndEndpointFailureClassification(t *testing.T) {
	if err := rawCaptureReadStatusError(nil); !errors.Is(err, dwn.ErrTransport) {
		t.Fatalf("nil read error = %v, want ErrTransport", err)
	}
	if err := rawCaptureReadStatusError(&dwn.RecordsReadResult{Reply: &dwn.DwnReply{
		Status: dwn.Status{Code: http.StatusInternalServerError, Detail: "failed"},
	}}); !errors.Is(err, dwn.ErrTransport) {
		t.Fatalf("500 read error = %v, want ErrTransport", err)
	}
	if err := rawCaptureReadStatusError(&dwn.RecordsReadResult{Reply: &dwn.DwnReply{
		Status: dwn.Status{Code: http.StatusNotFound, Detail: "missing"},
	}}); !errors.Is(err, errRawCaptureReadNotFound) || errors.Is(err, dwn.ErrTransport) {
		t.Fatalf("404 read error = %v, want distinct not-found", err)
	}
	if got := endpointFailureClass(fmt.Errorf("wrapped: %w", errAudienceKeyDeliveryAbsent)); got != "key-unavailable" {
		t.Fatalf("audience absence failure class = %q", got)
	}
}

func TestQueryAllRawMeshRecordsPaginationBoundsAndOpaqueCursor(t *testing.T) {
	client := newMaterializerTestClient()
	entry := func(id string) json.RawMessage {
		return materializerRecord(t, materializerRecordSpec{
			id: id, path: "network/node", parentContext: materializerNetworkID, recipient: materializerSelfDID,
			data: NodeRecord{MeshIP: "10.200.1.1"}, timestamp: "2026-07-11T12:00:00Z",
		})
	}
	reply := func(entries []json.RawMessage, cursor string) *dwn.DwnReply {
		rawEntries, err := json.Marshal(entries)
		if err != nil {
			t.Fatal(err)
		}
		return &dwn.DwnReply{Status: dwn.Status{Code: http.StatusOK}, Entries: rawEntries, Cursor: json.RawMessage(cursor)}
	}

	t.Run("multi-page cursor preserves large numeric lexeme", func(t *testing.T) {
		const cursor = ` { "position" : 9007199254740993123456789 } `
		const compact = `{"position":9007199254740993123456789}`
		pages := []*dwn.DwnReply{reply([]json.RawMessage{entry("node-a")}, cursor), reply([]json.RawMessage{entry("node-b")}, "")}
		calls := 0
		got, err := client.queryAllRawMeshRecordsWith(context.Background(), dwn.RecordsFilter{
			Protocol: protocols.MeshProtocolURI, ProtocolPath: "network/node", ContextID: materializerNetworkID,
		}, "", &fullStateFetchBudget{}, func(_ context.Context, pagination *dwn.Pagination) (*dwn.DwnReply, error) {
			if calls == 0 && len(pagination.Cursor) != 0 {
				t.Fatalf("first cursor = %s", pagination.Cursor)
			}
			if calls == 1 && string(pagination.Cursor) != compact {
				t.Fatalf("second cursor = %s, want %s", pagination.Cursor, compact)
			}
			page := pages[calls]
			calls++
			return page, nil
		})
		if err != nil || len(got) != 2 || calls != 2 {
			t.Fatalf("queryAll = (%d entries, %v), calls=%d", len(got), err, calls)
		}
	})

	t.Run("duplicate compact cursor fails", func(t *testing.T) {
		calls := 0
		_, err := client.queryAllRawMeshRecordsWith(context.Background(), dwn.RecordsFilter{
			Protocol: protocols.MeshProtocolURI, ProtocolPath: "network/node", ContextID: materializerNetworkID,
		}, "", &fullStateFetchBudget{}, func(context.Context, *dwn.Pagination) (*dwn.DwnReply, error) {
			calls++
			return reply(nil, ` { "messageCid" : "same" } `), nil
		})
		if err == nil || !strings.Contains(err.Error(), "repeated pagination cursor") || calls != 2 {
			t.Fatalf("duplicate cursor error=%v calls=%d", err, calls)
		}
	})

	t.Run("page limit fails", func(t *testing.T) {
		calls := 0
		_, err := client.queryAllRawMeshRecordsWith(context.Background(), dwn.RecordsFilter{
			Protocol: protocols.MeshProtocolURI, ProtocolPath: "network/node", ContextID: materializerNetworkID,
		}, "", &fullStateFetchBudget{}, func(context.Context, *dwn.Pagination) (*dwn.DwnReply, error) {
			calls++
			return reply(nil, fmt.Sprintf(`{"page":%d}`, calls)), nil
		})
		if err == nil || !strings.Contains(err.Error(), "page limit") || calls != fullStateMaxQueryPages {
			t.Fatalf("page limit error=%v calls=%d", err, calls)
		}
	})

	t.Run("global limits fail closed", func(t *testing.T) {
		budget := &fullStateFetchBudget{requests: fullStateMaxRequests}
		if err := budget.takeRequest(); err == nil {
			t.Fatal("request limit accepted another request")
		}
		budget = &fullStateFetchBudget{records: fullStateMaxRecords}
		if err := budget.retain([]json.RawMessage{json.RawMessage(`{}`)}, nil); err == nil {
			t.Fatal("record limit accepted another record")
		}
		budget = &fullStateFetchBudget{bytes: fullStateMaxBytes}
		if err := budget.retain(nil, json.RawMessage(`{}`)); err == nil {
			t.Fatal("byte limit accepted more data")
		}
	})
}

func TestLoadStateUsesBoundedConcurrentParentQueries(t *testing.T) {
	network, entries := rawCaptureLoadFixture(t)
	const peers = 12
	entries["network/member"] = nil
	entries["network/member/node"] = nil
	entries["network/member/node/nodeInfo"] = nil
	entries["network/member/node/endpoint"] = nil
	for i := 0; i < peers; i++ {
		memberID := fmt.Sprintf("member-%02d", i)
		nodeID := fmt.Sprintf("peer-node-%02d", i)
		memberDID := fmt.Sprintf("did:jwk:member-%02d", i)
		nodeDID := fmt.Sprintf("did:jwk:peer-%02d", i)
		timestamp := fmt.Sprintf("2026-07-11T12:00:%02dZ", 10+i)
		entries["network/member"] = append(entries["network/member"], materializerRecord(t, materializerRecordSpec{
			id: memberID, path: "network/member", parentContext: materializerNetworkID, recipient: memberDID,
			data: MemberRecord{Label: memberID}, timestamp: timestamp,
		}))
		nodeContext := materializerNetworkID + "/" + memberID
		entries["network/member/node"] = append(entries["network/member/node"], materializerRecord(t, materializerRecordSpec{
			id: nodeID, path: "network/member/node", parentContext: nodeContext, recipient: nodeDID,
			data: NodeRecord{MeshIP: fmt.Sprintf("10.200.2.%d", i+1), Label: nodeID}, timestamp: timestamp,
		}))
		nodeContext += "/" + nodeID
		entries["network/member/node/nodeInfo"] = append(entries["network/member/node/nodeInfo"], materializerRecord(t, materializerRecordSpec{
			id: "info-" + nodeID, path: "network/member/node/nodeInfo", parentContext: nodeContext,
			data: NodeInfoData{Hostname: nodeID}, timestamp: timestamp,
		}))
		entries["network/member/node/endpoint"] = append(entries["network/member/node/endpoint"], materializerRecord(t, materializerRecordSpec{
			id: "endpoint-" + nodeID, path: "network/member/node/endpoint", parentContext: nodeContext,
			data: EndpointData{LocalEndpoints: []string{fmt.Sprintf("192.0.2.%d:4242", i+1)}}, timestamp: timestamp,
		}))
	}
	control := &rawCaptureServerControl{queryDelay: 10 * time.Millisecond}
	client := newRawCaptureLoadClient(t, network, entries, control)
	response, err := client.LoadState(context.Background())
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if len(response.Peers) != peers {
		t.Fatalf("peers = %d, want %d", len(response.Peers), peers)
	}
	if maximum := control.maxConcurrentQueries.Load(); maximum <= 1 || maximum > fullStateQueryWorkers {
		t.Fatalf("maximum concurrent queries = %d, want 2..%d", maximum, fullStateQueryWorkers)
	}
	wantRequests := int64(7 + 3*peers)
	if got := control.requests.Load(); got != wantRequests {
		t.Fatalf("requests = %d, want %d", got, wantRequests)
	}
}

func TestLoadStateInstallsCompleteRawBaseline(t *testing.T) {
	network, entries := rawCaptureLoadFixture(t)
	client := newRawCaptureLoadClient(t, network, entries, nil)
	response, err := client.LoadState(context.Background())
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if response.Node == nil || len(response.Peers) != 1 {
		t.Fatalf("map response = %#v", response)
	}
	client.deltaMu.Lock()
	baseline := client.rawBaseline.clone()
	repair := client.fullReconciliation
	client.deltaMu.Unlock()
	if baseline == nil || repair {
		t.Fatalf("raw baseline = %v, repair = %v", baseline, repair)
	}
	wantPaths := []string{"network", "network/node", "network/member", "network/member/node", "network/relay", "network/aclPolicy", "network/node/nodeInfo", "network/member/node/nodeInfo", "network/node/endpoint", "network/member/node/endpoint"}
	gotPaths := make(map[string]int)
	for _, record := range baseline.all() {
		gotPaths[record.protocolPath]++
	}
	for _, path := range wantPaths {
		if got := gotPaths[path]; got != 1 {
			t.Fatalf("captured %s records = %d, want 1; all paths %#v", path, got, gotPaths)
		}
	}
	if len(gotPaths) != len(wantPaths) {
		t.Fatalf("captured paths = %#v", gotPaths)
	}
}

func TestLoadStateThenInlineSubscriptionDeltaUsesNoRemoteRequest(t *testing.T) {
	network, entries := rawCaptureLoadFixture(t)
	control := &rawCaptureServerControl{}
	client := newRawCaptureLoadClient(t, network, entries, control)
	initial, err := client.LoadState(context.Background())
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if initial.Node == nil || len(initial.Peers) != 1 {
		t.Fatalf("initial map = %#v, want self and one peer", initial)
	}

	var update map[string]any
	if err := json.Unmarshal(entries["network/member/node"][0], &update); err != nil {
		t.Fatal(err)
	}
	update["descriptor"].(map[string]any)["messageTimestamp"] = "2026-07-11T12:02:00Z"
	data, err := json.Marshal(NodeRecord{MeshIP: "10.200.1.99", Label: "peer-updated"})
	if err != nil {
		t.Fatal(err)
	}
	update["encodedData"] = base64.RawURLEncoding.EncodeToString(data)
	updateRaw, err := json.Marshal(update)
	if err != nil {
		t.Fatal(err)
	}
	messageCID, err := computeRawRecordMessageCID(updateRaw)
	if err != nil {
		t.Fatal(err)
	}
	event := rawRecordTestSubscription(updateRaw, "")
	event.MessageCID = messageCID
	event.Cursor = &dwn.ProgressToken{
		StreamID: "topology", Epoch: "epoch", Position: "1", MessageCID: messageCID,
	}
	beforeApply := control.requests.Load()
	if err := client.StageTopologyEvent(event); err != nil {
		t.Fatalf("StageTopologyEvent: %v", err)
	}
	response, err := client.ApplyPendingState(context.Background())
	if err != nil {
		t.Fatalf("ApplyPendingState: %v", err)
	}
	if got := control.requests.Load(); got != beforeApply {
		t.Fatalf("delta apply made %d remote requests, want 0", got-beforeApply)
	}
	var updated *Node
	for _, peer := range response.Peers {
		if peer.DID == materializerPeerDID {
			updated = peer
			break
		}
	}
	if updated == nil || updated.MeshIP.String() != "10.200.1.99" || updated.Label != "peer-updated" {
		t.Fatalf("updated peer = %#v", updated)
	}
}

func TestLoadStateFailurePreservesRawBaseline(t *testing.T) {
	network, entries := rawCaptureLoadFixture(t)
	control := &rawCaptureServerControl{}
	client := newRawCaptureLoadClient(t, network, entries, control)
	if _, err := client.LoadState(context.Background()); err != nil {
		t.Fatalf("initial LoadState: %v", err)
	}
	client.deltaMu.Lock()
	before := client.rawBaseline
	beforeCount := before.len()
	client.deltaMu.Unlock()

	control.failNetwork.Store(true)
	if _, err := client.LoadState(context.Background()); err == nil {
		t.Fatal("failed LoadState unexpectedly succeeded")
	}
	client.deltaMu.Lock()
	after := client.rawBaseline
	repair := client.fullReconciliation
	client.deltaMu.Unlock()
	if after != before {
		t.Fatal("failed LoadState replaced the last-good raw baseline")
	}
	if repair || after.len() != beforeCount {
		t.Fatalf("failed LoadState changed raw readiness: repair=%v records=%d want=%d", repair, after.len(), beforeCount)
	}
}

func TestLoadStateValidatedFailurePreservesParsedRawAndPendingState(t *testing.T) {
	network, entries := rawCaptureLoadFixture(t)
	client := newRawCaptureLoadClient(t, network, entries, nil)
	installDeltaTestBaseline(t, client, materializerBaseRecords(t))

	client.mu.RLock()
	oldNetwork := client.network
	oldNode := client.nodes[materializerSelfDID]
	client.mu.RUnlock()
	client.deltaMu.Lock()
	oldRaw := client.rawBaseline
	client.deltaMu.Unlock()
	if err := client.StageTopologyEvent(rawRecordTestSubscription(
		rawRecordTestDelete(t, "covered-by-full", "2026-07-11T12:10:00Z"), "",
	)); err != nil {
		t.Fatal(err)
	}
	client.deltaMu.Lock()
	oldSequence := client.pendingTopology[0].sequence
	oldMessage := client.pendingTopology[0].message
	client.deltaMu.Unlock()

	validationErr := errors.New("converter rejected full candidate")
	var validated *MapResponse
	response, err := client.LoadStateValidated(context.Background(), func(candidate *MapResponse) error {
		validated = candidate
		if client.loadMu.TryLock() {
			client.loadMu.Unlock()
			t.Error("validator ran without loadMu held")
		}
		return validationErr
	})
	if !errors.Is(err, validationErr) || response == nil || response != validated {
		t.Fatalf("LoadStateValidated = (%p, %v), validated %p", response, err, validated)
	}
	if response.Node == nil || len(response.Peers) != 1 {
		t.Fatalf("validated full candidate = %#v", response)
	}

	client.mu.RLock()
	afterNetwork := client.network
	afterNode := client.nodes[materializerSelfDID]
	client.mu.RUnlock()
	if afterNetwork != oldNetwork || afterNode != oldNode {
		t.Fatalf("validation failure advanced parsed state: network %p/%p node %p/%p", oldNetwork, afterNetwork, oldNode, afterNode)
	}
	client.deltaMu.Lock()
	defer client.deltaMu.Unlock()
	if client.rawBaseline != oldRaw || client.fullReconciliation {
		t.Fatalf("validation failure advanced raw state: baseline %p/%p repair=%v", oldRaw, client.rawBaseline, client.fullReconciliation)
	}
	if len(client.pendingTopology) != 1 || client.pendingTopology[0].sequence != oldSequence ||
		client.pendingTopology[0].message != oldMessage {
		t.Fatalf("validation failure trimmed pending prefix: %#v", client.pendingTopology)
	}
}

func TestLoadStateValidatedSuccessCommitsParsedRawAndPrefixAtomically(t *testing.T) {
	network, entries := rawCaptureLoadFixture(t)
	client := newRawCaptureLoadClient(t, network, entries, nil)
	installDeltaTestBaseline(t, client, materializerBaseRecords(t))
	client.deltaMu.Lock()
	oldRaw := client.rawBaseline
	client.deltaMu.Unlock()
	if err := client.StageTopologyEvent(rawRecordTestSubscription(
		rawRecordTestDelete(t, "covered-by-full", "2026-07-11T12:10:00Z"), "",
	)); err != nil {
		t.Fatal(err)
	}

	entered := make(chan struct{})
	release := make(chan struct{})
	type loadResult struct {
		response *MapResponse
		err      error
	}
	done := make(chan loadResult, 1)
	var validated *MapResponse
	go func() {
		response, err := client.LoadStateValidated(context.Background(), func(candidate *MapResponse) error {
			validated = candidate
			if client.loadMu.TryLock() {
				client.loadMu.Unlock()
				return errors.New("validator ran without loadMu held")
			}
			close(entered)
			<-release
			return nil
		})
		done <- loadResult{response: response, err: err}
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("full load did not reach validator")
	}

	client.deltaMu.Lock()
	if client.rawBaseline != oldRaw || len(client.pendingTopology) != 1 {
		client.deltaMu.Unlock()
		t.Fatal("raw baseline or pending prefix committed before validation")
	}
	client.deltaMu.Unlock()
	readerStarted := make(chan struct{})
	readNodes := make(chan map[string]*NodeRecord, 1)
	go func() {
		close(readerStarted)
		readNodes <- client.Nodes()
	}()
	<-readerStarted
	select {
	case <-readNodes:
		t.Fatal("snapshot reader escaped while full-load validation was pending")
	case <-time.After(25 * time.Millisecond):
	}

	close(release)
	var result loadResult
	select {
	case result = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("validated full load did not finish")
	}
	if result.err != nil || result.response == nil || result.response != validated {
		t.Fatalf("LoadStateValidated = (%p, %v), validated %p", result.response, result.err, validated)
	}
	var nodes map[string]*NodeRecord
	select {
	case nodes = <-readNodes:
	case <-time.After(5 * time.Second):
		t.Fatal("snapshot reader did not resume after commit")
	}
	if nodes[materializerSelfDID] == nil || nodes[materializerPeerDID] == nil {
		t.Fatalf("snapshot reader saw non-candidate nodes: %#v", nodes)
	}

	client.deltaMu.Lock()
	defer client.deltaMu.Unlock()
	if client.rawBaseline == nil || client.rawBaseline == oldRaw || client.fullReconciliation {
		t.Fatalf("successful validation did not commit raw state: old=%p current=%p repair=%v", oldRaw, client.rawBaseline, client.fullReconciliation)
	}
	if len(client.pendingTopology) != 0 {
		t.Fatalf("successful validation retained covered prefix: %#v", client.pendingTopology)
	}
}

func TestLoadStateValidatedRejectsNewerRepairMarkers(t *testing.T) {
	repairs := []struct {
		name string
		run  func(*testing.T, *DWNClient)
	}{
		{name: "lifecycle", run: func(_ *testing.T, client *DWNClient) { client.RequireFullReconciliation() }},
		{name: "poison", run: func(t *testing.T, client *DWNClient) {
			if err := client.StageTopologyEvent(&dwn.SubscriptionMessage{Type: dwn.SubscriptionEventType}); err != nil {
				t.Errorf("stage poison repair: %v", err)
			}
		}},
		{name: "overflow", run: func(t *testing.T, client *DWNClient) {
			event := rawRecordTestSubscription(rawRecordTestDelete(t, "overflow-repair", "2026-07-11T12:20:00Z"), "")
			for i := 0; i <= maxPendingTopologyEvents; i++ {
				if err := client.StageTopologyEvent(event); err != nil {
					t.Errorf("stage overflow repair: %v", err)
				}
			}
		}},
	}
	for _, phase := range []string{"remote-fetch", "validator"} {
		for _, repair := range repairs {
			t.Run(phase+"/"+repair.name, func(t *testing.T) {
				network, entries := rawCaptureLoadFixture(t)
				control := &rawCaptureServerControl{}
				if phase == "remote-fetch" {
					control.networkStarted = make(chan struct{})
					control.releaseNetwork = make(chan struct{})
				}
				client := newRawCaptureLoadClient(t, network, entries, control)
				installDeltaTestBaseline(t, client, materializerBaseRecords(t))
				client.mu.RLock()
				oldNetwork := client.network
				oldNode := client.nodes[materializerSelfDID]
				client.mu.RUnlock()
				client.deltaMu.Lock()
				oldRaw := client.rawBaseline
				client.deltaMu.Unlock()

				type result struct {
					response *MapResponse
					err      error
				}
				done := make(chan result, 1)
				go func() {
					response, err := client.LoadStateValidated(context.Background(), func(*MapResponse) error {
						if phase == "validator" {
							repair.run(t, client)
						}
						return nil
					})
					done <- result{response: response, err: err}
				}()
				if phase == "remote-fetch" {
					select {
					case <-control.networkStarted:
					case <-time.After(5 * time.Second):
						t.Fatal("load did not reach remote fetch")
					}
					repair.run(t, client)
					close(control.releaseNetwork)
				}
				var got result
				select {
				case got = <-done:
				case <-time.After(5 * time.Second):
					t.Fatal("load did not finish")
				}
				if got.response == nil || !errors.Is(got.err, ErrFullReconciliationRequired) {
					t.Fatalf("LoadStateValidated = (%#v, %v), want fenced candidate", got.response, got.err)
				}
				client.mu.RLock()
				parsedUnchanged := client.network == oldNetwork && client.nodes[materializerSelfDID] == oldNode
				client.mu.RUnlock()
				client.deltaMu.Lock()
				rawUnchanged := client.rawBaseline == oldRaw
				repairPending := client.fullReconciliation && client.repairSequence > 0
				client.deltaMu.Unlock()
				if !parsedUnchanged || !rawUnchanged || !repairPending {
					t.Fatalf("newer repair published state: parsed=%v raw=%v repair=%v", parsedUnchanged, rawUnchanged, repairPending)
				}
			})
		}
	}
}

func TestLoadStateMalformedRawRollsBackAuthoritativeLoad(t *testing.T) {
	network, entries := rawCaptureLoadFixture(t)
	var malformed map[string]any
	if err := json.Unmarshal(entries["network/node"][0], &malformed); err != nil {
		t.Fatal(err)
	}
	descriptor := malformed["descriptor"].(map[string]any)
	delete(descriptor, "protocol")
	delete(descriptor, "messageTimestamp")
	entries["network/node"][0], _ = json.Marshal(malformed)
	client := newRawCaptureLoadClient(t, network, entries, nil)
	installDeltaTestBaseline(t, client, materializerBaseRecords(t))
	client.mu.RLock()
	oldNetwork := client.network
	oldNode := client.nodes[materializerSelfDID]
	client.mu.RUnlock()
	client.deltaMu.Lock()
	oldRaw := client.rawBaseline
	client.deltaMu.Unlock()

	if response, err := client.LoadState(context.Background()); err == nil || response != nil {
		t.Fatalf("malformed authoritative load = (%#v, %v), want failure", response, err)
	}
	client.mu.RLock()
	parsedUnchanged := client.network == oldNetwork && client.nodes[materializerSelfDID] == oldNode
	client.mu.RUnlock()
	if !parsedUnchanged {
		t.Fatal("malformed authoritative load advanced parsed state")
	}
	client.deltaMu.Lock()
	rawUnchanged := client.rawBaseline == oldRaw
	client.deltaMu.Unlock()
	if !rawUnchanged {
		t.Fatal("malformed authoritative load replaced raw baseline")
	}
}

func TestLoadStatePreservesEventStagedAfterReconciliationCut(t *testing.T) {
	network, entries := rawCaptureLoadFixture(t)
	control := &rawCaptureServerControl{networkStarted: make(chan struct{}), releaseNetwork: make(chan struct{})}
	client := newRawCaptureLoadClient(t, network, entries, control)
	loadDone := make(chan error, 1)
	go func() {
		_, err := client.LoadState(context.Background())
		loadDone <- err
	}()
	select {
	case <-control.networkStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("full load did not reach blocked network read")
	}

	latest := true
	eventRaw := materializerRecord(t, materializerRecordSpec{
		id: "queued-endpoint", path: "network/node/endpoint", parentContext: materializerNetworkID + "/self-node",
		data: EndpointData{LocalEndpoints: []string{"192.0.2.1:3333"}}, timestamp: "2026-07-11T12:01:00Z",
	})
	if err := client.StageTopologyEvent(&dwn.SubscriptionMessage{
		Type: dwn.SubscriptionEventType, IsLatestBaseState: &latest, Event: &dwn.RecordEvent{Message: eventRaw},
	}); err != nil {
		t.Fatalf("StageTopologyEvent: %v", err)
	}
	close(control.releaseNetwork)
	select {
	case err := <-loadDone:
		if err != nil {
			t.Fatalf("LoadState: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("full load did not finish")
	}

	client.deltaMu.Lock()
	defer client.deltaMu.Unlock()
	if client.rawBaseline == nil || client.fullReconciliation {
		t.Fatalf("baseline = %v, repair = %v", client.rawBaseline, client.fullReconciliation)
	}
	if len(client.pendingTopology) != 1 {
		t.Fatalf("pending events = %d, want event staged after full-load cut", len(client.pendingTopology))
	}
	recordID, err := topologyWriteRecordID(client.pendingTopology[0].message)
	if err != nil || recordID != "queued-endpoint" {
		t.Fatalf("pending event record = %q, err = %v", recordID, err)
	}
}

func TestLoadStateHydratesMissingQueryDataIntoBaselineAndLegacyState(t *testing.T) {
	network, entries := rawCaptureLoadFixture(t)
	fullEntry := entries["network/aclPolicy"][0]
	withoutData, body := rawCaptureEntryWithoutInlineData(t, fullEntry)
	entries["network/aclPolicy"] = []json.RawMessage{withoutData}
	control := &rawCaptureServerControl{
		targetedReadEntry:  map[string]json.RawMessage{"acl-record": withoutData},
		targetedReadBodies: map[string][]byte{"acl-record": body},
	}
	client := newRawCaptureLoadClient(t, network, entries, control)

	if _, err := client.LoadState(context.Background()); err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if got := control.targetedReads.Load(); got != 1 {
		t.Fatalf("targeted RecordsRead calls = %d, want 1", got)
	}
	client.mu.RLock()
	acl := client.acl
	client.mu.RUnlock()
	if acl == nil || acl.Version != 1 {
		t.Fatalf("legacy ACL state = %#v, want hydrated version 1", acl)
	}
	client.deltaMu.Lock()
	baseline := client.rawBaseline
	repair := client.fullReconciliation
	client.deltaMu.Unlock()
	if baseline == nil || repair {
		t.Fatalf("raw baseline = %v, repair = %v", baseline, repair)
	}
	record, ok := baseline.get("acl-record")
	if !ok || !rawRecordHasEncodedData(record.raw) {
		t.Fatalf("hydrated ACL record missing from raw baseline: ok=%v record=%#v", ok, record)
	}
}

func TestLoadStateInlineQueryDataDoesNotReadRecords(t *testing.T) {
	network, entries := rawCaptureLoadFixture(t)
	control := &rawCaptureServerControl{}
	client := newRawCaptureLoadClient(t, network, entries, control)
	if _, err := client.LoadState(context.Background()); err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if got := control.targetedReads.Load(); got != 0 {
		t.Fatalf("targeted RecordsRead calls = %d, want 0", got)
	}
}

func TestLoadStateStaleHydrationRollsBackAuthoritativeLoad(t *testing.T) {
	network, entries := rawCaptureLoadFixture(t)
	fullEntry := entries["network/aclPolicy"][0]
	withoutData, _ := rawCaptureEntryWithoutInlineData(t, fullEntry)
	var stale map[string]any
	if err := json.Unmarshal(fullEntry, &stale); err != nil {
		t.Fatal(err)
	}
	stale["descriptor"].(map[string]any)["messageTimestamp"] = "2026-07-11T11:59:00Z"
	staleRaw, err := json.Marshal(stale)
	if err != nil {
		t.Fatal(err)
	}
	staleEntry, body := rawCaptureEntryWithoutInlineData(t, staleRaw)
	entries["network/aclPolicy"] = []json.RawMessage{withoutData}
	control := &rawCaptureServerControl{
		targetedReadEntry: map[string]json.RawMessage{"acl-record": staleEntry}, targetedReadBodies: map[string][]byte{"acl-record": body},
	}
	client := newRawCaptureLoadClient(t, network, entries, control)
	installDeltaTestBaseline(t, client, materializerBaseRecords(t))
	client.mu.RLock()
	oldNetwork := client.network
	client.mu.RUnlock()
	client.deltaMu.Lock()
	oldRaw := client.rawBaseline
	client.deltaMu.Unlock()

	if response, err := client.LoadState(context.Background()); err == nil || response != nil {
		t.Fatalf("stale hydration load = (%#v, %v), want failure", response, err)
	}
	if got := control.targetedReads.Load(); got != 1 {
		t.Fatalf("targeted RecordsRead calls = %d, want 1", got)
	}
	client.mu.RLock()
	afterNetwork := client.network
	client.mu.RUnlock()
	client.deltaMu.Lock()
	afterRaw := client.rawBaseline
	client.deltaMu.Unlock()
	if afterNetwork != oldNetwork || afterRaw != oldRaw {
		t.Fatal("stale hydration advanced parsed or raw state")
	}
}

func TestLoadStateNewerHydrationHeadWins(t *testing.T) {
	network, entries := rawCaptureLoadFixture(t)
	queryEntry, _ := rawCaptureEntryWithoutInlineData(t, entries["network/aclPolicy"][0])
	var newerMessage map[string]any
	if err := json.Unmarshal(entries["network/aclPolicy"][0], &newerMessage); err != nil {
		t.Fatal(err)
	}
	newerMessage["descriptor"].(map[string]any)["messageTimestamp"] = "2026-07-11T12:01:00Z"
	newerData, err := json.Marshal(ACLPolicyData{Version: 2, DefaultAction: "accept"})
	if err != nil {
		t.Fatal(err)
	}
	newerMessage["encodedData"] = base64.RawURLEncoding.EncodeToString(newerData)
	newerFull, err := json.Marshal(newerMessage)
	if err != nil {
		t.Fatal(err)
	}
	newerEntry, newerBody := rawCaptureEntryWithoutInlineData(t, newerFull)
	entries["network/aclPolicy"] = []json.RawMessage{queryEntry}
	control := &rawCaptureServerControl{
		targetedReadEntry:  map[string]json.RawMessage{"acl-record": newerEntry},
		targetedReadBodies: map[string][]byte{"acl-record": newerBody},
	}
	client := newRawCaptureLoadClient(t, network, entries, control)

	if _, err := client.LoadState(context.Background()); err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	client.mu.RLock()
	acl := client.acl
	client.mu.RUnlock()
	if acl == nil || acl.Version != 2 {
		t.Fatalf("legacy ACL state = %#v, want newer hydrated version 2", acl)
	}
	client.deltaMu.Lock()
	baseline := client.rawBaseline
	repair := client.fullReconciliation
	client.deltaMu.Unlock()
	if baseline == nil || repair {
		t.Fatalf("raw baseline = %v, repair = %v", baseline, repair)
	}
	record, ok := baseline.get("acl-record")
	if !ok {
		t.Fatal("newer ACL head missing from raw baseline")
	}
	identity, err := rawCaptureIdentity(record.raw)
	if err != nil {
		t.Fatal(err)
	}
	if identity.messageTimestamp != "2026-07-11T12:01:00Z" {
		t.Fatalf("baseline ACL revision = %q, want newer read head", identity.messageTimestamp)
	}
}

func TestLoadStateStopsBeforeHydrationAfterMalformedEarlierPath(t *testing.T) {
	network, entries := rawCaptureLoadFixture(t)
	var malformedNode map[string]any
	if err := json.Unmarshal(entries["network/node"][0], &malformedNode); err != nil {
		t.Fatal(err)
	}
	delete(malformedNode["descriptor"].(map[string]any), "protocol")
	entries["network/node"][0], _ = json.Marshal(malformedNode)

	fullACL := entries["network/aclPolicy"][0]
	withoutACL, body := rawCaptureEntryWithoutInlineData(t, fullACL)
	entries["network/aclPolicy"] = []json.RawMessage{withoutACL}
	control := &rawCaptureServerControl{
		targetedReadEntry: map[string]json.RawMessage{"acl-record": withoutACL}, targetedReadBodies: map[string][]byte{"acl-record": body},
	}
	client := newRawCaptureLoadClient(t, network, entries, control)
	installDeltaTestBaseline(t, client, materializerBaseRecords(t))
	client.deltaMu.Lock()
	oldRaw := client.rawBaseline
	client.deltaMu.Unlock()

	if response, err := client.LoadState(context.Background()); err == nil || response != nil {
		t.Fatalf("malformed authoritative load = (%#v, %v), want failure", response, err)
	}
	if got := control.targetedReads.Load(); got != 0 {
		t.Fatalf("targeted RecordsRead calls after fatal earlier path = %d, want 0", got)
	}
	client.deltaMu.Lock()
	defer client.deltaMu.Unlock()
	if client.rawBaseline != oldRaw {
		t.Fatal("fatal earlier path replaced raw baseline")
	}
}

func TestLoadStateRateLimitedHydrationPreservesLastGoodState(t *testing.T) {
	network, entries := rawCaptureLoadFixture(t)
	fullEntry := entries["network/aclPolicy"][0]
	withoutData, body := rawCaptureEntryWithoutInlineData(t, fullEntry)
	entries["network/aclPolicy"] = []json.RawMessage{withoutData}
	control := &rawCaptureServerControl{
		targetedReadEntry:  map[string]json.RawMessage{"acl-record": withoutData},
		targetedReadBodies: map[string][]byte{"acl-record": body},
	}
	client := newRawCaptureLoadClient(t, network, entries, control)
	if _, err := client.LoadState(context.Background()); err != nil {
		t.Fatalf("initial LoadState: %v", err)
	}
	client.deltaMu.Lock()
	beforeRaw := client.rawBaseline
	client.deltaMu.Unlock()
	client.mu.RLock()
	beforeNetwork := client.network
	beforeACL := client.acl
	client.mu.RUnlock()

	control.targetedRateLimit.Store(true)
	_, loadErr := client.LoadState(context.Background())
	if !errors.Is(loadErr, dwn.ErrRateLimited) {
		t.Fatalf("rate-limited LoadState error = %v, want ErrRateLimited", loadErr)
	}
	var rateErr *dwn.RateLimitError
	if !errors.As(loadErr, &rateErr) || rateErr.RetryAfter != 2*time.Second {
		t.Fatalf("rate-limited LoadState error = %#v, want 2s RetryAfter", loadErr)
	}
	client.deltaMu.Lock()
	afterRaw := client.rawBaseline
	repair := client.fullReconciliation
	client.deltaMu.Unlock()
	client.mu.RLock()
	afterNetwork := client.network
	afterACL := client.acl
	client.mu.RUnlock()
	if afterRaw != beforeRaw || repair {
		t.Fatalf("rate limit changed raw state: before=%p after=%p repair=%v", beforeRaw, afterRaw, repair)
	}
	if afterNetwork != beforeNetwork || afterACL != beforeACL {
		t.Fatalf("rate limit changed parsed state: network %p/%p ACL %p/%p", beforeNetwork, afterNetwork, beforeACL, afterACL)
	}
}

func TestShouldAbortStateLoadTransientFailures(t *testing.T) {
	if !shouldAbortStateLoad(context.Background(), fmt.Errorf("fetching audience material: %w", dwn.ErrTransport)) {
		t.Fatal("transport failure must abort and preserve last-good state")
	}
	if !shouldAbortStateLoad(context.Background(), &dwn.RateLimitError{RetryAfter: time.Second}) {
		t.Fatal("rate limit must abort and preserve last-good state")
	}
	if shouldAbortStateLoad(context.Background(), errors.New("permanently unreadable record")) {
		t.Fatal("permanent record error should not abort a usable legacy load")
	}
}

func rawCaptureEntryWithoutInlineData(t *testing.T, entry json.RawMessage) (json.RawMessage, []byte) {
	t.Helper()
	var object map[string]json.RawMessage
	if err := json.Unmarshal(entry, &object); err != nil {
		t.Fatal(err)
	}
	write := object
	if wrapped, ok := object["recordsWrite"]; ok {
		write = make(map[string]json.RawMessage)
		if err := json.Unmarshal(wrapped, &write); err != nil {
			t.Fatal(err)
		}
	}
	var encoded string
	if err := json.Unmarshal(write["encodedData"], &encoded); err != nil {
		t.Fatalf("fixture has no encodedData: %v", err)
	}
	body, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	delete(write, "encodedData")
	if _, wrapped := object["recordsWrite"]; wrapped {
		object["recordsWrite"], err = json.Marshal(write)
		if err != nil {
			t.Fatal(err)
		}
	}
	withoutData, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	return withoutData, body
}

func TestBuildMapResponseOwnsExposedSlices(t *testing.T) {
	const selfDID = "did:jwk:self"
	client := NewDWNClient("https://dwn.example", selfDID, "network-record", selfDID, nil)
	client.network = &NetworkConfig{
		Name:       "ownership",
		MeshCIDR:   "10.200.0.0/16",
		DNSServers: []string{"10.200.0.53"},
	}
	client.nodes[selfDID] = &NodeRecord{
		DID:      selfDID,
		MeshIP:   "10.200.0.1",
		RecordID: "self-node",
		Info: &NodeInfoData{
			Hostname:     "self",
			Capabilities: []string{"ssh"},
		},
	}

	first := client.buildMapResponse()
	if first == nil || first.Node == nil || first.DNSConfig == nil {
		t.Fatalf("map response = %#v", first)
	}
	first.Node.Capabilities[0] = "mutated"
	first.DNSConfig.Resolvers[0] = "203.0.113.53"

	second := client.buildMapResponse()
	if got := second.Node.Capabilities; len(got) != 1 || got[0] != "ssh" {
		t.Fatalf("capabilities alias cached NodeInfo: %v", got)
	}
	if got := second.DNSConfig.Resolvers; len(got) != 1 || got[0] != "10.200.0.53" {
		t.Fatalf("DNS resolvers alias cached NetworkConfig: %v", got)
	}

	// Under -race this also proves a consumer can mutate its response while a
	// subsequent response is built from the immutable control-plane snapshot.
	consumer := client.buildMapResponse()
	started := make(chan struct{})
	done := make(chan struct{})
	go func() {
		close(started)
		for i := 0; i < 1000; i++ {
			consumer.Node.Capabilities[0] = fmt.Sprintf("consumer-%d", i)
			consumer.DNSConfig.Resolvers[0] = fmt.Sprintf("192.0.2.%d", i%255)
		}
		close(done)
	}()
	<-started
	for i := 0; i < 1000; i++ {
		response := client.buildMapResponse()
		if response.Node.Capabilities[0] != "ssh" || response.DNSConfig.Resolvers[0] != "10.200.0.53" {
			t.Fatalf("cached state changed during consumer mutation: node=%v DNS=%v", response.Node.Capabilities, response.DNSConfig.Resolvers)
		}
	}
	<-done
}
