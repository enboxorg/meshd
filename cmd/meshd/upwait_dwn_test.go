package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/enboxorg/meshd/internal/did"
	"github.com/enboxorg/meshd/internal/dwn"
	"github.com/enboxorg/meshd/internal/invite"
	"github.com/enboxorg/meshd/internal/state"
	"github.com/enboxorg/meshd/protocols"
)

// fakeDWNQueryServer answers Records Query messages from canned entries keyed
// by protocolPath and accepts every Records Write, recording the paths seen.
type fakeDWNQueryServer struct {
	t *testing.T

	mu         sync.Mutex
	entries    map[string][]json.RawMessage // protocolPath -> query entries
	queries    []map[string]any             // observed query filters
	writePaths []string                     // observed write protocolPaths
	failAll    bool
}

func (f *fakeDWNQueryServer) handler(w http.ResponseWriter, r *http.Request) {
	if f.failAll {
		http.Error(w, "boom", http.StatusInternalServerError)
		return
	}
	var rpcReq dwn.JsonRpcRequest
	if err := json.Unmarshal([]byte(r.Header.Get("dwn-request")), &rpcReq); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if rpcReq.Params == nil || rpcReq.Params.Message == nil {
		http.Error(w, "missing DWN message", http.StatusBadRequest)
		return
	}
	msg := rpcReq.Params.Message
	method, _ := msg.Descriptor["method"].(string)
	switch method {
	case "Query":
		filter, _ := msg.Descriptor["filter"].(map[string]any)
		path, _ := filter["protocolPath"].(string)
		f.mu.Lock()
		f.queries = append(f.queries, filter)
		entries := f.entries[path]
		f.mu.Unlock()
		f.reply(w, rpcReq.ID, dwn.Status{Code: 200, Detail: "OK"}, entries)
	case "Write":
		path, _ := msg.Descriptor["protocolPath"].(string)
		f.mu.Lock()
		f.writePaths = append(f.writePaths, path)
		f.mu.Unlock()
		f.reply(w, rpcReq.ID, dwn.Status{Code: 202, Detail: "Accepted"}, nil)
	default:
		f.reply(w, rpcReq.ID, dwn.Status{Code: 400, Detail: "unexpected method " + method}, nil)
	}
}

func (f *fakeDWNQueryServer) reply(w http.ResponseWriter, id string, status dwn.Status, entries []json.RawMessage) {
	f.t.Helper()
	var entriesJSON json.RawMessage
	if entries != nil {
		var err error
		entriesJSON, err = json.Marshal(entries)
		if err != nil {
			f.t.Fatalf("marshal entries: %v", err)
		}
	}
	resp := &dwn.JsonRpcResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  &dwn.JsonRpcResult{Reply: &dwn.DwnReply{Status: status, Entries: entriesJSON}},
	}
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		f.t.Fatalf("write DWN reply: %v", err)
	}
}

func dwnQueryEntry(t *testing.T, recordID, contextID, protocolPath, recipient string, data any) json.RawMessage {
	t.Helper()
	dataBytes, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("marshal entry data: %v", err)
	}
	descriptor := map[string]any{
		"interface":        "Records",
		"method":           "Write",
		"protocol":         protocols.MeshProtocolURI,
		"protocolPath":     protocolPath,
		"dataFormat":       "application/json",
		"dateCreated":      dwn.Now(),
		"messageTimestamp": dwn.Now(),
	}
	if recipient != "" {
		descriptor["recipient"] = recipient
	}
	entry, err := json.Marshal(map[string]any{
		"recordId":    recordID,
		"contextId":   contextID,
		"descriptor":  descriptor,
		"encodedData": base64.RawURLEncoding.EncodeToString(dataBytes),
	})
	if err != nil {
		t.Fatalf("marshal entry: %v", err)
	}
	return entry
}

func pendingJoinTestState(endpoint string, nodeDID string) *state.NetworkState {
	return &state.NetworkState{
		NetworkRecordID: "net-1",
		AnchorDID:       "did:example:anchor",
		AnchorEndpoint:  endpoint,
		NetworkName:     "home",
		NodeDID:         nodeDID,
		OwnerDID:        "did:example:owner",
		MemberDID:       "did:example:owner",
	}
}

func TestPendingJoinApprovedDirectNodeRecord(t *testing.T) {
	identity, err := did.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	fake := &fakeDWNQueryServer{t: t, entries: map[string][]json.RawMessage{
		"network/node": {dwnQueryEntry(t, "node-1", "net-1", "network/node", identity.URI, map[string]string{"meshIP": "10.200.0.9"})},
	}}
	server := httptest.NewServer(http.HandlerFunc(fake.handler))
	defer server.Close()

	approved, err := pendingJoinApproved(context.Background(), pendingJoinTestState(server.URL, identity.URI), identity)
	if err != nil {
		t.Fatalf("pendingJoinApproved: %v", err)
	}
	if !approved {
		t.Fatal("expected direct node record to count as approved")
	}
	if len(fake.queries) != 1 {
		t.Fatalf("expected a single query, got %d", len(fake.queries))
	}
	if got, _ := fake.queries[0]["recipient"].(string); got != identity.URI {
		t.Fatalf("node query recipient = %q, want node DID", got)
	}
	if got, _ := fake.queries[0]["contextId"].(string); got != "net-1" {
		t.Fatalf("node query contextId = %q, want network record ID", got)
	}
}

func TestPendingJoinApprovedMemberNodeRecord(t *testing.T) {
	identity, err := did.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	fake := &fakeDWNQueryServer{t: t, entries: map[string][]json.RawMessage{
		"network/member":      {dwnQueryEntry(t, "member-1", "net-1", "network/member", "did:example:owner", map[string]string{})},
		"network/member/node": {dwnQueryEntry(t, "node-1", "net-1/member-1", "network/member/node", identity.URI, map[string]string{"meshIP": "10.200.0.9"})},
	}}
	server := httptest.NewServer(http.HandlerFunc(fake.handler))
	defer server.Close()

	approved, err := pendingJoinApproved(context.Background(), pendingJoinTestState(server.URL, identity.URI), identity)
	if err != nil {
		t.Fatalf("pendingJoinApproved: %v", err)
	}
	if !approved {
		t.Fatal("expected member-associated node record to count as approved")
	}
	// The member/node query must scope to the member record's context.
	last := fake.queries[len(fake.queries)-1]
	if got, _ := last["contextId"].(string); got != "net-1/member-1" {
		t.Fatalf("member node query contextId = %q, want net-1/member-1", got)
	}
}

func TestPendingJoinApprovedStillPending(t *testing.T) {
	identity, err := did.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	fake := &fakeDWNQueryServer{t: t, entries: map[string][]json.RawMessage{}}
	server := httptest.NewServer(http.HandlerFunc(fake.handler))
	defer server.Close()

	approved, err := pendingJoinApproved(context.Background(), pendingJoinTestState(server.URL, identity.URI), identity)
	if err != nil {
		t.Fatalf("pendingJoinApproved: %v", err)
	}
	if approved {
		t.Fatal("no records should mean still pending")
	}
}

func TestPendingJoinApprovedQueryErrorSurfaces(t *testing.T) {
	identity, err := did.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	fake := &fakeDWNQueryServer{t: t, failAll: true}
	server := httptest.NewServer(http.HandlerFunc(fake.handler))
	defer server.Close()

	if _, err := pendingJoinApproved(context.Background(), pendingJoinTestState(server.URL, identity.URI), identity); err == nil {
		t.Fatal("expected transport errors to surface for the wait loop's retry backoff")
	}
}

func TestResubmitPendingInviteJoin(t *testing.T) {
	identity, err := did.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	stateDir := t.TempDir()
	t.Setenv("MESHD_STATE_DIR", stateDir)

	fake := &fakeDWNQueryServer{t: t, entries: map[string][]json.RawMessage{}}
	server := httptest.NewServer(http.HandlerFunc(fake.handler))
	defer server.Close()

	ns := pendingJoinTestState(server.URL, identity.URI)
	ns.PendingJoinTokenID = "tok-1"
	if err := state.SaveNetworkState(stateDir, ns); err != nil {
		t.Fatalf("SaveNetworkState: %v", err)
	}

	encodeInvite := func(networkID, tokenID, expiresAt string) string {
		u, err := invite.Encode(invite.New(server.URL, ns.AnchorDID, networkID, "home", tokenID, "secret-value", expiresAt))
		if err != nil {
			t.Fatalf("Encode: %v", err)
		}
		return u
	}

	// A different network fails fast instead of being silently ignored.
	_, err = resubmitPendingInviteJoin(context.Background(), encodeInvite("other-net", "tok-2", ""), stateDir, ns, identity, "")
	if err == nil || !strings.Contains(err.Error(), "network leave") {
		t.Fatalf("expected different-network guidance, got %v", err)
	}
	if len(fake.writePaths) != 0 {
		t.Fatalf("no request should be written for a different network, got %v", fake.writePaths)
	}

	// Re-running with the already-submitted token is a no-op.
	got, err := resubmitPendingInviteJoin(context.Background(), encodeInvite("net-1", "tok-1", ""), stateDir, ns, identity, "")
	if err != nil {
		t.Fatalf("same-token resubmit: %v", err)
	}
	if got.PendingJoinTokenID != "tok-1" || len(fake.writePaths) != 0 {
		t.Fatalf("same token must not resubmit (writes=%v)", fake.writePaths)
	}

	// An expired invite is rejected before any write.
	expired := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	_, err = resubmitPendingInviteJoin(context.Background(), encodeInvite("net-1", "tok-2", expired), stateDir, ns, identity, "")
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected expired-invite error, got %v", err)
	}
	if len(fake.writePaths) != 0 {
		t.Fatalf("no request should be written for an expired invite, got %v", fake.writePaths)
	}

	// A fresh token resubmits the join request and persists the new token.
	got, err = resubmitPendingInviteJoin(context.Background(), encodeInvite("net-1", "tok-2", ""), stateDir, ns, identity, "")
	if err != nil {
		t.Fatalf("fresh-token resubmit: %v", err)
	}
	if got.PendingJoinTokenID != "tok-2" {
		t.Fatalf("PendingJoinTokenID = %q, want tok-2", got.PendingJoinTokenID)
	}
	if len(fake.writePaths) != 1 || fake.writePaths[0] != "network/nodeRequest" {
		t.Fatalf("expected one network/nodeRequest write, got %v", fake.writePaths)
	}
	reloaded, err := state.LoadNetworkState(stateDir)
	if err != nil {
		t.Fatalf("LoadNetworkState: %v", err)
	}
	if reloaded.PendingJoinTokenID != "tok-2" {
		t.Fatalf("persisted PendingJoinTokenID = %q, want tok-2", reloaded.PendingJoinTokenID)
	}
}
