package control

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/enboxorg/meshd/internal/dwn"
)

func TestLoadStateRollsBackCachedStateOnReplyRateLimit(t *testing.T) {
	identity, signer, _, _ := sealedTestOwner(t)

	oldNetwork := &NetworkConfig{Name: "old-network", MeshCIDR: "10.200.0.0/16"}
	oldNode := &NodeRecord{DID: identity.URI, MeshIP: "10.200.0.2", Label: "old-node", RecordID: "old-node-record"}
	oldMember := &MemberRecord{DID: "did:example:old-member", Label: "old-member", RecordID: "old-member-record"}
	oldRelay := &RelayData{URL: "https://old-relay.example", Region: "old-region"}
	oldACL := &ACLPolicyData{Version: 1, DefaultAction: "deny"}

	newNetworkEntry := stateTransactionEntry(t, "", "", NetworkConfig{
		Name:     "new-network",
		MeshCIDR: "10.201.0.0/16",
	})
	newNodeEntry := stateTransactionEntry(t, "new-node-record", identity.URI, NodeRecord{
		MeshIP: "10.201.0.2",
		Label:  "new-node",
	})
	newMemberEntry := stateTransactionEntry(t, "new-member-record", "did:example:new-member", MemberRecord{
		Label:   "new-member",
		AddedAt: "2026-07-11T00:00:00Z",
	})
	newRelayEntry := stateTransactionEntry(t, "", "", RelayData{
		URL:    "https://new-relay.example",
		Region: "new-region",
	})
	newACLEntry := stateTransactionEntry(t, "", "", ACLPolicyData{
		Version:       2,
		DefaultAction: "accept",
	})

	var requestCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request dwn.JsonRpcRequest
		if err := json.Unmarshal([]byte(r.Header.Get("dwn-request")), &request); err != nil {
			t.Errorf("decode DWN request: %v", err)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		reply := &dwn.DwnReply{Status: dwn.Status{Code: http.StatusOK, Detail: "OK"}}
		switch requestCount.Add(1) {
		case 1: // Network record read.
			reply.Entry = newNetworkEntry
		case 2: // Owner node query.
			reply.Entries = stateTransactionEntries(t, newNodeEntry)
		case 3: // Member query.
			reply.Entries = stateTransactionEntries(t, newMemberEntry)
		case 4: // Member-associated node query.
			reply.Entries = stateTransactionEntries(t)
		case 5: // Relay query.
			reply.Entries = stateTransactionEntries(t, newRelayEntry)
		case 6: // ACL policy query.
			reply.Entries = stateTransactionEntries(t, newACLEntry)
		case 7: // First node child query, after every cached state field changed.
			reply.Status = dwn.Status{
				Code:   http.StatusTooManyRequests,
				Detail: "RateLimitExceeded: tenant rate limit exceeded, retry after 6s",
			}
		default:
			t.Errorf("unexpected DWN request %d", requestCount.Load())
			reply.Status = dwn.Status{Code: http.StatusInternalServerError, Detail: "unexpected request"}
		}

		if err := json.NewEncoder(w).Encode(dwn.JsonRpcResponse{
			JSONRPC: "2.0",
			ID:      request.ID,
			Result:  &dwn.JsonRpcResult{Reply: reply},
		}); err != nil {
			t.Errorf("encode DWN response: %v", err)
		}
	}))
	defer server.Close()

	client := NewDWNClient(server.URL, identity.URI, "network-record", identity.URI, signer)
	client.network = oldNetwork
	client.nodes = map[string]*NodeRecord{oldNode.DID: oldNode}
	client.members = map[string]*MemberRecord{oldMember.DID: oldMember}
	client.relays = []*RelayData{oldRelay}
	client.acl = oldACL

	_, err := client.LoadState(context.Background())
	if !errors.Is(err, dwn.ErrRateLimited) {
		t.Fatalf("LoadState error = %v, want ErrRateLimited", err)
	}
	var rateErr *dwn.RateLimitError
	if !errors.As(err, &rateErr) {
		t.Fatalf("LoadState error = %T %v, want *dwn.RateLimitError", err, err)
	}
	if rateErr.RetryAfter != 6*time.Second {
		t.Fatalf("retry delay = %v, want 6s", rateErr.RetryAfter)
	}
	if got := requestCount.Load(); got != 7 {
		t.Fatalf("DWN request count = %d, want 7", got)
	}

	client.mu.RLock()
	defer client.mu.RUnlock()
	if client.network != oldNetwork {
		t.Errorf("network = %#v, want original cached pointer %#v", client.network, oldNetwork)
	}
	if len(client.nodes) != 1 || client.nodes[oldNode.DID] != oldNode {
		t.Errorf("nodes = %#v, want only original cached node %#v", client.nodes, oldNode)
	}
	if len(client.members) != 1 || client.members[oldMember.DID] != oldMember {
		t.Errorf("members = %#v, want only original cached member %#v", client.members, oldMember)
	}
	if len(client.relays) != 1 || client.relays[0] != oldRelay {
		t.Errorf("relays = %#v, want only original cached relay %#v", client.relays, oldRelay)
	}
	if client.acl != oldACL {
		t.Errorf("ACL = %#v, want original cached pointer %#v", client.acl, oldACL)
	}
}

func stateTransactionEntry(t *testing.T, recordID, recipient string, value any) json.RawMessage {
	t.Helper()

	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal entry data: %v", err)
	}
	entry, err := json.Marshal(map[string]any{
		"recordId": recordID,
		"descriptor": map[string]any{
			"recipient": recipient,
		},
		"encodedData": base64.RawURLEncoding.EncodeToString(data),
	})
	if err != nil {
		t.Fatalf("marshal entry: %v", err)
	}
	return entry
}

func stateTransactionEntries(t *testing.T, entries ...json.RawMessage) json.RawMessage {
	t.Helper()
	encoded, err := json.Marshal(entries)
	if err != nil {
		t.Fatalf("marshal entries: %v", err)
	}
	return encoded
}
