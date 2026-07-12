package control

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/enboxorg/meshd/internal/dwn"
)

func TestLoadStateRollsBackCachedStateOnReplyRateLimit(t *testing.T) {
	network, entries := rawCaptureLoadFixture(t)
	control := &rawCaptureServerControl{
		queryRateLimitPath:   "network/node/nodeInfo",
		queryRateLimitDetail: "RateLimitExceeded: tenant rate limit exceeded, retry after 6s",
	}
	client := newRawCaptureLoadClient(t, network, entries, control)

	oldNetwork := &NetworkConfig{Name: "old-network", MeshCIDR: "10.200.0.0/16"}
	oldNode := &NodeRecord{DID: materializerSelfDID, MeshIP: "10.200.0.2", Label: "old-node", RecordID: "old-node-record"}
	oldMember := &MemberRecord{DID: "did:example:old-member", Label: "old-member", RecordID: "old-member-record"}
	oldRelay := &RelayData{URL: "https://old-relay.example", Region: "old-region"}
	oldACL := &ACLPolicyData{Version: 1, DefaultAction: "deny"}
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
	if !errors.As(err, &rateErr) || rateErr.RetryAfter != 6*time.Second {
		t.Fatalf("LoadState error = %#v, want 6s retry", err)
	}

	client.mu.RLock()
	defer client.mu.RUnlock()
	if client.network != oldNetwork || len(client.nodes) != 1 || client.nodes[oldNode.DID] != oldNode ||
		len(client.members) != 1 || client.members[oldMember.DID] != oldMember ||
		len(client.relays) != 1 || client.relays[0] != oldRelay || client.acl != oldACL {
		t.Fatalf("rate-limited full load changed cached state: network=%#v nodes=%#v members=%#v relays=%#v ACL=%#v",
			client.network, client.nodes, client.members, client.relays, client.acl)
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
