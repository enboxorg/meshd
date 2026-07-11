package control

import (
	"testing"
	"time"
)

func TestBuildMapResponseNodeIdentityStableAcrossMembershipChanges(t *testing.T) {
	const (
		addedDID = "did:jwk:a"
		selfDID  = "did:jwk:b"
		peerDID  = "did:jwk:c"
	)
	c := NewDWNClient("https://dwn.example", "did:example:anchor", "network-1", selfDID, nil)
	c.network = &NetworkConfig{Name: "test", MeshCIDR: "10.200.0.0/16"}
	c.nodes[selfDID] = &NodeRecord{DID: selfDID, MeshIP: "10.200.0.2", RecordID: "self-record"}
	c.nodes[peerDID] = &NodeRecord{DID: peerDID, MeshIP: "10.200.0.3", RecordID: "peer-record"}

	before := c.buildMapResponse()
	if before == nil || before.Node == nil || len(before.Peers) != 1 {
		t.Fatalf("initial map = %#v, want self and one peer", before)
	}
	selfID, selfStableID := before.Node.ID, before.Node.StableID
	peerID, peerStableID := before.Peers[0].ID, before.Peers[0].StableID
	if selfID == 0 || peerID == 0 || selfStableID == "" || peerStableID == "" {
		t.Fatalf("initial identities are not usable: self=(%d,%q) peer=(%d,%q)",
			selfID, selfStableID, peerID, peerStableID)
	}

	// Insert a DID before both existing DIDs. Rank-based IDs renumbered the
	// existing peer here and left magicsock's key/NodeID indexes inconsistent.
	c.nodes[addedDID] = &NodeRecord{DID: addedDID, MeshIP: "10.200.0.4", RecordID: "added-record"}
	after := c.buildMapResponse()
	if after == nil || after.Node == nil || len(after.Peers) != 2 {
		t.Fatalf("expanded map = %#v, want self and two peers", after)
	}
	if after.Node.ID != selfID || after.Node.StableID != selfStableID {
		t.Fatalf("self identity changed after peer joined: before=(%d,%q) after=(%d,%q)",
			selfID, selfStableID, after.Node.ID, after.Node.StableID)
	}
	existing := peerByDID(t, after, peerDID)
	if existing.ID != peerID || existing.StableID != peerStableID {
		t.Fatalf("peer identity changed after peer joined: before=(%d,%q) after=(%d,%q)",
			peerID, peerStableID, existing.ID, existing.StableID)
	}
	if after.Peers[0].ID == after.Peers[1].ID || after.Peers[0].StableID == after.Peers[1].StableID {
		t.Fatalf("expanded peers have colliding identities: %+v", after.Peers)
	}

	delete(c.nodes, addedDID)
	again := c.buildMapResponse()
	if again == nil || again.Node.ID != selfID || again.Node.StableID != selfStableID ||
		len(again.Peers) != 1 || again.Peers[0].ID != peerID || again.Peers[0].StableID != peerStableID {
		t.Fatalf("identities changed after peer left: got %#v", again)
	}

	// Expire the earlier-sorting peer while both later nodes survive. The old
	// rank allocator renumbered both survivors when it skipped the expired DID.
	c.nodes[addedDID] = &NodeRecord{DID: addedDID, MeshIP: "10.200.0.4", RecordID: "added-record"}
	beforeExpiry := c.buildMapResponse()
	addedBeforeExpiry := peerByDID(t, beforeExpiry, addedDID)
	existingBeforeExpiry := peerByDID(t, beforeExpiry, peerDID)
	c.nodes[addedDID].ExpiresAt = time.Now().UTC().Add(-time.Minute).Format(time.RFC3339)
	expired := c.buildMapResponse()
	if expired == nil || expired.Node == nil || len(expired.Peers) != 1 {
		t.Fatalf("expired map = %#v, want self and one surviving peer", expired)
	}
	if expired.Node.ID != beforeExpiry.Node.ID || expired.Node.StableID != beforeExpiry.Node.StableID {
		t.Fatalf("self identity changed after earlier peer expired: before=%#v after=%#v",
			beforeExpiry.Node, expired.Node)
	}
	existingAfterExpiry := peerByDID(t, expired, peerDID)
	if existingAfterExpiry.ID != existingBeforeExpiry.ID ||
		existingAfterExpiry.StableID != existingBeforeExpiry.StableID {
		t.Fatalf("surviving peer identity changed after earlier peer expired: before=%#v after=%#v",
			existingBeforeExpiry, existingAfterExpiry)
	}
	c.nodes[addedDID].ExpiresAt = ""
	reappeared := c.buildMapResponse()
	addedAfterExpiry := peerByDID(t, reappeared, addedDID)
	if addedAfterExpiry.ID != addedBeforeExpiry.ID || addedAfterExpiry.StableID != addedBeforeExpiry.StableID {
		t.Fatalf("peer identity changed after expiry cleared: before=%#v after=%#v",
			addedBeforeExpiry, addedAfterExpiry)
	}
}

func TestNodeIdentityForDIDStableAndNetworkScoped(t *testing.T) {
	id, stableID := nodeIdentityForDID("network-1", "did:jwk:node")
	const wantID int64 = 6072770578351070
	const wantStableID = "dwn-b1759327152003de5a78be829ef8427d"
	if id != wantID || stableID != wantStableID {
		t.Fatalf("identity vector changed: got=(%d,%q) want=(%d,%q)",
			id, stableID, wantID, wantStableID)
	}
	if id <= 0 || id > 1<<53-1 {
		t.Fatalf("NodeID = %d, want positive exactly representable integer", id)
	}
	if againID, againStableID := nodeIdentityForDID("network-1", "did:jwk:node"); againID != id || againStableID != stableID {
		t.Fatalf("identity is not deterministic: first=(%d,%q) second=(%d,%q)",
			id, stableID, againID, againStableID)
	}
	otherID, otherStableID := nodeIdentityForDID("network-1", "did:jwk:other")
	if otherID == id || otherStableID == stableID {
		t.Fatalf("different DIDs collided: first=(%d,%q) other=(%d,%q)",
			id, stableID, otherID, otherStableID)
	}
	otherNetworkID, otherNetworkStableID := nodeIdentityForDID("network-2", "did:jwk:node")
	if otherNetworkID == id || otherNetworkStableID == stableID {
		t.Fatalf("different networks share identity: first=(%d,%q) other=(%d,%q)",
			id, stableID, otherNetworkID, otherNetworkStableID)
	}
}

func peerByDID(t *testing.T, resp *MapResponse, did string) *Node {
	t.Helper()
	if resp == nil {
		t.Fatal("map response is nil")
	}
	for _, peer := range resp.Peers {
		if peer.DID == did {
			return peer
		}
	}
	t.Fatalf("peer %s missing from map", did)
	return nil
}
