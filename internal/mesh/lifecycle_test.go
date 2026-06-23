package mesh_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/enboxorg/meshd/internal/control"
	"github.com/enboxorg/meshd/internal/dwn"
	dwncrypto "github.com/enboxorg/meshd/internal/dwn/crypto"
	"github.com/enboxorg/meshd/internal/mesh"
	"github.com/enboxorg/meshd/protocols"
)

// TestE2EFullMeshLifecycle exercises the complete mesh lifecycle with both
// owner-provisioned and member-associated nodes:
//
//  1. Anchor creates network
//  2. Anchor registers owner node (network/node path)
//  3. Anchor creates member record for an external user
//  4. Anchor registers member's node (network/member/node path)
//  5. Owner node writes its own nodeInfo and endpoint (recipient-based auth)
//  6. Member node writes its own nodeInfo and endpoint (recipient-based auth)
//  7. LoadState from anchor verifies both paths are merged
//  8. LoadState from non-anchor verifies role-based reads work
//
// This is the primary E2E integration test for issue #66. It validates
// the protocol redesign from PR #84: dual node paths, member layer,
// recipient-based write authorization, and LoadState dual-path merging.
//
// Requires DWN_ENDPOINT to be set (skipped otherwise).
func TestE2EFullMeshLifecycle(t *testing.T) {
	endpoint := testEndpoint(t)

	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()

	// ================================================================
	// Step 1: Create identities for anchor, owner device, and member
	// ================================================================
	t.Log("Step 1: Creating identities")
	anchor := newNode(t, endpoint) // network owner
	member := newNode(t, endpoint) // external member (person)
	t.Logf("  Anchor: %s", anchor.DID.URI)
	t.Logf("  Member: %s", member.DID.URI)

	// ================================================================
	// Step 2: Anchor installs the wireguard-mesh protocol with encryption
	// ================================================================
	t.Log("Step 2: Installing protocol on anchor DWN")
	protocolDef, err := dwncrypto.InjectEncryptionDirectives(
		protocols.MeshProtocolJSON,
		anchor.DID.EncryptionPrivateKey,
		anchor.DID.EncryptionKeyID(),
	)
	if err != nil {
		t.Fatalf("injecting encryption directives: %v", err)
	}

	status, err := anchor.API.ConfigureProtocol(ctx, anchor.DID.URI, protocolDef)
	if err != nil {
		t.Fatalf("ConfigureProtocol: %v", err)
	}
	if status.Code >= 300 && status.Code != 409 {
		t.Fatalf("ConfigureProtocol: %d %s", status.Code, status.Detail)
	}
	t.Logf("  Protocol installed: %d", status.Code)

	// ================================================================
	// Step 3: Anchor creates the network record
	// ================================================================
	t.Log("Step 3: Creating network record")
	meshCIDR := "10.200.0.0/16"
	networkData, _ := json.Marshal(map[string]any{
		"name":     "lifecycle-test",
		"meshCIDR": meshCIDR,
		"created":  time.Now().UTC().Format(time.RFC3339),
	})

	networkRecord, writeStatus, err := anchor.API.Write(ctx, anchor.DID.URI, dwn.WriteParams{
		Protocol:     protocols.MeshProtocolURI,
		ProtocolPath: "network",
		Schema:       "https://enbox.org/schemas/wireguard-mesh/network",
		DataFormat:   "application/json",
		Data:         networkData,
	})
	if err != nil {
		t.Fatalf("creating network record: %v", err)
	}
	if writeStatus.Code >= 300 {
		t.Fatalf("network create: %d %s", writeStatus.Code, writeStatus.Detail)
	}

	networkRecordID := networkRecord.ID
	if networkRecordID == "" {
		records, qs, err := anchor.API.Query(ctx, anchor.DID.URI, dwn.QueryParams{
			Filter: dwn.RecordsFilter{
				Protocol:     protocols.MeshProtocolURI,
				ProtocolPath: "network",
			},
		}, "")
		if err != nil || qs.Code != 200 || len(records) == 0 {
			t.Fatalf("could not get network record ID: err=%v, status=%v, records=%d", err, qs, len(records))
		}
		networkRecordID = records[0].ID
	}
	t.Logf("  Network record: %s", networkRecordID)
	shareContextKeyForTest(t, networkRecordID, anchor, member)

	// ================================================================
	// Step 4: Register anchor's own device as an owner node (network/node)
	// ================================================================
	t.Log("Step 4: Registering anchor's owner-provisioned node")
	anchorIP, err := mesh.AllocateMeshIP(meshCIDR, anchor.DID.URI)
	if err != nil {
		t.Fatalf("allocating anchor IP: %v", err)
	}

	regAnchor, err := mesh.RegisterNode(ctx, mesh.RegisterNodeParams{
		AnchorEndpoint:       endpoint,
		AnchorDID:            anchor.DID.URI,
		NetworkRecordID:      networkRecordID,
		NodeDID:              anchor.DID.URI,
		Signer:               anchor.Signer,
		EncryptionKeyManager: anchor.EncMgr,
		MeshIP:               anchorIP.String(),
		Label:                "anchor-device",
		UseContextEncryption: true,
	})
	if err != nil {
		t.Fatalf("registering anchor node: %v", err)
	}
	t.Logf("  Anchor node: IP=%s, record=%s", anchorIP, regAnchor.NodeRecordID)

	// ================================================================
	// Step 5: Anchor writes nodeInfo for its own device
	// ================================================================
	t.Log("Step 5: Anchor writes nodeInfo for its own device")
	err = mesh.WriteNodeInfo(ctx, mesh.WriteNodeInfoParams{
		AnchorEndpoint:       endpoint,
		AnchorDID:            anchor.DID.URI,
		NetworkRecordID:      networkRecordID,
		NodeRecordID:         regAnchor.NodeRecordID,
		Signer:               anchor.Signer,
		EncryptionKeyManager: anchor.EncMgr,
		Hostname:             "anchor-host",
		UseContextEncryption: true,
	})
	if err != nil {
		t.Fatalf("anchor WriteNodeInfo failed: %v", err)
	}
	t.Log("  Anchor nodeInfo written")

	// ================================================================
	// Step 6: Anchor writes endpoint for its own device
	// ================================================================
	t.Log("Step 6: Anchor writes endpoint for its own device")
	err = mesh.WriteEndpoint(ctx, mesh.WriteEndpointParams{
		AnchorEndpoint:       endpoint,
		AnchorDID:            anchor.DID.URI,
		NetworkRecordID:      networkRecordID,
		NodeRecordID:         regAnchor.NodeRecordID,
		Signer:               anchor.Signer,
		EncryptionKeyManager: anchor.EncMgr,
		PublicEndpoints: []control.PublicEndpoint{
			{Address: "198.51.100.1", Port: 51820, Source: "test"},
		},
		LocalEndpoints:       []string{"192.168.1.10:51820"},
		NATType:              "full-cone",
		UseContextEncryption: true,
	})
	if err != nil {
		t.Fatalf("anchor WriteEndpoint failed: %v", err)
	}
	t.Log("  Anchor endpoint written")

	// ================================================================
	// Step 7: Create member record (assigns network/member role)
	// ================================================================
	t.Log("Step 7: Creating member record for external user")
	memberReg, err := mesh.CreateMember(ctx, mesh.CreateMemberParams{
		AnchorEndpoint:       endpoint,
		AnchorDID:            anchor.DID.URI,
		NetworkRecordID:      networkRecordID,
		MemberDID:            member.DID.URI,
		Signer:               anchor.Signer,
		EncryptionKeyManager: anchor.EncMgr,
		Label:                "alice",
	})
	if err != nil {
		t.Fatalf("CreateMember failed: %v", err)
	}
	t.Logf("  Member record: %s", memberReg.MemberRecordID)

	// ================================================================
	// Step 8: Register member's device (network/member/node path)
	// ================================================================
	t.Log("Step 8: Registering member's device under member path")
	memberIP, err := mesh.AllocateMeshIP(meshCIDR, member.DID.URI)
	if err != nil {
		t.Fatalf("allocating member IP: %v", err)
	}

	regMember, err := mesh.RegisterNode(ctx, mesh.RegisterNodeParams{
		AnchorEndpoint:       endpoint,
		AnchorDID:            anchor.DID.URI,
		NetworkRecordID:      networkRecordID,
		MemberRecordID:       memberReg.MemberRecordID,
		NodeDID:              member.DID.URI,
		Signer:               anchor.Signer, // anchor creates member nodes
		EncryptionKeyManager: anchor.EncMgr,
		MeshIP:               memberIP.String(),
		Label:                "alice-laptop",
		UseContextEncryption: true,
	})
	if err != nil {
		t.Fatalf("registering member node: %v", err)
	}
	t.Logf("  Member node: IP=%s, record=%s", memberIP, regMember.NodeRecordID)

	// ================================================================
	// Step 9: Member writes its own nodeInfo (recipient-based write auth)
	// ================================================================
	t.Log("Step 9: Member writes its own nodeInfo (recipient-based write auth)")
	err = mesh.WriteNodeInfo(ctx, mesh.WriteNodeInfoParams{
		AnchorEndpoint:       endpoint,
		AnchorDID:            anchor.DID.URI,
		NetworkRecordID:      networkRecordID,
		MemberRecordID:       memberReg.MemberRecordID,
		NodeRecordID:         regMember.NodeRecordID,
		Signer:               member.Signer, // member signs its own record
		EncryptionKeyManager: member.EncMgr,
		Hostname:             "alice-laptop",
		UseContextEncryption: true,
	})
	if err != nil {
		t.Fatalf("member WriteNodeInfo failed: %v (this was the pre-PR#84 bug)", err)
	}
	t.Log("  Member nodeInfo written successfully (recipient-based auth works)")

	// ================================================================
	// Step 10: Member writes its own endpoint (recipient-based auth)
	// ================================================================
	t.Log("Step 10: Member writes its own endpoint")
	err = mesh.WriteEndpoint(ctx, mesh.WriteEndpointParams{
		AnchorEndpoint:       endpoint,
		AnchorDID:            anchor.DID.URI,
		NetworkRecordID:      networkRecordID,
		MemberRecordID:       memberReg.MemberRecordID,
		NodeRecordID:         regMember.NodeRecordID,
		Signer:               member.Signer,
		EncryptionKeyManager: member.EncMgr,
		PublicEndpoints: []control.PublicEndpoint{
			{Address: "203.0.113.50", Port: 51820, Source: "test"},
		},
		LocalEndpoints:       []string{"10.0.0.42:51820"},
		NATType:              "symmetric",
		UseContextEncryption: true,
	})
	if err != nil {
		t.Fatalf("member WriteEndpoint failed: %v", err)
	}
	t.Log("  Member endpoint written")

	// ================================================================
	// Step 11: LoadState from anchor perspective (reads as author)
	// ================================================================
	t.Log("Step 11: LoadState from anchor perspective")
	anchorClient := control.NewDWNClient(
		endpoint,
		anchor.DID.URI,
		networkRecordID,
		anchor.DID.URI,
		anchor.Signer,
		control.WithEncryptionKeyManager(anchor.EncMgr),
	)

	mapResp, err := anchorClient.LoadState(ctx)
	if err != nil {
		t.Fatalf("anchor LoadState failed: %v", err)
	}

	// Verify the MapResponse.
	if mapResp.Node == nil {
		t.Fatal("anchor MapResponse.Node is nil")
	}
	if mapResp.Node.DID != anchor.DID.URI {
		t.Fatalf("anchor self DID mismatch: got %q, want %q", mapResp.Node.DID, anchor.DID.URI)
	}
	if mapResp.Node.MeshIP != anchorIP {
		t.Fatalf("anchor self IP mismatch: got %s, want %s", mapResp.Node.MeshIP, anchorIP)
	}
	t.Logf("  Anchor self: DID=%s, IP=%s, Name=%s", mapResp.Node.DID[:30]+"...", mapResp.Node.MeshIP, mapResp.Node.Name)

	// Verify anchor's nodeInfo was attached.
	if mapResp.Node.Name != "anchor-host" {
		t.Errorf("anchor hostname not from nodeInfo: got %q, want %q", mapResp.Node.Name, "anchor-host")
	}

	// Verify peers include the member node.
	if len(mapResp.Peers) < 1 {
		t.Fatalf("expected at least 1 peer, got %d", len(mapResp.Peers))
	}

	var memberPeer *control.Node
	for _, p := range mapResp.Peers {
		if p.DID == member.DID.URI {
			memberPeer = p
			break
		}
	}
	if memberPeer == nil {
		t.Fatal("member node not found in peers")
	}
	t.Logf("  Member peer: DID=%s, IP=%s, Name=%s", memberPeer.DID[:30]+"...", memberPeer.MeshIP, memberPeer.Name)

	// Verify member's mesh IP.
	if memberPeer.MeshIP != memberIP {
		t.Errorf("member IP mismatch: got %s, want %s", memberPeer.MeshIP, memberIP)
	}

	// Verify member's nodeInfo was attached.
	if memberPeer.Name != "alice-laptop" {
		t.Errorf("member hostname not from nodeInfo: got %q, want %q", memberPeer.Name, "alice-laptop")
	}

	// Verify member's endpoints were attached.
	if len(memberPeer.Endpoints) == 0 {
		t.Error("member has no endpoints")
	} else {
		t.Logf("  Member endpoints: %v", memberPeer.Endpoints)
	}

	// Verify anchor's endpoints were attached.
	if len(mapResp.Node.Endpoints) == 0 {
		t.Error("anchor has no endpoints")
	} else {
		t.Logf("  Anchor endpoints: %v", mapResp.Node.Endpoints)
	}

	// Verify WireGuard keys are derived (non-empty).
	if mapResp.Node.Key == "" {
		t.Error("anchor WireGuard key is empty")
	}
	if memberPeer.Key == "" {
		t.Error("member WireGuard key is empty")
	}

	// Verify members map via the DWNClient.
	members := anchorClient.Members()
	if len(members) == 0 {
		t.Error("no members found")
	} else {
		m, ok := members[member.DID.URI]
		if !ok {
			t.Errorf("member DID %s not in members map", member.DID.URI[:30]+"...")
		} else {
			t.Logf("  Member record: DID=%s, label=%s", m.DID[:30]+"...", m.Label)
		}
	}

	// Verify nodes map includes both paths.
	nodes := anchorClient.Nodes()
	if len(nodes) < 2 {
		t.Errorf("expected at least 2 nodes, got %d", len(nodes))
	}
	for did, node := range nodes {
		t.Logf("  Node: DID=%s, IP=%s, record=%s, memberRecord=%s",
			did[:30]+"...", node.MeshIP, node.RecordID, node.MemberRecordID)
	}

	// Verify member node has MemberRecordID set (dual-path indicator).
	memberNode := nodes[member.DID.URI]
	if memberNode == nil {
		t.Fatal("member DID not in nodes map")
	}
	if memberNode.MemberRecordID == "" {
		t.Error("member node MemberRecordID is empty (should indicate member path)")
	}

	// Verify anchor node does NOT have MemberRecordID (owner path).
	anchorNode := nodes[anchor.DID.URI]
	if anchorNode == nil {
		t.Fatal("anchor DID not in nodes map")
	}
	if anchorNode.MemberRecordID != "" {
		t.Errorf("anchor node MemberRecordID should be empty, got %q", anchorNode.MemberRecordID)
	}

	// ================================================================
	// Summary
	// ================================================================
	t.Log("=== Full Mesh Lifecycle Test PASSED ===")
	t.Logf("  Network: lifecycle-test (%s)", networkRecordID)
	t.Logf("  Anchor: %s -> %s (owner path)", anchor.DID.URI[:30]+"...", anchorIP)
	t.Logf("  Member: %s -> %s (member path)", member.DID.URI[:30]+"...", memberIP)
	t.Log("  nodeInfo: written and attached for both nodes")
	t.Log("  endpoints: written and attached for both nodes")
	t.Log("  LoadState: dual-path merge verified")
	t.Log("  Recipient-based write auth: verified (member wrote own nodeInfo+endpoint)")
}

func shareContextKeyForTest(t *testing.T, contextID string, owner *nodeIdentity, recipient *nodeIdentity) {
	t.Helper()

	contextKey, err := owner.EncMgr.DeriveContextDecryptionKey(contextID)
	if err != nil {
		t.Fatalf("deriving context key for test: %v", err)
	}
	recipient.EncMgr.StoreContextKey(contextID, contextKey)
}

// TestE2ERecipientBasedOwnerNodeWrite verifies that an owner-provisioned
// node (non-anchor) can write its own nodeInfo and endpoint records using
// recipient-based authorization (the exact scenario that failed before PR #84).
//
// This is a focused regression test: the anchor creates a node record with
// the non-anchor's DID as recipient, then the non-anchor writes child records.
func TestE2ERecipientBasedOwnerNodeWrite(t *testing.T) {
	endpoint := testEndpoint(t)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	// Create anchor and a second node.
	anchor := newNode(t, endpoint)
	nodeB := newNode(t, endpoint)

	// Install protocol.
	protocolDef, err := dwncrypto.InjectEncryptionDirectives(
		protocols.MeshProtocolJSON,
		anchor.DID.EncryptionPrivateKey,
		anchor.DID.EncryptionKeyID(),
	)
	if err != nil {
		t.Fatalf("InjectEncryptionDirectives: %v", err)
	}
	status, err := anchor.API.ConfigureProtocol(ctx, anchor.DID.URI, protocolDef)
	if err != nil || (status.Code >= 300 && status.Code != 409) {
		t.Fatalf("ConfigureProtocol: err=%v, status=%v", err, status)
	}

	// Create network.
	networkData, _ := json.Marshal(map[string]any{
		"name":     "recipient-auth-test",
		"meshCIDR": "10.200.0.0/16",
	})
	networkRecord, ws, err := anchor.API.Write(ctx, anchor.DID.URI, dwn.WriteParams{
		Protocol:     protocols.MeshProtocolURI,
		ProtocolPath: "network",
		Schema:       "https://enbox.org/schemas/wireguard-mesh/network",
		DataFormat:   "application/json",
		Data:         networkData,
	})
	if err != nil || ws.Code >= 300 {
		t.Fatalf("creating network: err=%v, status=%v", err, ws)
	}
	networkRecordID := networkRecord.ID
	if networkRecordID == "" {
		records, _, _ := anchor.API.Query(ctx, anchor.DID.URI, dwn.QueryParams{
			Filter: dwn.RecordsFilter{Protocol: protocols.MeshProtocolURI, ProtocolPath: "network"},
		}, "")
		if len(records) > 0 {
			networkRecordID = records[0].ID
		}
	}
	shareContextKeyForTest(t, networkRecordID, anchor, nodeB)

	// Anchor registers node B (recipient = B's DID, assigns network/node role).
	ipB, err := mesh.AllocateMeshIP("10.200.0.0/16", nodeB.DID.URI)
	if err != nil {
		t.Fatalf("allocating IP for B: %v", err)
	}
	regB, err := mesh.RegisterNode(ctx, mesh.RegisterNodeParams{
		AnchorEndpoint:       endpoint,
		AnchorDID:            anchor.DID.URI,
		NetworkRecordID:      networkRecordID,
		NodeDID:              nodeB.DID.URI,
		Signer:               anchor.Signer,
		EncryptionKeyManager: anchor.EncMgr,
		MeshIP:               ipB.String(),
		Label:                "node-b",
		UseContextEncryption: true,
	})
	if err != nil {
		t.Fatalf("registering node B: %v", err)
	}
	t.Logf("  Node B registered: IP=%s, record=%s", ipB, regB.NodeRecordID)

	// ---- THE KEY TEST: Node B writes its own nodeInfo ----
	t.Log("Node B writes nodeInfo (recipient-based auth, no role needed)")
	err = mesh.WriteNodeInfo(ctx, mesh.WriteNodeInfoParams{
		AnchorEndpoint:       endpoint,
		AnchorDID:            anchor.DID.URI,
		NetworkRecordID:      networkRecordID,
		NodeRecordID:         regB.NodeRecordID,
		Signer:               nodeB.Signer, // B signs its own record
		EncryptionKeyManager: nodeB.EncMgr,
		Hostname:             "node-b-host",
		UseContextEncryption: true,
	})
	if err != nil {
		t.Fatalf("Node B WriteNodeInfo failed: %v — recipient-based auth is broken!", err)
	}
	t.Log("  nodeInfo written successfully")

	// ---- THE KEY TEST: Node B writes its own endpoint ----
	t.Log("Node B writes endpoint (recipient-based auth, no role needed)")
	err = mesh.WriteEndpoint(ctx, mesh.WriteEndpointParams{
		AnchorEndpoint:       endpoint,
		AnchorDID:            anchor.DID.URI,
		NetworkRecordID:      networkRecordID,
		NodeRecordID:         regB.NodeRecordID,
		Signer:               nodeB.Signer, // B signs its own record
		EncryptionKeyManager: nodeB.EncMgr,
		PublicEndpoints: []control.PublicEndpoint{
			{Address: "192.0.2.42", Port: 51820, Source: "test"},
		},
		LocalEndpoints:       []string{"172.16.0.5:51820"},
		NATType:              "port-restricted",
		UseContextEncryption: true,
	})
	if err != nil {
		t.Fatalf("Node B WriteEndpoint failed: %v — recipient-based auth is broken!", err)
	}
	t.Log("  endpoint written successfully")

	// Verify via LoadState that nodeInfo and endpoint are attached.
	// Register anchor node first so LoadState can find self.
	anchorIP, _ := mesh.AllocateMeshIP("10.200.0.0/16", anchor.DID.URI)
	_, err = mesh.RegisterNode(ctx, mesh.RegisterNodeParams{
		AnchorEndpoint:       endpoint,
		AnchorDID:            anchor.DID.URI,
		NetworkRecordID:      networkRecordID,
		NodeDID:              anchor.DID.URI,
		Signer:               anchor.Signer,
		EncryptionKeyManager: anchor.EncMgr,
		MeshIP:               anchorIP.String(),
		Label:                "anchor",
		UseContextEncryption: true,
	})
	if err != nil {
		t.Fatalf("registering anchor node: %v", err)
	}

	client := control.NewDWNClient(
		endpoint,
		anchor.DID.URI,
		networkRecordID,
		anchor.DID.URI,
		anchor.Signer,
		control.WithEncryptionKeyManager(anchor.EncMgr),
	)

	mapResp, err := client.LoadState(ctx)
	if err != nil {
		t.Fatalf("LoadState failed: %v", err)
	}

	// Find node B in peers.
	var peerB *control.Node
	for _, p := range mapResp.Peers {
		if p.DID == nodeB.DID.URI {
			peerB = p
			break
		}
	}
	if peerB == nil {
		t.Fatal("node B not found in peers after LoadState")
	}

	if peerB.Name != "node-b-host" {
		t.Errorf("node B hostname: got %q, want %q (nodeInfo not attached?)", peerB.Name, "node-b-host")
	}
	if len(peerB.Endpoints) == 0 {
		t.Error("node B has no endpoints (endpoint record not attached?)")
	}

	t.Log("=== Recipient-Based Owner Node Write Test PASSED ===")
	t.Logf("  Node B wrote nodeInfo: hostname=%q", peerB.Name)
	t.Logf("  Node B wrote endpoint: %v", peerB.Endpoints)
}

// TestE2EACLPolicyRoundTrip verifies that an ACL policy written to the
// anchor DWN is correctly loaded by LoadState and produces the expected
// packet filter rules.
func TestE2EACLPolicyRoundTrip(t *testing.T) {
	endpoint := testEndpoint(t)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	// Create anchor and two nodes.
	anchor := newNode(t, endpoint)
	nodeB := newNode(t, endpoint)

	// Install protocol.
	protocolDef, err := dwncrypto.InjectEncryptionDirectives(
		protocols.MeshProtocolJSON,
		anchor.DID.EncryptionPrivateKey,
		anchor.DID.EncryptionKeyID(),
	)
	if err != nil {
		t.Fatalf("InjectEncryptionDirectives: %v", err)
	}
	status, err := anchor.API.ConfigureProtocol(ctx, anchor.DID.URI, protocolDef)
	if err != nil || (status.Code >= 300 && status.Code != 409) {
		t.Fatalf("ConfigureProtocol: err=%v, status=%v", err, status)
	}

	// Create network.
	networkData, _ := json.Marshal(map[string]any{
		"name":     "acl-test",
		"meshCIDR": "10.200.0.0/16",
	})
	networkRecord, ws, err := anchor.API.Write(ctx, anchor.DID.URI, dwn.WriteParams{
		Protocol:     protocols.MeshProtocolURI,
		ProtocolPath: "network",
		Schema:       "https://enbox.org/schemas/wireguard-mesh/network",
		DataFormat:   "application/json",
		Data:         networkData,
	})
	if err != nil || ws.Code >= 300 {
		t.Fatalf("creating network: err=%v, status=%v", err, ws)
	}
	networkRecordID := networkRecord.ID
	if networkRecordID == "" {
		records, _, _ := anchor.API.Query(ctx, anchor.DID.URI, dwn.QueryParams{
			Filter: dwn.RecordsFilter{Protocol: protocols.MeshProtocolURI, ProtocolPath: "network"},
		}, "")
		if len(records) > 0 {
			networkRecordID = records[0].ID
		}
	}

	// Register two nodes.
	anchorIP, _ := mesh.AllocateMeshIP("10.200.0.0/16", anchor.DID.URI)
	_, err = mesh.RegisterNode(ctx, mesh.RegisterNodeParams{
		AnchorEndpoint:       endpoint,
		AnchorDID:            anchor.DID.URI,
		NetworkRecordID:      networkRecordID,
		NodeDID:              anchor.DID.URI,
		Signer:               anchor.Signer,
		EncryptionKeyManager: anchor.EncMgr,
		MeshIP:               anchorIP.String(),
		Label:                "anchor",
	})
	if err != nil {
		t.Fatalf("registering anchor: %v", err)
	}

	ipB, _ := mesh.AllocateMeshIP("10.200.0.0/16", nodeB.DID.URI)
	_, err = mesh.RegisterNode(ctx, mesh.RegisterNodeParams{
		AnchorEndpoint:       endpoint,
		AnchorDID:            anchor.DID.URI,
		NetworkRecordID:      networkRecordID,
		NodeDID:              nodeB.DID.URI,
		Signer:               anchor.Signer,
		EncryptionKeyManager: anchor.EncMgr,
		MeshIP:               ipB.String(),
		Label:                "node-b",
	})
	if err != nil {
		t.Fatalf("registering node B: %v", err)
	}

	// Write ACL policy: only allow anchor -> B on port 22.
	aclPolicy := control.ACLPolicyData{
		Version: 1,
		Groups: map[string][]string{
			"servers": {nodeB.DID.URI},
		},
		Rules: []control.ACLRule{
			{
				Action:   "accept",
				Src:      []string{anchor.DID.URI},
				Dst:      []string{"group:servers"},
				DstPorts: []string{"22"},
			},
		},
	}
	policyJSON, err := json.Marshal(aclPolicy)
	if err != nil {
		t.Fatalf("marshaling ACL policy: %v", err)
	}

	err = mesh.WriteACLPolicy(ctx, mesh.WriteACLPolicyParams{
		AnchorEndpoint:       endpoint,
		AnchorDID:            anchor.DID.URI,
		NetworkRecordID:      networkRecordID,
		Signer:               anchor.Signer,
		EncryptionKeyManager: anchor.EncMgr,
		PolicyData:           policyJSON,
	})
	if err != nil {
		t.Fatalf("WriteACLPolicy failed: %v", err)
	}
	t.Log("  ACL policy written")

	// LoadState and verify filter rules.
	client := control.NewDWNClient(
		endpoint,
		anchor.DID.URI,
		networkRecordID,
		anchor.DID.URI,
		anchor.Signer,
		control.WithEncryptionKeyManager(anchor.EncMgr),
	)

	mapResp, err := client.LoadState(ctx)
	if err != nil {
		t.Fatalf("LoadState failed: %v", err)
	}

	// Verify ACL policy was loaded.
	aclLoaded := client.ACLPolicy()
	if aclLoaded == nil {
		t.Fatal("ACL policy is nil after LoadState")
	}
	if aclLoaded.Version != 1 {
		t.Errorf("ACL version: got %d, want 1", aclLoaded.Version)
	}
	if len(aclLoaded.Rules) != 1 {
		t.Fatalf("ACL rules: got %d, want 1", len(aclLoaded.Rules))
	}
	t.Logf("  ACL policy loaded: version=%d, rules=%d", aclLoaded.Version, len(aclLoaded.Rules))

	// Verify the packet filter rules.
	if len(mapResp.PacketFilter) == 0 {
		t.Fatal("no packet filter rules")
	}
	t.Logf("  Filter rules: %d", len(mapResp.PacketFilter))

	// The rule should map anchor IP -> node B IP on port 22.
	foundRule := false
	for _, rule := range mapResp.PacketFilter {
		for _, src := range rule.SrcIPs {
			if src == anchorIP.String() {
				for _, dst := range rule.DstPorts {
					if dst.IP == ipB.String() && dst.Ports.First == 22 && dst.Ports.Last == 22 {
						foundRule = true
					}
				}
			}
		}
	}
	if !foundRule {
		t.Errorf("expected filter rule: %s -> %s:22, not found in %+v",
			anchorIP, ipB, mapResp.PacketFilter)
	}

	// Verify it's NOT a wildcard allow-all rule.
	isWildcard := false
	for _, rule := range mapResp.PacketFilter {
		for _, src := range rule.SrcIPs {
			if src == "*" {
				isWildcard = true
			}
		}
	}
	if isWildcard {
		t.Error("filter rules contain wildcard — ACL policy was not applied")
	}

	t.Log("=== ACL Policy Round-Trip Test PASSED ===")
	t.Logf("  Policy: anchor -> group:servers port 22")
	t.Logf("  Resolved: %s -> %s:22", anchorIP, ipB)
}

// TestE2ELoadStateNonAnchor verifies that a non-anchor node can successfully
// run LoadState using role-based read authorization (network/node role).
func TestE2ELoadStateNonAnchor(t *testing.T) {
	endpoint := testEndpoint(t)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	anchor := newNode(t, endpoint)
	nodeB := newNode(t, endpoint)

	// Install protocol.
	protocolDef, err := dwncrypto.InjectEncryptionDirectives(
		protocols.MeshProtocolJSON,
		anchor.DID.EncryptionPrivateKey,
		anchor.DID.EncryptionKeyID(),
	)
	if err != nil {
		t.Fatalf("InjectEncryptionDirectives: %v", err)
	}
	status, err := anchor.API.ConfigureProtocol(ctx, anchor.DID.URI, protocolDef)
	if err != nil || (status.Code >= 300 && status.Code != 409) {
		t.Fatalf("ConfigureProtocol: err=%v, status=%v", err, status)
	}

	// Create network.
	networkData, _ := json.Marshal(map[string]any{
		"name":     "non-anchor-loadstate-test",
		"meshCIDR": "10.200.0.0/16",
	})
	networkRecord, ws, err := anchor.API.Write(ctx, anchor.DID.URI, dwn.WriteParams{
		Protocol:     protocols.MeshProtocolURI,
		ProtocolPath: "network",
		Schema:       "https://enbox.org/schemas/wireguard-mesh/network",
		DataFormat:   "application/json",
		Data:         networkData,
	})
	if err != nil || ws.Code >= 300 {
		t.Fatalf("creating network: err=%v, status=%v", err, ws)
	}
	networkRecordID := networkRecord.ID
	if networkRecordID == "" {
		records, _, _ := anchor.API.Query(ctx, anchor.DID.URI, dwn.QueryParams{
			Filter: dwn.RecordsFilter{Protocol: protocols.MeshProtocolURI, ProtocolPath: "network"},
		}, "")
		if len(records) > 0 {
			networkRecordID = records[0].ID
		}
	}
	shareContextKeyForTest(t, networkRecordID, anchor, nodeB)

	// Register both nodes.
	anchorIP, _ := mesh.AllocateMeshIP("10.200.0.0/16", anchor.DID.URI)
	_, err = mesh.RegisterNode(ctx, mesh.RegisterNodeParams{
		AnchorEndpoint: endpoint, AnchorDID: anchor.DID.URI,
		NetworkRecordID: networkRecordID, NodeDID: anchor.DID.URI,
		Signer: anchor.Signer, EncryptionKeyManager: anchor.EncMgr,
		MeshIP: anchorIP.String(), Label: "anchor",
		UseContextEncryption: true,
	})
	if err != nil {
		t.Fatalf("registering anchor: %v", err)
	}

	ipB, _ := mesh.AllocateMeshIP("10.200.0.0/16", nodeB.DID.URI)
	_, err = mesh.RegisterNode(ctx, mesh.RegisterNodeParams{
		AnchorEndpoint: endpoint, AnchorDID: anchor.DID.URI,
		NetworkRecordID: networkRecordID, NodeDID: nodeB.DID.URI,
		Signer: anchor.Signer, EncryptionKeyManager: anchor.EncMgr,
		MeshIP: ipB.String(), Label: "node-b",
		UseContextEncryption: true,
	})
	if err != nil {
		t.Fatalf("registering node B: %v", err)
	}

	// Node B runs LoadState with the network/node role.
	t.Log("Node B runs LoadState with network/node role")
	nodeBClient := control.NewDWNClient(
		endpoint,
		anchor.DID.URI,
		networkRecordID,
		nodeB.DID.URI,
		nodeB.Signer,
		control.WithEncryptionKeyManager(nodeB.EncMgr),
		control.WithProtocolRole("network/node"),
	)

	mapResp, err := nodeBClient.LoadState(ctx)
	if err != nil {
		t.Fatalf("non-anchor LoadState failed: %v", err)
	}

	// Verify self is node B.
	if mapResp.Node == nil {
		t.Fatal("non-anchor MapResponse.Node is nil")
	}
	if mapResp.Node.DID != nodeB.DID.URI {
		t.Fatalf("non-anchor self DID: got %q, want %q", mapResp.Node.DID, nodeB.DID.URI)
	}
	if mapResp.Node.MeshIP != ipB {
		t.Fatalf("non-anchor self IP: got %s, want %s", mapResp.Node.MeshIP, ipB)
	}

	// Verify anchor is in peers.
	var anchorPeer *control.Node
	for _, p := range mapResp.Peers {
		if p.DID == anchor.DID.URI {
			anchorPeer = p
			break
		}
	}
	if anchorPeer == nil {
		t.Fatal("anchor not found in non-anchor's peers")
	}
	if anchorPeer.MeshIP != anchorIP {
		t.Errorf("anchor IP: got %s, want %s", anchorPeer.MeshIP, anchorIP)
	}

	t.Log("=== Non-Anchor LoadState Test PASSED ===")
	t.Logf("  Node B (non-anchor): self=%s, peers=%d", mapResp.Node.MeshIP, len(mapResp.Peers))
	t.Logf("  Anchor in peers: IP=%s", anchorPeer.MeshIP)
}
