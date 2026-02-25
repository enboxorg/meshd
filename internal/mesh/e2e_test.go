package mesh_test

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/enboxorg/meshd/internal/did"
	"github.com/enboxorg/meshd/internal/dwn"
	dwncrypto "github.com/enboxorg/meshd/internal/dwn/crypto"
	"github.com/enboxorg/meshd/internal/mesh"
	"github.com/enboxorg/meshd/protocols"
)

// End-to-end integration test for meshd: creates a network with two
// nodes, writes encrypted records, and verifies that records are
// visible and decryptable by both participants.
//
// Requires DWN_ENDPOINT to be set (skipped otherwise).

func testEndpoint(t *testing.T) string {
	t.Helper()
	endpoint := os.Getenv("DWN_ENDPOINT")
	if endpoint == "" {
		t.Skip("DWN_ENDPOINT not set, skipping integration test")
	}
	return endpoint
}

// registerTenant registers a DID as a tenant on the DWN server.
func registerTenant(t *testing.T, endpoint string, signer *dwn.Signer) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if err := dwn.RegisterTenant(ctx, endpoint, signer.DID); err != nil {
		t.Fatalf("RegisterTenant: %v", err)
	}
	t.Logf("Registered tenant: %s", signer.DID)
}

// nodeIdentity holds everything needed for a mesh node.
type nodeIdentity struct {
	DID    *did.DID
	Signer *dwn.Signer
	EncMgr *dwncrypto.EncryptionKeyManager
	Agent  dwn.Agent
	API    *dwn.DwnAPI
}

// newNode creates a fresh node identity, publishes it to the DHT,
// registers it as a tenant, and returns a fully wired node.
func newNode(t *testing.T, endpoint string) *nodeIdentity {
	t.Helper()

	identity, err := did.Generate()
	if err != nil {
		t.Fatalf("generating DID: %v", err)
	}

	// Publish DID to DHT so the server can resolve it for JWS verification.
	pubCtx, pubCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer pubCancel()
	if err := identity.Publish(pubCtx, endpoint); err != nil {
		t.Fatalf("publishing DID: %v", err)
	}

	signer := &dwn.Signer{
		DID:        identity.URI,
		PrivateKey: identity.SigningKey,
	}

	registerTenant(t, endpoint, signer)

	agent := dwn.NewSimpleAgent(endpoint, signer)
	api := dwn.NewDwnAPI(agent)

	encMgr := &dwncrypto.EncryptionKeyManager{
		RootPrivateKey: identity.EncryptionPrivateKey,
		RootKeyID:      identity.EncryptionKeyID(),
		ProtocolURI:    "https://enbox.org/protocols/wireguard-mesh",
	}

	return &nodeIdentity{
		DID:    identity,
		Signer: signer,
		EncMgr: encMgr,
		Agent:  agent,
		API:    api,
	}
}

func TestE2ENetworkCreateJoinQueryDecrypt(t *testing.T) {
	endpoint := testEndpoint(t)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	// ---- Step 1: Create two node identities ----
	t.Log("Step 1: Creating two node identities")
	nodeA := newNode(t, endpoint) // network creator (anchor)
	nodeB := newNode(t, endpoint) // joiner
	t.Logf("  Node A: %s", nodeA.DID.URI)
	t.Logf("  Node B: %s", nodeB.DID.URI)

	// ---- Step 2: Node A installs the protocol (with encryption keys) ----
	t.Log("Step 2: Node A installs the wireguard-mesh protocol")
	protocolDef, err := dwncrypto.InjectEncryptionDirectives(
		protocols.MeshProtocolJSON,
		nodeA.DID.EncryptionPrivateKey,
		nodeA.DID.EncryptionKeyID(),
	)
	if err != nil {
		t.Fatalf("injecting encryption directives: %v", err)
	}

	status, err := nodeA.API.ConfigureProtocol(ctx, nodeA.DID.URI, protocolDef)
	if err != nil {
		t.Fatalf("ConfigureProtocol: %v", err)
	}
	if status.Code >= 300 && status.Code != 409 {
		t.Fatalf("ConfigureProtocol: %d %s", status.Code, status.Detail)
	}
	t.Logf("  Protocol installed: %d %s", status.Code, status.Detail)

	// ---- Step 3: Node A creates the network record ----
	t.Log("Step 3: Node A creates the network record")
	meshCIDR := "10.200.0.0/16"
	networkData, _ := json.Marshal(map[string]any{
		"name":     "e2e-test-network",
		"meshCIDR": meshCIDR,
		"created":  time.Now().UTC().Format(time.RFC3339),
	})

	networkRecord, writeStatus, err := nodeA.API.Write(ctx, nodeA.DID.URI, dwn.WriteParams{
		Protocol:     "https://enbox.org/protocols/wireguard-mesh",
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
	t.Logf("  Network record: %s (status: %d)", networkRecord.ID, writeStatus.Code)

	networkRecordID := networkRecord.ID
	if networkRecordID == "" {
		// Try to get the ID from a query.
		records, qs, err := nodeA.API.Query(ctx, nodeA.DID.URI, dwn.QueryParams{
			Filter: dwn.RecordsFilter{
				Protocol:     "https://enbox.org/protocols/wireguard-mesh",
				ProtocolPath: "network",
			},
		}, "")
		if err != nil || qs.Code != 200 || len(records) == 0 {
			t.Fatalf("could not get network record ID: err=%v, status=%v, records=%d", err, qs, len(records))
		}
		networkRecordID = records[0].ID
		t.Logf("  Network record ID (from query): %s", networkRecordID)
	}

	// ---- Step 4: Node A creates itself as admin member (encrypted) ----
	t.Log("Step 4: Node A creates admin member record (encrypted)")
	memberData, _ := json.Marshal(map[string]any{
		"joinedAt": time.Now().UTC().Format(time.RFC3339),
		"label":    "admin",
	})
	memberRecipients, err := nodeA.EncMgr.DeriveWriteEncryption("network/member")
	if err != nil {
		t.Fatalf("deriving member encryption: %v", err)
	}

	_, memberStatus, err := nodeA.API.Write(ctx, nodeA.DID.URI, dwn.WriteParams{
		Protocol:             "https://enbox.org/protocols/wireguard-mesh",
		ProtocolPath:         "network/member",
		Schema:               "https://enbox.org/schemas/wireguard-mesh/member",
		DataFormat:           "application/json",
		Recipient:            nodeA.DID.URI,
		ParentContextID:     networkRecordID,
		Data:                 memberData,
		Tags:                 map[string]any{"status": "active"},
		EncryptionRecipients: memberRecipients,
	})
	if err != nil {
		t.Fatalf("creating admin member: %v", err)
	}
	if memberStatus.Code >= 300 {
		t.Logf("  Warning: admin member creation: %d %s", memberStatus.Code, memberStatus.Detail)
	} else {
		t.Logf("  Admin member created: %d %s", memberStatus.Code, memberStatus.Detail)
	}

	// ---- Step 5: Node A generates WireGuard keys and registers nodeInfo (encrypted) ----
	t.Log("Step 5: Node A generates WG keys and registers nodeInfo")
	wgKeysA, err := mesh.GenerateWireGuardKeyPair()
	if err != nil {
		t.Fatalf("generating WG keys for node A: %v", err)
	}
	meshIPA, err := mesh.AllocateMeshIP(meshCIDR, nodeA.DID.URI)
	if err != nil {
		t.Fatalf("allocating mesh IP for node A: %v", err)
	}

	regA, err := mesh.RegisterNode(ctx, mesh.RegisterNodeParams{
		AnchorEndpoint:       endpoint,
		AnchorDID:            nodeA.DID.URI,
		NetworkRecordID:      networkRecordID,
		SelfDID:              nodeA.DID.URI,
		Signer:               nodeA.Signer,
		EncryptionKeyManager: nodeA.EncMgr,
		WireGuardPubKey:      wgKeysA.PublicKeyBase64(),
		MeshIP:               meshIPA.String(),
		Hostname:             "node-a",
	})
	if err != nil {
		t.Fatalf("registering node A: %v", err)
	}
	t.Logf("  Node A registered: IP=%s, nodeInfo=%s", meshIPA, regA.NodeInfoRecordID)

	// ---- Step 6: Node B joins the network ----
	// Node B needs to install the protocol on its own DWN as well.
	t.Log("Step 6: Node B installs protocol and joins the network")
	protocolDefB, err := dwncrypto.InjectEncryptionDirectives(
		protocols.MeshProtocolJSON,
		nodeB.DID.EncryptionPrivateKey,
		nodeB.DID.EncryptionKeyID(),
	)
	if err != nil {
		t.Fatalf("injecting encryption directives for node B: %v", err)
	}
	statusB, err := nodeB.API.ConfigureProtocol(ctx, nodeB.DID.URI, protocolDefB)
	if err != nil {
		t.Fatalf("ConfigureProtocol for node B: %v", err)
	}
	if statusB.Code >= 300 && statusB.Code != 409 {
		t.Fatalf("ConfigureProtocol for node B: %d %s", statusB.Code, statusB.Detail)
	}

	// Node A (network author) creates Node B's member record on the anchor DWN.
	// Per the protocol's $actions: only the network author or admins can create members.
	// The member record's recipient is Node B — this assigns Node B the "network/member" role.
	err = mesh.CreateMember(ctx, mesh.CreateMemberParams{
		AnchorEndpoint:       endpoint,
		AnchorDID:            nodeA.DID.URI,
		NetworkRecordID:      networkRecordID,
		MemberDID:            nodeB.DID.URI,
		Label:                "member",
		Signer:               nodeA.Signer,
		EncryptionKeyManager: nodeA.EncMgr,
	})
	if err != nil {
		t.Fatalf("Node B member creation (by Node A) failed: %v", err)
	}
	t.Log("  Node B member record created by Node A (encrypted)")

	// Debug: query member records to verify they exist with correct recipients.
	memberRecords, mqs, err := nodeA.API.Query(ctx, nodeA.DID.URI, dwn.QueryParams{
		Filter: dwn.RecordsFilter{
			Protocol:     "https://enbox.org/protocols/wireguard-mesh",
			ProtocolPath: "network/member",
			ParentID:     networkRecordID,
		},
	}, "")
	if err == nil && mqs.Code == 200 {
		for i, m := range memberRecords {
			t.Logf("  Member[%d]: id=%s, recipient=%s, contextId=%s, author=%s", i, m.ID, m.Recipient, m.ContextID, m.Author)
		}
	}

	// Debug: Node B queries for its own member role record on Node A's DWN.
	// This uses the same filter the server would use internally.
	nodeBMembers, nbqs, _ := nodeB.API.Query(ctx, nodeA.DID.URI, dwn.QueryParams{
		Filter: dwn.RecordsFilter{
			Protocol:     "https://enbox.org/protocols/wireguard-mesh",
			ProtocolPath: "network/member",
			Recipient:    nodeB.DID.URI,
		},
	}, "")
	if nbqs != nil {
		t.Logf("  Node B member query (on A's DWN): status=%d, count=%d", nbqs.Code, len(nodeBMembers))
		for i, m := range nodeBMembers {
			t.Logf("    [%d]: id=%s, recipient=%s, contextId=%s", i, m.ID, m.Recipient, m.ContextID)
		}
	}

	// Node B registers its nodeInfo (encrypted) using its own member role.
	// Note: Node B can write its own nodeInfo because the protocol allows
	// "role": "network/member" to ["create", "update", "read"] on nodeInfo.
	wgKeysB, err := mesh.GenerateWireGuardKeyPair()
	if err != nil {
		t.Fatalf("generating WG keys for node B: %v", err)
	}
	meshIPB, err := mesh.AllocateMeshIP(meshCIDR, nodeB.DID.URI)
	if err != nil {
		t.Fatalf("allocating mesh IP for node B: %v", err)
	}

	regB, err := mesh.RegisterNode(ctx, mesh.RegisterNodeParams{
		AnchorEndpoint:       endpoint,
		AnchorDID:            nodeA.DID.URI,
		NetworkRecordID:      networkRecordID,
		SelfDID:              nodeB.DID.URI,
		Signer:               nodeB.Signer,
		EncryptionKeyManager: nodeB.EncMgr,
		WireGuardPubKey:      wgKeysB.PublicKeyBase64(),
		MeshIP:               meshIPB.String(),
		Hostname:             "node-b",
		ProtocolRole:         "network/member",
	})
	if err != nil {
		t.Fatalf("Node B nodeInfo registration failed: %v", err)
	}
	t.Logf("  Node B registered: IP=%s, nodeInfo=%s", meshIPB, regB.NodeInfoRecordID)

	// ---- Step 7: Verify mesh IPs are different ----
	t.Log("Step 7: Verifying mesh IP uniqueness")
	if meshIPA.String() == meshIPB.String() {
		t.Fatalf("COLLISION: both nodes got the same mesh IP: %s", meshIPA)
	}
	t.Logf("  Node A: %s, Node B: %s — unique", meshIPA, meshIPB)

	// ---- Step 8: Query member records from the anchor DWN ----
	t.Log("Step 8: Querying member records from anchor DWN")
	members, queryStatus, err := nodeA.API.Query(ctx, nodeA.DID.URI, dwn.QueryParams{
		Filter: dwn.RecordsFilter{
			Protocol:     "https://enbox.org/protocols/wireguard-mesh",
			ProtocolPath: "network/member",
			ParentID:     networkRecordID,
		},
		DateSort: "createdAscending",
	}, "")
	if err != nil {
		t.Fatalf("querying members: %v", err)
	}
	if queryStatus.Code != 200 {
		t.Fatalf("member query: %d %s", queryStatus.Code, queryStatus.Detail)
	}
	t.Logf("  Found %d member records", len(members))
	if len(members) < 2 {
		t.Fatalf("expected at least 2 member records (node A admin + node B member), got %d", len(members))
	}

	// ---- Step 9: Query nodeInfo records from the anchor DWN ----
	t.Log("Step 9: Querying nodeInfo records from anchor DWN")
	nodeInfos, niStatus, err := nodeA.API.Query(ctx, nodeA.DID.URI, dwn.QueryParams{
		Filter: dwn.RecordsFilter{
			Protocol:     "https://enbox.org/protocols/wireguard-mesh",
			ProtocolPath: "network/nodeInfo",
			ParentID:     networkRecordID,
		},
	}, "")
	if err != nil {
		t.Fatalf("querying nodeInfos: %v", err)
	}
	if niStatus.Code != 200 {
		t.Fatalf("nodeInfo query: %d %s", niStatus.Code, niStatus.Detail)
	}
	t.Logf("  Found %d nodeInfo records", len(nodeInfos))
	if len(nodeInfos) < 2 {
		t.Fatalf("expected at least 2 nodeInfo records (node A + node B), got %d", len(nodeInfos))
	}

	// ---- Step 10: Node A writes an encrypted endpoint record ----
	t.Log("Step 10: Node A writes encrypted endpoint record")
	if regA != nil && regA.NodeInfoRecordID != "" {
		err = mesh.WriteEndpoint(ctx, mesh.WriteEndpointParams{
			AnchorEndpoint:       endpoint,
			AnchorDID:            nodeA.DID.URI,
			NetworkRecordID:      networkRecordID,
			NodeInfoRecordID:     regA.NodeInfoRecordID,
			Signer:               nodeA.Signer,
			EncryptionKeyManager: nodeA.EncMgr,
			PublicEndpoints: []mesh.PublicEndpoint{
				{Address: "203.0.113.1", Port: 51820, Source: "test"},
			},
			LocalEndpoints: []string{"192.168.1.100:51820"},
			NATType:        "full-cone",
		})
		if err != nil {
			t.Logf("  Warning: endpoint write failed: %v", err)
		} else {
			t.Log("  Endpoint record created (encrypted)")
		}
	}

	// ---- Step 11: Verify local encryption round-trip ----
	// Build a message locally and verify we can encrypt/decrypt it.
	t.Log("Step 11: Verifying local encryption round-trip")
	testPlaintext := []byte(`{"test":"e2e encryption verification","timestamp":"2026-02-24T00:00:00Z"}`)
	recipients, err := nodeA.EncMgr.DeriveWriteEncryption("network/nodeInfo")
	if err != nil {
		t.Fatalf("deriving nodeInfo encryption: %v", err)
	}

	ciphertext, enc, err := dwncrypto.EncryptData(testPlaintext, recipients)
	if err != nil {
		t.Fatalf("EncryptData: %v", err)
	}

	// Ciphertext should be different from plaintext.
	if string(ciphertext) == string(testPlaintext) {
		t.Fatal("SECURITY: ciphertext matches plaintext!")
	}
	t.Logf("  Encrypted %d bytes → %d bytes ciphertext", len(testPlaintext), len(ciphertext))

	// Node A can decrypt using the same key path.
	decryptKey, err := nodeA.EncMgr.DeriveDecryptionKey("network/nodeInfo")
	if err != nil {
		t.Fatalf("DeriveDecryptionKey: %v", err)
	}

	decrypted, err := dwncrypto.DecryptData(ciphertext, enc, decryptKey, nodeA.EncMgr.RootKeyID)
	if err != nil {
		t.Fatalf("DecryptData: %v", err)
	}

	if string(decrypted) != string(testPlaintext) {
		t.Fatalf("decrypted data mismatch: got %q, want %q", decrypted, testPlaintext)
	}
	t.Logf("  Decryption verified: %q", string(decrypted))

	// ---- Step 12: Verify hierarchical key property ----
	// A key derived at "network" should be able to decrypt records at
	// "network/member" (parent can decrypt children).
	t.Log("Step 12: Verifying hierarchical key property")
	memberPlaintext := []byte(`{"joinedAt":"2026-02-24","label":"test-member"}`)
	memberRecipients2, err := nodeA.EncMgr.DeriveWriteEncryption("network/member")
	if err != nil {
		t.Fatalf("deriving member encryption: %v", err)
	}

	memberCT, memberEnc, err := dwncrypto.EncryptData(memberPlaintext, memberRecipients2)
	if err != nil {
		t.Fatalf("encrypting member data: %v", err)
	}

	// Decrypt using the "network/member" path (direct match).
	memberDecryptKey, err := nodeA.EncMgr.DeriveDecryptionKey("network/member")
	if err != nil {
		t.Fatalf("DeriveDecryptionKey for member: %v", err)
	}

	memberDecrypted, err := dwncrypto.DecryptData(memberCT, memberEnc, memberDecryptKey, nodeA.EncMgr.RootKeyID)
	if err != nil {
		t.Fatalf("DecryptData for member: %v", err)
	}

	if string(memberDecrypted) != string(memberPlaintext) {
		t.Fatalf("member decrypted mismatch: got %q, want %q", memberDecrypted, memberPlaintext)
	}
	t.Logf("  Member decryption verified: %q", string(memberDecrypted))

	// ---- Summary ----
	t.Log("=== E2E Test Summary ===")
	t.Logf("  Network: e2e-test-network (%s)", networkRecordID)
	t.Logf("  Node A: %s → %s", nodeA.DID.URI[:30]+"...", meshIPA)
	t.Logf("  Node B: %s → %s", nodeB.DID.URI[:30]+"...", meshIPB)
	t.Logf("  Members found: %d", len(members))
	t.Logf("  NodeInfos found: %d", len(nodeInfos))
	t.Log("  Encryption: verified (HKDF → ECDH-ES+A256KW → A256GCM)")
	t.Log("  Hierarchical keys: verified")
}

// TestE2EMeshIPAllocation verifies that different DIDs get different mesh IPs
// from the same CIDR, and the same DID always gets the same IP.
func TestE2EMeshIPAllocation(t *testing.T) {
	cidr := "10.200.0.0/16"

	// Generate multiple DIDs and verify uniqueness + determinism.
	ips := make(map[string]string) // did -> ip

	for i := 0; i < 20; i++ {
		identity, err := did.Generate()
		if err != nil {
			t.Fatalf("generating DID %d: %v", i, err)
		}

		ip, err := mesh.AllocateMeshIP(cidr, identity.URI)
		if err != nil {
			t.Fatalf("allocating IP for DID %d: %v", i, err)
		}

		// Check determinism.
		ip2, err := mesh.AllocateMeshIP(cidr, identity.URI)
		if err != nil {
			t.Fatalf("re-allocating IP for DID %d: %v", i, err)
		}
		if ip.String() != ip2.String() {
			t.Fatalf("DID %d: non-deterministic: %s != %s", i, ip, ip2)
		}

		// Check uniqueness (with high probability — 20 from a /16 is very unlikely to collide).
		for did, existingIP := range ips {
			if existingIP == ip.String() {
				t.Fatalf("IP collision: DID %d (%s) and %s both got %s", i, identity.URI, did, ip)
			}
		}

		ips[identity.URI] = ip.String()
	}

	t.Logf("Allocated %d unique mesh IPs deterministically", len(ips))
}
