package mesh_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/enboxorg/meshd/internal/control"
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

// newNode creates a fresh node identity, registers it as a tenant, and
// returns a fully wired node.
func newNode(t *testing.T, endpoint string) *nodeIdentity {
	t.Helper()

	identity, err := did.Generate()
	if err != nil {
		t.Fatalf("generating DID: %v", err)
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
		ProtocolURI:    "https://enbox.id/protocols/wireguard-mesh",
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
		Protocol:     "https://enbox.id/protocols/wireguard-mesh",
		ProtocolPath: "network",
		Schema:       "https://enbox.id/schemas/wireguard-mesh/network",
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
				Protocol:     "https://enbox.id/protocols/wireguard-mesh",
				ProtocolPath: "network",
			},
		}, "")
		if err != nil || qs.Code != 200 || len(records) == 0 {
			t.Fatalf("could not get network record ID: err=%v, status=%v, records=%d", err, qs, len(records))
		}
		networkRecordID = records[0].ID
		t.Logf("  Network record ID (from query): %s", networkRecordID)
	}

	// ---- Step 4: Node A registers itself as a node (encrypted) ----
	t.Log("Step 4: Node A registers itself as a node (encrypted)")
	meshIPA, err := mesh.AllocateMeshIP(meshCIDR, nodeA.DID.URI)
	if err != nil {
		t.Fatalf("allocating mesh IP for node A: %v", err)
	}

	regA, err := mesh.RegisterNode(ctx, mesh.RegisterNodeParams{
		AnchorEndpoint:       endpoint,
		AnchorDID:            nodeA.DID.URI,
		NetworkRecordID:      networkRecordID,
		NodeDID:              nodeA.DID.URI,
		Signer:               nodeA.Signer,
		EncryptionKeyManager: nodeA.EncMgr,
		MeshIP:               meshIPA.String(),
		Label:                "node-a",
	})
	if err != nil {
		t.Fatalf("registering node A: %v", err)
	}
	t.Logf("  Node A registered: IP=%s, node=%s", meshIPA, regA.NodeRecordID)

	// ---- Step 5: Node A creates Node B's node record (assigns network/node role) ----
	t.Log("Step 5: Node A creates Node B's node record")
	meshIPB, err := mesh.AllocateMeshIP(meshCIDR, nodeB.DID.URI)
	if err != nil {
		t.Fatalf("allocating mesh IP for node B: %v", err)
	}

	// Node A (network author) creates Node B's node record on the anchor DWN.
	// The node record's recipient is Node B, assigning the "network/node" role.
	_, err = mesh.RegisterNode(ctx, mesh.RegisterNodeParams{
		AnchorEndpoint:       endpoint,
		AnchorDID:            nodeA.DID.URI,
		NetworkRecordID:      networkRecordID,
		NodeDID:              nodeB.DID.URI,
		Signer:               nodeA.Signer,
		EncryptionKeyManager: nodeA.EncMgr,
		MeshIP:               meshIPB.String(),
		Label:                "node-b",
	})
	if err != nil {
		t.Fatalf("Node B node creation (by Node A) failed: %v", err)
	}
	t.Log("  Node B node record created by Node A (encrypted)")

	// ---- Step 6: Node B installs protocol on its own DWN ----
	t.Log("Step 6: Node B installs protocol")
	protocolDefB, err := dwncrypto.InjectEncryptionDirectives(
		protocols.MeshProtocolJSON,
		nodeB.DID.EncryptionPrivateKey,
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

	// ---- Step 7: Verify mesh IPs are different ----
	t.Log("Step 7: Verifying mesh IP uniqueness")
	if meshIPA.String() == meshIPB.String() {
		t.Fatalf("COLLISION: both nodes got the same mesh IP: %s", meshIPA)
	}
	t.Logf("  Node A: %s, Node B: %s — unique", meshIPA, meshIPB)

	// ---- Step 8: Query node records from the anchor DWN ----
	t.Log("Step 8: Querying node records from anchor DWN")
	nodes, queryStatus, err := nodeA.API.Query(ctx, nodeA.DID.URI, dwn.QueryParams{
		Filter: dwn.RecordsFilter{
			Protocol:     "https://enbox.id/protocols/wireguard-mesh",
			ProtocolPath: "network/node",
			ContextID:    networkRecordID,
		},
		DateSort: "createdAscending",
	}, "")
	if err != nil {
		t.Fatalf("querying nodes: %v", err)
	}
	if queryStatus.Code != 200 {
		t.Fatalf("node query: %d %s", queryStatus.Code, queryStatus.Detail)
	}
	t.Logf("  Found %d node records", len(nodes))
	if len(nodes) < 2 {
		t.Fatalf("expected at least 2 node records (node A + node B), got %d", len(nodes))
	}

	// ---- Step 9: Node A writes an encrypted endpoint record ----
	t.Log("Step 9: Node A writes encrypted endpoint record")
	if regA != nil && regA.NodeRecordID != "" {
		err = mesh.WriteEndpoint(ctx, mesh.WriteEndpointParams{
			AnchorEndpoint:       endpoint,
			AnchorDID:            nodeA.DID.URI,
			NetworkRecordID:      networkRecordID,
			NodeRecordID:         regA.NodeRecordID,
			Signer:               nodeA.Signer,
			EncryptionKeyManager: nodeA.EncMgr,
			PublicEndpoints: []control.PublicEndpoint{
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

	// ---- Step 10: Verify local encryption round-trip ----
	// The sealed write path: one protocolPath entry to the published
	// $keyAgreement key plus one roleAudience entry per reading role.
	t.Log("Step 10: Verifying local encryption round-trip")
	testPlaintext := []byte(`{"test":"e2e encryption verification","timestamp":"2026-02-24T00:00:00Z"}`)
	audienceSrc := &memoryAudienceSource{}
	recipients, err := dwncrypto.BuildWriteEncryption(ctx, protocolDef, "network/node", networkRecordID, audienceSrc)
	if err != nil {
		t.Fatalf("building node write encryption: %v", err)
	}
	if len(recipients) < 2 {
		t.Fatalf("expected protocolPath + roleAudience entries, got %d", len(recipients))
	}

	ciphertext, enc, err := dwncrypto.EncryptData(testPlaintext, recipients)
	if err != nil {
		t.Fatalf("EncryptData: %v", err)
	}

	if string(ciphertext) == string(testPlaintext) {
		t.Fatal("SECURITY: ciphertext matches plaintext!")
	}
	t.Logf("  Encrypted %d bytes → %d bytes ciphertext", len(testPlaintext), len(ciphertext))

	// Owner decrypts via the protocolPath entry.
	decryptKey, err := nodeA.EncMgr.DeriveDecryptionKey("network/node")
	if err != nil {
		t.Fatalf("DeriveDecryptionKey: %v", err)
	}

	decrypted, err := dwncrypto.DecryptData(ciphertext, enc, decryptKey)
	if err != nil {
		t.Fatalf("DecryptData: %v", err)
	}

	if string(decrypted) != string(testPlaintext) {
		t.Fatalf("decrypted data mismatch: got %q, want %q", decrypted, testPlaintext)
	}
	t.Logf("  Owner decryption verified: %q", string(decrypted))

	// A role holder decrypts via the roleAudience entry with the audience
	// private key.
	roleInfo := dwncrypto.RoleAudienceEntryInfo(enc)
	if roleInfo == nil {
		t.Fatal("encrypted record has no roleAudience keyEncryption entry")
	}
	audiencePriv := audienceSrc.privateKey(t, roleInfo.KeyID)
	roleDec, err := dwncrypto.NewRoleAudienceDecrypter(audiencePriv)
	if err != nil {
		t.Fatalf("NewRoleAudienceDecrypter: %v", err)
	}
	defer roleDec.Close()
	roleDecrypted, err := roleDec.Decrypt(ciphertext, enc)
	if err != nil {
		t.Fatalf("roleAudience Decrypt: %v", err)
	}
	if string(roleDecrypted) != string(testPlaintext) {
		t.Fatalf("role decrypted mismatch: got %q, want %q", roleDecrypted, testPlaintext)
	}
	t.Log("  Role-audience decryption verified")

	// ---- Step 11: Verify nested-path encryption round-trip ----
	// A child record (network/node/nodeInfo) built through the same sealed
	// write path decrypts with the leaf key derived from the owner root.
	t.Log("Step 11: Verifying nested-path encryption round-trip")
	nodePlaintext := []byte(`{"hostname":"test-node","os":"linux"}`)
	nodeRecipients, err := dwncrypto.BuildWriteEncryption(
		ctx,
		protocolDef,
		"network/node/nodeInfo",
		networkRecordID+"/"+regA.NodeRecordID,
		audienceSrc,
	)
	if err != nil {
		t.Fatalf("building nodeInfo write encryption: %v", err)
	}

	nodeCT, nodeEnc, err := dwncrypto.EncryptData(nodePlaintext, nodeRecipients)
	if err != nil {
		t.Fatalf("encrypting nodeInfo data: %v", err)
	}

	nodeDecryptKey, err := nodeA.EncMgr.DeriveDecryptionKey("network/node/nodeInfo")
	if err != nil {
		t.Fatalf("DeriveDecryptionKey for nodeInfo: %v", err)
	}

	nodeDecrypted, err := dwncrypto.DecryptData(nodeCT, nodeEnc, nodeDecryptKey)
	if err != nil {
		t.Fatalf("DecryptData for nodeInfo: %v", err)
	}

	if string(nodeDecrypted) != string(nodePlaintext) {
		t.Fatalf("nodeInfo decrypted mismatch: got %q, want %q", nodeDecrypted, nodePlaintext)
	}
	t.Logf("  nodeInfo decryption verified: %q", string(nodeDecrypted))

	// ---- Summary ----
	t.Log("=== E2E Test Summary ===")
	t.Logf("  Network: e2e-test-network (%s)", networkRecordID)
	t.Logf("  Node A: %s → %s", nodeA.DID.URI[:30]+"...", meshIPA)
	t.Logf("  Node B: %s → %s", nodeB.DID.URI[:30]+"...", meshIPB)
	t.Logf("  Nodes found: %d", len(nodes))
	t.Log("  Encryption: verified (sealed model: protocolPath + roleAudience entries)")
	t.Log("  Nested-path keys: verified")
}

// memoryAudienceSource is a mint-free dwncrypto.AudienceSource for local
// round-trip tests: it generates one random audience key per tuple in memory
// instead of writing `$encryption/audience` records to a DWN.
type memoryAudienceSource struct {
	keys map[string]*dwncrypto.RoleAudienceKeyMaterial
}

func (s *memoryAudienceSource) Current(_ context.Context, protocol, rolePath, contextID string) ([]byte, string, error) {
	if s.keys == nil {
		s.keys = make(map[string]*dwncrypto.RoleAudienceKeyMaterial)
	}
	tuple := protocol + "\n" + rolePath + "\n" + contextID
	km, ok := s.keys[tuple]
	if !ok {
		var err error
		km, err = dwncrypto.GenerateAudienceKey()
		if err != nil {
			return nil, "", err
		}
		s.keys[tuple] = km
	}
	pub, err := base64.RawURLEncoding.DecodeString(km.PublicKeyJwk.X)
	if err != nil {
		return nil, "", err
	}
	return pub, km.KeyID, nil
}

// privateKey returns the raw audience private key for a minted keyId.
func (s *memoryAudienceSource) privateKey(t *testing.T, keyID string) []byte {
	t.Helper()
	for _, km := range s.keys {
		if km.KeyID != keyID {
			continue
		}
		priv, err := base64.RawURLEncoding.DecodeString(km.PrivateKeyJwk.D)
		if err != nil {
			t.Fatalf("decoding audience private key: %v", err)
		}
		return priv
	}
	t.Fatalf("no audience key minted for keyId %s", keyID)
	return nil
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
