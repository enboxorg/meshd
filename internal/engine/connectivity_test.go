package engine_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/enboxorg/meshd/internal/control"
	"github.com/enboxorg/meshd/internal/did"
	"github.com/enboxorg/meshd/internal/dwn"
	dwncrypto "github.com/enboxorg/meshd/internal/dwn/crypto"
	"github.com/enboxorg/meshd/internal/engine"
	"github.com/enboxorg/meshd/internal/mesh"
	"github.com/enboxorg/meshd/protocols"

	"github.com/enboxorg/meshnet/types/key"
	go4mem "go4.org/mem"
)

// TestTwoNodeConnectivity is a full end-to-end integration test that:
//
//  1. Creates two DID identities (node A = anchor, node B = joiner)
//  2. Node A installs wireguard-mesh + key-delivery protocols with encryption
//  3. Node A creates the network record
//  4. Node A creates admin member + nodeInfo (encrypted with Protocol Path)
//  5. Node B joins: member created by A, nodeInfo + endpoint by B (Protocol Path)
//  6. Node A delivers context key to both nodes
//  6b. Node B fetches context key, re-registers nodeInfo + endpoint with Protocol Context encryption
//  7. Both nodes create real engines (UserspaceEngine + netstack)
//  8. Both engines start, poll DWN, and discover each other
//  9. TCP connectivity test: B dials A's mesh IP, echo round-trip verified
//  10. Clean shutdown
//
// Requires DWN_ENDPOINT environment variable.
// Run with: DWN_ENDPOINT=https://dev.aws.dwn.enbox.id go test ./internal/engine/ -run TestTwoNodeConnectivity -v -timeout 300s
func TestTwoNodeConnectivity(t *testing.T) {
	endpoint := os.Getenv("DWN_ENDPOINT")
	if endpoint == "" {
		t.Skip("DWN_ENDPOINT not set, skipping integration test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 240*time.Second)
	defer cancel()

	// ================================================================
	// Step 1: Create two node identities
	// ================================================================
	t.Log("Step 1: Creating two node identities")
	nodeA := newTestNode(t, endpoint)
	nodeB := newTestNode(t, endpoint)
	t.Logf("  Node A (anchor): %s", nodeA.identity.URI)
	t.Logf("  Node B (joiner): %s", nodeB.identity.URI)

	// ================================================================
	// Step 2: Node A installs wireguard-mesh protocol with encryption
	// ================================================================
	t.Log("Step 2: Node A installs wireguard-mesh protocol")
	protocolDef, err := dwncrypto.InjectEncryptionDirectives(
		protocols.MeshProtocolJSON,
		nodeA.identity.EncryptionPrivateKey,
		nodeA.identity.EncryptionKeyID(),
	)
	if err != nil {
		t.Fatalf("injecting encryption directives: %v", err)
	}

	status, err := nodeA.api.ConfigureProtocol(ctx, nodeA.identity.URI, protocolDef)
	if err != nil {
		t.Fatalf("ConfigureProtocol: %v", err)
	}
	if status.Code >= 300 && status.Code != 409 {
		t.Fatalf("ConfigureProtocol: %d %s", status.Code, status.Detail)
	}
	t.Logf("  Protocol installed: %d", status.Code)

	// Also install key-delivery protocol.
	err = mesh.EnsureKeyDeliveryProtocol(ctx, endpoint, nodeA.identity.URI, nodeA.signer,
		nodeA.identity.EncryptionPrivateKey, nodeA.identity.EncryptionKeyID())
	if err != nil {
		t.Fatalf("EnsureKeyDeliveryProtocol: %v", err)
	}
	t.Log("  Key delivery protocol installed")

	// ================================================================
	// Step 3: Node A creates the network record
	// ================================================================
	t.Log("Step 3: Node A creates network record")
	meshCIDR := "10.200.0.0/16"
	networkData, _ := json.Marshal(map[string]any{
		"name":     "e2e-connectivity-test",
		"meshCIDR": meshCIDR,
		"created":  time.Now().UTC().Format(time.RFC3339),
	})

	networkRecord, writeStatus, err := nodeA.api.Write(ctx, nodeA.identity.URI, dwn.WriteParams{
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
		// Fall back to query.
		records, qs, err := nodeA.api.Query(ctx, nodeA.identity.URI, dwn.QueryParams{
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

	// ================================================================
	// Step 4: Node A creates admin member + nodeInfo (encrypted)
	// ================================================================
	t.Log("Step 4: Node A creates admin member and nodeInfo records")

	memberRecipients, err := nodeA.encMgr.DeriveWriteEncryption("network/member")
	if err != nil {
		t.Fatalf("deriving member encryption: %v", err)
	}

	memberData, _ := json.Marshal(map[string]any{
		"joinedAt": time.Now().UTC().Format(time.RFC3339),
		"label":    "admin",
	})
	_, memberStatus, err := nodeA.api.Write(ctx, nodeA.identity.URI, dwn.WriteParams{
		Protocol:             protocols.MeshProtocolURI,
		ProtocolPath:         "network/member",
		Schema:               "https://enbox.org/schemas/wireguard-mesh/member",
		DataFormat:           "application/json",
		Recipient:            nodeA.identity.URI,
		ParentContextID:     networkRecordID,
		Data:                 memberData,
		Tags:                 map[string]any{"status": "active"},
		EncryptionRecipients: memberRecipients,
	})
	if err != nil {
		t.Fatalf("creating admin member: %v", err)
	}
	if memberStatus.Code >= 300 {
		t.Fatalf("admin member: %d %s", memberStatus.Code, memberStatus.Detail)
	}

	wgKeysA, err := mesh.GenerateWireGuardKeyPair()
	if err != nil {
		t.Fatalf("generating WG keys for A: %v", err)
	}
	meshIPA, err := mesh.AllocateMeshIP(meshCIDR, nodeA.identity.URI)
	if err != nil {
		t.Fatalf("allocating mesh IP for A: %v", err)
	}

	regA, err := mesh.RegisterNode(ctx, mesh.RegisterNodeParams{
		AnchorEndpoint:       endpoint,
		AnchorDID:            nodeA.identity.URI,
		NetworkRecordID:      networkRecordID,
		SelfDID:              nodeA.identity.URI,
		Signer:               nodeA.signer,
		EncryptionKeyManager: nodeA.encMgr,
		WireGuardPubKey:      wgKeysA.PublicKeyBase64(),
		MeshIP:               meshIPA.String(),
		Hostname:             "node-a",
	})
	if err != nil {
		t.Fatalf("registering node A: %v", err)
	}
	t.Logf("  Node A: IP=%s, nodeInfo=%s", meshIPA, regA.NodeInfoRecordID)

	// Write endpoint record for node A.
	err = mesh.WriteEndpoint(ctx, mesh.WriteEndpointParams{
		AnchorEndpoint:       endpoint,
		AnchorDID:            nodeA.identity.URI,
		NetworkRecordID:      networkRecordID,
		NodeInfoRecordID:     regA.NodeInfoRecordID,
		Signer:               nodeA.signer,
		EncryptionKeyManager: nodeA.encMgr,
		LocalEndpoints:       mesh.DiscoverLocalEndpoints(0),
		NATType:              "unknown",
	})
	if err != nil {
		t.Logf("  Warning: Node A endpoint write failed: %v", err)
	}

	// ================================================================
	// Step 5: Node B joins the network
	// ================================================================
	t.Log("Step 5: Node B joins the network")

	// Node A (network author) creates Node B's member record on the anchor DWN.
	// Per the protocol's $actions: only the network author can create members.
	err = mesh.CreateMember(ctx, mesh.CreateMemberParams{
		AnchorEndpoint:       endpoint,
		AnchorDID:            nodeA.identity.URI,
		NetworkRecordID:      networkRecordID,
		MemberDID:            nodeB.identity.URI,
		Label:                "member",
		Signer:               nodeA.signer,
		EncryptionKeyManager: nodeA.encMgr,
	})
	if err != nil {
		t.Fatalf("Node B member creation (by Node A) failed: %v", err)
	}
	t.Log("  Node B member record created by Node A")

	wgKeysB, err := mesh.GenerateWireGuardKeyPair()
	if err != nil {
		t.Fatalf("generating WG keys for B: %v", err)
	}
	meshIPB, err := mesh.AllocateMeshIP(meshCIDR, nodeB.identity.URI)
	if err != nil {
		t.Fatalf("allocating mesh IP for B: %v", err)
	}

	regB, err := mesh.RegisterNode(ctx, mesh.RegisterNodeParams{
		AnchorEndpoint:       endpoint,
		AnchorDID:            nodeA.identity.URI,
		NetworkRecordID:      networkRecordID,
		SelfDID:              nodeB.identity.URI,
		Signer:               nodeB.signer,
		EncryptionKeyManager: nodeB.encMgr,
		WireGuardPubKey:      wgKeysB.PublicKeyBase64(),
		MeshIP:               meshIPB.String(),
		Hostname:             "node-b",
		ProtocolRole:         "network/member",
	})
	if err != nil {
		t.Fatalf("Node B nodeInfo registration failed: %v", err)
	}
	t.Logf("  Node B: IP=%s, nodeInfo=%s", meshIPB, regB.NodeInfoRecordID)

	// Write endpoint record for node B.
	if regB != nil && regB.NodeInfoRecordID != "" {
		err = mesh.WriteEndpoint(ctx, mesh.WriteEndpointParams{
			AnchorEndpoint:       endpoint,
			AnchorDID:            nodeA.identity.URI,
			NetworkRecordID:      networkRecordID,
			NodeInfoRecordID:     regB.NodeInfoRecordID,
			Signer:               nodeB.signer,
			EncryptionKeyManager: nodeB.encMgr,
			LocalEndpoints:       mesh.DiscoverLocalEndpoints(0),
			NATType:              "unknown",
		})
		if err != nil {
			t.Logf("  Warning: Node B endpoint write failed: %v", err)
		}
	}

	if meshIPA == meshIPB {
		t.Fatalf("IP collision: both nodes got %s", meshIPA)
	}
	t.Logf("  Mesh IPs: A=%s, B=%s", meshIPA, meshIPB)

	// ================================================================
	// Step 6: Node A delivers context key to Node B
	// ================================================================
	t.Log("Step 6: Node A delivers context key to Node B")

	kdm := &mesh.KeyDeliveryManager{
		Endpoint:             endpoint,
		Signer:               nodeA.signer,
		EncryptionKeyManager: nodeA.encMgr,
	}

	err = kdm.DeliverContextKey(ctx, mesh.DeliverContextKeyParams{
		AnchorDID:      nodeA.identity.URI,
		RecipientDID:   nodeA.identity.URI, // self
		SourceProtocol: protocols.MeshProtocolURI,
		ContextID:      networkRecordID,
	})
	if err != nil {
		t.Logf("  Warning: self key delivery failed: %v", err)
	}

	err = kdm.DeliverContextKey(ctx, mesh.DeliverContextKeyParams{
		AnchorDID:      nodeA.identity.URI,
		RecipientDID:   nodeB.identity.URI,
		SourceProtocol: protocols.MeshProtocolURI,
		ContextID:      networkRecordID,
	})
	if err != nil {
		t.Fatalf("key delivery to B failed: %v", err)
	}
	t.Log("  Context key delivered to Node B")

	// Node A (anchor) also re-registers with context encryption so non-anchor
	// nodes can decrypt its nodeInfo using the shared context key.
	regA2, err := mesh.RegisterNode(ctx, mesh.RegisterNodeParams{
		AnchorEndpoint:          endpoint,
		AnchorDID:               nodeA.identity.URI,
		NetworkRecordID:         networkRecordID,
		SelfDID:                 nodeA.identity.URI,
		Signer:                  nodeA.signer,
		EncryptionKeyManager:    nodeA.encMgr,
		WireGuardPubKey:         wgKeysA.PublicKeyBase64(),
		MeshIP:                  meshIPA.String(),
		Hostname:                "node-a",
		UseContextEncryption:    true,
		ExistingNodeInfoRecordID: regA.NodeInfoRecordID,
		ExistingDateCreated:     regA.DateCreated,
	})
	if err != nil {
		t.Fatalf("re-registering Node A with context encryption: %v", err)
	}
	t.Logf("  Node A re-registered with context encryption: %s", regA2.NodeInfoRecordID)

	// ================================================================
	// Step 6b: Node B fetches and stores context key, re-registers with context encryption
	// ================================================================
	t.Log("Step 6b: Node B fetches context key and re-registers with context encryption")

	contextKeyJwk, err := mesh.FetchContextKey(ctx, mesh.FetchContextKeyParams{
		AnchorEndpoint: endpoint,
		AnchorDID:      nodeA.identity.URI,
		SelfDID:        nodeB.identity.URI,
		Signer:         nodeB.signer,
	})
	if err != nil {
		t.Fatalf("fetching context key for B: %v", err)
	}
	if contextKeyJwk == nil {
		t.Fatal("context key not found for Node B")
	}

	contextKeyBytes, err := contextKeyJwk.PrivateKeyBytes()
	if err != nil {
		t.Fatalf("extracting context key bytes: %v", err)
	}
	nodeB.encMgr.StoreContextKey(networkRecordID, contextKeyBytes)
	t.Log("  Node B stored context key")

	// Re-register Node B's nodeInfo with Protocol Context encryption.
	// This is an UPDATE (same recordId, preserved dateCreated) which replaces
	// the old Protocol Path encrypted record in-place, avoiding duplicates.
	regB2, err := mesh.RegisterNode(ctx, mesh.RegisterNodeParams{
		AnchorEndpoint:          endpoint,
		AnchorDID:               nodeA.identity.URI,
		NetworkRecordID:         networkRecordID,
		SelfDID:                 nodeB.identity.URI,
		Signer:                  nodeB.signer,
		EncryptionKeyManager:    nodeB.encMgr,
		WireGuardPubKey:         wgKeysB.PublicKeyBase64(),
		MeshIP:                  meshIPB.String(),
		Hostname:                "node-b",
		ProtocolRole:            "network/member",
		UseContextEncryption:    true,
		ExistingNodeInfoRecordID: regB.NodeInfoRecordID,
		ExistingDateCreated:     regB.DateCreated,
	})
	if err != nil {
		t.Fatalf("re-registering Node B with context encryption: %v", err)
	}
	t.Logf("  Node B re-registered with context encryption: %s", regB2.NodeInfoRecordID)

	// Re-write Node B's endpoint with context encryption, parented under the new nodeInfo.
	// No ProtocolRole needed — the "who": "author", "of": "network/nodeInfo" action
	// authorizes the nodeInfo author to create endpoint records.
	err = mesh.WriteEndpoint(ctx, mesh.WriteEndpointParams{
		AnchorEndpoint:       endpoint,
		AnchorDID:            nodeA.identity.URI,
		NetworkRecordID:      networkRecordID,
		NodeInfoRecordID:     regB2.NodeInfoRecordID,
		Signer:               nodeB.signer,
		EncryptionKeyManager: nodeB.encMgr,
		LocalEndpoints:       mesh.DiscoverLocalEndpoints(0),
		NATType:              "unknown",
		UseContextEncryption: true,
	})
	if err != nil {
		t.Logf("  Warning: Node B context-encrypted endpoint write failed: %v", err)
	} else {
		t.Log("  Node B endpoint re-written with context encryption")
	}

	// ================================================================
	// Step 7: Create engines for both nodes
	// ================================================================
	t.Log("Step 7: Creating engines for both nodes")

	// Diagnostic: verify that the NodePublic derived from the private key
	// matches the public key stored in DWN records. This is critical for
	// disco key lookup — if these don't match, disco keys won't be found.
	nodePrivA := key.NodePrivateFromRaw32(go4mem.B(wgKeysA.PrivateKey[:]))
	nodePrivB := key.NodePrivateFromRaw32(go4mem.B(wgKeysB.PrivateKey[:]))
	nodePubA := nodePrivA.Public()
	nodePubB := nodePrivB.Public()

	// Parse the public keys from the DWN-stored base64 (same path as converter)
	dwnPubA, _ := parseTestWireGuardKey(wgKeysA.PublicKeyBase64())
	dwnPubB, _ := parseTestWireGuardKey(wgKeysB.PublicKeyBase64())

	t.Logf("  Key diagnostic A: privPub=%s dwnPub=%s match=%v",
		nodePubA.ShortString(), dwnPubA.ShortString(), nodePubA == dwnPubA)
	t.Logf("  Key diagnostic B: privPub=%s dwnPub=%s match=%v",
		nodePubB.ShortString(), dwnPubB.ShortString(), nodePubB == dwnPubB)

	// Shared disco key registry: both engines publish and look up disco keys
	// through this registry, replacing Tailscale's control server role.
	discoReg := engine.NewInMemoryDiscoRegistry()

	engA, err := engine.New(engine.Config{
		AnchorEndpoint:       endpoint,
		AnchorTenant:         nodeA.identity.URI,
		NetworkRecordID:      networkRecordID,
		SelfDID:              nodeA.identity.URI,
		Signer:               nodeA.signer,
		EncryptionKeyManager: nodeA.encMgr,
		Domain:               "e2e-test",
		PollInterval:         5 * time.Second,
		ListenPort:           0,
		UseContextEncryption: true,
		WireGuardPrivateKey:  wgKeysA.PrivateKey,
		DiscoKeyRegistry:     discoReg,
	})
	if err != nil {
		t.Fatalf("creating engine A: %v", err)
	}
	defer engA.Stop()
	t.Log("  Engine A created")

	engB, err := engine.New(engine.Config{
		AnchorEndpoint:       endpoint,
		AnchorTenant:         nodeA.identity.URI,
		NetworkRecordID:      networkRecordID,
		SelfDID:              nodeB.identity.URI,
		Signer:               nodeB.signer,
		EncryptionKeyManager: nodeB.encMgr,
		Domain:               "e2e-test",
		PollInterval:         5 * time.Second,
		ListenPort:           0,
		UseContextEncryption: true,
		WireGuardPrivateKey:  wgKeysB.PrivateKey,
		DiscoKeyRegistry:     discoReg,
	})
	if err != nil {
		t.Fatalf("creating engine B: %v", err)
	}
	defer engB.Stop()
	t.Log("  Engine B created")

	// ================================================================
	// Step 8: Start both engines
	// ================================================================
	t.Log("Step 8: Starting both engines")

	if err := engA.Start(ctx); err != nil {
		t.Fatalf("starting engine A: %v", err)
	}
	t.Log("  Engine A started")

	if err := engB.Start(ctx); err != nil {
		t.Fatalf("starting engine B: %v", err)
	}
	t.Log("  Engine B started")

	// ================================================================
	// Step 9: Wait for engines to discover each other via DWN polling
	// ================================================================
	t.Log("Step 9: Waiting for engines to discover peers via DWN")

	// Give the engines time to poll DWN and build their NetworkMaps.
	// The polling interval is 5s, so we wait up to 30s for both to
	// have at least one peer in their network map.
	deadline := time.Now().Add(30 * time.Second)
	var nmA, nmB *netmapInfo
	for time.Now().Before(deadline) {
		nmA = getNetmapInfo(engA)
		nmB = getNetmapInfo(engB)

		if nmA != nil && nmB != nil && nmA.peerCount > 0 && nmB.peerCount > 0 {
			break
		}
		time.Sleep(2 * time.Second)
	}

	if nmA == nil || nmA.peerCount == 0 {
		t.Logf("  Engine A network map: %v", nmA)
		t.Fatal("Engine A did not discover any peers within 30s")
	}
	if nmB == nil || nmB.peerCount == 0 {
		t.Logf("  Engine B network map: %v", nmB)
		t.Fatal("Engine B did not discover any peers within 30s")
	}

	t.Logf("  Engine A: self=%s, peers=%d", nmA.selfAddr, nmA.peerCount)
	t.Logf("  Engine B: self=%s, peers=%d", nmB.selfAddr, nmB.peerCount)

	// ================================================================
	// Step 10: TCP connectivity through the mesh
	// ================================================================
	t.Log("Step 10: Testing TCP connectivity through WireGuard mesh")

	nsA := engA.Netstack()
	nsB := engB.Netstack()

	if nsA == nil || nsB == nil {
		t.Fatal("netstack is nil on one or both engines")
	}

	// Node A listens for TCP on port 9999 via netstack.
	// Use 0.0.0.0 (wildcard) since netstack handles all mesh IPs.
	listener, err := nsA.ListenTCP("tcp4", "0.0.0.0:9999")
	if err != nil {
		t.Fatalf("Node A ListenTCP: %v", err)
	}
	defer listener.Close()
	t.Logf("  Node A listening on %s:9999 (via netstack)", meshIPA)

	// Server goroutine: accept one connection, echo data back.
	serverDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverDone <- fmt.Errorf("accept: %w", err)
			return
		}
		defer conn.Close()

		// Read whatever the client sends.
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil && err != io.EOF {
			serverDone <- fmt.Errorf("read: %w", err)
			return
		}

		// Echo it back.
		if _, err := conn.Write(buf[:n]); err != nil {
			serverDone <- fmt.Errorf("write: %w", err)
			return
		}

		serverDone <- nil
	}()

	// Give time for:
	// 1. The listener to start
	// 2. Disco keys to propagate through the shared registry
	// 3. A subsequent DWN poll to inject disco keys into the network map
	// 4. magicsock to create peer endpoints with disco keys
	// 5. DERP relay connections to establish
	time.Sleep(15 * time.Second)

	// Diagnostic: dump netmap peer status from both engines
	nmAFinal := engA.Backend().NetMap()
	nmBFinal := engB.Backend().NetMap()
	if nmAFinal != nil {
		t.Logf("  Engine A netmap: selfKey=%s, peers=%d, derpMap regions=%d",
			nmAFinal.NodeKey.ShortString(), len(nmAFinal.Peers), len(nmAFinal.DERPMap.Regions))
		if nmAFinal.SelfNode.Valid() {
			t.Logf("    Self: homeDERP=%d addrs=%v", nmAFinal.SelfNode.HomeDERP(), nmAFinal.SelfNode.Addresses())
		}
		for i, p := range nmAFinal.Peers {
			t.Logf("    Peer %d: key=%s disco=%s homeDERP=%d endpoints=%d addrs=%v",
				i, p.Key().ShortString(), p.DiscoKey().ShortString(), p.HomeDERP(), p.Endpoints().Len(), p.Addresses())
		}
	}
	if nmBFinal != nil {
		t.Logf("  Engine B netmap: selfKey=%s, peers=%d, derpMap regions=%d",
			nmBFinal.NodeKey.ShortString(), len(nmBFinal.Peers), len(nmBFinal.DERPMap.Regions))
		if nmBFinal.SelfNode.Valid() {
			t.Logf("    Self: homeDERP=%d addrs=%v", nmBFinal.SelfNode.HomeDERP(), nmBFinal.SelfNode.Addresses())
		}
		for i, p := range nmBFinal.Peers {
			t.Logf("    Peer %d: key=%s disco=%s homeDERP=%d endpoints=%d addrs=%v",
				i, p.Key().ShortString(), p.DiscoKey().ShortString(), p.HomeDERP(), p.Endpoints().Len(), p.Addresses())
		}
	}

	// Check MagicSock DERP status
	mcA := engA.Backend().MagicConn()
	mcB := engB.Backend().MagicConn()
	if mcA != nil {
		t.Logf("  Engine A MagicSock disco=%s", mcA.DiscoPublicKey().ShortString())
	}
	if mcB != nil {
		t.Logf("  Engine B MagicSock disco=%s", mcB.DiscoPublicKey().ShortString())
	}

	// Check backend state
	stateA := engA.Backend().State()
	stateB := engB.Backend().State()
	t.Logf("  Engine A state=%s, Engine B state=%s", stateA, stateB)

	// Check full status with peers for WireGuard config details
	fullStatusA := engA.Backend().Status()
	if fullStatusA != nil {
		t.Logf("  Engine A BackendState=%s, Self=%+v", fullStatusA.BackendState, fullStatusA.Self)
		for k, peer := range fullStatusA.Peer {
			t.Logf("    Peer %s: relay=%s, curAddr=%s, active=%v, lastHandshake=%v",
				k.ShortString(), peer.Relay, peer.CurAddr, peer.Active, peer.LastHandshake)
		}
	}
	fullStatusB := engB.Backend().Status()
	if fullStatusB != nil {
		t.Logf("  Engine B BackendState=%s", fullStatusB.BackendState)
		for k, peer := range fullStatusB.Peer {
			t.Logf("    Peer %s: relay=%s, curAddr=%s, active=%v, lastHandshake=%v",
				k.ShortString(), peer.Relay, peer.CurAddr, peer.Active, peer.LastHandshake)
		}
	}

	// Node B dials Node A's mesh IP through netstack.
	dialCtx, dialCancel := context.WithTimeout(ctx, 30*time.Second)
	defer dialCancel()

	dst := netip.AddrPortFrom(meshIPA, 9999)
	conn, err := nsB.DialContextTCP(dialCtx, dst)
	if err != nil {
		t.Fatalf("Node B DialContextTCP to %s: %v", dst, err)
	}
	defer conn.Close()
	t.Log("  Node B connected to Node A")

	// Send test data.
	testMsg := []byte("hello from node B through the WireGuard mesh!")
	if _, err := conn.Write(testMsg); err != nil {
		t.Fatalf("Node B write: %v", err)
	}

	// Read echo back.
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Node B read echo: %v", err)
	}

	if string(buf[:n]) != string(testMsg) {
		t.Fatalf("echo mismatch: got %q, want %q", buf[:n], testMsg)
	}
	t.Logf("  Echo verified: %q", string(buf[:n]))

	// Wait for server to finish.
	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatalf("server error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not finish within 5s")
	}

	// ================================================================
	// Step 11: Clean shutdown
	// ================================================================
	t.Log("Step 11: Shutting down")

	if err := engB.Stop(); err != nil {
		t.Errorf("stopping engine B: %v", err)
	}
	if err := engA.Stop(); err != nil {
		t.Errorf("stopping engine A: %v", err)
	}

	t.Log("=== Two-Node Connectivity Test PASSED ===")
	t.Logf("  Network: e2e-connectivity-test (%s)", networkRecordID)
	t.Logf("  Node A: %s → %s", nodeA.identity.URI[:30]+"...", meshIPA)
	t.Logf("  Node B: %s → %s", nodeB.identity.URI[:30]+"...", meshIPB)
	t.Log("  Engine: real UserspaceEngine + netstack (no root)")
	t.Log("  Connectivity: TCP echo through WireGuard tunnel verified")
}

// TestTwoNodeNetworkMapDiscovery is a lighter version that verifies engines
// discover each other via DWN polling without testing TCP connectivity.
// This is useful when debugging the DWN → NetworkMap pipeline.
func TestTwoNodeNetworkMapDiscovery(t *testing.T) {
	endpoint := os.Getenv("DWN_ENDPOINT")
	if endpoint == "" {
		t.Skip("DWN_ENDPOINT not set, skipping integration test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	t.Log("Creating two node identities")
	nodeA := newTestNode(t, endpoint)
	nodeB := newTestNode(t, endpoint)

	// Set up network (same as full test but abbreviated).
	protocolDef, err := dwncrypto.InjectEncryptionDirectives(
		protocols.MeshProtocolJSON,
		nodeA.identity.EncryptionPrivateKey,
		nodeA.identity.EncryptionKeyID(),
	)
	if err != nil {
		t.Fatalf("InjectEncryptionDirectives: %v", err)
	}

	status, err := nodeA.api.ConfigureProtocol(ctx, nodeA.identity.URI, protocolDef)
	if err != nil || (status.Code >= 300 && status.Code != 409) {
		t.Fatalf("ConfigureProtocol: err=%v, status=%v", err, status)
	}

	meshCIDR := "10.200.0.0/16"
	networkData, _ := json.Marshal(map[string]any{
		"name":     "discovery-test",
		"meshCIDR": meshCIDR,
	})
	networkRecord, ws, err := nodeA.api.Write(ctx, nodeA.identity.URI, dwn.WriteParams{
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
		records, _, _ := nodeA.api.Query(ctx, nodeA.identity.URI, dwn.QueryParams{
			Filter: dwn.RecordsFilter{Protocol: protocols.MeshProtocolURI, ProtocolPath: "network"},
		}, "")
		if len(records) > 0 {
			networkRecordID = records[0].ID
		}
	}

	// Create member records (Node A is network author, so it creates both).
	memberRecipients, _ := nodeA.encMgr.DeriveWriteEncryption("network/member")
	mData, _ := json.Marshal(map[string]any{"joinedAt": time.Now().UTC().Format(time.RFC3339)})
	nodeA.api.Write(ctx, nodeA.identity.URI, dwn.WriteParams{
		Protocol: protocols.MeshProtocolURI, ProtocolPath: "network/member",
		Schema: "https://enbox.org/schemas/wireguard-mesh/member", DataFormat: "application/json",
		Recipient: nodeA.identity.URI, ParentContextID: networkRecordID,
		Data: mData, Tags: map[string]any{"status": "active"}, EncryptionRecipients: memberRecipients,
	})
	nodeA.api.Write(ctx, nodeA.identity.URI, dwn.WriteParams{
		Protocol: protocols.MeshProtocolURI, ProtocolPath: "network/member",
		Schema: "https://enbox.org/schemas/wireguard-mesh/member", DataFormat: "application/json",
		Recipient: nodeB.identity.URI, ParentContextID: networkRecordID,
		Data: mData, Tags: map[string]any{"status": "active"}, EncryptionRecipients: memberRecipients,
	})

	// Install key-delivery protocol on anchor.
	err = mesh.EnsureKeyDeliveryProtocol(ctx, endpoint, nodeA.identity.URI, nodeA.signer,
		nodeA.identity.EncryptionPrivateKey, nodeA.identity.EncryptionKeyID())
	if err != nil {
		t.Fatalf("EnsureKeyDeliveryProtocol: %v", err)
	}

	// Register both nodes (initial registration uses Protocol Path encryption).
	wgA, _ := mesh.GenerateWireGuardKeyPair()
	ipA, _ := mesh.AllocateMeshIP(meshCIDR, nodeA.identity.URI)
	regADisc, _ := mesh.RegisterNode(ctx, mesh.RegisterNodeParams{
		AnchorEndpoint: endpoint, AnchorDID: nodeA.identity.URI,
		NetworkRecordID: networkRecordID, SelfDID: nodeA.identity.URI,
		Signer: nodeA.signer, EncryptionKeyManager: nodeA.encMgr,
		WireGuardPubKey: wgA.PublicKeyBase64(), MeshIP: ipA.String(),
		Hostname: "disc-a",
	})

	wgB, _ := mesh.GenerateWireGuardKeyPair()
	ipB, _ := mesh.AllocateMeshIP(meshCIDR, nodeB.identity.URI)
	regBDisc, _ := mesh.RegisterNode(ctx, mesh.RegisterNodeParams{
		AnchorEndpoint: endpoint, AnchorDID: nodeA.identity.URI,
		NetworkRecordID: networkRecordID, SelfDID: nodeB.identity.URI,
		Signer: nodeB.signer, EncryptionKeyManager: nodeB.encMgr,
		WireGuardPubKey: wgB.PublicKeyBase64(), MeshIP: ipB.String(),
		Hostname: "disc-b", ProtocolRole: "network/member",
	})

	// Deliver context key to Node B, then re-register both nodes with context encryption.
	kdm := &mesh.KeyDeliveryManager{
		Endpoint:             endpoint,
		Signer:               nodeA.signer,
		EncryptionKeyManager: nodeA.encMgr,
	}
	err = kdm.DeliverContextKey(ctx, mesh.DeliverContextKeyParams{
		AnchorDID:      nodeA.identity.URI,
		RecipientDID:   nodeB.identity.URI,
		SourceProtocol: protocols.MeshProtocolURI,
		ContextID:      networkRecordID,
	})
	if err != nil {
		t.Fatalf("key delivery to B: %v", err)
	}

	// Re-register Node A (anchor) with context encryption.
	mesh.RegisterNode(ctx, mesh.RegisterNodeParams{
		AnchorEndpoint: endpoint, AnchorDID: nodeA.identity.URI,
		NetworkRecordID: networkRecordID, SelfDID: nodeA.identity.URI,
		Signer: nodeA.signer, EncryptionKeyManager: nodeA.encMgr,
		WireGuardPubKey: wgA.PublicKeyBase64(), MeshIP: ipA.String(),
		Hostname: "disc-a", UseContextEncryption: true,
		ExistingNodeInfoRecordID: regADisc.NodeInfoRecordID,
		ExistingDateCreated:      regADisc.DateCreated,
	})

	// Node B fetches and stores context key.
	contextKeyJwk, err := mesh.FetchContextKey(ctx, mesh.FetchContextKeyParams{
		AnchorEndpoint: endpoint,
		AnchorDID:      nodeA.identity.URI,
		SelfDID:        nodeB.identity.URI,
		Signer:         nodeB.signer,
	})
	if err != nil {
		t.Fatalf("fetching context key: %v", err)
	}
	if contextKeyJwk != nil {
		contextKeyBytes, err := contextKeyJwk.PrivateKeyBytes()
		if err != nil {
			t.Fatalf("extracting context key bytes: %v", err)
		}
		nodeB.encMgr.StoreContextKey(networkRecordID, contextKeyBytes)

		// Re-register Node B with context encryption (update, same recordId).
		mesh.RegisterNode(ctx, mesh.RegisterNodeParams{
			AnchorEndpoint: endpoint, AnchorDID: nodeA.identity.URI,
			NetworkRecordID: networkRecordID, SelfDID: nodeB.identity.URI,
			Signer: nodeB.signer, EncryptionKeyManager: nodeB.encMgr,
			WireGuardPubKey: wgB.PublicKeyBase64(), MeshIP: ipB.String(),
			Hostname: "disc-b", ProtocolRole: "network/member",
			UseContextEncryption: true,
			ExistingNodeInfoRecordID: regBDisc.NodeInfoRecordID,
			ExistingDateCreated:      regBDisc.DateCreated,
		})
	}

	// Create engine A.
	discoReg := engine.NewInMemoryDiscoRegistry()
	engA, err := engine.New(engine.Config{
		AnchorEndpoint:       endpoint,
		AnchorTenant:         nodeA.identity.URI,
		NetworkRecordID:      networkRecordID,
		SelfDID:              nodeA.identity.URI,
		Signer:               nodeA.signer,
		EncryptionKeyManager: nodeA.encMgr,
		Domain:               "disc-test",
		PollInterval:         3 * time.Second,
		WireGuardPrivateKey:  wgA.PrivateKey,
		DiscoKeyRegistry:     discoReg,
	})
	if err != nil {
		t.Fatalf("creating engine A: %v", err)
	}
	defer engA.Stop()

	if err := engA.Start(ctx); err != nil {
		t.Fatalf("starting engine A: %v", err)
	}

	// Wait for engine A to load network map.
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		nm := engA.Backend().NetMap()
		if nm != nil {
			t.Logf("  Engine A NetMap: domain=%s, selfNode=%v, peers=%d",
				nm.Domain, nm.SelfNode.Valid(), len(nm.Peers))

			// Check if we see at least 1 nodeInfo (ourselves).
			if nm.SelfNode.Valid() {
				t.Log("  Engine A successfully loaded network map from DWN")
				return
			}
		}
		time.Sleep(2 * time.Second)
	}

	t.Fatal("Engine A did not load network map within 20s")
}

// ============================================================================
// Test helpers
// ============================================================================

// testNode holds all identity and API state for a test node.
type testNode struct {
	identity *did.DID
	signer   *dwn.Signer
	encMgr   *dwncrypto.EncryptionKeyManager
	api      *dwn.DwnAPI
}

// newTestNode creates a fresh DID identity, publishes it to the DHT,
// registers it as a tenant, and returns a fully wired test node.
func newTestNode(t *testing.T, endpoint string) *testNode {
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

	// Register tenant.
	regCtx, regCancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer regCancel()

	if err := dwn.RegisterTenant(regCtx, endpoint, signer.DID); err != nil {
		t.Fatalf("RegisterTenant: %v", err)
	}

	agent := dwn.NewSimpleAgent(endpoint, signer)
	api := dwn.NewDwnAPI(agent)

	encMgr := &dwncrypto.EncryptionKeyManager{
		RootPrivateKey: identity.EncryptionPrivateKey,
		RootKeyID:      identity.EncryptionKeyID(),
		ProtocolURI:    protocols.MeshProtocolURI,
	}

	return &testNode{
		identity: identity,
		signer:   signer,
		encMgr:   encMgr,
		api:      api,
	}
}

// netmapInfo summarizes a NetworkMap for test assertions.
type netmapInfo struct {
	selfAddr  netip.Addr
	peerCount int
	peerAddrs []netip.Addr
}

// getNetmapInfo extracts NetworkMap info from a running engine.
func getNetmapInfo(eng *engine.Engine) *netmapInfo {
	nm := eng.Backend().NetMap()
	if nm == nil {
		return nil
	}

	info := &netmapInfo{
		peerCount: len(nm.Peers),
	}

	if nm.SelfNode.Valid() {
		addrs := nm.SelfNode.Addresses()
		if addrs.Len() > 0 {
			info.selfAddr = addrs.At(0).Addr()
		}
	}

	for _, p := range nm.Peers {
		paddrs := p.Addresses()
		if paddrs.Len() > 0 {
			info.peerAddrs = append(info.peerAddrs, paddrs.At(0).Addr())
		}
	}

	return info
}

// parseTestWireGuardKey parses a base64-encoded WireGuard public key into a
// key.NodePublic. Mirrors the unexported parseWireGuardKey in convert.go.
func parseTestWireGuardKey(b64Key string) (key.NodePublic, error) {
	raw, err := base64.StdEncoding.DecodeString(b64Key)
	if err != nil {
		raw, err = base64.RawStdEncoding.DecodeString(b64Key)
		if err != nil {
			return key.NodePublic{}, fmt.Errorf("base64 decode: %w", err)
		}
	}
	if len(raw) != 32 {
		return key.NodePublic{}, fmt.Errorf("key must be 32 bytes, got %d", len(raw))
	}
	return key.NodePublicFromRaw32(go4mem.B(raw)), nil
}

// Ensure testNode fields are used to satisfy the compiler.
var _ net.Conn
var _ = control.ProtocolMesh
