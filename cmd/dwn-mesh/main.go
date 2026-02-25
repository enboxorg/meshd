package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/enboxorg/dwn-mesh/internal/did"
	"github.com/enboxorg/dwn-mesh/internal/dwn"
	dwncrypto "github.com/enboxorg/dwn-mesh/internal/dwn/crypto"
	"github.com/enboxorg/dwn-mesh/internal/engine"
	"github.com/enboxorg/dwn-mesh/internal/mesh"
	"github.com/enboxorg/dwn-mesh/internal/state"
	"github.com/enboxorg/dwn-mesh/pkg/dids"
	"github.com/enboxorg/dwn-mesh/pkg/dids/didcore"
	"github.com/enboxorg/dwn-mesh/protocols"
)

const usage = `dwn-mesh - Decentralized WireGuard mesh networking via DWN

Usage:
  dwn-mesh <command> [arguments]

Commands:
  init              Generate DID identity and publish to DHT
  network create    Create a new mesh network on a DWN
  network join      Join an existing mesh network
  network leave     Leave the current mesh network
  peer list         List all peers in the mesh
  peer approve      Deliver encryption keys to a peer (anchor only)
  status            Show mesh status and identity info
  up                Start the mesh agent daemon
  down              Stop the mesh agent daemon

Init flags:
  --dwn-endpoint <url>    DWN endpoint to include in DID Document
  --gateway <url>         Pkarr gateway for DHT publication
  --no-publish            Skip publishing DID to DHT
  --force-publish         Re-publish existing DID to DHT

Flags:
  -h, --help        Show this help message
  -v, --version     Show version information

Environment:
  DWN_MESH_STATE_DIR    State directory (default: ~/.dwn-mesh)
  DWN_ENDPOINT          Default DWN endpoint URL
`

var version = "dev"

func main() {
	if len(os.Args) < 2 {
		fmt.Print(usage)
		os.Exit(1)
	}

	// Combine two-word commands.
	cmd := os.Args[1]
	args := os.Args[2:]
	if len(os.Args) >= 3 {
		combined := os.Args[1] + " " + os.Args[2]
		switch combined {
		case "network create", "network join", "network leave",
			"peer list", "peer add", "peer remove", "peer approve":
			cmd = combined
			args = os.Args[3:]
		}
	}

	ctx := context.Background()

	var err error
	switch cmd {
	case "-h", "--help", "help":
		fmt.Print(usage)
		return
	case "-v", "--version", "version":
		fmt.Printf("dwn-mesh %s\n", version)
		return
	case "init":
		err = cmdInit(ctx, args)
	case "network create":
		err = cmdNetworkCreate(ctx, args)
	case "network join":
		err = cmdNetworkJoin(ctx, args)
	case "network leave":
		err = cmdNetworkLeave(ctx, args)
	case "peer list":
		err = cmdPeerList(ctx, args)
	case "peer approve":
		err = cmdPeerApprove(ctx, args)
	case "status":
		err = cmdStatus(ctx, args)
	case "up":
		err = cmdUp(ctx, args)
	case "down":
		err = cmdDown(ctx, args)
	default:
		fmt.Fprintf(os.Stderr, "dwn-mesh: unknown command %q\n", cmd)
		fmt.Fprintf(os.Stderr, "Run 'dwn-mesh --help' for usage.\n")
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "dwn-mesh: %v\n", err)
		os.Exit(1)
	}
}

// cmdInit generates a DID identity, stores it, and publishes it to the DHT.
func cmdInit(ctx context.Context, args []string) error {
	// Parse init flags.
	var dwnEndpoint, gateway string
	noPublish := false
	forcePublish := false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--dwn-endpoint":
			if i+1 < len(args) {
				dwnEndpoint = args[i+1]
				i++
			}
		case "--gateway":
			if i+1 < len(args) {
				gateway = args[i+1]
				i++
			}
		case "--no-publish":
			noPublish = true
		case "--force-publish":
			forcePublish = true
		}
	}

	// Fall back to DWN_ENDPOINT env var.
	if dwnEndpoint == "" {
		dwnEndpoint = os.Getenv("DWN_ENDPOINT")
	}

	stateDir := state.DefaultStateDir()

	if did.Exists(stateDir) {
		identity, err := did.Load(stateDir)
		if err != nil {
			return fmt.Errorf("loading existing identity: %w", err)
		}
		fmt.Printf("Already initialized.\n")
		fmt.Printf("  DID: %s\n", identity.URI)
		fmt.Printf("  State: %s\n", stateDir)

		// Re-publish if forced.
		if forcePublish && !noPublish {
			if err := publishDID(ctx, identity, dwnEndpoint, gateway); err != nil {
				return err
			}
		}
		return nil
	}

	identity, err := did.Generate()
	if err != nil {
		return fmt.Errorf("generating DID: %w", err)
	}

	if err := identity.Store(stateDir); err != nil {
		return fmt.Errorf("storing identity: %w", err)
	}

	fmt.Printf("Initialized new identity.\n")
	fmt.Printf("  DID: %s\n", identity.URI)
	fmt.Printf("  State: %s\n", stateDir)

	// Publish to DHT unless opted out.
	if !noPublish {
		if err := publishDID(ctx, identity, dwnEndpoint, gateway); err != nil {
			return err
		}
	}

	return nil
}

// publishDID publishes the DID Document to the DHT via a Pkarr gateway.
func publishDID(ctx context.Context, identity *did.DID, dwnEndpoint, gateway string) error {
	var opts []did.PublishOption
	if gateway != "" {
		opts = append(opts, did.WithGatewayURL(gateway))
	}

	if dwnEndpoint != "" {
		fmt.Printf("  DWN Endpoint: %s\n", dwnEndpoint)
	}

	fmt.Printf("  Publishing DID to DHT...")
	if err := identity.Publish(ctx, dwnEndpoint, opts...); err != nil {
		fmt.Printf(" failed\n")
		return fmt.Errorf("publishing DID: %w", err)
	}
	fmt.Printf(" done\n")
	return nil
}

// cmdNetworkCreate creates a new mesh network.
//
// Usage: dwn-mesh network create <name> --endpoint <dwn-url>
func cmdNetworkCreate(ctx context.Context, args []string) error {
	if len(args) < 3 {
		return fmt.Errorf("usage: dwn-mesh network create <name> --endpoint <dwn-url>")
	}

	name := args[0]
	endpoint := ""
	for i := 1; i < len(args); i++ {
		if args[i] == "--endpoint" && i+1 < len(args) {
			endpoint = args[i+1]
			break
		}
	}
	if endpoint == "" {
		return fmt.Errorf("--endpoint is required")
	}

	stateDir := state.DefaultStateDir()
	identity, err := loadIdentity(stateDir)
	if err != nil {
		return err
	}

	if state.HasNetwork(stateDir) {
		return fmt.Errorf("already in a network. Use 'dwn-mesh network leave' first.")
	}

	signer := &dwn.Signer{
		DID:        identity.URI,
		PrivateKey: identity.SigningKey,
	}
	agent := dwn.NewSimpleAgent(endpoint, signer)
	api := dwn.NewDwnAPI(agent)

	// 1. Install the wireguard-mesh protocol on the DWN.
	// Inject derived encryption keys into the protocol definition.
	protocolDef, err := dwncrypto.InjectEncryptionDirectives(
		protocols.MeshProtocolJSON,
		identity.EncryptionPrivateKey,
		identity.EncryptionKeyID(),
	)
	if err != nil {
		return fmt.Errorf("injecting encryption keys: %w", err)
	}

	status, err := api.ConfigureProtocol(ctx, identity.URI, protocolDef)
	if err != nil {
		return fmt.Errorf("configuring protocol: %w", err)
	}
	if status.Code >= 300 && status.Code != 409 {
		// 409 = already configured, which is fine.
		return fmt.Errorf("protocol configure failed: %d %s", status.Code, status.Detail)
	}
	fmt.Printf("  Protocol installed on DWN (with encryption keys).\n")

	// Install the key-delivery protocol (needed for multi-party key exchange).
	if err := mesh.EnsureKeyDeliveryProtocol(ctx, endpoint, identity.URI, signer, identity.EncryptionPrivateKey, identity.EncryptionKeyID()); err != nil {
		fmt.Printf("  Warning: key-delivery protocol installation failed: %v\n", err)
	} else {
		fmt.Printf("  Key delivery protocol installed.\n")
	}

	// Set up encryption key manager for encrypted writes.
	encMgr := &dwncrypto.EncryptionKeyManager{
		RootPrivateKey: identity.EncryptionPrivateKey,
		RootKeyID:      identity.EncryptionKeyID(),
		ProtocolURI:    "https://enbox.org/protocols/wireguard-mesh",
	}

	// 2. Create the network record.
	// The "network" type does NOT have encryptionRequired — it's publicly
	// readable as the anchor record. No encryption on this write.
	meshCIDR := "10.200.0.0/16"
	networkData, _ := json.Marshal(map[string]any{
		"name":     name,
		"meshCIDR": meshCIDR,
		"created":  time.Now().UTC().Format(time.RFC3339),
	})

	record, writeStatus, err := api.Write(ctx, identity.URI, dwn.WriteParams{
		Protocol:     "https://enbox.org/protocols/wireguard-mesh",
		ProtocolPath: "network",
		Schema:       "https://enbox.org/schemas/wireguard-mesh/network",
		DataFormat:   "application/json",
		Data:         networkData,
	})
	if err != nil {
		return fmt.Errorf("creating network record: %w", err)
	}
	if writeStatus.Code >= 300 {
		return fmt.Errorf("network create failed: %d %s", writeStatus.Code, writeStatus.Detail)
	}

	// 3. Deliver context key to self (anchor always needs this for context-based decryption).
	kdm := &mesh.KeyDeliveryManager{
		Endpoint:             endpoint,
		Signer:               signer,
		EncryptionKeyManager: encMgr,
	}
	if err := kdm.DeliverContextKey(ctx, mesh.DeliverContextKeyParams{
		AnchorDID:      identity.URI,
		RecipientDID:   identity.URI,
		SourceProtocol: "https://enbox.org/protocols/wireguard-mesh",
		ContextID:      record.ID,
	}); err != nil {
		fmt.Printf("  Warning: context key self-delivery failed: %v\n", err)
	} else {
		fmt.Printf("  Context key delivered to self.\n")
	}

	// 4. Create self as admin member (encrypted).
	memberRecipients, err := encMgr.DeriveWriteEncryption("network/member")
	if err != nil {
		return fmt.Errorf("deriving member encryption: %w", err)
	}

	memberData, _ := json.Marshal(map[string]any{
		"joinedAt": time.Now().UTC().Format(time.RFC3339),
		"label":    "admin",
	})

	_, memberStatus, err := api.Write(ctx, identity.URI, dwn.WriteParams{
		Protocol:             "https://enbox.org/protocols/wireguard-mesh",
		ProtocolPath:         "network/member",
		Schema:               "https://enbox.org/schemas/wireguard-mesh/member",
		DataFormat:           "application/json",
		Recipient:            identity.URI,
		ParentContextID:     record.ID,
		Data:                 memberData,
		Tags:                 map[string]any{"status": "active"},
		EncryptionRecipients: memberRecipients,
	})
	if err != nil {
		return fmt.Errorf("creating member record: %w", err)
	}
	if memberStatus.Code >= 300 {
		fmt.Printf("  Warning: member record creation failed: %d %s\n",
			memberStatus.Code, memberStatus.Detail)
	} else {
		fmt.Printf("  Created admin member record (encrypted).\n")
	}

	// 5. Generate WireGuard keys and allocate mesh IP.
	wgKeys, err := mesh.GenerateWireGuardKeyPair()
	if err != nil {
		return fmt.Errorf("generating WireGuard keys: %w", err)
	}

	meshIP, err := mesh.AllocateMeshIP(meshCIDR, identity.URI)
	if err != nil {
		return fmt.Errorf("allocating mesh IP: %w", err)
	}

	// 6. Register nodeInfo on DWN (encrypted).
	reg, err := mesh.RegisterNode(ctx, mesh.RegisterNodeParams{
		AnchorEndpoint:       endpoint,
		AnchorDID:            identity.URI,
		NetworkRecordID:      record.ID,
		SelfDID:              identity.URI,
		Signer:               signer,
		EncryptionKeyManager: encMgr,
		WireGuardPubKey:      wgKeys.PublicKeyBase64(),
		MeshIP:               meshIP.String(),
	})
	if err != nil {
		fmt.Printf("  Warning: nodeInfo registration failed: %v\n", err)
	} else {
		fmt.Printf("  Registered node (encrypted): IP=%s\n", meshIP)
	}

	// 7. Persist network state.
	ns := &state.NetworkState{
		NetworkRecordID:     record.ID,
		AnchorDID:           identity.URI,
		AnchorEndpoint:      endpoint,
		NetworkName:         name,
		MeshCIDR:            meshCIDR,
		MeshIP:              meshIP.String(),
		WireGuardPublicKey:  wgKeys.PublicKeyBase64(),
		WireGuardPrivateKey: wgKeys.PrivateKeyBase64(),
	}
	if reg != nil {
		ns.NodeInfoRecordID = reg.NodeInfoRecordID
	}
	if err := state.SaveNetworkState(stateDir, ns); err != nil {
		return fmt.Errorf("saving network state: %w", err)
	}

	fmt.Printf("Network created.\n")
	fmt.Printf("  Name: %s\n", name)
	fmt.Printf("  CIDR: %s\n", meshCIDR)
	fmt.Printf("  Mesh IP: %s\n", meshIP)
	fmt.Printf("  Record: %s\n", record.ID)
	fmt.Printf("  Anchor: %s\n", endpoint)
	fmt.Printf("\nShare this join token with peers:\n")
	fmt.Printf("  dwn-mesh network join --endpoint %s --anchor %s --network %s\n",
		endpoint, identity.URI, record.ID)

	return nil
}

// cmdNetworkJoin joins an existing mesh network.
//
// Usage: dwn-mesh network join --endpoint <url> --anchor <did> --network <id>
func cmdNetworkJoin(ctx context.Context, args []string) error {
	var endpoint, anchorDID, networkID string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--endpoint":
			if i+1 < len(args) {
				endpoint = args[i+1]
				i++
			}
		case "--anchor":
			if i+1 < len(args) {
				anchorDID = args[i+1]
				i++
			}
		case "--network":
			if i+1 < len(args) {
				networkID = args[i+1]
				i++
			}
		}
	}

	if endpoint == "" || anchorDID == "" || networkID == "" {
		return fmt.Errorf("usage: dwn-mesh network join --endpoint <url> --anchor <did> --network <id>")
	}

	stateDir := state.DefaultStateDir()
	identity, err := loadIdentity(stateDir)
	if err != nil {
		return err
	}

	if state.HasNetwork(stateDir) {
		return fmt.Errorf("already in a network. Use 'dwn-mesh network leave' first.")
	}

	signer := &dwn.Signer{
		DID:        identity.URI,
		PrivateKey: identity.SigningKey,
	}
	agent := dwn.NewSimpleAgent(endpoint, signer)
	api := dwn.NewDwnAPI(agent)

	// Read the network record to verify it exists.
	record, readStatus, err := api.Read(ctx, anchorDID, dwn.RecordsFilter{
		RecordID: networkID,
	}, "network/member")
	if err != nil {
		return fmt.Errorf("reading network: %w", err)
	}
	if readStatus.Code != 200 || record == nil {
		return fmt.Errorf("network not found: %d %s", readStatus.Code, readStatus.Detail)
	}

	var networkData struct {
		Name     string `json:"name"`
		MeshCIDR string `json:"meshCIDR"`
	}
	if err := record.Data().JSON(ctx, &networkData); err != nil {
		// Data might be in binary body, try status only.
		slog.Warn("could not read network data", slog.Any("error", err))
		networkData.Name = "unknown"
		networkData.MeshCIDR = "10.200.0.0/16"
	}

	// Generate WireGuard keys and allocate mesh IP.
	wgKeys, err := mesh.GenerateWireGuardKeyPair()
	if err != nil {
		return fmt.Errorf("generating WireGuard keys: %w", err)
	}

	meshIP, err := mesh.AllocateMeshIP(networkData.MeshCIDR, identity.URI)
	if err != nil {
		return fmt.Errorf("allocating mesh IP: %w", err)
	}

	// Set up encryption for the anchor's protocol.
	// Note: The joining node uses the anchor DWN owner's encryption context.
	// The anchor's EncryptionKeyManager is needed to encrypt records that
	// the anchor can decrypt. For now, use our own key (the anchor would
	// need to have granted us access via key delivery protocol for full
	// multi-party encryption). This is sufficient for single-owner networks.
	encMgr := newEncryptionKeyManager(identity)

	// Create member record (encrypted).
	err = mesh.CreateMember(ctx, mesh.CreateMemberParams{
		AnchorEndpoint:       endpoint,
		AnchorDID:            anchorDID,
		NetworkRecordID:      networkID,
		MemberDID:            identity.URI,
		Label:                "member",
		Signer:               signer,
		EncryptionKeyManager: encMgr,
	})
	if err != nil {
		fmt.Printf("  Warning: member record creation failed: %v\n", err)
	} else {
		fmt.Printf("  Created member record (encrypted).\n")
	}

	// Register nodeInfo (encrypted), invoking the network/member role for authorization.
	var nodeInfoRecordID string
	reg, err := mesh.RegisterNode(ctx, mesh.RegisterNodeParams{
		AnchorEndpoint:       endpoint,
		AnchorDID:            anchorDID,
		NetworkRecordID:      networkID,
		SelfDID:              identity.URI,
		Signer:               signer,
		EncryptionKeyManager: encMgr,
		WireGuardPubKey:      wgKeys.PublicKeyBase64(),
		MeshIP:               meshIP.String(),
		ProtocolRole:         "network/member",
	})
	if err != nil {
		fmt.Printf("  Warning: nodeInfo registration failed: %v\n", err)
	} else {
		nodeInfoRecordID = reg.NodeInfoRecordID
		fmt.Printf("  Registered node (encrypted): IP=%s\n", meshIP)
	}

	// Save network state locally.
	ns := &state.NetworkState{
		NetworkRecordID:     networkID,
		AnchorDID:           anchorDID,
		AnchorEndpoint:      endpoint,
		NetworkName:         networkData.Name,
		MeshCIDR:            networkData.MeshCIDR,
		MeshIP:              meshIP.String(),
		WireGuardPublicKey:  wgKeys.PublicKeyBase64(),
		WireGuardPrivateKey: wgKeys.PrivateKeyBase64(),
		NodeInfoRecordID:    nodeInfoRecordID,
	}
	if err := state.SaveNetworkState(stateDir, ns); err != nil {
		return fmt.Errorf("saving network state: %w", err)
	}

	fmt.Printf("Joined network.\n")
	fmt.Printf("  Name: %s\n", networkData.Name)
	fmt.Printf("  CIDR: %s\n", networkData.MeshCIDR)
	fmt.Printf("  Mesh IP: %s\n", meshIP)
	fmt.Printf("  Anchor: %s\n", anchorDID)
	fmt.Printf("\nRun 'dwn-mesh up' to start the mesh.\n")

	return nil
}

// cmdNetworkLeave leaves the current mesh network.
func cmdNetworkLeave(ctx context.Context, args []string) error {
	stateDir := state.DefaultStateDir()

	if !state.HasNetwork(stateDir) {
		fmt.Println("Not in a network.")
		return nil
	}

	ns, err := state.LoadNetworkState(stateDir)
	if err != nil {
		return fmt.Errorf("loading network state: %w", err)
	}

	if err := state.ClearNetworkState(stateDir); err != nil {
		return fmt.Errorf("clearing network state: %w", err)
	}

	name := "unknown"
	if ns != nil {
		name = ns.NetworkName
	}
	fmt.Printf("Left network %q.\n", name)
	return nil
}

// cmdPeerList lists all peers in the current mesh network.
func cmdPeerList(ctx context.Context, args []string) error {
	stateDir := state.DefaultStateDir()
	identity, err := loadIdentity(stateDir)
	if err != nil {
		return err
	}

	ns, err := state.LoadNetworkState(stateDir)
	if err != nil {
		return fmt.Errorf("loading network state: %w", err)
	}
	if ns == nil {
		return fmt.Errorf("not in a network. Use 'dwn-mesh network join' first.")
	}

	signer := &dwn.Signer{
		DID:        identity.URI,
		PrivateKey: identity.SigningKey,
	}
	agent := dwn.NewSimpleAgent(ns.AnchorEndpoint, signer)
	api := dwn.NewDwnAPI(agent)

	// Query member records.
	records, status, err := api.Query(ctx, ns.AnchorDID, dwn.QueryParams{
		Filter: dwn.RecordsFilter{
			Protocol:     "https://enbox.org/protocols/wireguard-mesh",
			ProtocolPath: "network/member",
			ContextID:    ns.NetworkRecordID,
		},
		DateSort: "createdAscending",
	}, "network/member")
	if err != nil {
		return fmt.Errorf("querying peers: %w", err)
	}

	if status.Code != 200 {
		return fmt.Errorf("query failed: %d %s", status.Code, status.Detail)
	}

	if len(records) == 0 {
		fmt.Println("No peers found.")
		return nil
	}

	fmt.Printf("Peers in %q:\n", ns.NetworkName)
	fmt.Printf("%-50s %-16s %s\n", "DID", "MESH IP", "STATUS")
	fmt.Println(strings.Repeat("-", 80))

	for _, r := range records {
		var member struct {
			DID    string `json:"did"`
			MeshIP string `json:"meshIp"`
			Role   string `json:"role"`
		}
		if err := r.Data().JSON(ctx, &member); err != nil {
			// Data may not be inline.
			fmt.Printf("%-50s %-16s %s\n", truncate(r.Recipient, 50), "?", "no data")
			continue
		}
		fmt.Printf("%-50s %-16s %s\n",
			truncate(member.DID, 50),
			member.MeshIP,
			member.Role)
	}

	return nil
}

// cmdPeerApprove delivers encryption keys to a peer so they can decrypt
// mesh records. This must be run by the network anchor (owner).
//
// Usage: dwn-mesh peer approve <did>
func cmdPeerApprove(ctx context.Context, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: dwn-mesh peer approve <did>")
	}

	peerDID := args[0]

	stateDir := state.DefaultStateDir()
	identity, err := loadIdentity(stateDir)
	if err != nil {
		return err
	}

	ns, err := state.LoadNetworkState(stateDir)
	if err != nil {
		return fmt.Errorf("loading network state: %w", err)
	}
	if ns == nil {
		return fmt.Errorf("not in a network. Use 'dwn-mesh network create' first.")
	}

	// Only the anchor (network owner) can deliver context keys.
	if ns.AnchorDID != identity.URI {
		return fmt.Errorf("only the network anchor (%s) can approve peers", ns.AnchorDID)
	}

	signer := &dwn.Signer{
		DID:        identity.URI,
		PrivateKey: identity.SigningKey,
	}
	encMgr := newEncryptionKeyManager(identity)

	kdm := &mesh.KeyDeliveryManager{
		Endpoint:             ns.AnchorEndpoint,
		Signer:               signer,
		EncryptionKeyManager: encMgr,
	}

	err = kdm.DeliverContextKey(ctx, mesh.DeliverContextKeyParams{
		AnchorDID:      identity.URI,
		RecipientDID:   peerDID,
		SourceProtocol: "https://enbox.org/protocols/wireguard-mesh",
		ContextID:      ns.NetworkRecordID,
	})
	if err != nil {
		return fmt.Errorf("delivering context key: %w", err)
	}

	fmt.Printf("Context key delivered to %s.\n", peerDID)
	fmt.Printf("The peer can now decrypt mesh records in this network.\n")
	return nil
}

// cmdStatus shows the current mesh status and identity info.
func cmdStatus(ctx context.Context, args []string) error {
	stateDir := state.DefaultStateDir()

	// Identity.
	if !did.Exists(stateDir) {
		fmt.Println("Not initialized. Run 'dwn-mesh init' first.")
		return nil
	}

	identity, err := did.Load(stateDir)
	if err != nil {
		return fmt.Errorf("loading identity: %w", err)
	}

	fmt.Printf("Identity:\n")
	fmt.Printf("  DID: %s\n", identity.URI)
	fmt.Printf("  State: %s\n", stateDir)

	// Network.
	ns, err := state.LoadNetworkState(stateDir)
	if err != nil {
		return fmt.Errorf("loading network state: %w", err)
	}
	if ns == nil {
		fmt.Printf("\nNetwork: none (run 'dwn-mesh network create' or 'network join')\n")
		return nil
	}

	fmt.Printf("\nNetwork:\n")
	fmt.Printf("  Name: %s\n", ns.NetworkName)
	fmt.Printf("  CIDR: %s\n", ns.MeshCIDR)
	fmt.Printf("  Anchor DID: %s\n", ns.AnchorDID)
	fmt.Printf("  Anchor Endpoint: %s\n", ns.AnchorEndpoint)
	fmt.Printf("  Network Record: %s\n", ns.NetworkRecordID)
	if ns.MeshIP != "" {
		fmt.Printf("  Mesh IP: %s\n", ns.MeshIP)
	}
	if ns.WireGuardPublicKey != "" {
		fmt.Printf("  WireGuard Key: %s\n", ns.WireGuardPublicKey)
	}
	if ns.NodeInfoRecordID != "" {
		fmt.Printf("  NodeInfo Record: %s\n", ns.NodeInfoRecordID)
	}

	return nil
}

// cmdUp starts the mesh agent daemon.
//
// This brings up the WireGuard tunnel by:
//  1. Loading identity and network state
//  2. Creating the engine (DWN client + meshnet backend)
//  3. Starting the WireGuard tunnel
//  4. Blocking until interrupted (Ctrl+C / SIGTERM)
func cmdUp(ctx context.Context, args []string) error {
	stateDir := state.DefaultStateDir()
	identity, err := loadIdentity(stateDir)
	if err != nil {
		return err
	}

	ns, err := state.LoadNetworkState(stateDir)
	if err != nil {
		return fmt.Errorf("loading network state: %w", err)
	}
	if ns == nil {
		return fmt.Errorf("not in a network. Use 'dwn-mesh network create' or 'network join' first.")
	}

	// Parse optional flags.
	var listenPort uint16
	var pollInterval time.Duration
	verbose := false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--port":
			if i+1 < len(args) {
				var p int
				if _, err := fmt.Sscanf(args[i+1], "%d", &p); err == nil && p > 0 && p <= 65535 {
					listenPort = uint16(p)
				}
				i++
			}
		case "--poll-interval":
			if i+1 < len(args) {
				if d, err := time.ParseDuration(args[i+1]); err == nil {
					pollInterval = d
				}
				i++
			}
		case "-v", "--verbose":
			verbose = true
		}
	}

	// Set up logging.
	logLevel := slog.LevelInfo
	if verbose {
		logLevel = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: logLevel,
	}))

	signer := &dwn.Signer{
		DID:        identity.URI,
		PrivateKey: identity.SigningKey,
	}

	encMgr := newEncryptionKeyManager(identity)

	// For non-anchor nodes: fetch the context key from the anchor so we
	// can encrypt records with Protocol Context scheme (which the anchor
	// can decrypt using the shared context key).
	useContextEncryption := false
	if ns.AnchorDID != identity.URI {
		contextKey, err := fetchContextKey(ctx, identity, ns)
		if err != nil {
			slog.Warn("context key fetch failed (will retry on next up)",
				slog.Any("error", err),
			)
		} else if contextKey != nil {
			privBytes, err := contextKey.PrivateKeyBytes()
			if err != nil {
				return fmt.Errorf("extracting context key bytes: %w", err)
			}
			encMgr.StoreContextKey(ns.NetworkRecordID, privBytes)
			useContextEncryption = true
			fmt.Printf("  Context key: received (Protocol Context encryption enabled)\n")
		} else {
			fmt.Printf("  Context key: not yet delivered (run 'peer approve' on anchor)\n")
			fmt.Printf("  Records will be written with Protocol Path encryption.\n")
		}
	}

	fmt.Printf("Starting dwn-mesh...\n")
	fmt.Printf("  Network: %s\n", ns.NetworkName)
	fmt.Printf("  DID: %s\n", identity.URI)
	fmt.Printf("  Mesh IP: %s\n", ns.MeshIP)
	fmt.Printf("  Anchor: %s\n", ns.AnchorEndpoint)

	// If we have a context key, re-register nodeInfo with Protocol Context
	// encryption. The initial registration during "network join" used Protocol
	// Path encryption (our own key) which the anchor can't decrypt. Re-writing
	// with Protocol Context encryption allows the anchor to read our nodeInfo.
	// The $squash directive means this overwrites the existing record.
	if useContextEncryption && ns.NodeInfoRecordID != "" {
		reg, err := mesh.RegisterNode(ctx, mesh.RegisterNodeParams{
			AnchorEndpoint:       ns.AnchorEndpoint,
			AnchorDID:            ns.AnchorDID,
			NetworkRecordID:      ns.NetworkRecordID,
			SelfDID:              identity.URI,
			Signer:               signer,
			EncryptionKeyManager: encMgr,
			WireGuardPubKey:      ns.WireGuardPublicKey,
			MeshIP:               ns.MeshIP,
			ProtocolRole:         "network/member",
			UseContextEncryption: true,
			ExistingNodeInfoRecordID: ns.NodeInfoRecordID,
		})
		if err != nil {
			logger.Warn("nodeInfo re-registration with context encryption failed",
				slog.Any("error", err),
			)
		} else {
			fmt.Printf("  NodeInfo re-encrypted with context key.\n")
			_ = reg // recordID unchanged due to $squash
		}
	}

	// Write/update endpoint record (encrypted) before starting the engine.
	if ns.NodeInfoRecordID != "" {
		localEndpoints := mesh.DiscoverLocalEndpoints(listenPort)
		wpParams := mesh.WriteEndpointParams{
			AnchorEndpoint:       ns.AnchorEndpoint,
			AnchorDID:            ns.AnchorDID,
			NetworkRecordID:      ns.NetworkRecordID,
			NodeInfoRecordID:     ns.NodeInfoRecordID,
			Signer:               signer,
			EncryptionKeyManager: encMgr,
			LocalEndpoints:       localEndpoints,
			NATType:              "unknown",
			UseContextEncryption: useContextEncryption,
		}
		// Non-anchor nodes must invoke their role for authorization.
		if ns.AnchorDID != identity.URI {
			wpParams.ProtocolRole = "network/member"
		}
		err = mesh.WriteEndpoint(ctx, wpParams)
		if err != nil {
			logger.Warn("endpoint write failed (non-fatal)", slog.Any("error", err))
		} else {
			fmt.Printf("  Endpoint record updated (encrypted).\n")
		}
	}

	// If this node is the anchor, enable automatic context key delivery
	// so new members get decryption keys without manual "peer approve".
	var autoKeyDelivery *engine.AutoKeyDelivery
	if ns.AnchorDID == identity.URI {
		autoKeyDelivery = engine.NewAutoKeyDelivery(engine.AutoKeyDeliveryConfig{
			Endpoint:             ns.AnchorEndpoint,
			AnchorDID:            ns.AnchorDID,
			NetworkRecordID:      ns.NetworkRecordID,
			Signer:               signer,
			EncryptionKeyManager: encMgr,
			Logger:               logger,
		})
		if autoKeyDelivery != nil {
			fmt.Printf("  Auto key delivery: enabled (anchor node)\n")
		}
	}

	eng, err := engine.New(engine.Config{
		AnchorEndpoint:       ns.AnchorEndpoint,
		AnchorTenant:         ns.AnchorDID,
		NetworkRecordID:      ns.NetworkRecordID,
		SelfDID:              identity.URI,
		Signer:               signer,
		Resolver:             universalResolver{},
		EncryptionKeyManager: encMgr,
		NodeInfoRecordID:     ns.NodeInfoRecordID,
		AutoKeyDelivery:      autoKeyDelivery,
		UseContextEncryption: useContextEncryption,
		Domain:               ns.NetworkName,
		ListenPort:           listenPort,
		PollInterval:         pollInterval,
		Logger:               logger,
	})
	if err != nil {
		return fmt.Errorf("creating engine: %w", err)
	}

	// Start the engine.
	if err := eng.Start(ctx); err != nil {
		return fmt.Errorf("starting engine: %w", err)
	}

	fmt.Printf("  Status: running\n")
	if ns.MeshIP != "" {
		fmt.Printf("  Mesh IP: %s\n", ns.MeshIP)
	}
	fmt.Printf("\nPress Ctrl+C to stop.\n")

	// Block until interrupted.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	fmt.Printf("\nShutting down...\n")
	if err := eng.Stop(); err != nil {
		return fmt.Errorf("stopping engine: %w", err)
	}

	fmt.Printf("Stopped.\n")
	return nil
}

// cmdDown stops the mesh agent daemon.
//
// Currently this sends SIGTERM to a running `dwn-mesh up` process.
// In the future, this will communicate with a proper daemon via Unix socket.
func cmdDown(ctx context.Context, args []string) error {
	// For now, `down` is a placeholder. The `up` command runs in the foreground
	// and can be stopped with Ctrl+C. A proper daemon mode with `down` support
	// will be added when we implement the IPN socket-based architecture.
	fmt.Println("dwn-mesh down: not yet implemented for daemon mode.")
	fmt.Println("Stop the running 'dwn-mesh up' process with Ctrl+C or SIGTERM.")
	return nil
}

// loadIdentity loads the DID identity, or returns an error if not initialized.
func loadIdentity(stateDir string) (*did.DID, error) {
	if !did.Exists(stateDir) {
		return nil, fmt.Errorf("not initialized. Run 'dwn-mesh init' first.")
	}
	identity, err := did.Load(stateDir)
	if err != nil {
		return nil, fmt.Errorf("loading identity: %w", err)
	}
	return identity, nil
}

// newEncryptionKeyManager creates an EncryptionKeyManager from a DID identity.
func newEncryptionKeyManager(identity *did.DID) *dwncrypto.EncryptionKeyManager {
	return &dwncrypto.EncryptionKeyManager{
		RootPrivateKey: identity.EncryptionPrivateKey,
		RootKeyID:      identity.EncryptionKeyID(),
		ProtocolURI:    "https://enbox.org/protocols/wireguard-mesh",
	}
}

// fetchContextKey fetches the Protocol Context key from the anchor's DWN
// for the current network. This allows a non-anchor node to encrypt records
// using the Protocol Context scheme, which the anchor can decrypt.
//
// Returns nil (no error) if no context key has been delivered yet.
func fetchContextKey(ctx context.Context, identity *did.DID, ns *state.NetworkState) (*dwncrypto.DerivedPrivateJwk, error) {
	signer := &dwn.Signer{
		DID:        identity.URI,
		PrivateKey: identity.SigningKey,
	}

	// Derive the decryption key for the key-delivery protocol's contextKey
	// path. The anchor encrypted the contextKey record using Protocol Path
	// scheme for the key-delivery protocol, so we need our own root key to
	// derive the key-delivery decryption key.
	decryptionKey, err := dwncrypto.DeriveKeyDeliveryDecryptionKey(
		identity.EncryptionPrivateKey,
		protocols.KeyDeliveryProtocolURI,
	)
	if err != nil {
		return nil, fmt.Errorf("deriving key-delivery decryption key: %w", err)
	}

	return mesh.FetchContextKey(ctx, mesh.FetchContextKeyParams{
		AnchorEndpoint:       ns.AnchorEndpoint,
		AnchorDID:            ns.AnchorDID,
		SelfDID:              identity.URI,
		Signer:               signer,
		SourceProtocol:       protocols.MeshProtocolURI,
		ContextID:            ns.NetworkRecordID,
		DecryptionPrivateKey: decryptionKey,
		DecryptionKeyID:      identity.EncryptionKeyID(),
	})
}

// universalResolver adapts the pkg/dids universal resolver to the
// control.Resolver interface.
type universalResolver struct{}

func (r universalResolver) ResolveWithContext(ctx context.Context, uri string) (didcore.ResolutionResult, error) {
	return dids.ResolveWithContext(ctx, uri)
}

// truncate shortens a string to maxLen, adding "..." if truncated.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}
