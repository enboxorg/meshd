package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/enboxorg/meshd/internal/daemon"
	"github.com/enboxorg/meshd/internal/did"
	"github.com/enboxorg/meshd/internal/dwn"
	dwncrypto "github.com/enboxorg/meshd/internal/dwn/crypto"
	"github.com/enboxorg/meshd/internal/engine"
	"github.com/enboxorg/meshd/internal/mesh"
	"github.com/enboxorg/meshd/internal/profile"
	"github.com/enboxorg/meshd/internal/state"
	"github.com/enboxorg/meshd/pkg/dids"
	"github.com/enboxorg/meshd/pkg/dids/didcore"
	"github.com/enboxorg/meshd/protocols"
)

const usage = `meshd - Decentralized WireGuard mesh networking via DWN

Usage:
  meshd <command> [arguments]

Identity:
  auth login        Create a new identity profile
  auth list         List all profiles
  auth use <name>   Set the default profile
  auth logout       Remove a profile from config
  init              Generate DID identity and publish to DHT

Network:
  network create    Create a new mesh network on a DWN
  network join      Join an existing mesh network
  network leave     Leave the current mesh network
  peer add          Add a peer to the mesh (anchor only)
  peer list         List all peers in the mesh
  peer approve      Deliver encryption keys to a peer (anchor only)
  status            Show mesh status and identity info
  up                Start the mesh agent daemon
  down              Stop the mesh agent daemon

Up flags:
  --create <name>   Create a new network and start (anchor mode)
  --endpoint <url>  DWN endpoint (or set DWN_ENDPOINT env var)
  --anchor <did>    Anchor DID when joining a network
  --network <id>    Network record ID when joining a network
  --tun [name]      Create a real TUN device (default: meshd0, auto if root)
  --no-tun          Disable auto TUN even when running as root
  --port <n>        WireGuard UDP listen port (default: auto)
  --poll-interval   DWN poll interval (default: 30s)
  -v, --verbose     Enable debug logging

Quick start:
  meshd up --create my-network --endpoint https://dwn.example.com
  meshd up --endpoint <url> --anchor <did> --network <id>

Global flags:
  --profile <name>  Use a specific identity profile
  -h, --help        Show this help message
  -v, --version     Show version information

Environment:
  ENBOX_HOME         Override ~/.enbox base directory
  ENBOX_PROFILE      Override active profile
  MESHD_STATE_DIR    Override state directory (bypasses profiles)
  DWN_ENDPOINT       Default DWN endpoint URL
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
			"peer list", "peer add", "peer remove", "peer approve",
			"auth login", "auth list", "auth use", "auth logout":
			cmd = combined
			args = os.Args[3:]
		}
	}

	// Extract --profile flag from args before dispatching.
	flagProfile, args := extractProfileFlag(args)

	ctx := context.Background()

	var err error
	switch cmd {
	case "-h", "--help", "help":
		fmt.Print(usage)
		return
	case "-v", "--version", "version":
		fmt.Printf("meshd %s\n", version)
		return
	case "auth", "auth login":
		err = cmdAuthLogin(ctx, args)
	case "auth list":
		err = cmdAuthList()
	case "auth use":
		err = cmdAuthUse(args)
	case "auth logout":
		err = cmdAuthLogout(args)
	case "init":
		err = cmdInit(ctx, args, flagProfile)
	case "network create":
		err = cmdNetworkCreate(ctx, args, flagProfile)
	case "network join":
		err = cmdNetworkJoin(ctx, args, flagProfile)
	case "network leave":
		err = cmdNetworkLeave(ctx, args, flagProfile)
	case "peer add":
		err = cmdPeerAdd(ctx, args, flagProfile)
	case "peer list":
		err = cmdPeerList(ctx, args, flagProfile)
	case "peer approve":
		err = cmdPeerApprove(ctx, args, flagProfile)
	case "status":
		err = cmdStatus(ctx, args, flagProfile)
	case "up":
		err = cmdUp(ctx, args, flagProfile)
	case "down":
		err = cmdDown(ctx, args)
	default:
		fmt.Fprintf(os.Stderr, "meshd: unknown command %q\n", cmd)
		fmt.Fprintf(os.Stderr, "Run 'meshd --help' for usage.\n")
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "meshd: %v\n", err)
		os.Exit(1)
	}
}

// cmdInit generates a did:jwk identity and stores it locally.
func cmdInit(ctx context.Context, args []string, flagProfile string) error {
	stateDir, err := resolveStateDir(flagProfile)
	if err != nil {
		return err
	}

	if did.Exists(stateDir) {
		identity, err := did.Load(stateDir)
		if err != nil {
			return fmt.Errorf("loading existing identity: %w", err)
		}
		fmt.Printf("Already initialized.\n")
		fmt.Printf("  DID: %s\n", identity.URI)
		fmt.Printf("  State: %s\n", stateDir)
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
	return nil
}



// cmdNetworkCreate creates a new mesh network.
//
// Usage: meshd network create <name> --endpoint <dwn-url>
func cmdNetworkCreate(ctx context.Context, args []string, flagProfile string) error {
	if len(args) < 3 {
		return fmt.Errorf("usage: meshd network create <name> --endpoint <dwn-url>")
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

	stateDir, err := resolveStateDir(flagProfile)
	if err != nil {
		return err
	}
	identity, err := loadIdentity(stateDir)
	if err != nil {
		return err
	}

	if state.HasNetwork(stateDir) {
		return fmt.Errorf("already in a network. Use 'meshd network leave' first.")
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

	// 5. Allocate mesh IP.
	meshIP, err := mesh.AllocateMeshIP(meshCIDR, identity.URI)
	if err != nil {
		return fmt.Errorf("allocating mesh IP: %w", err)
	}

	// 6. Register node on DWN (encrypted).
	reg, err := mesh.RegisterNode(ctx, mesh.RegisterNodeParams{
		AnchorEndpoint:       endpoint,
		AnchorDID:            identity.URI,
		NetworkRecordID:      record.ID,
		SelfDID:              identity.URI,
		Signer:               signer,
		EncryptionKeyManager: encMgr,
		MeshIP:               meshIP.String(),
	})
	if err != nil {
		fmt.Printf("  Warning: node registration failed: %v\n", err)
	} else {
		fmt.Printf("  Registered node (encrypted): IP=%s\n", meshIP)
	}

	// 7. Persist network state.
	ns := &state.NetworkState{
		NetworkRecordID: record.ID,
		AnchorDID:       identity.URI,
		AnchorEndpoint:  endpoint,
		NetworkName:     name,
		MeshCIDR:        meshCIDR,
		MeshIP:          meshIP.String(),
	}
	if reg != nil {
		ns.NodeRecordID = reg.NodeRecordID
		ns.NodeDateCreated = reg.DateCreated
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
	fmt.Printf("  meshd network join --endpoint %s --anchor %s --network %s\n",
		endpoint, identity.URI, record.ID)

	return nil
}

// cmdNetworkJoin joins an existing mesh network.
//
// Usage: meshd network join --endpoint <url> --anchor <did> --network <id>
func cmdNetworkJoin(ctx context.Context, args []string, flagProfile string) error {
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
		return fmt.Errorf("usage: meshd network join --endpoint <url> --anchor <did> --network <id>")
	}

	stateDir, err := resolveStateDir(flagProfile)
	if err != nil {
		return err
	}
	identity, err := loadIdentity(stateDir)
	if err != nil {
		return err
	}

	if state.HasNetwork(stateDir) {
		return fmt.Errorf("already in a network. Use 'meshd network leave' first.")
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

	// Allocate mesh IP.
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

	// Register node (encrypted). The node record replaces the old separate
	// member + nodeInfo records. The recipient field (SelfDID) assigns the
	// network/node role for authorization.
	var nodeRecordID string
	var nodeDateCreated string
	reg, err := mesh.RegisterNode(ctx, mesh.RegisterNodeParams{
		AnchorEndpoint:       endpoint,
		AnchorDID:            anchorDID,
		NetworkRecordID:      networkID,
		SelfDID:              identity.URI,
		Signer:               signer,
		EncryptionKeyManager: encMgr,
		MeshIP:               meshIP.String(),
		ProtocolRole:         "network/node",
	})
	if err != nil {
		fmt.Printf("  Warning: node registration failed: %v\n", err)
	} else {
		nodeRecordID = reg.NodeRecordID
		nodeDateCreated = reg.DateCreated
		fmt.Printf("  Registered node (encrypted): IP=%s\n", meshIP)
	}

	// Save network state locally.
	ns := &state.NetworkState{
		NetworkRecordID: networkID,
		AnchorDID:       anchorDID,
		AnchorEndpoint:  endpoint,
		NetworkName:     networkData.Name,
		MeshCIDR:        networkData.MeshCIDR,
		MeshIP:          meshIP.String(),
		NodeRecordID:    nodeRecordID,
		NodeDateCreated: nodeDateCreated,
	}
	if err := state.SaveNetworkState(stateDir, ns); err != nil {
		return fmt.Errorf("saving network state: %w", err)
	}

	fmt.Printf("Joined network.\n")
	fmt.Printf("  Name: %s\n", networkData.Name)
	fmt.Printf("  CIDR: %s\n", networkData.MeshCIDR)
	fmt.Printf("  Mesh IP: %s\n", meshIP)
	fmt.Printf("  Anchor: %s\n", anchorDID)
	fmt.Printf("\nRun 'meshd up' to start the mesh.\n")

	return nil
}

// cmdNetworkLeave leaves the current mesh network.
func cmdNetworkLeave(ctx context.Context, args []string, flagProfile string) error {
	stateDir, err := resolveStateDir(flagProfile)
	if err != nil {
		return err
	}

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
func cmdPeerList(ctx context.Context, args []string, flagProfile string) error {
	stateDir, err := resolveStateDir(flagProfile)
	if err != nil {
		return err
	}
	identity, err := loadIdentity(stateDir)
	if err != nil {
		return err
	}

	ns, err := state.LoadNetworkState(stateDir)
	if err != nil {
		return fmt.Errorf("loading network state: %w", err)
	}
	if ns == nil {
		return fmt.Errorf("not in a network. Use 'meshd network join' first.")
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

// cmdPeerAdd adds a peer to the mesh network. This creates a member record
// for the given DID on the anchor DWN and delivers the context encryption
// key so the peer can immediately decrypt mesh records.
//
// This must be run by the network anchor (owner). It combines the member
// record creation and key delivery into a single command.
//
// Usage: meshd peer add <did> [--label <label>]
func cmdPeerAdd(ctx context.Context, args []string, flagProfile string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: meshd peer add <did> [--label <label>]")
	}

	peerDID := args[0]
	label := "member"
	for i := 1; i < len(args); i++ {
		if args[i] == "--label" && i+1 < len(args) {
			label = args[i+1]
			i++
		}
	}

	stateDir, err := resolveStateDir(flagProfile)
	if err != nil {
		return err
	}
	identity, err := loadIdentity(stateDir)
	if err != nil {
		return err
	}

	ns, err := state.LoadNetworkState(stateDir)
	if err != nil {
		return fmt.Errorf("loading network state: %w", err)
	}
	if ns == nil {
		return fmt.Errorf("not in a network. Use 'meshd network create' first.")
	}

	// Only the anchor (network owner) can add peers.
	if ns.AnchorDID != identity.URI {
		return fmt.Errorf("only the network anchor (%s) can add peers", ns.AnchorDID)
	}

	signer := &dwn.Signer{
		DID:        identity.URI,
		PrivateKey: identity.SigningKey,
	}
	encMgr := newEncryptionKeyManager(identity)

	// 1. Create a node record for the peer (assigns the network/node role).
	// The peer's mesh IP is derived deterministically from their DID.
	fmt.Printf("Adding peer %s...\n", peerDID)
	peerMeshIP, err := mesh.AllocateMeshIP(ns.MeshCIDR, peerDID)
	if err != nil {
		return fmt.Errorf("allocating mesh IP for peer: %w", err)
	}
	_, err = mesh.RegisterNode(ctx, mesh.RegisterNodeParams{
		AnchorEndpoint:       ns.AnchorEndpoint,
		AnchorDID:            ns.AnchorDID,
		NetworkRecordID:      ns.NetworkRecordID,
		SelfDID:              peerDID,
		Signer:               signer,
		EncryptionKeyManager: encMgr,
		MeshIP:               peerMeshIP.String(),
		Label:                label,
	})
	if err != nil {
		return fmt.Errorf("creating node record: %w", err)
	}
	fmt.Printf("  Node record created (IP=%s).\n", peerMeshIP)

	// 2. Deliver the context encryption key so the peer can decrypt records.
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
		// Non-fatal: the member was created, key delivery can be retried
		// with `peer approve`.
		fmt.Printf("  Warning: context key delivery failed: %v\n", err)
		fmt.Printf("  The member was added but cannot decrypt records yet.\n")
		fmt.Printf("  Retry with: meshd peer approve %s\n", peerDID)
		return nil
	}
	fmt.Printf("  Context key delivered.\n")

	fmt.Printf("\nPeer added to network %q.\n", ns.NetworkName)
	fmt.Printf("The peer can now join with:\n")
	fmt.Printf("  meshd network join --endpoint %s --anchor %s --network %s\n",
		ns.AnchorEndpoint, ns.AnchorDID, ns.NetworkRecordID)

	return nil
}

// cmdPeerApprove delivers encryption keys to a peer so they can decrypt
// mesh records. This must be run by the network anchor (owner).
//
// Usage: meshd peer approve <did>
func cmdPeerApprove(ctx context.Context, args []string, flagProfile string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: meshd peer approve <did>")
	}

	peerDID := args[0]

	stateDir, err := resolveStateDir(flagProfile)
	if err != nil {
		return err
	}
	identity, err := loadIdentity(stateDir)
	if err != nil {
		return err
	}

	ns, err := state.LoadNetworkState(stateDir)
	if err != nil {
		return fmt.Errorf("loading network state: %w", err)
	}
	if ns == nil {
		return fmt.Errorf("not in a network. Use 'meshd network create' first.")
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
//
// If a daemon is running, it also queries live status via the control socket.
func cmdStatus(ctx context.Context, args []string, flagProfile string) error {
	stateDir, err := resolveStateDir(flagProfile)
	if err != nil {
		return err
	}

	// Identity.
	if !did.Exists(stateDir) {
		fmt.Println("Not initialized. Run 'meshd auth login' to create a profile.")
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
		fmt.Printf("\nNetwork: none (run 'meshd network create' or 'network join')\n")
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
	// WireGuard public key is derived from the identity, not stored.
	if identity != nil {
		wgPubKey, wgErr := mesh.WireGuardPubKeyFromDID(identity.URI)
		if wgErr == nil {
			fmt.Printf("  WireGuard Key: %s\n", wgPubKey)
		}
	}
	if ns.NodeRecordID != "" {
		fmt.Printf("  Node Record: %s\n", ns.NodeRecordID)
	}

	// Query live daemon status if running.
	client := daemon.NewClient(daemon.DefaultSocketPath())
	if client.IsRunning() {
		live, err := client.GetStatus(ctx)
		if err != nil {
			fmt.Printf("\nDaemon: running (status query failed: %v)\n", err)
		} else {
			fmt.Printf("\nDaemon:\n")
			fmt.Printf("  Running: yes (PID %d)\n", live.PID)
			fmt.Printf("  Uptime: %s\n", live.Uptime)
			if live.TUNDevice != "" {
				fmt.Printf("  TUN device: %s\n", live.TUNDevice)
			}
		}
	} else {
		fmt.Printf("\nDaemon: not running\n")
	}

	return nil
}

// upFlags holds parsed flags for the `meshd up` command.
type upFlags struct {
	// Network setup flags.
	createNetwork string // --create <name>: create a new network
	endpoint      string // --endpoint <url>: DWN endpoint
	anchorDID     string // --anchor <did>: anchor DID for joining
	networkID     string // --network <id>: network record ID for joining

	// Engine flags.
	tunName      string        // --tun [name]: TUN device name
	noTun        bool          // --no-tun: disable auto TUN
	listenPort   uint16        // --port <n>
	pollInterval time.Duration // --poll-interval <dur>
	verbose      bool          // -v / --verbose
}

func parseUpFlags(args []string) upFlags {
	var f upFlags
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--create":
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				f.createNetwork = args[i+1]
				i++
			}
		case "--endpoint":
			if i+1 < len(args) {
				f.endpoint = args[i+1]
				i++
			}
		case "--anchor":
			if i+1 < len(args) {
				f.anchorDID = args[i+1]
				i++
			}
		case "--network":
			if i+1 < len(args) {
				f.networkID = args[i+1]
				i++
			}
		case "--port":
			if i+1 < len(args) {
				var p int
				if _, err := fmt.Sscanf(args[i+1], "%d", &p); err == nil && p > 0 && p <= 65535 {
					f.listenPort = uint16(p)
				}
				i++
			}
		case "--poll-interval":
			if i+1 < len(args) {
				if d, err := time.ParseDuration(args[i+1]); err == nil {
					f.pollInterval = d
				}
				i++
			}
		case "--tun":
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				f.tunName = args[i+1]
				i++
			} else {
				f.tunName = "meshd0"
			}
		case "--no-tun":
			f.noTun = true
		case "-v", "--verbose":
			f.verbose = true
		}
	}

	// Fall back to DWN_ENDPOINT env var.
	if f.endpoint == "" {
		f.endpoint = os.Getenv("DWN_ENDPOINT")
	}

	// Auto-enable TUN when running as root (unless --no-tun or --tun already set).
	if f.tunName == "" && !f.noTun && os.Getuid() == 0 {
		f.tunName = "meshd0"
	}

	return f
}

// cmdUp starts the mesh agent daemon.
//
// This is the main entry point for meshd. It handles the full lifecycle:
//  1. Creates an identity profile if none exists
//  2. Creates or joins a network if not yet in one
//  3. Starts the WireGuard tunnel
//  4. Blocks until interrupted (Ctrl+C / SIGTERM)
//
// Flags like --create, --endpoint, --anchor, --network allow one-command
// setup. Without flags, it guides the user interactively.
func cmdUp(ctx context.Context, args []string, flagProfile string) error {
	f := parseUpFlags(args)

	// ── Step 1: Ensure identity exists ──────────────────────────────
	stateDir, err := resolveStateDir(flagProfile)
	if err != nil {
		return err
	}

	var identity *did.DID
	if did.Exists(stateDir) {
		identity, err = did.Load(stateDir)
		if err != nil {
			return fmt.Errorf("loading identity: %w", err)
		}
	} else {
		fmt.Println("No identity found. Creating one...")
		identity, err = ensureIdentity(ctx, flagProfile, f.endpoint)
		if err != nil {
			return err
		}
		// Re-resolve stateDir after profile creation.
		stateDir, err = resolveStateDir(flagProfile)
		if err != nil {
			return err
		}
	}

	// ── Step 2: Ensure network membership ───────────────────────────
	ns, err := state.LoadNetworkState(stateDir)
	if err != nil {
		return fmt.Errorf("loading network state: %w", err)
	}

	if ns == nil {
		// Not in a network. Use flags or prompt interactively.
		ns, err = ensureNetwork(ctx, f, stateDir, identity)
		if err != nil {
			return err
		}
	}

	// ── Step 3: Start the engine ────────────────────────────────────

	// Set up logging.
	logLevel := slog.LevelInfo
	if f.verbose {
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

	// Derive WireGuard key pair from identity (no separate WG key generation).
	wgKeys, err := mesh.WireGuardKeyFromIdentity(identity.EncryptionPrivateKey)
	if err != nil {
		return fmt.Errorf("deriving WireGuard keys from identity: %w", err)
	}

	fmt.Printf("Starting meshd...\n")
	fmt.Printf("  Network: %s\n", ns.NetworkName)
	fmt.Printf("  DID: %s\n", identity.URI)
	fmt.Printf("  Mesh IP: %s\n", ns.MeshIP)
	fmt.Printf("  Anchor: %s\n", ns.AnchorEndpoint)

	// If we have a context key, re-register node with Protocol Context
	// encryption. The initial registration during "network join" used Protocol
	// Path encryption (our own key) which the anchor can't decrypt. Re-writing
	// with Protocol Context encryption allows the anchor to read our node record.
	// This is a RecordsWrite update (same recordId, preserved dateCreated).
	if useContextEncryption && ns.NodeRecordID != "" {
		reg, err := mesh.RegisterNode(ctx, mesh.RegisterNodeParams{
			AnchorEndpoint:       ns.AnchorEndpoint,
			AnchorDID:            ns.AnchorDID,
			NetworkRecordID:      ns.NetworkRecordID,
			SelfDID:              identity.URI,
			Signer:               signer,
			EncryptionKeyManager: encMgr,
			MeshIP:               ns.MeshIP,
			ProtocolRole:         "network/node",
			UseContextEncryption: true,
			ExistingNodeRecordID: ns.NodeRecordID,
			ExistingDateCreated:  ns.NodeDateCreated,
		})
		if err != nil {
			logger.Warn("node re-registration with context encryption failed",
				slog.Any("error", err),
			)
		} else {
			// Update state — recordId stays the same for updates, but store dateCreated.
			if reg.NodeRecordID != "" {
				ns.NodeRecordID = reg.NodeRecordID
			}
			if reg.DateCreated != "" {
				ns.NodeDateCreated = reg.DateCreated
			}
			fmt.Printf("  Node re-encrypted with context key.\n")
		}
	}

	// Write/update endpoint record (encrypted) before starting the engine.
	if ns.NodeRecordID != "" {
		localEndpoints := mesh.DiscoverLocalEndpoints(f.listenPort)
		wpParams := mesh.WriteEndpointParams{
			AnchorEndpoint:       ns.AnchorEndpoint,
			AnchorDID:            ns.AnchorDID,
			NetworkRecordID:      ns.NetworkRecordID,
			NodeRecordID:         ns.NodeRecordID,
			Signer:               signer,
			EncryptionKeyManager: encMgr,
			LocalEndpoints:       localEndpoints,
			NATType:              "unknown",
			UseContextEncryption: useContextEncryption,
		}
		// Non-anchor nodes must invoke their role for authorization.
		if ns.AnchorDID != identity.URI {
			wpParams.ProtocolRole = "network/node"
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
		NodeInfoRecordID:     ns.NodeRecordID,
		AutoKeyDelivery:      autoKeyDelivery,
		UseContextEncryption: useContextEncryption,
		WireGuardPrivateKey:  wgKeys.PrivateKey,
		TUNName:             f.tunName,
		Domain:               ns.NetworkName,
		ListenPort:           f.listenPort,
		PollInterval:         f.pollInterval,
		Logger:               logger,
	})
	if err != nil {
		return fmt.Errorf("creating engine: %w", err)
	}

	// Start the engine.
	if err := eng.Start(ctx); err != nil {
		return fmt.Errorf("starting engine: %w", err)
	}

	// ── Step 4: Start the daemon control socket ────────────────────
	socketPath := daemon.DefaultSocketPath()
	daemonSrv := daemon.NewServer(socketPath, func() daemon.Status {
		return daemon.Status{
			TUNDevice: eng.TUNDeviceName(),
			MeshIP:    ns.MeshIP,
			Network:   ns.NetworkName,
		}
	}, logger)

	if err := daemonSrv.Start(); err != nil {
		// Non-fatal: the mesh still works without the control socket.
		logger.Warn("daemon control socket failed to start", slog.Any("error", err))
	} else {
		defer daemonSrv.Stop()
	}

	fmt.Printf("  Status: running\n")
	if devName := eng.TUNDeviceName(); devName != "" {
		fmt.Printf("  TUN device: %s\n", devName)
	} else {
		fmt.Printf("  Mode: userspace (use --tun for kernel routing)\n")
	}
	if ns.MeshIP != "" {
		fmt.Printf("  Mesh IP: %s\n", ns.MeshIP)
	}
	fmt.Printf("  Socket: %s\n", socketPath)
	fmt.Printf("\nPress Ctrl+C or run 'meshd down' to stop.\n")

	// Block until interrupted by signal or daemon shutdown request.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	select {
	case <-sigCh:
	case <-daemonSrv.ShutdownCh():
	}

	fmt.Printf("\nShutting down...\n")
	if err := eng.Stop(); err != nil {
		return fmt.Errorf("stopping engine: %w", err)
	}

	fmt.Printf("Stopped.\n")
	return nil
}

// ensureIdentity creates a new identity profile when none exists.
// It's called by cmdUp when no identity is found.
func ensureIdentity(ctx context.Context, flagProfile, endpoint string) (*did.DID, error) {
	profileName := flagProfile
	if profileName == "" {
		profileName = "default"
	}

	identity, err := did.Generate()
	if err != nil {
		return nil, fmt.Errorf("generating DID: %w", err)
	}

	dataPath := profile.DataPath(profileName)
	if err := identity.Store(dataPath); err != nil {
		return nil, fmt.Errorf("storing identity: %w", err)
	}
	if err := profile.UpsertProfile(profileName, identity.URI); err != nil {
		return nil, fmt.Errorf("saving profile: %w", err)
	}

	fmt.Printf("  Profile: %s\n", profileName)
	fmt.Printf("  DID:     %s\n", identity.URI)
	fmt.Println()

	return identity, nil
}

// ensureNetwork handles network setup when the user is not yet in a network.
// It checks flags (--create, --anchor+--network) and falls back to an
// interactive prompt.
func ensureNetwork(ctx context.Context, f upFlags, stateDir string, identity *did.DID) (*state.NetworkState, error) {
	switch {
	case f.createNetwork != "":
		return setupCreateNetwork(ctx, f, stateDir, identity)
	case f.anchorDID != "" && f.networkID != "":
		return setupJoinNetwork(ctx, f, stateDir, identity)
	default:
		return setupInteractive(ctx, f, stateDir, identity)
	}
}

// setupCreateNetwork creates a new mesh network (anchor mode).
// This is the --create flag path.
func setupCreateNetwork(ctx context.Context, f upFlags, stateDir string, identity *did.DID) (*state.NetworkState, error) {
	if f.endpoint == "" {
		return nil, fmt.Errorf("--endpoint (or DWN_ENDPOINT env) is required to create a network")
	}

	fmt.Printf("Creating network %q on %s...\n", f.createNetwork, f.endpoint)

	// Delegate to the existing network create logic.
	err := cmdNetworkCreate(ctx, []string{f.createNetwork, "--endpoint", f.endpoint}, "")
	if err != nil {
		return nil, err
	}

	// Reload the network state that cmdNetworkCreate saved.
	ns, err := state.LoadNetworkState(stateDir)
	if err != nil {
		return nil, fmt.Errorf("loading network state after create: %w", err)
	}
	if ns == nil {
		return nil, fmt.Errorf("network state not found after create")
	}
	return ns, nil
}

// setupJoinNetwork joins an existing network using --anchor and --network flags.
func setupJoinNetwork(ctx context.Context, f upFlags, stateDir string, identity *did.DID) (*state.NetworkState, error) {
	if f.endpoint == "" {
		return nil, fmt.Errorf("--endpoint (or DWN_ENDPOINT env) is required to join a network")
	}

	fmt.Printf("Joining network on %s...\n", f.endpoint)

	err := cmdNetworkJoin(ctx, []string{
		"--endpoint", f.endpoint,
		"--anchor", f.anchorDID,
		"--network", f.networkID,
	}, "")
	if err != nil {
		return nil, err
	}

	ns, err := state.LoadNetworkState(stateDir)
	if err != nil {
		return nil, fmt.Errorf("loading network state after join: %w", err)
	}
	if ns == nil {
		return nil, fmt.Errorf("network state not found after join")
	}
	return ns, nil
}

// setupInteractive prompts the user to create or join a network.
func setupInteractive(ctx context.Context, f upFlags, stateDir string, identity *did.DID) (*state.NetworkState, error) {
	fmt.Println("No network configured. What would you like to do?")
	fmt.Println()
	fmt.Println("  1) Create a new network")
	fmt.Println("  2) Join an existing network")
	fmt.Println()
	fmt.Print("Choice [1/2]: ")

	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		return nil, fmt.Errorf("no input received")
	}
	choice := strings.TrimSpace(scanner.Text())

	fmt.Println()

	switch choice {
	case "1":
		return interactiveCreate(ctx, f, stateDir, identity, scanner)
	case "2":
		return interactiveJoin(ctx, f, stateDir, identity, scanner)
	default:
		return nil, fmt.Errorf("invalid choice %q (expected 1 or 2)", choice)
	}
}

// interactiveCreate guides the user through creating a new network.
func interactiveCreate(ctx context.Context, f upFlags, stateDir string, identity *did.DID, scanner *bufio.Scanner) (*state.NetworkState, error) {
	endpoint := f.endpoint
	if endpoint == "" {
		fmt.Print("DWN endpoint URL: ")
		if !scanner.Scan() {
			return nil, fmt.Errorf("no input received")
		}
		endpoint = strings.TrimSpace(scanner.Text())
		if endpoint == "" {
			return nil, fmt.Errorf("endpoint URL is required")
		}
	}

	fmt.Print("Network name: ")
	if !scanner.Scan() {
		return nil, fmt.Errorf("no input received")
	}
	name := strings.TrimSpace(scanner.Text())
	if name == "" {
		return nil, fmt.Errorf("network name is required")
	}

	fmt.Println()
	f.endpoint = endpoint
	f.createNetwork = name
	return setupCreateNetwork(ctx, f, stateDir, identity)
}

// interactiveJoin guides the user through joining an existing network.
func interactiveJoin(ctx context.Context, f upFlags, stateDir string, identity *did.DID, scanner *bufio.Scanner) (*state.NetworkState, error) {
	endpoint := f.endpoint
	if endpoint == "" {
		fmt.Print("DWN endpoint URL: ")
		if !scanner.Scan() {
			return nil, fmt.Errorf("no input received")
		}
		endpoint = strings.TrimSpace(scanner.Text())
		if endpoint == "" {
			return nil, fmt.Errorf("endpoint URL is required")
		}
	}

	fmt.Print("Anchor DID: ")
	if !scanner.Scan() {
		return nil, fmt.Errorf("no input received")
	}
	anchorDID := strings.TrimSpace(scanner.Text())
	if anchorDID == "" {
		return nil, fmt.Errorf("anchor DID is required")
	}

	fmt.Print("Network ID: ")
	if !scanner.Scan() {
		return nil, fmt.Errorf("no input received")
	}
	networkID := strings.TrimSpace(scanner.Text())
	if networkID == "" {
		return nil, fmt.Errorf("network ID is required")
	}

	fmt.Println()
	f.endpoint = endpoint
	f.anchorDID = anchorDID
	f.networkID = networkID
	return setupJoinNetwork(ctx, f, stateDir, identity)
}

// cmdDown stops the mesh agent daemon by sending a shutdown request via the
// Unix control socket.
//
// Usage: meshd down
func cmdDown(ctx context.Context, args []string) error {
	socketPath := daemon.DefaultSocketPath()
	client := daemon.NewClient(socketPath)

	if !client.IsRunning() {
		fmt.Println("meshd is not running.")
		return nil
	}

	fmt.Printf("Stopping meshd (socket: %s)...\n", socketPath)
	if err := client.Shutdown(ctx); err != nil {
		return fmt.Errorf("shutdown failed: %w", err)
	}

	// Wait for the daemon to actually stop (socket goes away).
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if !client.IsRunning() {
			fmt.Println("Stopped.")
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}

	fmt.Println("Shutdown request sent but daemon is still running.")
	fmt.Println("You may need to send SIGTERM manually.")
	return nil
}

// loadIdentity loads the DID identity, or returns an error if not initialized.
func loadIdentity(stateDir string) (*did.DID, error) {
	if !did.Exists(stateDir) {
		return nil, fmt.Errorf("not initialized. Run 'meshd auth login' to create a profile")
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

	// contextKey records are written unencrypted (access controlled by
	// key-delivery protocol $actions). The recipient can query and read
	// their own records via the DWN's implicit recipient authorization.
	return mesh.FetchContextKey(ctx, mesh.FetchContextKeyParams{
		AnchorEndpoint: ns.AnchorEndpoint,
		AnchorDID:      ns.AnchorDID,
		SelfDID:        identity.URI,
		Signer:         signer,
	})
}

// universalResolver adapts the pkg/dids universal resolver to the
// control.Resolver interface.
type universalResolver struct{}

func (r universalResolver) ResolveWithContext(ctx context.Context, uri string) (didcore.ResolutionResult, error) {
	return dids.ResolveWithContext(ctx, uri)
}

// extractProfileFlag extracts --profile <name> from args, returning the
// profile name and the remaining args with the flag removed.
func extractProfileFlag(args []string) (string, []string) {
	for i := 0; i < len(args); i++ {
		if args[i] == "--profile" && i+1 < len(args) {
			name := args[i+1]
			remaining := make([]string, 0, len(args)-2)
			remaining = append(remaining, args[:i]...)
			remaining = append(remaining, args[i+2:]...)
			return name, remaining
		}
	}
	return "", args
}

// resolveStateDir resolves the state directory from the active profile.
// If MESHD_STATE_DIR is set, it takes absolute precedence.
func resolveStateDir(flagProfile string) (string, error) {
	return profile.ResolveDataPath(flagProfile)
}

// cmdAuthLogin creates a new identity profile.
//
// Usage: meshd auth login [name]
func cmdAuthLogin(ctx context.Context, args []string) error {
	var profileName string
	for i := 0; i < len(args); i++ {
		if profileName == "" && !strings.HasPrefix(args[i], "-") {
			profileName = args[i]
		}
	}

	if profileName == "" {
		profileName = "default"
	}

	if err := profile.ValidateName(profileName); err != nil {
		return err
	}

	// Check if profile already exists.
	cfg, err := profile.ReadConfig()
	if err != nil {
		return err
	}
	if cfg.Profiles[profileName] != nil {
		return fmt.Errorf("profile %q already exists (DID: %s)", profileName, cfg.Profiles[profileName].DID)
	}

	// Generate identity.
	identity, err := did.Generate()
	if err != nil {
		return fmt.Errorf("generating DID: %w", err)
	}

	// Store identity in profile directory.
	dataPath := profile.DataPath(profileName)
	if err := identity.Store(dataPath); err != nil {
		return fmt.Errorf("storing identity: %w", err)
	}

	// Register profile in config.json.
	if err := profile.UpsertProfile(profileName, identity.URI); err != nil {
		return fmt.Errorf("saving profile: %w", err)
	}

	fmt.Printf("Created profile %q.\n", profileName)
	fmt.Printf("  DID:   %s\n", identity.URI)
	fmt.Printf("  State: %s\n", dataPath)

	return nil
}

// cmdAuthList lists all identity profiles.
func cmdAuthList() error {
	cfg, err := profile.ReadConfig()
	if err != nil {
		return err
	}

	if len(cfg.Profiles) == 0 {
		fmt.Println("No profiles configured.")
		fmt.Println("Run 'meshd auth login [name]' to create one.")
		return nil
	}

	fmt.Printf("Profiles (%s):\n\n", profile.EnboxHome())

	for _, entry := range cfg.Profiles {
		marker := "  "
		suffix := ""
		if entry.Name == cfg.DefaultProfile {
			marker = "* "
			suffix = " (default)"
		}
		fmt.Printf("%s%s%s\n", marker, entry.Name, suffix)
		fmt.Printf("    DID:     %s\n", entry.DID)
		fmt.Printf("    Created: %s\n", entry.CreatedAt)
		fmt.Println()
	}

	return nil
}

// cmdAuthUse sets the default profile.
//
// Usage: meshd auth use <name>
func cmdAuthUse(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: meshd auth use <name>")
	}

	name := args[0]

	cfg, err := profile.ReadConfig()
	if err != nil {
		return err
	}

	if cfg.Profiles[name] == nil {
		return fmt.Errorf("profile %q not found", name)
	}

	cfg.DefaultProfile = name
	if err := profile.WriteConfig(cfg); err != nil {
		return err
	}

	fmt.Printf("Default profile set to %q.\n", name)
	return nil
}

// cmdAuthLogout removes a profile from config.
//
// Usage: meshd auth logout [name]
func cmdAuthLogout(args []string) error {
	name := ""
	if len(args) > 0 {
		name = args[0]
	}

	if name == "" {
		// Use the default profile.
		cfg, err := profile.ReadConfig()
		if err != nil {
			return err
		}
		name = cfg.DefaultProfile
		if name == "" {
			return fmt.Errorf("usage: meshd auth logout <name>")
		}
	}

	if err := profile.RemoveProfile(name); err != nil {
		return err
	}

	fmt.Printf("Removed profile %q from config.\n", name)
	fmt.Printf("Data directory preserved at: %s\n", profile.DataPath(name))
	return nil
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
