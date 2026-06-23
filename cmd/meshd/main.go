package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/enboxorg/meshd/internal/control"
	"github.com/enboxorg/meshd/internal/daemon"
	"github.com/enboxorg/meshd/internal/did"
	"github.com/enboxorg/meshd/internal/dwn"
	dwncrypto "github.com/enboxorg/meshd/internal/dwn/crypto"
	"github.com/enboxorg/meshd/internal/engine"
	"github.com/enboxorg/meshd/internal/invite"
	"github.com/enboxorg/meshd/internal/mesh"
	"github.com/enboxorg/meshd/internal/profile"
	"github.com/enboxorg/meshd/internal/state"
	"github.com/enboxorg/meshd/pkg/dids"
	"github.com/enboxorg/meshd/pkg/dids/didcore"
	"github.com/enboxorg/meshd/protocols"
	"golang.org/x/term"
)

const usage = `meshd - Decentralized WireGuard mesh networking via DWN

Usage:
  meshd <command> [arguments]

Identity:
  auth login        Create a new identity profile
  auth list         List all profiles
  auth use <name>   Set the default profile
  auth logout       Remove a profile from config
  init              Generate DID identity and store locally
  vault status      Show local vault state
  vault init        Encrypt a legacy plaintext identity
  vault unlock      Verify the vault password and show identity

Network:
  network create    Create a new mesh network on a DWN
  network join      Join an existing mesh network
  network leave     Leave the current mesh network
  invite create     Create an invite URL for joining this network
  join <url>        Join a network from a meshd://invite URL
  peer add          Add a peer to the mesh (anchor only)
  peer list         List all peers in the mesh
  peer approve      Deliver encryption keys to a peer (anchor only)
  acl set <file>    Set ACL policy from a JSON file (anchor only)
  acl show          Show the current ACL policy
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
  meshd invite create
  meshd join meshd://invite/<token>

Global flags:
  --profile <name>  Use a specific identity profile
  -h, --help        Show this help message
  -v, --version     Show version information

Environment:
  ENBOX_HOME         Override ~/.enbox base directory
  ENBOX_PROFILE      Override active profile
  MESHD_STATE_DIR    Override state directory (bypasses profiles)
  MESHD_VAULT_PASSWORD
                     Unlock/create vault non-interactively
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
			"invite create",
			"peer list", "peer add", "peer approve",
			"acl set", "acl show",
			"auth login", "auth list", "auth use", "auth logout",
			"vault status", "vault init", "vault unlock":
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
	case "vault status":
		err = cmdVaultStatus(args, flagProfile)
	case "vault init":
		err = cmdVaultInit(args, flagProfile)
	case "vault unlock":
		err = cmdVaultUnlock(args, flagProfile)
	case "network create":
		err = cmdNetworkCreate(ctx, args, flagProfile)
	case "network join":
		err = cmdNetworkJoin(ctx, args, flagProfile)
	case "network leave":
		err = cmdNetworkLeave(ctx, args, flagProfile)
	case "invite create":
		err = cmdInviteCreate(ctx, args, flagProfile)
	case "join":
		err = cmdJoin(ctx, args, flagProfile)
	case "peer add":
		err = cmdPeerAdd(ctx, args, flagProfile)
	case "peer list":
		err = cmdPeerList(ctx, args, flagProfile)
	case "peer approve":
		err = cmdPeerApprove(ctx, args, flagProfile)
	case "acl set":
		err = cmdACLSet(ctx, args, flagProfile)
	case "acl show":
		err = cmdACLShow(ctx, args, flagProfile)
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
	profileName := ""
	if os.Getenv("MESHD_STATE_DIR") == "" {
		profileName = profileNameForWrite(flagProfile)
	}

	stateDir, err := resolveStateDir(flagProfile)
	if err == profile.ErrNoProfiles {
		stateDir = profile.DataPath(profileName)
		err = nil
	}
	if err != nil {
		return err
	}

	if identityExists(stateDir) {
		identity, err := loadIdentity(stateDir)
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

	if err := storeIdentityForCLI(identity, stateDir); err != nil {
		return fmt.Errorf("storing identity: %w", err)
	}
	if profileName != "" {
		if err := profile.UpsertProfile(profileName, identity.URI); err != nil {
			return fmt.Errorf("saving profile: %w", err)
		}
	}

	fmt.Printf("Initialized new identity.\n")
	fmt.Printf("  DID: %s\n", identity.URI)
	fmt.Printf("  State: %s\n", stateDir)
	fmt.Printf("  Vault: encrypted\n")
	return nil
}

func cmdVaultStatus(args []string, flagProfile string) error {
	if len(args) > 0 {
		return fmt.Errorf("usage: meshd vault status")
	}

	stateDir, err := resolveStateDir(flagProfile)
	if err == profile.ErrNoProfiles {
		fmt.Println("Vault: uninitialized")
		fmt.Println("Identity: none")
		return nil
	}
	if err != nil {
		return err
	}

	switch {
	case did.EncryptedExists(stateDir):
		fmt.Println("Vault: encrypted")
		if did.Exists(stateDir) {
			fmt.Println("Legacy plaintext identity: present")
			fmt.Println("Run 'meshd vault init' to remove the plaintext identity after unlock.")
		}
	case did.Exists(stateDir):
		fmt.Println("Vault: plaintext legacy")
		fmt.Println("Run 'meshd vault init' to encrypt it.")
	default:
		fmt.Println("Vault: uninitialized")
		fmt.Println("Identity: none")
	}
	fmt.Printf("State: %s\n", stateDir)
	return nil
}

func cmdVaultInit(args []string, flagProfile string) error {
	if len(args) > 0 {
		return fmt.Errorf("usage: meshd vault init")
	}

	stateDir, err := resolveStateDir(flagProfile)
	if err != nil {
		return err
	}
	if did.EncryptedExists(stateDir) {
		if did.Exists(stateDir) {
			if _, err := loadIdentity(stateDir); err != nil {
				return err
			}
			if err := did.RemovePlaintext(stateDir); err != nil {
				return err
			}
			fmt.Println("Removed legacy plaintext identity.")
		}
		fmt.Println("Vault already initialized.")
		fmt.Printf("State: %s\n", stateDir)
		return nil
	}
	if !did.Exists(stateDir) {
		return fmt.Errorf("no plaintext identity found to encrypt")
	}

	password, err := vaultPasswordForCreate()
	if err != nil {
		return err
	}
	if err := did.MigrateToEncrypted(stateDir, password); err != nil {
		return err
	}

	fmt.Println("Vault initialized.")
	fmt.Printf("State: %s\n", stateDir)
	return nil
}

func cmdVaultUnlock(args []string, flagProfile string) error {
	if len(args) > 0 {
		return fmt.Errorf("usage: meshd vault unlock")
	}

	stateDir, err := resolveStateDir(flagProfile)
	if err != nil {
		return err
	}
	identity, err := loadIdentity(stateDir)
	if err != nil {
		return err
	}

	fmt.Println("Vault unlocked.")
	fmt.Printf("DID: %s\n", identity.URI)
	fmt.Printf("State: %s\n", stateDir)
	return nil
}

// cmdNetworkCreate creates a new mesh network.
//
// Usage: meshd network create [name] [--endpoint <dwn-url>]
func cmdNetworkCreate(ctx context.Context, args []string, flagProfile string) error {
	name, endpoint := parseNetworkCreateArgs(args)
	if name == "" || endpoint == "" {
		if !stdinIsTerminal() {
			return fmt.Errorf("usage: meshd network create [name] [--endpoint <dwn-url>]")
		}
		scanner := bufio.NewScanner(os.Stdin)
		var err error
		if name == "" {
			name, err = promptRequired(scanner, "Network name")
			if err != nil {
				return err
			}
		}
		if endpoint == "" {
			endpoint, err = promptRequired(scanner, "DWN endpoint URL")
			if err != nil {
				return err
			}
		}
	}

	stateDir, identity, err := ensureIdentityForCommand(ctx, flagProfile, endpoint)
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
		ProtocolURI:    protocols.MeshProtocolURI,
	}

	// 2. Create the network record.
	// The "network" type does NOT have encryptionRequired — it's publicly
	// readable as the anchor record. No encryption on this write.
	meshCIDR := "10.200.0.0/16"
	networkData, _ := json.Marshal(map[string]any{
		"name":     name,
		"meshCIDR": meshCIDR,
	})

	record, writeStatus, err := api.Write(ctx, identity.URI, dwn.WriteParams{
		Protocol:     protocols.MeshProtocolURI,
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
		SourceProtocol: protocols.MeshProtocolURI,
		ContextID:      record.ID,
	}); err != nil {
		fmt.Printf("  Warning: context key self-delivery failed: %v\n", err)
	} else {
		fmt.Printf("  Context key delivered to self.\n")
	}

	// 4. Allocate mesh IP.
	meshIP, err := mesh.AllocateMeshIP(meshCIDR, identity.URI)
	if err != nil {
		return fmt.Errorf("allocating mesh IP: %w", err)
	}

	// 5. Register node on DWN (encrypted with Protocol Context).
	// Use context encryption so that peers with the shared context key can
	// decrypt the anchor's node record. The anchor already self-delivered the
	// context key above, and as the DWN owner it can derive the key from root.
	reg, err := mesh.RegisterNode(ctx, mesh.RegisterNodeParams{
		AnchorEndpoint:       endpoint,
		AnchorDID:            identity.URI,
		NetworkRecordID:      record.ID,
		NodeDID:              identity.URI,
		Signer:               signer,
		EncryptionKeyManager: encMgr,
		MeshIP:               meshIP.String(),
		UseContextEncryption: true,
	})
	if err != nil {
		fmt.Printf("  Warning: node registration failed: %v\n", err)
	} else {
		fmt.Printf("  Registered node (encrypted): IP=%s\n", meshIP)

		// 5b. Write nodeInfo (device-operational data: hostname, OS).
		if err := mesh.WriteNodeInfo(ctx, mesh.WriteNodeInfoParams{
			AnchorEndpoint:       endpoint,
			AnchorDID:            identity.URI,
			NetworkRecordID:      record.ID,
			NodeRecordID:         reg.NodeRecordID,
			Signer:               signer,
			EncryptionKeyManager: encMgr,
			UseContextEncryption: true,
		}); err != nil {
			fmt.Printf("  Warning: nodeInfo write failed: %v\n", err)
		} else {
			fmt.Printf("  NodeInfo written.\n")
		}
	}

	// 6. Persist network state.
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
	fmt.Printf("\nCreate a join invite with:\n")
	fmt.Printf("  meshd invite create\n")

	return nil
}

func parseNetworkCreateArgs(args []string) (name string, endpoint string) {
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--endpoint":
			if i+1 < len(args) {
				endpoint = args[i+1]
				i++
			}
		default:
			if name == "" && !strings.HasPrefix(args[i], "-") {
				name = args[i]
			}
		}
	}
	if endpoint == "" {
		endpoint = os.Getenv("DWN_ENDPOINT")
	}
	return name, endpoint
}

// cmdNetworkJoin joins an existing mesh network.
//
// Usage: meshd network join <invite-url>
// Usage: meshd network join --endpoint <url> --anchor <did> --network <id>
func cmdNetworkJoin(ctx context.Context, args []string, flagProfile string) error {
	if len(args) == 1 && strings.HasPrefix(strings.TrimSpace(args[0]), invite.SchemePrefix) {
		return cmdJoin(ctx, args, flagProfile)
	}

	endpoint, anchorDID, networkID, preauthRequested := parseNetworkJoinArgs(args)
	if endpoint == "" || anchorDID == "" || networkID == "" {
		if !stdinIsTerminal() {
			return fmt.Errorf("usage: meshd network join <invite-url> OR meshd network join --endpoint <url> --anchor <did> --network <id>")
		}
		scanner := bufio.NewScanner(os.Stdin)
		if len(args) == 0 {
			fmt.Print("Invite URL (or press Enter for manual join): ")
			if !scanner.Scan() {
				return fmt.Errorf("no input received")
			}
			inviteURL := strings.TrimSpace(scanner.Text())
			if inviteURL != "" {
				if !strings.HasPrefix(inviteURL, invite.SchemePrefix) {
					return fmt.Errorf("invite URL must start with %s", invite.SchemePrefix)
				}
				return cmdJoin(ctx, []string{inviteURL}, flagProfile)
			}
		}

		var err error
		if endpoint == "" {
			endpoint, err = promptRequired(scanner, "DWN endpoint URL")
			if err != nil {
				return err
			}
		}
		if anchorDID == "" {
			anchorDID, err = promptRequired(scanner, "Anchor DID")
			if err != nil {
				return err
			}
		}
		if networkID == "" {
			networkID, err = promptRequired(scanner, "Network record ID")
			if err != nil {
				return err
			}
		}
	}

	stateDir, identity, err := ensureIdentityForCommand(ctx, flagProfile, endpoint)
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
	// Network record is publicly readable (anyone can read).
	record, readStatus, err := api.Read(ctx, anchorDID, dwn.RecordsFilter{
		RecordID: networkID,
	}, "")
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

	// In the new protocol, the anchor creates node records via `peer add`.
	// The joining node discovers its pre-created node record by querying
	// for records where it is the recipient.
	//
	// Try to find our node record in both paths:
	//   - network/node (owner-provisioned)
	//   - network/member/node (member-associated)
	encMgr := newEncryptionKeyManager(identity)

	var nodeRecordID, nodeDateCreated, meshIP, memberRecordID string

	// Query network/node records to find one with our DID as recipient.
	nodeRecords, queryStatus, err := api.Query(ctx, anchorDID, dwn.QueryParams{
		Filter: dwn.RecordsFilter{
			Protocol:     protocols.MeshProtocolURI,
			ProtocolPath: "network/node",
			ContextID:    networkID,
			Recipient:    identity.URI,
		},
		DateSort: "createdDescending",
	}, "")
	if err != nil {
		fmt.Printf("  Warning: node query failed: %v\n", err)
	} else if queryStatus.Code == 200 && len(nodeRecords) > 0 {
		nodeRecordID = nodeRecords[0].ID
		nodeDateCreated = nodeRecords[0].DateCreated
		var nodeData struct {
			MeshIP string `json:"meshIP"`
		}
		if err := nodeRecords[0].Data().JSON(ctx, &nodeData); err == nil && nodeData.MeshIP != "" {
			meshIP = nodeData.MeshIP
		}
		fmt.Printf("  Found node record (owner-provisioned).\n")
	}

	// If not found, try network/member/node.
	if nodeRecordID == "" {
		memberNodeRecords, mQueryStatus, mErr := api.Query(ctx, anchorDID, dwn.QueryParams{
			Filter: dwn.RecordsFilter{
				Protocol:     protocols.MeshProtocolURI,
				ProtocolPath: "network/member/node",
				ContextID:    networkID,
				Recipient:    identity.URI,
			},
			DateSort: "createdDescending",
		}, "")
		if mErr != nil {
			fmt.Printf("  Warning: member node query failed: %v\n", mErr)
		} else if mQueryStatus.Code == 200 && len(memberNodeRecords) > 0 {
			nodeRecordID = memberNodeRecords[0].ID
			nodeDateCreated = memberNodeRecords[0].DateCreated
			var nodeData struct {
				MeshIP string `json:"meshIP"`
			}
			if err := memberNodeRecords[0].Data().JSON(ctx, &nodeData); err == nil && nodeData.MeshIP != "" {
				meshIP = nodeData.MeshIP
			}
			fmt.Printf("  Found node record (member-associated).\n")

			// Find the member record for this node.
			memberRecords, memStatus, memErr := api.Query(ctx, anchorDID, dwn.QueryParams{
				Filter: dwn.RecordsFilter{
					Protocol:     protocols.MeshProtocolURI,
					ProtocolPath: "network/member",
					ContextID:    networkID,
					Recipient:    identity.URI,
				},
				DateSort: "createdDescending",
			}, "")
			if memErr == nil && memStatus.Code == 200 && len(memberRecords) > 0 {
				memberRecordID = memberRecords[0].ID
			}
		}
	}

	// If no node record found, the anchor hasn't added us yet.
	// Allocate a mesh IP deterministically and save partial state.
	if meshIP == "" {
		allocatedIP, allocErr := mesh.AllocateMeshIP(networkData.MeshCIDR, identity.URI)
		if allocErr != nil {
			return fmt.Errorf("allocating mesh IP: %w", allocErr)
		}
		meshIP = allocatedIP.String()
	}

	if nodeRecordID == "" {
		if preauthRequested {
			fmt.Printf("  Join request submitted. Waiting for the anchor to approve this invite.\n")
			fmt.Printf("  Run 'meshd up' again after the anchor has processed the request.\n")
		} else {
			fmt.Printf("  No node record found — the anchor needs to run:\n")
			fmt.Printf("    meshd peer add %s\n", identity.URI)
		}
	}

	// Fetch and persist context key if available.
	var contextKeyPriv []byte
	useContextEnc := false
	if nodeRecordID != "" {
		contextKey, ckErr := fetchContextKey(ctx, identity, &state.NetworkState{
			AnchorEndpoint:  endpoint,
			AnchorDID:       anchorDID,
			NetworkRecordID: networkID,
		})
		if ckErr == nil && contextKey != nil {
			privBytes, pbErr := contextKey.PrivateKeyBytes()
			if pbErr == nil {
				encMgr.StoreContextKey(networkID, privBytes)
				contextKeyPriv = privBytes
				useContextEnc = true
			}
		}
	}

	// Write nodeInfo if we have a node record (so the network sees our hostname/OS).
	if nodeRecordID != "" {
		// Determine protocol role for the nodeInfo write.
		nodeInfoRole := "network/node"
		if memberRecordID != "" {
			nodeInfoRole = "network/member/node"
		}

		if err := mesh.WriteNodeInfo(ctx, mesh.WriteNodeInfoParams{
			AnchorEndpoint:       endpoint,
			AnchorDID:            anchorDID,
			NetworkRecordID:      networkID,
			MemberRecordID:       memberRecordID,
			NodeRecordID:         nodeRecordID,
			Signer:               signer,
			EncryptionKeyManager: encMgr,
			ProtocolRole:         nodeInfoRole,
			UseContextEncryption: useContextEnc,
		}); err != nil {
			fmt.Printf("  Warning: nodeInfo write failed: %v\n", err)
		} else {
			fmt.Printf("  NodeInfo written.\n")
		}
	}

	// Save network state locally (including context key for offline resilience).
	ns := &state.NetworkState{
		NetworkRecordID: networkID,
		AnchorDID:       anchorDID,
		AnchorEndpoint:  endpoint,
		NetworkName:     networkData.Name,
		MeshCIDR:        networkData.MeshCIDR,
		MeshIP:          meshIP,
		NodeRecordID:    nodeRecordID,
		NodeDateCreated: nodeDateCreated,
		MemberRecordID:  memberRecordID,
	}
	if err := attachContextKeyForNetworkSave(stateDir, ns, contextKeyPriv); err != nil {
		return fmt.Errorf("caching context key: %w", err)
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

func parseNetworkJoinArgs(args []string) (endpoint string, anchorDID string, networkID string, preauthRequested bool) {
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
		case "--preauth":
			preauthRequested = true
		}
	}
	if endpoint == "" {
		endpoint = os.Getenv("DWN_ENDPOINT")
	}
	return endpoint, anchorDID, networkID, preauthRequested
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

// cmdInviteCreate creates a preauth invite URL for the current network.
//
// Usage: meshd invite create [--label <label>] [--expires <duration>] [--reusable] [--ephemeral]
func cmdInviteCreate(ctx context.Context, args []string, flagProfile string) error {
	label := ""
	expires := 24 * time.Hour
	reusable := false
	ephemeral := false

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--label":
			if i+1 < len(args) {
				label = args[i+1]
				i++
			}
		case "--expires":
			if i+1 < len(args) {
				if args[i+1] == "never" || args[i+1] == "0" {
					expires = 0
				} else {
					d, err := time.ParseDuration(args[i+1])
					if err != nil {
						return fmt.Errorf("invalid --expires duration %q: %w", args[i+1], err)
					}
					expires = d
				}
				i++
			}
		case "--reusable":
			reusable = true
		case "--ephemeral":
			ephemeral = true
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
	if ns.AnchorDID != identity.URI {
		return fmt.Errorf("only the network anchor (%s) can create invites", ns.AnchorDID)
	}

	expiresAt := time.Time{}
	if expires > 0 {
		expiresAt = time.Now().Add(expires)
	}
	if label == "" {
		label = ns.NetworkName
	}

	signer := &dwn.Signer{DID: identity.URI, PrivateKey: identity.SigningKey}
	result, err := mesh.CreatePreAuthKey(ctx, mesh.CreatePreAuthKeyParams{
		AnchorEndpoint:       ns.AnchorEndpoint,
		AnchorDID:            ns.AnchorDID,
		NetworkRecordID:      ns.NetworkRecordID,
		NetworkName:          ns.NetworkName,
		Signer:               signer,
		EncryptionKeyManager: newEncryptionKeyManager(identity),
		Label:                label,
		ExpiresAt:            expiresAt,
		Reusable:             reusable,
		Ephemeral:            ephemeral,
	})
	if err != nil {
		return err
	}

	fmt.Printf("Invite created for %q.\n", ns.NetworkName)
	if result.ExpiresAt != "" {
		fmt.Printf("  Expires: %s\n", result.ExpiresAt)
	}
	if reusable {
		fmt.Printf("  Reusable: yes\n")
	} else {
		fmt.Printf("  Reusable: no\n")
	}
	fmt.Printf("\n%s\n", result.URL)
	fmt.Printf("\nJoin from another device with:\n")
	fmt.Printf("  meshd join %s\n", result.URL)
	return nil
}

// cmdJoin joins a network from a meshd://invite URL.
//
// Usage: meshd join <meshd://invite/...>
func cmdJoin(ctx context.Context, args []string, flagProfile string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: meshd join <meshd://invite/...>")
	}

	payload, err := invite.Decode(args[0])
	if err != nil {
		return err
	}

	stateDir, identity, err := ensureIdentityForCommand(ctx, flagProfile, payload.Endpoint)
	if err != nil {
		return err
	}
	if state.HasNetwork(stateDir) {
		ns, loadErr := state.LoadNetworkState(stateDir)
		if loadErr != nil {
			return fmt.Errorf("loading network state: %w", loadErr)
		}
		if ns != nil && ns.NetworkRecordID == payload.NetworkID && ns.AnchorDID == payload.AnchorDID && ns.NodeRecordID == "" {
			refreshed, err := refreshPendingJoin(ctx, stateDir, ns, flagProfile)
			if err != nil {
				return err
			}
			if refreshed.NodeRecordID == "" {
				fmt.Printf("Join request is still pending anchor approval.\n")
			}
			return nil
		}
		return fmt.Errorf("already in a network. Use 'meshd network leave' first.")
	}

	preauth := payload.TokenID != "" || payload.Secret != ""
	if preauth {
		if err := payload.ValidatePreAuth(); err != nil {
			return err
		}
		label, _ := os.Hostname()
		signer := &dwn.Signer{DID: identity.URI, PrivateKey: identity.SigningKey}
		if err := mesh.WritePreAuthNodeRequest(ctx, mesh.WritePreAuthNodeRequestParams{
			Invite:  payload,
			NodeDID: identity.URI,
			Signer:  signer,
			Label:   label,
		}); err != nil {
			return err
		}
		fmt.Printf("Join request submitted for %q.\n", payload.NetworkName)
	}

	joinArgs := []string{
		"--endpoint", payload.Endpoint,
		"--anchor", payload.AnchorDID,
		"--network", payload.NetworkID,
	}
	if preauth {
		joinArgs = append(joinArgs, "--preauth")
	}
	return cmdNetworkJoin(ctx, joinArgs, flagProfile)
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

	// Determine protocol role for queries.
	queryRole := ""
	if ns.AnchorDID != identity.URI {
		queryRole = "network/node"
	}

	// Query owner-provisioned node records (network/node).
	records, status, err := api.Query(ctx, ns.AnchorDID, dwn.QueryParams{
		Filter: dwn.RecordsFilter{
			Protocol:     protocols.MeshProtocolURI,
			ProtocolPath: "network/node",
			ContextID:    ns.NetworkRecordID,
		},
		DateSort: "createdAscending",
	}, queryRole)
	if err != nil {
		return fmt.Errorf("querying peers: %w", err)
	}

	if status.Code != 200 {
		return fmt.Errorf("query failed: %d %s", status.Code, status.Detail)
	}

	// Also query member-associated node records (network/member/node).
	memberRecords, mStatus, mErr := api.Query(ctx, ns.AnchorDID, dwn.QueryParams{
		Filter: dwn.RecordsFilter{
			Protocol:     protocols.MeshProtocolURI,
			ProtocolPath: "network/member/node",
			ContextID:    ns.NetworkRecordID,
		},
		DateSort: "createdAscending",
	}, queryRole)
	if mErr == nil && mStatus.Code == 200 {
		records = append(records, memberRecords...)
	}

	if len(records) == 0 {
		fmt.Println("No peers found.")
		return nil
	}

	fmt.Printf("Peers in %q:\n", ns.NetworkName)
	fmt.Printf("%-50s %-16s %-12s %s\n", "DID", "MESH IP", "LABEL", "PATH")
	fmt.Println(strings.Repeat("-", 90))

	for _, r := range records {
		var node struct {
			MeshIP string `json:"meshIP"`
			Label  string `json:"label"`
		}
		if err := r.Data().JSON(ctx, &node); err != nil {
			// Data may not be inline (encrypted records need context key).
			fmt.Printf("%-50s %-16s %-12s %s\n", truncate(r.Recipient, 50), "?", "(encrypted)", r.ProtocolPath)
			continue
		}
		peerDID := r.Recipient
		if peerDID == "" {
			peerDID = "(unknown)"
		}
		fmt.Printf("%-50s %-16s %-12s %s\n",
			truncate(peerDID, 50),
			node.MeshIP,
			node.Label,
			r.ProtocolPath)
	}

	return nil
}

// cmdPeerAdd adds a peer to the mesh network. This creates a node record
// for the given DID on the anchor DWN and delivers the context encryption
// key so the peer can immediately decrypt mesh records.
//
// This must be run by the network anchor (owner). It combines the node
// record creation and key delivery into a single command.
//
// Usage: meshd peer add <did> [--label <label>]
func cmdPeerAdd(ctx context.Context, args []string, flagProfile string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: meshd peer add <did> [--label <label>]")
	}

	peerDID := args[0]
	label := "peer"
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
	// Use Protocol Context encryption so all peers with the shared context
	// key can decrypt each other's node records.
	fmt.Printf("Adding peer %s...\n", peerDID)
	peerMeshIP, err := mesh.AllocateMeshIP(ns.MeshCIDR, peerDID)
	if err != nil {
		return fmt.Errorf("allocating mesh IP for peer: %w", err)
	}
	_, err = mesh.RegisterNode(ctx, mesh.RegisterNodeParams{
		AnchorEndpoint:       ns.AnchorEndpoint,
		AnchorDID:            ns.AnchorDID,
		NetworkRecordID:      ns.NetworkRecordID,
		NodeDID:              peerDID,
		Signer:               signer,
		EncryptionKeyManager: encMgr,
		MeshIP:               peerMeshIP.String(),
		Label:                label,
		UseContextEncryption: true,
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
		SourceProtocol: protocols.MeshProtocolURI,
		ContextID:      ns.NetworkRecordID,
	})
	if err != nil {
		// Non-fatal: the node was created, key delivery can be retried
		// with `peer approve`.
		fmt.Printf("  Warning: context key delivery failed: %v\n", err)
		fmt.Printf("  The node was added but cannot decrypt records yet.\n")
		fmt.Printf("  Retry with: meshd peer approve %s\n", peerDID)
		return nil
	}
	fmt.Printf("  Context key delivered.\n")

	fmt.Printf("\nPeer added to network %q.\n", ns.NetworkName)
	joinURL, err := invite.Encode(invite.New(ns.AnchorEndpoint, ns.AnchorDID, ns.NetworkRecordID, ns.NetworkName, "", "", ""))
	if err != nil {
		return err
	}
	fmt.Printf("The peer can now join with:\n")
	fmt.Printf("  meshd join %s\n", joinURL)

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
		SourceProtocol: protocols.MeshProtocolURI,
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
	if !identityExists(stateDir) {
		fmt.Println("Not initialized. Run 'meshd auth login' to create a profile.")
		return nil
	}

	identity, err := loadIdentity(stateDir)
	if err != nil {
		return fmt.Errorf("loading identity: %w", err)
	}

	fmt.Printf("Identity:\n")
	fmt.Printf("  DID: %s\n", identity.URI)
	fmt.Printf("  State: %s\n", stateDir)
	if did.EncryptedExists(stateDir) {
		fmt.Printf("  Vault: encrypted\n")
	} else {
		fmt.Printf("  Vault: plaintext legacy\n")
	}

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
	inviteURL     string // positional meshd://invite URL

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
		default:
			if !strings.HasPrefix(args[i], "-") && strings.HasPrefix(strings.TrimSpace(args[i]), invite.SchemePrefix) {
				f.inviteURL = args[i]
			}
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
	stateDir, identity, err := ensureIdentityForCommand(ctx, flagProfile, f.endpoint)
	if err != nil {
		return err
	}

	// ── Step 2: Ensure network membership ───────────────────────────
	ns, err := state.LoadNetworkState(stateDir)
	if err != nil {
		return fmt.Errorf("loading network state: %w", err)
	}

	if ns == nil {
		// Not in a network. Use flags or prompt interactively.
		ns, err = ensureNetwork(ctx, f, stateDir, identity, flagProfile)
		if err != nil {
			return err
		}
	}
	if ns.NodeRecordID == "" && ns.AnchorDID != identity.URI {
		ns, err = refreshPendingJoin(ctx, stateDir, ns, flagProfile)
		if err != nil {
			return err
		}
		if ns.NodeRecordID == "" {
			return fmt.Errorf("join request is still pending anchor approval; run 'meshd up' again after the anchor is online")
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

	// Enable Protocol Context encryption so all nodes (including the anchor)
	// write records that any peer with the shared context key can decrypt.
	// The anchor derives the context key from its root key (HKDF).
	// Non-anchor nodes fetch it from the anchor's key-delivery protocol.
	useContextEncryption := false
	if ns.AnchorDID == identity.URI {
		// Anchor: always use context encryption. The EncryptionKeyManager
		// derives the context key from the root key automatically.
		useContextEncryption = true
	} else {
		// Try cached context key first (survives DWN outages at startup).
		source, ok, err := loadLocalContextKeyForCLI(stateDir, ns, encMgr)
		if err != nil {
			slog.Warn("cached context key load failed, will fetch from DWN",
				slog.Any("error", err),
			)
		} else if ok {
			useContextEncryption = true
			fmt.Printf("  Context key: loaded from %s\n", source)
		}

		// Fall back to DWN fetch if not cached.
		if !useContextEncryption {
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

				// Persist for next startup.
				if saveErr := saveContextKeyForCommand(stateDir, ns, privBytes); saveErr != nil {
					slog.Warn("failed to persist context key", slog.Any("error", saveErr))
				}
				fmt.Printf("  Context key: received (Protocol Context encryption enabled)\n")
			} else {
				fmt.Printf("  Context key: not yet delivered (run 'peer approve' on anchor)\n")
				fmt.Printf("  Records will be written with Protocol Path encryption.\n")
			}
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

	// Write/update endpoint record (encrypted) before starting the engine.
	if ns.NodeRecordID != "" {
		localEndpoints := mesh.DiscoverLocalEndpoints(f.listenPort)
		// Determine the protocol role for the endpoint write. Devices write
		// their own endpoint records using recipient-based authorization.
		endpointRole := ""
		if ns.AnchorDID != identity.URI {
			endpointRole = "network/node"
			if ns.MemberRecordID != "" {
				endpointRole = "network/member/node"
			}
		}
		wpParams := mesh.WriteEndpointParams{
			AnchorEndpoint:       ns.AnchorEndpoint,
			AnchorDID:            ns.AnchorDID,
			NetworkRecordID:      ns.NetworkRecordID,
			MemberRecordID:       ns.MemberRecordID,
			NodeRecordID:         ns.NodeRecordID,
			Signer:               signer,
			EncryptionKeyManager: encMgr,
			LocalEndpoints:       localEndpoints,
			NATType:              "unknown",
			ProtocolRole:         endpointRole,
			UseContextEncryption: useContextEncryption,
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
	if ns.AnchorDID == identity.URI {
		approvePreAuthRequests(ctx, ns, signer, encMgr, logger)
	}

	// Determine the protocol role for DWN queries. The anchor reads as
	// author (no role needed). Non-anchor nodes use their node role.
	protocolRole := ""
	if ns.AnchorDID != identity.URI {
		protocolRole = "network/node"
	}

	eng, err := engine.New(engine.Config{
		AnchorEndpoint:       ns.AnchorEndpoint,
		AnchorTenant:         ns.AnchorDID,
		NetworkRecordID:      ns.NetworkRecordID,
		SelfDID:              identity.URI,
		Signer:               signer,
		Resolver:             universalResolver{},
		EncryptionKeyManager: encMgr,
		NodeRecordID:         ns.NodeRecordID,
		MemberRecordID:       ns.MemberRecordID,
		ProtocolRole:         protocolRole,
		AutoKeyDelivery:      autoKeyDelivery,
		UseContextEncryption: useContextEncryption,
		WireGuardPrivateKey:  wgKeys.PrivateKey,
		TUNName:              f.tunName,
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

	var stopPreAuthApproval chan struct{}
	if ns.AnchorDID == identity.URI {
		stopPreAuthApproval = make(chan struct{})
		interval := f.pollInterval
		if interval == 0 {
			interval = 30 * time.Second
		}
		go runPreAuthApprovalLoop(ctx, stopPreAuthApproval, interval, ns, signer, encMgr, logger)
		defer close(stopPreAuthApproval)
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
	profileName := profileNameForWrite(flagProfile)

	identity, err := did.Generate()
	if err != nil {
		return nil, fmt.Errorf("generating DID: %w", err)
	}

	dataPath := profile.DataPath(profileName)
	useProfiles := os.Getenv("MESHD_STATE_DIR") == ""
	if !useProfiles {
		dataPath = os.Getenv("MESHD_STATE_DIR")
	}
	if err := storeIdentityForCLI(identity, dataPath); err != nil {
		return nil, fmt.Errorf("storing identity: %w", err)
	}
	if useProfiles {
		if err := profile.UpsertProfile(profileName, identity.URI); err != nil {
			return nil, fmt.Errorf("saving profile: %w", err)
		}
	}

	if useProfiles {
		fmt.Printf("  Profile: %s\n", profileName)
	}
	fmt.Printf("  DID:     %s\n", identity.URI)
	fmt.Printf("  Vault:   encrypted\n")
	fmt.Println()

	return identity, nil
}

func ensureIdentityForCommand(ctx context.Context, flagProfile, endpoint string) (string, *did.DID, error) {
	stateDir, err := resolveStateDir(flagProfile)
	if err == profile.ErrNoProfiles {
		fmt.Println("No identity found. Creating one...")
		if _, err := ensureIdentity(ctx, flagProfile, endpoint); err != nil {
			return "", nil, err
		}
		stateDir, err = resolveStateDir(flagProfile)
	}
	if err != nil {
		return "", nil, err
	}

	if identityExists(stateDir) {
		identity, err := loadIdentity(stateDir)
		if err != nil {
			return "", nil, fmt.Errorf("loading identity: %w", err)
		}
		return stateDir, identity, nil
	}

	fmt.Println("No identity found. Creating one...")
	identity, err := ensureIdentity(ctx, flagProfile, endpoint)
	if err != nil {
		return "", nil, err
	}
	stateDir, err = resolveStateDir(flagProfile)
	if err != nil {
		return "", nil, err
	}
	return stateDir, identity, nil
}

// ensureNetwork handles network setup when the user is not yet in a network.
// It checks flags (--create, --anchor+--network) and falls back to an
// interactive prompt.
func ensureNetwork(ctx context.Context, f upFlags, stateDir string, identity *did.DID, flagProfile string) (*state.NetworkState, error) {
	switch {
	case f.inviteURL != "":
		return setupJoinInvite(ctx, f, stateDir, identity, flagProfile)
	case f.createNetwork != "":
		return setupCreateNetwork(ctx, f, stateDir, identity, flagProfile)
	case f.anchorDID != "" && f.networkID != "":
		return setupJoinNetwork(ctx, f, stateDir, identity, flagProfile)
	default:
		return setupInteractive(ctx, f, stateDir, identity, flagProfile)
	}
}

// setupCreateNetwork creates a new mesh network (anchor mode).
// This is the --create flag path.
func setupCreateNetwork(ctx context.Context, f upFlags, stateDir string, identity *did.DID, flagProfile string) (*state.NetworkState, error) {
	if f.endpoint == "" {
		return nil, fmt.Errorf("--endpoint (or DWN_ENDPOINT env) is required to create a network")
	}

	fmt.Printf("Creating network %q on %s...\n", f.createNetwork, f.endpoint)

	// Delegate to the existing network create logic.
	err := cmdNetworkCreate(ctx, []string{f.createNetwork, "--endpoint", f.endpoint}, flagProfile)
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
func setupJoinNetwork(ctx context.Context, f upFlags, stateDir string, identity *did.DID, flagProfile string) (*state.NetworkState, error) {
	if f.endpoint == "" {
		return nil, fmt.Errorf("--endpoint (or DWN_ENDPOINT env) is required to join a network")
	}

	fmt.Printf("Joining network on %s...\n", f.endpoint)

	err := cmdNetworkJoin(ctx, []string{
		"--endpoint", f.endpoint,
		"--anchor", f.anchorDID,
		"--network", f.networkID,
	}, flagProfile)
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

// setupJoinInvite joins an existing network from an invite URL.
func setupJoinInvite(ctx context.Context, f upFlags, stateDir string, identity *did.DID, flagProfile string) (*state.NetworkState, error) {
	if err := cmdJoin(ctx, []string{f.inviteURL}, flagProfile); err != nil {
		return nil, err
	}
	ns, err := state.LoadNetworkState(stateDir)
	if err != nil {
		return nil, fmt.Errorf("loading network state after invite join: %w", err)
	}
	if ns == nil {
		return nil, fmt.Errorf("network state not found after invite join")
	}
	return ns, nil
}

func refreshPendingJoin(ctx context.Context, stateDir string, ns *state.NetworkState, flagProfile string) (*state.NetworkState, error) {
	if ns == nil {
		return nil, fmt.Errorf("network state is missing")
	}
	previous := *ns

	fmt.Printf("Checking pending join approval...\n")
	if err := state.ClearNetworkState(stateDir); err != nil {
		return nil, fmt.Errorf("clearing pending network state: %w", err)
	}
	err := cmdNetworkJoin(ctx, []string{
		"--endpoint", ns.AnchorEndpoint,
		"--anchor", ns.AnchorDID,
		"--network", ns.NetworkRecordID,
		"--preauth",
	}, flagProfile)
	if err != nil {
		_ = state.SaveNetworkState(stateDir, &previous)
		return nil, err
	}

	refreshed, err := state.LoadNetworkState(stateDir)
	if err != nil {
		_ = state.SaveNetworkState(stateDir, &previous)
		return nil, fmt.Errorf("loading refreshed network state: %w", err)
	}
	if refreshed == nil {
		_ = state.SaveNetworkState(stateDir, &previous)
		return &previous, nil
	}
	return refreshed, nil
}

// setupInteractive prompts the user to create or join a network.
func setupInteractive(ctx context.Context, f upFlags, stateDir string, identity *did.DID, flagProfile string) (*state.NetworkState, error) {
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
		return interactiveCreate(ctx, f, stateDir, identity, flagProfile, scanner)
	case "2":
		return interactiveJoin(ctx, f, stateDir, identity, flagProfile, scanner)
	default:
		return nil, fmt.Errorf("invalid choice %q (expected 1 or 2)", choice)
	}
}

func stdinIsTerminal() bool {
	return term.IsTerminal(int(os.Stdin.Fd()))
}

func promptRequired(scanner *bufio.Scanner, label string) (string, error) {
	fmt.Printf("%s: ", label)
	if !scanner.Scan() {
		return "", fmt.Errorf("no input received")
	}
	value := strings.TrimSpace(scanner.Text())
	if value == "" {
		return "", fmt.Errorf("%s is required", strings.ToLower(label))
	}
	return value, nil
}

// interactiveCreate guides the user through creating a new network.
func interactiveCreate(ctx context.Context, f upFlags, stateDir string, identity *did.DID, flagProfile string, scanner *bufio.Scanner) (*state.NetworkState, error) {
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
	return setupCreateNetwork(ctx, f, stateDir, identity, flagProfile)
}

// interactiveJoin guides the user through joining an existing network.
func interactiveJoin(ctx context.Context, f upFlags, stateDir string, identity *did.DID, flagProfile string, scanner *bufio.Scanner) (*state.NetworkState, error) {
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
	return setupJoinNetwork(ctx, f, stateDir, identity, flagProfile)
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

const vaultPasswordEnv = "MESHD_VAULT_PASSWORD"

var cachedVaultPassword string

func defaultProfileName(flagProfile string) string {
	if flagProfile != "" {
		return flagProfile
	}
	if env := os.Getenv("ENBOX_PROFILE"); env != "" {
		return env
	}
	return "default"
}

func profileNameForWrite(flagProfile string) string {
	if os.Getenv("MESHD_STATE_DIR") != "" {
		return defaultProfileName(flagProfile)
	}
	if name, err := profile.Resolve(flagProfile); err == nil {
		return name
	}
	return defaultProfileName(flagProfile)
}

func identityExists(stateDir string) bool {
	return did.EncryptedExists(stateDir) || did.Exists(stateDir)
}

func storeIdentityForCLI(identity *did.DID, stateDir string) error {
	password, err := vaultPasswordForCreate()
	if err != nil {
		return err
	}
	return identity.StoreEncrypted(stateDir, password)
}

func vaultPasswordForUnlock() (string, error) {
	if password := os.Getenv(vaultPasswordEnv); password != "" {
		cachedVaultPassword = password
		return password, nil
	}
	if cachedVaultPassword != "" {
		return cachedVaultPassword, nil
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", fmt.Errorf("vault password required; run in a terminal or set %s", vaultPasswordEnv)
	}

	fmt.Print("Vault password: ")
	passwordBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return "", fmt.Errorf("reading vault password: %w", err)
	}
	password := string(passwordBytes)
	if password == "" {
		return "", fmt.Errorf("vault password is required")
	}
	cachedVaultPassword = password
	return password, nil
}

func vaultPasswordForCreate() (string, error) {
	if password := os.Getenv(vaultPasswordEnv); password != "" {
		cachedVaultPassword = password
		return password, nil
	}
	if cachedVaultPassword != "" {
		return cachedVaultPassword, nil
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", fmt.Errorf("vault password required; run in a terminal or set %s", vaultPasswordEnv)
	}

	fmt.Print("Create vault password: ")
	firstBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return "", fmt.Errorf("reading vault password: %w", err)
	}
	password := string(firstBytes)
	if password == "" {
		return "", fmt.Errorf("vault password is required")
	}

	fmt.Print("Confirm vault password: ")
	confirmBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return "", fmt.Errorf("reading vault password confirmation: %w", err)
	}
	if password != string(confirmBytes) {
		return "", fmt.Errorf("vault passwords do not match")
	}
	cachedVaultPassword = password
	return password, nil
}

// loadIdentity loads the DID identity, or returns an error if not initialized.
func loadIdentity(stateDir string) (*did.DID, error) {
	if did.EncryptedExists(stateDir) {
		password, err := vaultPasswordForUnlock()
		if err != nil {
			return nil, err
		}
		identity, err := did.LoadEncrypted(stateDir, password)
		if err != nil {
			return nil, fmt.Errorf("unlocking vault: %w", err)
		}
		if identity == nil {
			return nil, fmt.Errorf("encrypted identity is missing")
		}
		return identity, nil
	}

	if !did.Exists(stateDir) {
		return nil, fmt.Errorf("not initialized. Run 'meshd auth login' to create a profile")
	}
	identity, err := did.Load(stateDir)
	if err != nil {
		return nil, fmt.Errorf("loading identity: %w", err)
	}
	return identity, nil
}

func loadLocalContextKeyForCLI(stateDir string, ns *state.NetworkState, encMgr *dwncrypto.EncryptionKeyManager) (string, bool, error) {
	if ns == nil || ns.NetworkRecordID == "" {
		return "", false, nil
	}

	if did.EncryptedExists(stateDir) {
		password, err := vaultPasswordForUnlock()
		if err != nil {
			return "", false, err
		}
		privBytes, ok, err := state.LoadContextKey(stateDir, password, ns.NetworkRecordID)
		if err != nil {
			return "", false, err
		}
		if ok {
			encMgr.StoreContextKey(ns.NetworkRecordID, privBytes)
			return "vault", true, nil
		}
	}

	if ns.ContextKey == "" {
		return "", false, nil
	}
	privBytes, err := base64.StdEncoding.DecodeString(ns.ContextKey)
	if err != nil {
		return "", false, fmt.Errorf("decode cached context key: %w", err)
	}
	encMgr.StoreContextKey(ns.NetworkRecordID, privBytes)

	if did.EncryptedExists(stateDir) {
		password, err := vaultPasswordForUnlock()
		if err != nil {
			return "", false, err
		}
		if err := state.StoreContextKey(stateDir, password, ns.NetworkRecordID, privBytes); err != nil {
			return "", false, err
		}
		ns.ContextKey = ""
		if err := state.SaveNetworkState(stateDir, ns); err != nil {
			return "", false, err
		}
		return "legacy cache (migrated)", true, nil
	}

	return "legacy cache", true, nil
}

func attachContextKeyForNetworkSave(stateDir string, ns *state.NetworkState, privateKey []byte) error {
	if len(privateKey) == 0 {
		return nil
	}
	if did.EncryptedExists(stateDir) {
		password, err := vaultPasswordForUnlock()
		if err != nil {
			return err
		}
		if err := state.StoreContextKey(stateDir, password, ns.NetworkRecordID, privateKey); err != nil {
			return err
		}
		ns.ContextKey = ""
		return nil
	}

	ns.ContextKey = base64.StdEncoding.EncodeToString(privateKey)
	return nil
}

func saveContextKeyForCommand(stateDir string, ns *state.NetworkState, privateKey []byte) error {
	if err := attachContextKeyForNetworkSave(stateDir, ns, privateKey); err != nil {
		return err
	}
	return state.SaveNetworkState(stateDir, ns)
}

// newEncryptionKeyManager creates an EncryptionKeyManager from a DID identity.
func newEncryptionKeyManager(identity *did.DID) *dwncrypto.EncryptionKeyManager {
	return &dwncrypto.EncryptionKeyManager{
		RootPrivateKey: identity.EncryptionPrivateKey,
		RootKeyID:      identity.EncryptionKeyID(),
		ProtocolURI:    protocols.MeshProtocolURI,
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

func approvePreAuthRequests(ctx context.Context, ns *state.NetworkState, signer *dwn.Signer, encMgr *dwncrypto.EncryptionKeyManager, logger *slog.Logger) {
	result, err := mesh.ApprovePreAuthRequests(ctx, mesh.ApprovePreAuthRequestsParams{
		AnchorEndpoint:       ns.AnchorEndpoint,
		AnchorDID:            ns.AnchorDID,
		NetworkRecordID:      ns.NetworkRecordID,
		MeshCIDR:             ns.MeshCIDR,
		Signer:               signer,
		EncryptionKeyManager: encMgr,
	})
	if err != nil {
		logger.Warn("preauth approval failed", slog.Any("error", err))
		return
	}
	if result.Approved > 0 {
		fmt.Printf("  Invite requests approved: %d\n", result.Approved)
	}
	if result.Rejected > 0 || result.Pending > 0 {
		logger.Debug("processed invite requests",
			slog.Int("approved", result.Approved),
			slog.Int("rejected", result.Rejected),
			slog.Int("pending", result.Pending),
		)
	}
}

func runPreAuthApprovalLoop(ctx context.Context, stop <-chan struct{}, interval time.Duration, ns *state.NetworkState, signer *dwn.Signer, encMgr *dwncrypto.EncryptionKeyManager, logger *slog.Logger) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-stop:
			return
		case <-ticker.C:
			approvePreAuthRequests(ctx, ns, signer, encMgr, logger)
		}
	}
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
	if err := storeIdentityForCLI(identity, dataPath); err != nil {
		return fmt.Errorf("storing identity: %w", err)
	}

	// Register profile in config.json.
	if err := profile.UpsertProfile(profileName, identity.URI); err != nil {
		return fmt.Errorf("saving profile: %w", err)
	}

	fmt.Printf("Created profile %q.\n", profileName)
	fmt.Printf("  DID:   %s\n", identity.URI)
	fmt.Printf("  State: %s\n", dataPath)
	fmt.Printf("  Vault: encrypted\n")

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

// cmdACLSet reads an ACL policy from a JSON file and writes it to the anchor DWN.
// This is an anchor-only operation.
//
// Usage: meshd acl set <policy.json>
func cmdACLSet(ctx context.Context, args []string, flagProfile string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: meshd acl set <policy.json>")
	}

	policyFile := args[0]
	policyBytes, err := os.ReadFile(policyFile)
	if err != nil {
		return fmt.Errorf("reading policy file: %w", err)
	}

	// Validate the JSON is a valid ACL policy.
	var policy control.ACLPolicyData
	if err := json.Unmarshal(policyBytes, &policy); err != nil {
		return fmt.Errorf("invalid ACL policy JSON: %w", err)
	}
	if policy.Version == 0 {
		return fmt.Errorf("ACL policy must have a \"version\" field (integer >= 1)")
	}
	if len(policy.Rules) == 0 {
		return fmt.Errorf("ACL policy must have at least one rule")
	}
	for i, r := range policy.Rules {
		if r.Action != "accept" && r.Action != "drop" {
			return fmt.Errorf("rule %d: action must be \"accept\" or \"drop\", got %q", i, r.Action)
		}
		if len(r.Src) == 0 {
			return fmt.Errorf("rule %d: src must not be empty", i)
		}
		if len(r.Dst) == 0 {
			return fmt.Errorf("rule %d: dst must not be empty", i)
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

	// Verify this is the anchor node.
	if identity.URI != ns.AnchorDID {
		return fmt.Errorf("only the network anchor can set ACL policy (you: %s, anchor: %s)",
			truncate(identity.URI, 40), truncate(ns.AnchorDID, 40))
	}

	signer := &dwn.Signer{
		DID:        identity.URI,
		PrivateKey: identity.SigningKey,
	}
	encMgr := newEncryptionKeyManager(identity)

	if err := mesh.WriteACLPolicy(ctx, mesh.WriteACLPolicyParams{
		AnchorEndpoint:       ns.AnchorEndpoint,
		AnchorDID:            ns.AnchorDID,
		NetworkRecordID:      ns.NetworkRecordID,
		Signer:               signer,
		EncryptionKeyManager: encMgr,
		PolicyData:           policyBytes,
	}); err != nil {
		return err
	}

	fmt.Printf("ACL policy set (version %d, %d rules).\n", policy.Version, len(policy.Rules))
	return nil
}

// cmdACLShow reads and displays the current ACL policy from the anchor DWN.
//
// Usage: meshd acl show
func cmdACLShow(ctx context.Context, args []string, flagProfile string) error {
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
	encMgr := newEncryptionKeyManager(identity)

	// Load context key for decryption. Try cached key first, then DWN fetch.
	if ns.AnchorDID != identity.URI {
		_, contextKeyLoaded, loadErr := loadLocalContextKeyForCLI(stateDir, ns, encMgr)
		if loadErr != nil {
			fmt.Printf("  Warning: cached context key load failed: %v\n", loadErr)
		}
		if !contextKeyLoaded {
			contextKey, ckErr := fetchContextKey(ctx, identity, ns)
			if ckErr != nil {
				fmt.Printf("  Warning: context key fetch failed: %v\n", ckErr)
			} else if contextKey != nil {
				privBytes, pbErr := contextKey.PrivateKeyBytes()
				if pbErr != nil {
					return fmt.Errorf("extracting context key bytes: %w", pbErr)
				}
				encMgr.StoreContextKey(ns.NetworkRecordID, privBytes)

				// Persist for next time.
				if saveErr := saveContextKeyForCommand(stateDir, ns, privBytes); saveErr != nil {
					fmt.Printf("  Warning: failed to persist context key: %v\n", saveErr)
				}
			}
		}
	}

	// Determine protocol role for queries.
	aclQueryRole := ""
	if ns.AnchorDID != identity.URI {
		aclQueryRole = "network/node"
	}

	client := control.NewDWNClient(
		ns.AnchorEndpoint,
		ns.AnchorDID,
		ns.NetworkRecordID,
		identity.URI,
		signer,
		control.WithEncryptionKeyManager(encMgr),
		control.WithProtocolRole(aclQueryRole),
	)

	// Load state (which now includes ACL policy).
	_, err = client.LoadState(ctx)
	if err != nil {
		return fmt.Errorf("loading mesh state: %w", err)
	}

	policy := client.ACLPolicy()
	if policy == nil {
		fmt.Println("No ACL policy configured. Default: allow all traffic.")
		return nil
	}

	// Pretty-print the policy as JSON.
	out, err := json.MarshalIndent(policy, "", "  ")
	if err != nil {
		return fmt.Errorf("formatting policy: %w", err)
	}
	fmt.Println(string(out))
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
