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
			"peer list", "peer add", "peer remove":
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

	// 3. Create self as admin member (encrypted).
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
		ParentID:             record.ID,
		ContextID:            record.ID,
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

	// 4. Persist network state.
	ns := &state.NetworkState{
		NetworkRecordID: record.ID,
		AnchorDID:       identity.URI,
		AnchorEndpoint:  endpoint,
		NetworkName:     name,
		MeshCIDR:        meshCIDR,
	}
	if err := state.SaveNetworkState(stateDir, ns); err != nil {
		return fmt.Errorf("saving network state: %w", err)
	}

	fmt.Printf("Network created.\n")
	fmt.Printf("  Name: %s\n", name)
	fmt.Printf("  CIDR: %s\n", meshCIDR)
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

	// Save network state locally.
	ns := &state.NetworkState{
		NetworkRecordID: networkID,
		AnchorDID:       anchorDID,
		AnchorEndpoint:  endpoint,
		NetworkName:     networkData.Name,
		MeshCIDR:        networkData.MeshCIDR,
	}
	if err := state.SaveNetworkState(stateDir, ns); err != nil {
		return fmt.Errorf("saving network state: %w", err)
	}

	fmt.Printf("Joined network.\n")
	fmt.Printf("  Name: %s\n", networkData.Name)
	fmt.Printf("  CIDR: %s\n", networkData.MeshCIDR)
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

	fmt.Printf("Starting dwn-mesh...\n")
	fmt.Printf("  Network: %s\n", ns.NetworkName)
	fmt.Printf("  DID: %s\n", identity.URI)
	fmt.Printf("  Anchor: %s\n", ns.AnchorEndpoint)

	eng, err := engine.New(engine.Config{
		AnchorEndpoint:       ns.AnchorEndpoint,
		AnchorTenant:         ns.AnchorDID,
		NetworkRecordID:      ns.NetworkRecordID,
		SelfDID:              identity.URI,
		Signer:               signer,
		Resolver:             universalResolver{},
		EncryptionKeyManager: newEncryptionKeyManager(identity),
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
