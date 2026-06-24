package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
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
	"github.com/enboxorg/meshd/internal/walletconnect"
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
  auth connect      Connect this CLI profile to an Enbox Wallet
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
  peer add          Add a peer node to the mesh (anchor only)
  peer remove       Remove a peer node from the mesh (anchor only)
  peer list         List all peers in the mesh
  peer approve      Deliver encryption keys to a peer (anchor only)
  acl set <file>    Set ACL policy from a JSON file (anchor only)
  acl show          Show the current ACL policy
  admin             Open the meshd admin dashboard
  status            Show mesh status and identity info
  doctor            Diagnose identity, wallet, daemon, TUN, and routes
  up                Start the mesh agent daemon
  down              Stop the mesh agent daemon

Up flags:
  --create <name>   Create a new network and start (anchor mode)
  --endpoint <url>  DWN endpoint override for create/join/owner requests
  --anchor <did>    Anchor DID when joining a network
  --network <id>    Network record ID when joining a network
  --owner <did>     Wallet owner DID for this local node when joining
  --tun [name]      Create a real TUN device (default; asks sudo when needed)
  --no-tun          Use userspace mode without OS routes
  --port <n>        WireGuard UDP listen port (default: auto)
  --poll-interval   DWN poll interval (default: 30s)
  --foreground      Run in the current terminal instead of background
  -v, --verbose     Enable debug logging

Admin flags:
  --owner <did>     Open the dashboard for a specific wallet/owner DID
  --network <id>    Preselect a network record in the dashboard
  --dashboard <url> Dashboard URL override
  --print           Print the dashboard URL without opening a browser

Quick start:
  meshd up
  meshd invite create
  meshd up meshd://invite/<token>

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
  MESHD_VAULT_CACHE_TTL
                     Cache interactive vault unlocks for this duration (default: 5m, 0 disables)
  DWN_ENDPOINT       Default DWN endpoint URL override
  MESHD_WALLET_RESPONSE_ENDPOINT
                     DWN endpoint for wallet approval handoff on headless devices
`

var version = "dev"

const (
	sudoChildEnv    = "MESHD_SUDO_CHILD"
	upBackgroundEnv = "MESHD_UP_BACKGROUND_CHILD"
	backgroundWait  = 30 * time.Second
	daemonLogName   = "meshd.log"
	walletWaitTime  = 10 * time.Minute

	walletResponseEndpointEnv     = "MESHD_WALLET_RESPONSE_ENDPOINT"
	defaultWalletResponseEndpoint = "https://dev.aws.dwn.enbox.id"
)

var defaultOwnerRequestEndpoint = defaultWalletResponseEndpoint

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
			"peer list", "peer add", "peer remove", "peer approve",
			"acl set", "acl show",
			"auth login", "auth connect", "auth list", "auth use", "auth logout",
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
	case "auth connect":
		err = cmdAuthConnect(ctx, args, flagProfile)
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
	case "peer remove":
		err = cmdPeerRemove(ctx, args, flagProfile)
	case "peer list":
		err = cmdPeerList(ctx, args, flagProfile)
	case "peer approve":
		err = cmdPeerApprove(ctx, args, flagProfile)
	case "acl set":
		err = cmdACLSet(ctx, args, flagProfile)
	case "acl show":
		err = cmdACLShow(ctx, args, flagProfile)
	case "admin":
		err = cmdAdmin(ctx, args, flagProfile)
	case "status":
		err = cmdStatus(ctx, args, flagProfile)
	case "doctor":
		err = cmdDoctor(ctx, args, flagProfile)
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

	password, err := vaultPasswordForCreate(stateDir)
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
	fmt.Printf("Local Node DID: %s\n", identity.URI)
	fmt.Printf("State: %s\n", stateDir)
	return nil
}

// cmdNetworkCreate creates a new mesh network.
//
// Usage: meshd network create [name] [--endpoint <dwn-url>] [--no-wait]
// Usage: meshd network create --response <wallet-response.json>
func cmdNetworkCreate(ctx context.Context, args []string, flagProfile string) error {
	opts, err := parseNetworkCreateOptions(args)
	if err != nil {
		return err
	}
	if opts.responseIn != "" {
		return importNetworkCreateResponse(ctx, flagProfile, opts.responseIn)
	}

	name, endpoint := opts.name, opts.endpoint
	if opts.meshCIDR == "" {
		opts.meshCIDR = "10.200.0.0/16"
	}
	if name == "" {
		if !stdinIsTerminal() {
			return fmt.Errorf("usage: meshd network create [name] [--endpoint <dwn-url>]")
		}
		scanner := bufio.NewScanner(os.Stdin)
		name, err = promptRequired(scanner, "Network name")
		if err != nil {
			return err
		}
	}
	if endpoint == "" && !stdinIsTerminal() && !isWalletAuthorizedNodeProfile(flagProfile) {
		return fmt.Errorf("usage: meshd network create [name] [--endpoint <dwn-url>]")
	}

	stateDir, identity, err := ensureIdentityForCommand(ctx, flagProfile, endpoint)
	if err != nil {
		return err
	}
	meta := resolveIdentityMetadata(flagProfile, identity.URI)
	nodeDID := firstNonEmpty(meta.NodeDID, identity.URI)
	ownerDID := firstNonEmpty(meta.OwnerDID, nodeDID)
	if meta.AuthType == profile.AuthTypeWalletAuthorizedNode && ownerDID != nodeDID {
		return createWalletNetworkCreateRequest(ctx, flagProfile, stateDir, identity, name, endpoint, opts)
	}

	if endpoint == "" {
		if !stdinIsTerminal() {
			return fmt.Errorf("usage: meshd network create [name] [--endpoint <dwn-url>]")
		}
		scanner := bufio.NewScanner(os.Stdin)
		endpoint, err = promptRequired(scanner, "DWN endpoint URL")
		if err != nil {
			return err
		}
	}

	if state.HasNetwork(stateDir) {
		return fmt.Errorf("already in a network. Use 'meshd network leave' first.")
	}
	if err := ensureDWNTenantRegistered(ctx, endpoint, identity); err != nil {
		return err
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
	meshCIDR := opts.meshCIDR
	networkData, _ := json.Marshal(map[string]any{
		"name":           name,
		"meshCIDR":       meshCIDR,
		"anchorEndpoint": endpoint,
	})

	record, writeStatus, err := api.Write(ctx, identity.URI, dwn.WriteParams{
		Protocol:     protocols.MeshProtocolURI,
		ProtocolPath: "network",
		Schema:       "https://enbox.id/schemas/wireguard-mesh/network",
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
		RecipientDID:   nodeDID,
		SourceProtocol: protocols.MeshProtocolURI,
		ContextID:      record.ID,
	}); err != nil {
		fmt.Printf("  Warning: context key self-delivery failed: %v\n", err)
	} else {
		fmt.Printf("  Context key delivered to self.\n")
	}

	// 4. Allocate mesh IP.
	meshIP, err := mesh.AllocateMeshIP(meshCIDR, nodeDID)
	if err != nil {
		return fmt.Errorf("allocating mesh IP: %w", err)
	}

	// 5. Register node on DWN (encrypted with Protocol Context).
	// Use context encryption so that peers with the shared context key can
	// decrypt the anchor's node record. The anchor already self-delivered the
	// context key above, and as the DWN owner it can derive the key from root.
	nodeKeyDelivery, err := walletconnect.NewKeyDeliveryPublic(identity)
	if err != nil {
		return fmt.Errorf("deriving node key-delivery public key: %w", err)
	}
	reg, err := mesh.RegisterNode(ctx, mesh.RegisterNodeParams{
		AnchorEndpoint:       endpoint,
		AnchorDID:            identity.URI,
		NetworkRecordID:      record.ID,
		NodeDID:              nodeDID,
		Signer:               signer,
		EncryptionKeyManager: encMgr,
		MeshIP:               meshIP.String(),
		OwnerDID:             ownerDID,
		DelegateDID:          meta.DelegateDID,
		NodeKeyDelivery:      nodeKeyDelivery,
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
		NodeDID:         nodeDID,
		OwnerDID:        ownerDID,
		MemberDID:       ownerDID,
		DelegateDID:     meta.DelegateDID,
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

type networkCreateOptions struct {
	name       string
	endpoint   string
	meshCIDR   string
	requestOut string
	responseIn string
	walletURL  string
	noWait     bool
}

func parseNetworkCreateArgs(args []string) (name string, endpoint string) {
	opts, _ := parseNetworkCreateOptions(args)
	return opts.name, opts.endpoint
}

func parseNetworkCreateOptions(args []string) (networkCreateOptions, error) {
	opts := networkCreateOptions{
		meshCIDR:  "10.200.0.0/16",
		walletURL: "https://wallet.enbox.id",
	}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--endpoint":
			if i+1 < len(args) {
				opts.endpoint = args[i+1]
				i++
			} else {
				return opts, fmt.Errorf("--endpoint requires a URL")
			}
		case "--cidr":
			if i+1 < len(args) {
				opts.meshCIDR = args[i+1]
				i++
			} else {
				return opts, fmt.Errorf("--cidr requires a CIDR")
			}
		case "--request-out":
			if i+1 < len(args) {
				opts.requestOut = args[i+1]
				i++
			} else {
				return opts, fmt.Errorf("--request-out requires a path")
			}
		case "--response":
			if i+1 < len(args) {
				opts.responseIn = args[i+1]
				i++
			} else {
				return opts, fmt.Errorf("--response requires a path")
			}
		case "--wallet":
			if i+1 < len(args) {
				opts.walletURL = args[i+1]
				i++
			} else {
				return opts, fmt.Errorf("--wallet requires a URL")
			}
		case "--no-wait":
			opts.noWait = true
		default:
			if strings.HasPrefix(args[i], "-") {
				return opts, fmt.Errorf("unknown network create flag %q", args[i])
			}
			if opts.name == "" {
				opts.name = args[i]
			} else {
				return opts, fmt.Errorf("unexpected argument %q", args[i])
			}
		}
	}
	if opts.endpoint == "" {
		opts.endpoint = os.Getenv("DWN_ENDPOINT")
	}
	return opts, nil
}

type walletResponseCallback struct {
	url        string
	server     *http.Server
	responseCh chan []byte
	errCh      chan error
}

type walletResponseRelay struct {
	endpoint string
	token    string
}

func shouldWaitForWalletResponse(walletURL, requestOut string, noWait bool) bool {
	return walletURL != "" && requestOut == "" && !noWait && stdinIsTerminal()
}

func shouldUseWalletResponseRelay(walletURL, requestOut string, noWait bool) bool {
	return walletURL != "" && requestOut == "" && !noWait
}

func walletResponseEndpoint(fallbackEndpoint string) string {
	if endpoint := strings.TrimSpace(os.Getenv(walletResponseEndpointEnv)); endpoint != "" {
		return strings.TrimRight(endpoint, "/")
	}
	if fallbackEndpoint = strings.TrimSpace(fallbackEndpoint); fallbackEndpoint != "" {
		return strings.TrimRight(fallbackEndpoint, "/")
	}
	if endpoint := strings.TrimSpace(os.Getenv("DWN_ENDPOINT")); endpoint != "" {
		return strings.TrimRight(endpoint, "/")
	}
	return defaultWalletResponseEndpoint
}

func setupWalletResponseRelay(ctx context.Context, endpoint string, identity *did.DID) (*walletResponseRelay, error) {
	endpoint = strings.TrimRight(strings.TrimSpace(endpoint), "/")
	if endpoint == "" || identity == nil {
		return nil, nil
	}
	token, err := walletconnect.GenerateChallenge()
	if err != nil {
		return nil, err
	}
	if err := dwn.RegisterTenant(ctx, endpoint, identity.URI); err != nil {
		return nil, fmt.Errorf("registering wallet response tenant: %w", err)
	}
	signer := &dwn.Signer{DID: identity.URI, PrivateKey: identity.SigningKey}
	api := dwn.NewDwnAPI(dwn.NewSimpleAgent(endpoint, signer))
	status, err := api.ConfigureProtocol(ctx, identity.URI, protocols.WalletResponseProtocolJSON)
	if err != nil {
		return nil, fmt.Errorf("configuring wallet response protocol: %w", err)
	}
	if status.Code >= 300 && status.Code != 409 {
		return nil, fmt.Errorf("wallet response protocol configure failed: %d %s", status.Code, status.Detail)
	}
	return &walletResponseRelay{endpoint: endpoint, token: token}, nil
}

func browserOpenCommand(goos string, rawURL string) (string, []string, bool) {
	switch goos {
	case "darwin":
		return "open", []string{rawURL}, true
	case "windows":
		return "rundll32", []string{"url.dll,FileProtocolHandler", rawURL}, true
	default:
		return "xdg-open", []string{rawURL}, true
	}
}

func openBrowser(rawURL string) error {
	if rawURL == "" {
		return fmt.Errorf("wallet URL is empty")
	}
	name, args, ok := browserOpenCommand(runtime.GOOS, rawURL)
	if !ok {
		return fmt.Errorf("unsupported OS")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	output, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return fmt.Errorf("%s did not return within 5s", name)
	}
	if err != nil {
		detail := strings.TrimSpace(string(output))
		if detail != "" {
			return fmt.Errorf("%s failed: %w: %s", name, err, detail)
		}
		return fmt.Errorf("%s failed: %w", name, err)
	}
	return nil
}

func printWalletURL(rawURL string, autoOpen bool, remoteHandoff bool) {
	fmt.Printf("\nOpen in wallet:\n  %s\n", rawURL)
	if remoteHandoff {
		fmt.Printf("  This URL can be opened on another device; meshd will wait for the wallet response over DWN.\n")
	}
	if !autoOpen {
		return
	}
	if err := openBrowser(rawURL); err != nil {
		fmt.Printf("  Could not open browser automatically: %v\n", err)
	} else {
		fmt.Printf("  Browser opened. Approve the request there, then return here.\n")
	}
}

type adminOptions struct {
	dashboardURL    string
	printOnly       bool
	ownerDID        string
	networkRecordID string
}

const defaultAdminDashboardURL = "https://meshd-admin.pages.dev"

func parseAdminArgs(args []string) (adminOptions, error) {
	opts := adminOptions{dashboardURL: defaultAdminDashboardURL}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--dashboard", "--wallet":
			if i+1 >= len(args) {
				return opts, fmt.Errorf("%s requires a URL", args[i])
			}
			opts.dashboardURL = args[i+1]
			i++
		case "--owner":
			if i+1 >= len(args) {
				return opts, fmt.Errorf("--owner requires a DID")
			}
			opts.ownerDID = strings.TrimSpace(args[i+1])
			if opts.ownerDID == "" {
				return opts, fmt.Errorf("--owner requires a DID")
			}
			i++
		case "--network":
			if i+1 >= len(args) {
				return opts, fmt.Errorf("--network requires a record ID")
			}
			opts.networkRecordID = strings.TrimSpace(args[i+1])
			if opts.networkRecordID == "" {
				return opts, fmt.Errorf("--network requires a record ID")
			}
			i++
		case "--print", "--no-open":
			opts.printOnly = true
		default:
			return opts, fmt.Errorf("unknown admin flag %q", args[i])
		}
	}
	return opts, nil
}

// cmdAdmin opens the meshd admin dashboard, preselecting the active owner and
// network when local state is available.
func cmdAdmin(ctx context.Context, args []string, flagProfile string) error {
	opts, err := parseAdminArgs(args)
	if err != nil {
		return err
	}
	adminURL := buildAdminURL(opts.dashboardURL, adminContextFromOptions(opts, adminContextFromProfile(flagProfile)))
	fmt.Printf("meshd admin:\n  %s\n", adminURL)
	if opts.printOnly || !stdinIsTerminal() {
		return nil
	}
	if err := openBrowser(adminURL); err != nil {
		fmt.Printf("  Could not open browser automatically: %v\n", err)
	} else {
		fmt.Printf("  Browser opened.\n")
	}
	return nil
}

type adminContext struct {
	OwnerDID        string
	NetworkRecordID string
}

func adminContextFromOptions(opts adminOptions, fallback adminContext) adminContext {
	ctx := fallback
	if opts.ownerDID != "" {
		ctx.OwnerDID = opts.ownerDID
	}
	if opts.networkRecordID != "" {
		ctx.NetworkRecordID = opts.networkRecordID
	}
	return ctx
}

func adminContextFromProfile(flagProfile string) adminContext {
	ctx := adminContext{}
	if os.Getenv("MESHD_STATE_DIR") == "" {
		if name, err := profile.Resolve(flagProfile); err == nil {
			if cfg, cfgErr := profile.ReadConfig(); cfgErr == nil && cfg.Profiles[name] != nil {
				ctx.OwnerDID = cfg.Profiles[name].EffectiveOwnerDID()
			}
		}
	}
	stateDir, err := resolveStateDir(flagProfile)
	if err != nil {
		return ctx
	}
	ns, err := state.LoadNetworkState(stateDir)
	if err != nil || ns == nil {
		return ctx
	}
	ctx.OwnerDID = networkOwnerDID(ns, ctx.OwnerDID)
	ctx.NetworkRecordID = ns.NetworkRecordID
	return ctx
}

func buildAdminURL(walletURL string, ctx adminContext) string {
	base := strings.TrimRight(strings.TrimSpace(walletURL), "/")
	if base == "" {
		base = defaultAdminDashboardURL
	}
	adminURL := base
	values := url.Values{}
	if ctx.OwnerDID != "" {
		values.Set("owner", ctx.OwnerDID)
	}
	if ctx.NetworkRecordID != "" {
		values.Set("network", ctx.NetworkRecordID)
	}
	if encoded := values.Encode(); encoded != "" {
		adminURL += "?" + encoded
	}
	return adminURL
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func adminDashboardCommand(ctx adminContext, printOnly bool) string {
	args := []string{"meshd", "admin"}
	if ctx.OwnerDID != "" {
		args = append(args, "--owner", shellQuote(ctx.OwnerDID))
	}
	if ctx.NetworkRecordID != "" {
		args = append(args, "--network", shellQuote(ctx.NetworkRecordID))
	}
	if printOnly {
		args = append(args, "--print")
	}
	return strings.Join(args, " ")
}

func startWalletResponseCallback() (*walletResponseCallback, error) {
	token, err := walletconnect.GenerateChallenge()
	if err != nil {
		return nil, err
	}
	path := "/meshd/wallet-callback/" + token
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("start wallet callback listener: %w", err)
	}

	cb := &walletResponseCallback{
		responseCh: make(chan []byte, 1),
		errCh:      make(chan error, 1),
	}
	mux := http.NewServeMux()
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.Header().Set("Access-Control-Allow-Private-Network", "true")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		defer r.Body.Close()
		data, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
		if err != nil {
			http.Error(w, "read response", http.StatusBadRequest)
			return
		}
		if len(data) == 0 {
			http.Error(w, "empty response", http.StatusBadRequest)
			return
		}
		select {
		case cb.responseCh <- data:
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte("ok\n"))
		default:
			http.Error(w, "response already received", http.StatusConflict)
		}
	})

	cb.server = &http.Server{Handler: mux}
	addr := ln.Addr().(*net.TCPAddr)
	cb.url = fmt.Sprintf("http://127.0.0.1:%d%s", addr.Port, path)
	go func() {
		if err := cb.server.Serve(ln); err != nil && err != http.ErrServerClosed {
			select {
			case cb.errCh <- err:
			default:
			}
		}
	}()
	return cb, nil
}

func (cb *walletResponseCallback) close() {
	if cb == nil || cb.server == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = cb.server.Shutdown(ctx)
}

func (cb *walletResponseCallback) wait(ctx context.Context) ([]byte, error) {
	timer := time.NewTimer(walletWaitTime)
	defer timer.Stop()
	select {
	case data := <-cb.responseCh:
		return data, nil
	case err := <-cb.errCh:
		return nil, fmt.Errorf("wallet callback failed: %w", err)
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timer.C:
		return nil, fmt.Errorf("timed out waiting for wallet response")
	}
}

func waitForWalletDelivery(ctx context.Context, callback *walletResponseCallback, relay *walletResponseRelay, identity *did.DID) ([]byte, error) {
	waitCtx, cancel := context.WithTimeout(ctx, walletWaitTime)
	defer cancel()

	type result struct {
		data []byte
		err  error
	}
	results := make(chan result, 2)
	pending := 0
	if callback != nil {
		pending++
		go func() {
			data, err := callback.wait(waitCtx)
			results <- result{data: data, err: err}
		}()
	}
	if relay != nil {
		pending++
		go func() {
			data, err := relay.wait(waitCtx, identity)
			results <- result{data: data, err: err}
		}()
	}
	if pending == 0 {
		return nil, fmt.Errorf("no wallet response delivery channel configured")
	}

	var lastErr error
	for pending > 0 {
		select {
		case res := <-results:
			pending--
			if res.err == nil {
				return res.data, nil
			}
			lastErr = res.err
		case <-waitCtx.Done():
			if lastErr != nil {
				return nil, lastErr
			}
			return nil, waitCtx.Err()
		}
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("wallet response was not received")
}

func (r *walletResponseRelay) wait(ctx context.Context, identity *did.DID) ([]byte, error) {
	if r == nil || r.endpoint == "" || r.token == "" || identity == nil {
		return nil, fmt.Errorf("wallet response relay is not configured")
	}
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	var lastErr error
	for {
		data, ok, err := r.fetch(ctx, identity)
		if err != nil {
			lastErr = err
		}
		if ok {
			return data, nil
		}
		select {
		case <-ctx.Done():
			if lastErr != nil {
				return nil, fmt.Errorf("timed out waiting for wallet response relay: %w", lastErr)
			}
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
}

func (r *walletResponseRelay) fetch(ctx context.Context, identity *did.DID) ([]byte, bool, error) {
	signer := &dwn.Signer{DID: identity.URI, PrivateKey: identity.SigningKey}
	api := dwn.NewDwnAPI(dwn.NewSimpleAgent(r.endpoint, signer))
	records, status, err := api.Query(ctx, identity.URI, dwn.QueryParams{
		Filter: dwn.RecordsFilter{
			Protocol:     protocols.WalletResponseProtocolURI,
			ProtocolPath: "response",
			Recipient:    identity.URI,
		},
		DateSort: "createdDescending",
	}, "")
	if err != nil {
		return nil, false, err
	}
	if status.Code != 200 {
		return nil, false, fmt.Errorf("wallet response query failed: %d %s", status.Code, status.Detail)
	}
	for _, queryRecord := range records {
		record, readStatus, err := api.Read(ctx, identity.URI, dwn.RecordsFilter{
			RecordID: queryRecord.ID,
		}, "")
		if err != nil {
			return nil, false, err
		}
		if readStatus.Code != 200 || record == nil {
			continue
		}
		data, err := record.Data().Bytes(ctx)
		if err != nil {
			return nil, false, err
		}
		var env walletconnect.ResponseEnvelope
		if err := json.Unmarshal(data, &env); err != nil {
			continue
		}
		if env.ResponseToken != r.token {
			continue
		}
		if err := env.Validate(); err != nil {
			return nil, false, err
		}
		if status, err := api.Delete(ctx, identity.URI, queryRecord.ID, false, ""); err != nil {
			fmt.Printf("  Warning: wallet response cleanup failed: %v\n", err)
		} else if status.Code >= 300 && status.Code != 404 {
			fmt.Printf("  Warning: wallet response cleanup failed: %d %s\n", status.Code, status.Detail)
		}
		return append([]byte(nil), env.Response...), true, nil
	}
	return nil, false, nil
}

func createWalletNetworkCreateRequest(ctx context.Context, flagProfile string, stateDir string, identity *did.DID, name string, endpoint string, opts networkCreateOptions) error {
	if state.HasNetwork(stateDir) {
		return fmt.Errorf("already in a network. Use 'meshd network leave' first.")
	}
	var err error
	var callback *walletResponseCallback
	if shouldWaitForWalletResponse(opts.walletURL, opts.requestOut, opts.noWait) {
		callback, err = startWalletResponseCallback()
		if err != nil {
			return err
		}
		defer callback.close()
	}
	var relay *walletResponseRelay
	if shouldUseWalletResponseRelay(opts.walletURL, opts.requestOut, opts.noWait) {
		relay, err = setupWalletResponseRelay(ctx, walletResponseEndpoint(endpoint), identity)
		if err != nil {
			fmt.Printf("  Warning: wallet response handoff unavailable: %v\n", err)
			relay = nil
		}
	}
	profileName := profileNameForWrite(flagProfile)
	delegateIdentity, err := ensureWalletDelegateIdentity(stateDir)
	if err != nil {
		return err
	}
	req, err := walletconnect.NewNetworkCreateRequest(profileName, identity, name, endpoint, opts.meshCIDR, delegateIdentity)
	if err != nil {
		return err
	}
	if callback != nil {
		req.CallbackURL = callback.url
	}
	if relay != nil {
		req.ResponseEndpoint = relay.endpoint
		req.ResponseToken = relay.token
	}
	if err := walletconnect.SignNetworkCreateRequest(identity, &req); err != nil {
		return err
	}
	requestURL, err := walletconnect.EncodeNetworkCreateRequest(req)
	if err != nil {
		return err
	}
	if opts.requestOut != "" {
		data, err := json.MarshalIndent(req, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal network create request: %w", err)
		}
		if err := os.WriteFile(opts.requestOut, data, 0600); err != nil {
			return fmt.Errorf("write network create request: %w", err)
		}
	}

	fmt.Println("Wallet approval required to create this network.")
	fmt.Printf("  Profile: %s\n", profileName)
	fmt.Printf("  Node DID: %s\n", identity.URI)
	fmt.Printf("  Delegate DID: %s\n", delegateIdentity.URI)
	fmt.Printf("  Network: %s\n", name)
	fmt.Printf("  CIDR: %s\n", opts.meshCIDR)
	if endpoint != "" {
		fmt.Printf("  Requested DWN: %s\n", endpoint)
	}
	if opts.requestOut != "" {
		fmt.Printf("  Request: %s\n", opts.requestOut)
	}
	if relay != nil {
		fmt.Printf("  Response handoff: %s\n", relay.endpoint)
	}
	fmt.Printf("\nRequest URL:\n  %s\n", requestURL)
	if opts.walletURL != "" {
		walletURL := strings.TrimRight(opts.walletURL, "/") + "/meshd/create?request=" + url.QueryEscape(requestURL)
		printWalletURL(walletURL, callback != nil, relay != nil)
	}
	if callback == nil && relay == nil {
		fmt.Printf("\nAfter wallet approval, save the response JSON and run:\n")
		fmt.Printf("  meshd network create --response <response.json>\n")
		return nil
	}
	fmt.Printf("\nWaiting for wallet approval...\n")
	data, err := waitForWalletDelivery(ctx, callback, relay, identity)
	if err != nil {
		return err
	}
	return importNetworkCreateResponseData(ctx, flagProfile, data)
}

func importNetworkCreateResponse(ctx context.Context, flagProfile string, responsePath string) error {
	var data []byte
	var err error
	if responsePath == "-" {
		data, err = io.ReadAll(os.Stdin)
	} else {
		data, err = os.ReadFile(responsePath)
	}
	if err != nil {
		return fmt.Errorf("read network create response: %w", err)
	}
	return importNetworkCreateResponseData(ctx, flagProfile, data)
}

func importNetworkCreateResponseData(ctx context.Context, flagProfile string, data []byte) error {
	var resp walletconnect.NetworkCreateResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return fmt.Errorf("parse network create response: %w", err)
	}
	if err := resp.Validate(); err != nil {
		return err
	}
	resp.NormalizeOwnerDID()
	ownerDID := resp.EffectiveOwnerDID()

	profileFlag := firstNonEmpty(flagProfile, resp.ProfileName)
	stateDir, identity, err := ensureIdentityForCommand(ctx, profileFlag, resp.AnchorEndpoint)
	if err != nil {
		return err
	}
	if resp.NodeDID != identity.URI {
		return fmt.Errorf("network create response node DID %s does not match local node DID %s", resp.NodeDID, identity.URI)
	}
	if state.HasNetwork(stateDir) {
		return fmt.Errorf("already in a network. Use 'meshd network leave' first.")
	}

	password, err := vaultPasswordForUnlock(stateDir)
	if err != nil {
		return err
	}
	if _, err := requireWalletResponseDelegateIdentity(stateDir, resp.DelegateDID, resp.NodeDID, "network create response"); err != nil {
		return err
	}
	existingSession, err := state.LoadWalletSession(stateDir, password)
	if err != nil {
		return err
	}
	nodeContextKeys := resp.EffectiveNodeContextKeys()
	nodeProtocols := resp.EffectiveNodeMultiPartyProtocols()
	session := &state.WalletSession{
		Version:                 1,
		OwnerDID:                ownerDID,
		ConnectedDID:            ownerDID,
		DelegateDID:             resp.DelegateDID,
		NodeDID:                 resp.NodeDID,
		WalletOrigin:            resp.WalletOrigin,
		ExpiresAt:               resp.ExpiresAt,
		Grants:                  resp.Grants,
		NodeContextKeys:         nodeContextKeys,
		NodeMultiPartyProtocols: nodeProtocols,
	}
	if existingSession != nil {
		if existingOwnerDID := existingSession.EffectiveOwnerDID(); existingOwnerDID != "" && existingOwnerDID != ownerDID {
			return fmt.Errorf("wallet session owner DID %s does not match network response owner DID %s", existingOwnerDID, ownerDID)
		}
		if existingSession.NodeDID != "" && existingSession.NodeDID != resp.NodeDID {
			return fmt.Errorf("wallet session node DID %s does not match network response node DID %s", existingSession.NodeDID, resp.NodeDID)
		}
		if session.DelegateDID == "" {
			session.DelegateDID = existingSession.DelegateDID
		}
		if existingSession.DelegateDID != "" && session.DelegateDID != "" && existingSession.DelegateDID != session.DelegateDID {
			return fmt.Errorf("wallet session delegate DID %s does not match network response delegate DID %s", existingSession.DelegateDID, session.DelegateDID)
		}
		session.Grants = append(existingSession.Grants, resp.Grants...)
		session.DelegateDecryptionKeys = existingSession.DelegateDecryptionKeys
		session.NodeContextKeys = append(existingSession.EffectiveNodeContextKeys(), nodeContextKeys...)
		if len(nodeProtocols) == 0 {
			session.NodeMultiPartyProtocols = existingSession.EffectiveNodeMultiPartyProtocols()
		}
	}
	if err := state.StoreWalletSession(stateDir, password, session); err != nil {
		return err
	}

	contextKeyCount, err := storeWalletNodeContextKeys(stateDir, password, nodeContextKeys)
	if err != nil {
		return err
	}

	ns := &state.NetworkState{
		NetworkRecordID:   resp.NetworkRecordID,
		AnchorDID:         ownerDID,
		AnchorEndpoint:    resp.AnchorEndpoint,
		NetworkName:       resp.NetworkName,
		MeshCIDR:          resp.MeshCIDR,
		MeshIP:            resp.MeshIP,
		NodeDID:           resp.NodeDID,
		OwnerDID:          ownerDID,
		MemberDID:         ownerDID,
		DelegateDID:       session.DelegateDID,
		NodeRecordID:      resp.NodeRecordID,
		NodeDateCreated:   resp.NodeDateCreated,
		MemberRecordID:    resp.MemberRecordID,
		MemberDateCreated: resp.MemberDateCreated,
	}
	if err := state.SaveNetworkState(stateDir, ns); err != nil {
		return fmt.Errorf("saving network state: %w", err)
	}

	if os.Getenv("MESHD_STATE_DIR") == "" {
		profileName := profileNameForWrite(profileFlag)
		if err := profile.UpsertProfileEntry(&profile.Entry{
			Name:         profileName,
			DID:          identity.URI,
			AuthType:     profile.AuthTypeWalletAuthorizedNode,
			OwnerDID:     ownerDID,
			ConnectedDID: ownerDID,
			DelegateDID:  session.DelegateDID,
			NodeDID:      identity.URI,
			WalletOrigin: resp.WalletOrigin,
			ExpiresAt:    resp.ExpiresAt,
		}); err != nil {
			return fmt.Errorf("saving wallet-connected profile: %w", err)
		}
	}

	fmt.Println("Wallet-created network imported.")
	fmt.Printf("  Name: %s\n", resp.NetworkName)
	fmt.Printf("  CIDR: %s\n", resp.MeshCIDR)
	fmt.Printf("  Mesh IP: %s\n", resp.MeshIP)
	fmt.Printf("  Wallet Owner DID: %s\n", ownerDID)
	if session.DelegateDID != "" {
		fmt.Printf("  Delegate DID: %s\n", session.DelegateDID)
	}
	fmt.Printf("  Node DID: %s\n", resp.NodeDID)
	fmt.Printf("  Anchor DID: %s\n", ownerDID)
	fmt.Printf("  Anchor Endpoint: %s\n", resp.AnchorEndpoint)
	fmt.Printf("  Network Record: %s\n", resp.NetworkRecordID)
	if resp.MemberRecordID != "" {
		fmt.Printf("  Member Record: %s\n", resp.MemberRecordID)
	}
	if resp.NodeRecordID != "" {
		fmt.Printf("  Node Record: %s\n", resp.NodeRecordID)
	}
	if contextKeyCount > 0 {
		fmt.Printf("  Context keys: %d imported\n", contextKeyCount)
	}
	fmt.Printf("\nRun 'meshd up' to start the mesh.\n")
	return nil
}

// cmdNetworkJoin joins an existing mesh network.
//
// Usage: meshd network join <invite-url>
// Usage: meshd network join --endpoint <url> --anchor <did> --network <id>
func cmdNetworkJoin(ctx context.Context, args []string, flagProfile string) error {
	if len(args) == 1 && strings.HasPrefix(strings.TrimSpace(args[0]), invite.SchemePrefix) {
		return cmdJoin(ctx, args, flagProfile)
	}

	joinOpts := parseNetworkJoinOptions(args)
	endpoint, anchorDID, networkID, preauthRequested := joinOpts.endpoint, joinOpts.anchorDID, joinOpts.networkID, joinOpts.preauthRequested
	requestedOwnerDID := parseOwnerDIDArg(args)
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
	meta := resolveIdentityMetadata(flagProfile, identity.URI)
	nodeDID := firstNonEmpty(meta.NodeDID, identity.URI)
	ownerDID := firstNonEmpty(requestedOwnerDID, meta.OwnerDID, nodeDID)

	if state.HasNetwork(stateDir) {
		return fmt.Errorf("already in a network. Use 'meshd network leave' first.")
	}
	if err := ensureDWNTenantRegistered(ctx, endpoint, identity); err != nil {
		return err
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

	var nodeRecordID, nodeDateCreated, meshIP, memberRecordID, nodeExpiresAt string

	// Query network/node records to find one with our DID as recipient.
	nodeRecords, queryStatus, err := api.Query(ctx, anchorDID, dwn.QueryParams{
		Filter: dwn.RecordsFilter{
			Protocol:     protocols.MeshProtocolURI,
			ProtocolPath: "network/node",
			ContextID:    networkID,
			Recipient:    nodeDID,
		},
		DateSort: "createdDescending",
	}, "")
	if err != nil {
		fmt.Printf("  Warning: node query failed: %v\n", err)
	} else if queryStatus.Code == 200 && len(nodeRecords) > 0 {
		nodeRecordID = nodeRecords[0].ID
		nodeDateCreated = nodeRecords[0].DateCreated
		var nodeData struct {
			MeshIP    string `json:"meshIP"`
			ExpiresAt string `json:"expiresAt"`
		}
		if err := nodeRecords[0].Data().JSON(ctx, &nodeData); err == nil {
			if nodeData.MeshIP != "" {
				meshIP = nodeData.MeshIP
			}
			nodeExpiresAt = strings.TrimSpace(nodeData.ExpiresAt)
		}
		fmt.Printf("  Found node record (owner-provisioned).\n")
	}

	// If not found, try member-associated nodes. DWN requires nested
	// protocol queries to include the direct parent contextId, so first
	// discover the member record and then query its child node records.
	if nodeRecordID == "" {
		memberRecords, memStatus, memErr := api.Query(ctx, anchorDID, dwn.QueryParams{
			Filter: dwn.RecordsFilter{
				Protocol:     protocols.MeshProtocolURI,
				ProtocolPath: "network/member",
				ContextID:    networkID,
				Recipient:    ownerDID,
			},
			DateSort: "createdDescending",
		}, "network/member")
		if memErr != nil {
			fmt.Printf("  Warning: member query failed: %v\n", memErr)
		} else if memStatus.Code == 200 {
			for _, memberRecord := range memberRecords {
				memberNodeRecords, mQueryStatus, mErr := api.Query(ctx, anchorDID, dwn.QueryParams{
					Filter: dwn.RecordsFilter{
						Protocol:     protocols.MeshProtocolURI,
						ProtocolPath: "network/member/node",
						ContextID:    networkID + "/" + memberRecord.ID,
						Recipient:    nodeDID,
					},
					DateSort: "createdDescending",
				}, "network/member")
				if mErr != nil {
					fmt.Printf("  Warning: member node query failed: %v\n", mErr)
					continue
				}
				if mQueryStatus.Code != 200 || len(memberNodeRecords) == 0 {
					continue
				}

				memberRecordID = memberRecord.ID
				nodeRecordID = memberNodeRecords[0].ID
				nodeDateCreated = memberNodeRecords[0].DateCreated
				var nodeData struct {
					MeshIP    string `json:"meshIP"`
					ExpiresAt string `json:"expiresAt"`
				}
				if err := memberNodeRecords[0].Data().JSON(ctx, &nodeData); err == nil {
					if nodeData.MeshIP != "" {
						meshIP = nodeData.MeshIP
					}
					nodeExpiresAt = strings.TrimSpace(nodeData.ExpiresAt)
				}
				fmt.Printf("  Found node record (member-associated).\n")
				break
			}
		}
	}

	// If a member node was not found but the member record exists, keep
	// the member record ID so future writes can use the correct protocol path.
	if nodeRecordID == "" && memberRecordID == "" {
		memberRecords, memStatus, memErr := api.Query(ctx, anchorDID, dwn.QueryParams{
			Filter: dwn.RecordsFilter{
				Protocol:     protocols.MeshProtocolURI,
				ProtocolPath: "network/member",
				ContextID:    networkID,
				Recipient:    ownerDID,
			},
			DateSort: "createdDescending",
		}, "network/member")
		if memErr == nil && memStatus.Code == 200 && len(memberRecords) > 0 {
			memberRecordID = memberRecords[0].ID
		}
	}
	// If no node record found, the anchor hasn't added us yet.
	// Allocate a mesh IP deterministically and save partial state.
	if meshIP == "" {
		allocatedIP, allocErr := mesh.AllocateMeshIP(networkData.MeshCIDR, nodeDID)
		if allocErr != nil {
			return fmt.Errorf("allocating mesh IP: %w", allocErr)
		}
		meshIP = allocatedIP.String()
	}

	if nodeRecordID == "" {
		if !preauthRequested {
			fmt.Printf("  No node record found — the anchor needs to run:\n")
			fmt.Printf("    meshd peer add %s\n", nodeDID)
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
		nodeInfoGrantID, grantErr := walletGrantIDForDWNOperation(stateDir, meta, dwn.InterfaceRecordsWrite, protocols.MeshProtocolURI, nodeInfoProtocolPath(&state.NetworkState{MemberRecordID: memberRecordID}), networkID, false)
		if grantErr != nil {
			return grantErr
		}
		nodeInfoSigner := signer
		if nodeInfoGrantID != "" {
			operationIdentity, err := loadDWNOperationIdentity(stateDir, meta, identity)
			if err != nil {
				return err
			}
			nodeInfoSigner = dwnSigner(operationIdentity)
		}
		if err := mesh.WriteNodeInfo(ctx, mesh.WriteNodeInfoParams{
			AnchorEndpoint:       endpoint,
			AnchorDID:            anchorDID,
			NetworkRecordID:      networkID,
			MemberRecordID:       memberRecordID,
			NodeRecordID:         nodeRecordID,
			Signer:               nodeInfoSigner,
			EncryptionKeyManager: encMgr,
			UseContextEncryption: useContextEnc,
			PermissionGrantID:    nodeInfoGrantID,
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
		NodeExpiresAt:   nodeExpiresAt,
		NodeDID:         nodeDID,
		OwnerDID:        ownerDID,
		MemberDID:       ownerDID,
		DelegateDID:     meta.DelegateDID,
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

	if nodeRecordID == "" {
		if preauthRequested {
			fmt.Printf("Join request is pending approval.\n")
			fmt.Printf("  Name: %s\n", networkData.Name)
			fmt.Printf("  CIDR: %s\n", networkData.MeshCIDR)
			fmt.Printf("  Reserved Mesh IP: %s\n", meshIP)
			fmt.Printf("  Anchor: %s\n", anchorDID)
			if !joinOpts.noStartHint {
				fmt.Printf("\nAfter approval, run 'meshd up' to start the mesh.\n")
			}
		} else {
			fmt.Printf("Join state saved, but this node has not been approved yet.\n")
			if !joinOpts.noStartHint {
				fmt.Printf("\nAfter the anchor adds this node, run 'meshd up' to start the mesh.\n")
			}
		}
		return nil
	}

	fmt.Printf("Joined network.\n")
	fmt.Printf("  Name: %s\n", networkData.Name)
	fmt.Printf("  CIDR: %s\n", networkData.MeshCIDR)
	fmt.Printf("  Mesh IP: %s\n", meshIP)
	fmt.Printf("  Anchor: %s\n", anchorDID)
	if !joinOpts.noStartHint {
		fmt.Printf("\nRun 'meshd up' to start the mesh.\n")
	}

	return nil
}

type networkJoinOptions struct {
	endpoint         string
	anchorDID        string
	networkID        string
	preauthRequested bool
	noStartHint      bool
}

func parseNetworkJoinArgs(args []string) (endpoint string, anchorDID string, networkID string, preauthRequested bool) {
	opts := parseNetworkJoinOptions(args)
	return opts.endpoint, opts.anchorDID, opts.networkID, opts.preauthRequested
}

func parseNetworkJoinOptions(args []string) networkJoinOptions {
	var opts networkJoinOptions
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--endpoint":
			if i+1 < len(args) {
				opts.endpoint = args[i+1]
				i++
			}
		case "--anchor":
			if i+1 < len(args) {
				opts.anchorDID = args[i+1]
				i++
			}
		case "--network":
			if i+1 < len(args) {
				opts.networkID = args[i+1]
				i++
			}
		case "--preauth":
			opts.preauthRequested = true
		case "--no-start-hint":
			opts.noStartHint = true
		}
	}
	if opts.endpoint == "" {
		opts.endpoint = os.Getenv("DWN_ENDPOINT")
	}
	return opts
}

func parseOwnerDIDArg(args []string) string {
	for i := 0; i < len(args); i++ {
		if (args[i] == "--owner" || args[i] == "--member") && i+1 < len(args) {
			return strings.TrimSpace(args[i+1])
		}
	}
	return ""
}

func parseMemberDIDArg(args []string) string {
	return parseOwnerDIDArg(args)
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
	meta, useContextEncryption, err := requireNetworkOwnerProfile(flagProfile, identity, ns)
	if err != nil {
		return err
	}

	encMgr, err := prepareNetworkCommandEncryption(stateDir, identity, ns, useContextEncryption)
	if err != nil {
		return err
	}
	writeGrantID, err := walletGrantIDForDWNOperation(stateDir, meta, dwn.InterfaceRecordsWrite, protocols.MeshProtocolURI, "", ns.NetworkRecordID, useContextEncryption)
	if err != nil {
		return err
	}
	expiresAt := time.Time{}
	if expires > 0 {
		expiresAt = time.Now().Add(expires)
	}
	if label == "" {
		label = ns.NetworkName
	}

	operationIdentity, err := loadDWNOperationIdentity(stateDir, meta, identity)
	if err != nil {
		return err
	}
	signer := dwnSigner(operationIdentity)
	result, err := mesh.CreatePreAuthKey(ctx, mesh.CreatePreAuthKeyParams{
		AnchorEndpoint:       ns.AnchorEndpoint,
		AnchorDID:            ns.AnchorDID,
		NetworkRecordID:      ns.NetworkRecordID,
		NetworkName:          ns.NetworkName,
		Signer:               signer,
		EncryptionKeyManager: encMgr,
		Label:                label,
		ExpiresAt:            expiresAt,
		Reusable:             reusable,
		Ephemeral:            ephemeral,
		PermissionGrantID:    writeGrantID,
		UseContextEncryption: useContextEncryption,
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
		return fmt.Errorf("usage: meshd join <meshd://invite/...> [--owner <did>]")
	}

	inviteURL, requestedOwnerDID, noStartHint, err := parseJoinCommandArgs(args)
	if err != nil {
		return err
	}

	payload, err := invite.Decode(inviteURL)
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
			if err := ensureDWNTenantRegistered(ctx, payload.Endpoint, identity); err != nil {
				return err
			}
			refreshed, err := refreshPendingJoin(ctx, stateDir, ns, flagProfile, noStartHint)
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
	if err := ensureDWNTenantRegistered(ctx, payload.Endpoint, identity); err != nil {
		return err
	}
	meta := resolveIdentityMetadata(flagProfile, identity.URI)
	nodeDID := firstNonEmpty(meta.NodeDID, identity.URI)
	ownerDID := firstNonEmpty(requestedOwnerDID, meta.OwnerDID, nodeDID)

	preauth := payload.TokenID != "" || payload.Secret != ""
	if preauth {
		if err := payload.ValidatePreAuth(); err != nil {
			return err
		}
		label, _ := os.Hostname()
		signer := &dwn.Signer{DID: identity.URI, PrivateKey: identity.SigningKey}
		nodeKeyDelivery, err := walletconnect.NewKeyDeliveryPublic(identity)
		if err != nil {
			return fmt.Errorf("deriving node key-delivery public key: %w", err)
		}
		if err := mesh.WritePreAuthNodeRequest(ctx, mesh.WritePreAuthNodeRequestParams{
			Invite:          payload,
			NodeDID:         nodeDID,
			MemberDID:       ownerDID,
			DelegateDID:     meta.DelegateDID,
			RequestedBy:     identity.URI,
			Signer:          signer,
			Label:           label,
			NodeKeyDelivery: nodeKeyDelivery,
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
	if ownerDID != "" && ownerDID != nodeDID {
		joinArgs = append(joinArgs, "--owner", ownerDID)
	}
	if noStartHint {
		joinArgs = append(joinArgs, "--no-start-hint")
	}
	return cmdNetworkJoin(ctx, joinArgs, flagProfile)
}

func parseJoinCommandArgs(args []string) (inviteURL string, ownerDID string, noStartHint bool, err error) {
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--owner", "--member":
			if i+1 >= len(args) {
				return "", "", false, fmt.Errorf("%s requires a DID", args[i])
			}
			ownerDID = strings.TrimSpace(args[i+1])
			i++
		case "--no-start-hint":
			noStartHint = true
		default:
			if strings.HasPrefix(args[i], "-") {
				return "", "", false, fmt.Errorf("unknown join flag %q", args[i])
			}
			if inviteURL == "" {
				inviteURL = args[i]
			}
		}
	}
	if inviteURL == "" {
		return "", "", false, fmt.Errorf("usage: meshd join <meshd://invite/...> [--owner <did>]")
	}
	return inviteURL, ownerDID, noStartHint, nil
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
	selfNodeDID := networkNodeDID(ns, identity.URI)
	meta := resolveIdentityMetadata(flagProfile, identity.URI)
	selfOwnerDID := networkOwnerDID(ns, firstNonEmpty(meta.OwnerDID, identity.URI))

	operationIdentity, err := loadDWNOperationIdentity(stateDir, meta, identity)
	if err != nil {
		return err
	}
	signer := dwnSigner(operationIdentity)
	agent := dwn.NewSimpleAgent(ns.AnchorEndpoint, signer)
	api := dwn.NewDwnAPI(agent)

	// Determine protocol role for queries.
	queryRole := ""
	if ns.AnchorDID != identity.URI {
		queryRole = "network/node"
	}
	readGrantID, err := walletGrantIDForDWNOperation(stateDir, meta, dwn.InterfaceRecordsQuery, protocols.MeshProtocolURI, "", ns.NetworkRecordID, false)
	if err != nil {
		return err
	}
	encMgr := newEncryptionKeyManager(identity)
	if ns.AnchorDID != selfNodeDID {
		_, _, _ = loadLocalContextKeyForCLI(stateDir, ns, encMgr)
	}
	if resp, err := loadControlStateForCLI(ctx, ns, identity, operationIdentity, encMgr, readGrantID); err == nil {
		if refreshed, _, saveErr := refreshLocalMembershipMetadataFromMap(stateDir, ns, resp); saveErr == nil && refreshed != nil {
			ns = refreshed
			selfOwnerDID = networkOwnerDID(ns, firstNonEmpty(meta.OwnerDID, identity.URI))
		}
		printPeerListRows(ns.NetworkName, peerListRowsFromMapResponse(ns, resp, selfNodeDID, selfOwnerDID))
		return nil
	}

	// Query owner-provisioned node records (network/node).
	records, status, err := api.Query(ctx, ns.AnchorDID, dwn.QueryParams{
		Filter: dwn.RecordsFilter{
			Protocol:     protocols.MeshProtocolURI,
			ProtocolPath: "network/node",
			ContextID:    ns.NetworkRecordID,
		},
		DateSort:          "createdAscending",
		PermissionGrantID: readGrantID,
	}, queryRole)
	if err != nil {
		return fmt.Errorf("querying peers: %w", err)
	}

	if status.Code != 200 {
		return fmt.Errorf("query failed: %d %s", status.Code, status.Detail)
	}

	// Also query member-associated node records (network/member/node).
	// Nested protocol queries must use the direct parent member context.
	memberRecords, mStatus, mErr := api.Query(ctx, ns.AnchorDID, dwn.QueryParams{
		Filter: dwn.RecordsFilter{
			Protocol:     protocols.MeshProtocolURI,
			ProtocolPath: "network/member",
			ContextID:    ns.NetworkRecordID,
		},
		DateSort:          "createdAscending",
		PermissionGrantID: readGrantID,
	}, queryRole)
	if mErr == nil && mStatus.Code == 200 {
		for _, memberRecord := range memberRecords {
			memberNodeRecords, mnStatus, mnErr := api.Query(ctx, ns.AnchorDID, dwn.QueryParams{
				Filter: dwn.RecordsFilter{
					Protocol:     protocols.MeshProtocolURI,
					ProtocolPath: "network/member/node",
					ContextID:    ns.NetworkRecordID + "/" + memberRecord.ID,
				},
				DateSort:          "createdAscending",
				PermissionGrantID: readGrantID,
			}, queryRole)
			if mnErr == nil && mnStatus.Code == 200 {
				records = append(records, memberNodeRecords...)
			}
		}
	}

	if len(records) == 0 {
		fmt.Println("No peers found.")
		return nil
	}

	var rows []peerListRow
	for _, r := range records {
		peerDID := r.Recipient
		displayDID := peerDID
		if displayDID == "" {
			displayDID = "(unknown)"
		}
		device := peerListDevice(peerDID, selfNodeDID)

		var node struct {
			MeshIP    string `json:"meshIP"`
			Label     string `json:"label"`
			MemberDID string `json:"memberDID"`
			ExpiresAt string `json:"expiresAt"`
		}
		if err := r.Data().JSON(ctx, &node); err != nil {
			// Data may not be inline (encrypted records need context key).
			rows = append(rows, peerListRow{
				NodeDID: displayDID,
				MeshIP:  peerListMeshIP(ns.MeshCIDR, peerDID, ""),
				Device:  device,
				Owner:   peerListOwner(peerDID, "", selfNodeDID, selfOwnerDID),
				Label:   "(encrypted)",
				Expires: "unknown",
				Path:    r.ProtocolPath,
			})
			continue
		}
		rows = append(rows, peerListRow{
			NodeDID: displayDID,
			MeshIP:  peerListMeshIP(ns.MeshCIDR, peerDID, node.MeshIP),
			Device:  device,
			Owner:   peerListOwner(peerDID, node.MemberDID, selfNodeDID, selfOwnerDID),
			Label:   node.Label,
			Expires: node.ExpiresAt,
			Path:    r.ProtocolPath,
		})
	}
	printPeerListRows(ns.NetworkName, rows)

	return nil
}

func loadControlStateForCLI(ctx context.Context, ns *state.NetworkState, identity *did.DID, signerIdentity *did.DID, encMgr *dwncrypto.EncryptionKeyManager, readGrantID string) (*control.MapResponse, error) {
	if ns == nil || identity == nil {
		return nil, fmt.Errorf("network state and identity are required")
	}
	if signerIdentity == nil {
		signerIdentity = identity
	}
	selfNodeDID := networkNodeDID(ns, identity.URI)
	protocolRole := ""
	if ns.AnchorDID != selfNodeDID {
		protocolRole = "network/node"
	}
	signer := dwnSigner(signerIdentity)
	client := control.NewDWNClient(
		ns.AnchorEndpoint,
		ns.AnchorDID,
		ns.NetworkRecordID,
		selfNodeDID,
		signer,
		control.WithEncryptionKeyManager(encMgr),
		control.WithProtocolRole(protocolRole),
		control.WithPermissionGrantID(readGrantID),
	)
	return client.LoadState(ctx)
}

func refreshLocalMembershipMetadataFromMap(stateDir string, ns *state.NetworkState, resp *control.MapResponse) (*state.NetworkState, bool, error) {
	if ns == nil || resp == nil || resp.Node == nil {
		return ns, false, nil
	}

	refreshed := *ns
	changed := false

	if resp.Node.MeshIP.IsValid() {
		meshIP := resp.Node.MeshIP.String()
		if refreshed.MeshIP != meshIP {
			refreshed.MeshIP = meshIP
			changed = true
		}
	}

	expiresAt := strings.TrimSpace(resp.Node.ExpiresAt)
	if refreshed.NodeExpiresAt != expiresAt {
		refreshed.NodeExpiresAt = expiresAt
		changed = true
	}

	if resp.Node.MemberDID != "" && refreshed.OwnerDID != resp.Node.MemberDID {
		refreshed.OwnerDID = resp.Node.MemberDID
		refreshed.MemberDID = resp.Node.MemberDID
		changed = true
	}
	if resp.Node.MemberRecordID != "" && refreshed.MemberRecordID != resp.Node.MemberRecordID {
		refreshed.MemberRecordID = resp.Node.MemberRecordID
		changed = true
	}

	if !changed {
		return ns, false, nil
	}
	if err := state.SaveNetworkState(stateDir, &refreshed); err != nil {
		return nil, false, fmt.Errorf("saving refreshed membership metadata: %w", err)
	}
	return &refreshed, true, nil
}

type peerListRow struct {
	NodeDID string
	MeshIP  string
	Device  string
	Owner   string
	Label   string
	Expires string
	Path    string
}

func peerListRowsFromMapResponse(ns *state.NetworkState, resp *control.MapResponse, selfNodeDID string, selfOwnerDID string) []peerListRow {
	if resp == nil {
		return nil
	}
	nodes := make([]*control.Node, 0, 1+len(resp.Peers))
	if resp.Node != nil {
		nodes = append(nodes, resp.Node)
	}
	nodes = append(nodes, resp.Peers...)

	rows := make([]peerListRow, 0, len(nodes))
	for _, node := range nodes {
		if node == nil || node.DID == "" {
			continue
		}
		meshIP := ""
		if node.MeshIP.IsValid() {
			meshIP = node.MeshIP.String()
		}
		rows = append(rows, peerListRow{
			NodeDID: node.DID,
			MeshIP:  peerListMeshIP(ns.MeshCIDR, node.DID, meshIP),
			Device:  peerListDevice(node.DID, selfNodeDID),
			Owner:   peerListOwner(node.DID, node.MemberDID, selfNodeDID, selfOwnerDID),
			Label:   node.Name,
			Expires: node.ExpiresAt,
			Path:    peerListPath(node),
		})
	}
	return rows
}

func printPeerListRows(networkName string, rows []peerListRow) {
	if len(rows) == 0 {
		fmt.Println("No peers found.")
		return
	}
	fmt.Printf("Peers in %q:\n", networkName)
	fmt.Printf("%-44s %-15s %-11s %-28s %-12s %-17s %s\n", "NODE DID", "MESH IP", "DEVICE", "OWNER", "LABEL", "EXPIRES", "PATH")
	fmt.Println(strings.Repeat("-", 139))
	for _, row := range rows {
		fmt.Printf("%-44s %-15s %-11s %-28s %-12s %-17s %s\n",
			truncate(firstNonEmpty(row.NodeDID, "(unknown)"), 44),
			row.MeshIP,
			row.Device,
			truncate(row.Owner, 28),
			truncate(row.Label, 12),
			peerListExpiry(row.Expires),
			row.Path,
		)
	}
}

func peerListExpiry(expiresAt string) string {
	expiresAt = strings.TrimSpace(expiresAt)
	if expiresAt == "" {
		return "never"
	}
	parsed, err := time.Parse(time.RFC3339, expiresAt)
	if err != nil {
		return truncate(expiresAt, 17)
	}
	if time.Now().UTC().After(parsed) {
		return "expired"
	}
	return parsed.UTC().Format("2006-01-02 15:04")
}

func peerListDevice(peerDID string, selfDID string) string {
	if peerDID != "" && peerDID == selfDID {
		return "this device"
	}
	return "peer"
}

func peerListOwner(peerDID string, recordOwnerDID string, selfNodeDID string, selfOwnerDID string) string {
	ownerDID := recordOwnerDID
	if ownerDID == "" && peerDID != "" && peerDID == selfNodeDID {
		ownerDID = selfOwnerDID
	}
	if ownerDID == "" || ownerDID == peerDID {
		return "node"
	}
	return ownerDID
}

func peerListPath(node *control.Node) string {
	if node != nil && node.MemberRecordID != "" {
		return "network/member/node"
	}
	return "network/node"
}

func peerListMeshIP(meshCIDR string, peerDID string, recordMeshIP string) string {
	if recordMeshIP != "" {
		return recordMeshIP
	}
	if meshCIDR == "" || peerDID == "" {
		return "?"
	}
	ip, err := mesh.AllocateMeshIP(meshCIDR, peerDID)
	if err != nil {
		return "?"
	}
	return ip.String()
}

// cmdPeerAdd adds a peer to the mesh network. This creates a node record
// for the given DID on the anchor DWN and delivers the context encryption
// key so the peer can immediately decrypt mesh records.
//
// This must be run by the network anchor (owner). It combines the node
// record creation and key delivery into a single command.
//
// Usage: meshd peer add <node-did> [--owner <owner-did>] [--label <label>]
func cmdPeerAdd(ctx context.Context, args []string, flagProfile string) error {
	opts, err := parsePeerAddOptions(args)
	if err != nil {
		return err
	}
	peerDID := opts.nodeDID

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

	meta, useContextEncryption, err := requireNetworkOwnerProfile(flagProfile, identity, ns)
	if err != nil {
		return err
	}
	encMgr, err := prepareNetworkCommandEncryption(stateDir, identity, ns, useContextEncryption)
	if err != nil {
		return err
	}
	writeGrantID, err := walletGrantIDForDWNOperation(stateDir, meta, dwn.InterfaceRecordsWrite, protocols.MeshProtocolURI, "", ns.NetworkRecordID, useContextEncryption)
	if err != nil {
		return err
	}
	keyDeliveryGrantID, err := walletGrantIDForDWNOperation(stateDir, meta, dwn.InterfaceRecordsWrite, protocols.KeyDeliveryProtocolURI, "", "", useContextEncryption)
	if err != nil {
		return err
	}

	operationIdentity, err := loadDWNOperationIdentity(stateDir, meta, identity)
	if err != nil {
		return err
	}
	signer := dwnSigner(operationIdentity)

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
		Label:                opts.label,
		OwnerDID:             opts.ownerDID,
		UseContextEncryption: true,
		PermissionGrantID:    writeGrantID,
	})
	if err != nil {
		return fmt.Errorf("creating node record: %w", err)
	}
	fmt.Printf("  Node record created (IP=%s).\n", peerMeshIP)
	if opts.ownerDID != "" && opts.ownerDID != peerDID {
		fmt.Printf("  Owner: %s\n", opts.ownerDID)
	}

	// 2. Deliver the context encryption key so the peer can decrypt records.
	kdm := &mesh.KeyDeliveryManager{
		Endpoint:             ns.AnchorEndpoint,
		Signer:               signer,
		EncryptionKeyManager: encMgr,
	}
	err = kdm.DeliverContextKey(ctx, mesh.DeliverContextKeyParams{
		AnchorDID:         ns.AnchorDID,
		RecipientDID:      peerDID,
		SourceProtocol:    protocols.MeshProtocolURI,
		ContextID:         ns.NetworkRecordID,
		PermissionGrantID: keyDeliveryGrantID,
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

type peerAddOptions struct {
	nodeDID  string
	ownerDID string
	label    string
}

func parsePeerAddOptions(args []string) (peerAddOptions, error) {
	opts := peerAddOptions{label: "peer"}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--label":
			if i+1 >= len(args) {
				return opts, fmt.Errorf("--label requires a value")
			}
			opts.label = args[i+1]
			i++
		case "--member", "--owner":
			if i+1 >= len(args) {
				return opts, fmt.Errorf("%s requires a DID", args[i])
			}
			opts.ownerDID = args[i+1]
			i++
		default:
			if strings.HasPrefix(args[i], "-") {
				return opts, fmt.Errorf("unknown peer add flag %q", args[i])
			}
			if opts.nodeDID != "" {
				return opts, fmt.Errorf("unexpected argument %q", args[i])
			}
			opts.nodeDID = args[i]
		}
	}
	if opts.nodeDID == "" {
		return opts, fmt.Errorf("usage: meshd peer add <node-did> [--owner <owner-did>] [--label <label>]")
	}
	return opts, nil
}

// cmdPeerRemove removes a peer node record from the mesh network.
//
// This removes the device from peer discovery by deleting its network/node or
// network/member/node record and pruning child records such as nodeInfo and
// endpoints. It does not delete the owning member record.
//
// Usage: meshd peer remove <node-did>
func cmdPeerRemove(ctx context.Context, args []string, flagProfile string) error {
	opts, err := parsePeerRemoveOptions(args)
	if err != nil {
		return err
	}
	peerDID := opts.nodeDID

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

	selfNodeDID := networkNodeDID(ns, identity.URI)
	if peerDID == selfNodeDID {
		return fmt.Errorf("refusing to remove this device from the mesh; use 'meshd network leave' on this device")
	}

	meta, useContextEncryption, err := requireNetworkOwnerProfile(flagProfile, identity, ns)
	if err != nil {
		return err
	}
	readGrantID, err := walletGrantIDForDWNOperation(stateDir, meta, dwn.InterfaceRecordsQuery, protocols.MeshProtocolURI, "", ns.NetworkRecordID, useContextEncryption)
	if err != nil {
		return err
	}
	deleteGrantID, err := walletGrantIDForDWNOperation(stateDir, meta, dwn.InterfaceRecordsDelete, protocols.MeshProtocolURI, "", ns.NetworkRecordID, useContextEncryption)
	if err != nil {
		return err
	}
	keyDeliveryReadGrantID, err := walletGrantIDForDWNOperation(stateDir, meta, dwn.InterfaceRecordsQuery, protocols.KeyDeliveryProtocolURI, "", "", false)
	if err != nil {
		return err
	}
	keyDeliveryDeleteGrantID, err := walletGrantIDForDWNOperation(stateDir, meta, dwn.InterfaceRecordsDelete, protocols.KeyDeliveryProtocolURI, "", "", false)
	if err != nil {
		return err
	}

	operationIdentity, err := loadDWNOperationIdentity(stateDir, meta, identity)
	if err != nil {
		return err
	}
	signer := dwnSigner(operationIdentity)
	api := dwn.NewDwnAPI(dwn.NewSimpleAgent(ns.AnchorEndpoint, signer))
	protocolRole := ""
	if ns.AnchorDID != selfNodeDID {
		protocolRole = "network/node"
	}

	candidates, err := queryPeerRemoveCandidates(ctx, api, ns, peerDID, readGrantID, protocolRole)
	if err != nil {
		return err
	}
	if len(candidates) == 0 {
		return fmt.Errorf("peer node %s was not found in %q", peerDID, ns.NetworkName)
	}

	fmt.Printf("Removing peer %s from %q...\n", peerDID, ns.NetworkName)
	for _, candidate := range candidates {
		status, err := api.Delete(ctx, ns.AnchorDID, candidate.RecordID, true, protocolRole, deleteGrantID)
		if err != nil {
			return fmt.Errorf("deleting %s record %s: %w", candidate.Path, candidate.RecordID, err)
		}
		if status.Code >= 300 {
			return fmt.Errorf("delete %s record %s failed: %d %s", candidate.Path, candidate.RecordID, status.Code, status.Detail)
		}
		fmt.Printf("  Removed %s record %s\n", candidate.Path, candidate.RecordID)
	}
	removedContextKeys, err := removeDeliveredContextKeysForPeer(ctx, api, ns, peerDID, keyDeliveryReadGrantID, keyDeliveryDeleteGrantID)
	if err != nil {
		fmt.Printf("  Warning: delivered context key cleanup failed: %v\n", err)
	} else if removedContextKeys > 0 {
		fmt.Printf("  Removed delivered context keys: %d\n", removedContextKeys)
	}
	fmt.Printf("Peer removed. For cryptographic revocation, rotate network context keys before re-adding this node.\n")
	return nil
}

type peerRemoveOptions struct {
	nodeDID string
}

func parsePeerRemoveOptions(args []string) (peerRemoveOptions, error) {
	var opts peerRemoveOptions
	for _, arg := range args {
		if strings.HasPrefix(arg, "-") {
			return opts, fmt.Errorf("unknown peer remove flag %q", arg)
		}
		if opts.nodeDID != "" {
			return opts, fmt.Errorf("unexpected argument %q", arg)
		}
		opts.nodeDID = arg
	}
	if opts.nodeDID == "" {
		return opts, fmt.Errorf("usage: meshd peer remove <node-did>")
	}
	return opts, nil
}

type peerRemoveCandidate struct {
	RecordID       string
	Path           string
	MemberRecordID string
}

func queryPeerRemoveCandidates(ctx context.Context, api *dwn.DwnAPI, ns *state.NetworkState, peerDID, readGrantID, protocolRole string) ([]peerRemoveCandidate, error) {
	if api == nil || ns == nil || peerDID == "" {
		return nil, nil
	}
	var candidates []peerRemoveCandidate

	records, status, err := api.Query(ctx, ns.AnchorDID, dwn.QueryParams{
		Filter: dwn.RecordsFilter{
			Protocol:     protocols.MeshProtocolURI,
			ProtocolPath: "network/node",
			ContextID:    ns.NetworkRecordID,
			Recipient:    peerDID,
		},
		DateSort:          "createdAscending",
		PermissionGrantID: readGrantID,
	}, protocolRole)
	if err != nil {
		return nil, fmt.Errorf("querying owner node records: %w", err)
	}
	if status.Code != 200 {
		return nil, fmt.Errorf("owner node query failed: %d %s", status.Code, status.Detail)
	}
	candidates = appendPeerRemoveCandidates(candidates, records, "")

	memberRecords, status, err := api.Query(ctx, ns.AnchorDID, dwn.QueryParams{
		Filter: dwn.RecordsFilter{
			Protocol:     protocols.MeshProtocolURI,
			ProtocolPath: "network/member",
			ContextID:    ns.NetworkRecordID,
		},
		DateSort:          "createdAscending",
		PermissionGrantID: readGrantID,
	}, protocolRole)
	if err != nil {
		return nil, fmt.Errorf("querying member records: %w", err)
	}
	if status.Code != 200 {
		return nil, fmt.Errorf("member query failed: %d %s", status.Code, status.Detail)
	}
	for _, memberRecord := range memberRecords {
		if memberRecord == nil || memberRecord.ID == "" {
			continue
		}
		memberNodeRecords, mnStatus, mnErr := api.Query(ctx, ns.AnchorDID, dwn.QueryParams{
			Filter: dwn.RecordsFilter{
				Protocol:     protocols.MeshProtocolURI,
				ProtocolPath: "network/member/node",
				ContextID:    ns.NetworkRecordID + "/" + memberRecord.ID,
				Recipient:    peerDID,
			},
			DateSort:          "createdAscending",
			PermissionGrantID: readGrantID,
		}, protocolRole)
		if mnErr != nil {
			return nil, fmt.Errorf("querying member node records for %s: %w", memberRecord.ID, mnErr)
		}
		if mnStatus.Code != 200 {
			return nil, fmt.Errorf("member node query for %s failed: %d %s", memberRecord.ID, mnStatus.Code, mnStatus.Detail)
		}
		candidates = appendPeerRemoveCandidates(candidates, memberNodeRecords, memberRecord.ID)
	}
	return candidates, nil
}

func appendPeerRemoveCandidates(candidates []peerRemoveCandidate, records []*dwn.Record, memberRecordID string) []peerRemoveCandidate {
	for _, record := range records {
		candidate, ok := peerRemoveCandidateFromRecord(record, memberRecordID)
		if ok {
			candidates = append(candidates, candidate)
		}
	}
	return candidates
}

func peerRemoveCandidateFromRecord(record *dwn.Record, memberRecordID string) (peerRemoveCandidate, bool) {
	if record == nil || record.ID == "" {
		return peerRemoveCandidate{}, false
	}
	path := record.ProtocolPath
	if path == "" {
		if memberRecordID != "" {
			path = "network/member/node"
		} else {
			path = "network/node"
		}
	}
	return peerRemoveCandidate{
		RecordID:       record.ID,
		Path:           path,
		MemberRecordID: memberRecordID,
	}, true
}

func removeDeliveredContextKeysForPeer(ctx context.Context, api *dwn.DwnAPI, ns *state.NetworkState, peerDID, readGrantID, deleteGrantID string) (int, error) {
	if api == nil || ns == nil || peerDID == "" {
		return 0, nil
	}
	records, status, err := api.Query(ctx, ns.AnchorDID, dwn.QueryParams{
		Filter: dwn.RecordsFilter{
			Protocol:     protocols.KeyDeliveryProtocolURI,
			ProtocolPath: "contextKey",
			Recipient:    peerDID,
		},
		DateSort:          "createdAscending",
		PermissionGrantID: readGrantID,
	}, "")
	if err != nil {
		return 0, fmt.Errorf("querying delivered context keys: %w", err)
	}
	if status.Code != 200 {
		return 0, fmt.Errorf("context key query failed: %d %s", status.Code, status.Detail)
	}

	removed := 0
	for _, record := range records {
		if !deliveredContextKeyMatchesNetwork(record, ns.NetworkRecordID) {
			continue
		}
		status, err := api.Delete(ctx, ns.AnchorDID, record.ID, false, "", deleteGrantID)
		if err != nil {
			return removed, fmt.Errorf("deleting contextKey record %s: %w", record.ID, err)
		}
		if status.Code >= 300 {
			return removed, fmt.Errorf("delete contextKey record %s failed: %d %s", record.ID, status.Code, status.Detail)
		}
		removed++
	}
	return removed, nil
}

func deliveredContextKeyMatchesNetwork(record *dwn.Record, networkRecordID string) bool {
	if record == nil || record.ID == "" || networkRecordID == "" {
		return false
	}
	return tagString(record.Tags, "protocol") == protocols.MeshProtocolURI &&
		tagString(record.Tags, "contextId") == networkRecordID
}

func tagString(tags map[string]any, key string) string {
	if tags == nil {
		return ""
	}
	value, ok := tags[key]
	if !ok {
		return ""
	}
	switch v := value.(type) {
	case string:
		return v
	case fmt.Stringer:
		return v.String()
	default:
		return fmt.Sprint(v)
	}
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

	meta, useContextEncryption, err := requireNetworkOwnerProfile(flagProfile, identity, ns)
	if err != nil {
		return err
	}
	readGrantID, err := walletGrantIDForDWNOperation(stateDir, meta, dwn.InterfaceRecordsQuery, protocols.MeshProtocolURI, "", ns.NetworkRecordID, useContextEncryption)
	if err != nil {
		return err
	}
	keyDeliveryGrantID, err := walletGrantIDForDWNOperation(stateDir, meta, dwn.InterfaceRecordsWrite, protocols.KeyDeliveryProtocolURI, "", "", useContextEncryption)
	if err != nil {
		return err
	}

	operationIdentity, err := loadDWNOperationIdentity(stateDir, meta, identity)
	if err != nil {
		return err
	}
	signer := dwnSigner(operationIdentity)
	encMgr, err := prepareNetworkCommandEncryption(stateDir, identity, ns, useContextEncryption)
	if err != nil {
		return err
	}
	recipientKeyDelivery, lookupErr := lookupPeerKeyDelivery(ctx, stateDir, ns, identity, operationIdentity, encMgr, readGrantID, peerDID)
	if lookupErr != nil {
		fmt.Printf("  Warning: node key-delivery lookup failed: %v\n", lookupErr)
	}

	kdm := &mesh.KeyDeliveryManager{
		Endpoint:             ns.AnchorEndpoint,
		Signer:               signer,
		EncryptionKeyManager: encMgr,
	}

	err = kdm.DeliverContextKey(ctx, mesh.DeliverContextKeyParams{
		AnchorDID:            ns.AnchorDID,
		RecipientDID:         peerDID,
		SourceProtocol:       protocols.MeshProtocolURI,
		ContextID:            ns.NetworkRecordID,
		PermissionGrantID:    keyDeliveryGrantID,
		RecipientKeyDelivery: recipientKeyDelivery,
	})
	if err != nil {
		return fmt.Errorf("delivering context key: %w", err)
	}

	fmt.Printf("Context key delivered to %s.\n", peerDID)
	if recipientKeyDelivery != nil {
		fmt.Printf("  Encrypted to node key-delivery key: %s\n", recipientKeyDelivery.RootKeyID)
	}
	fmt.Printf("The peer can now decrypt mesh records in this network.\n")
	return nil
}

func lookupPeerKeyDelivery(ctx context.Context, stateDir string, ns *state.NetworkState, identity *did.DID, signerIdentity *did.DID, encMgr *dwncrypto.EncryptionKeyManager, readGrantID string, peerDID string) (*dwncrypto.KeyDeliveryPublic, error) {
	if ns == nil || identity == nil || peerDID == "" {
		return nil, nil
	}
	if encMgr == nil {
		encMgr = newEncryptionKeyManager(identity)
	}
	if ns.AnchorDID != networkNodeDID(ns, identity.URI) && !encMgr.HasContextKey(ns.NetworkRecordID) {
		if _, _, err := loadLocalContextKeyForCLI(stateDir, ns, encMgr); err != nil {
			return nil, err
		}
	}
	resp, err := loadControlStateForCLI(ctx, ns, identity, signerIdentity, encMgr, readGrantID)
	if err != nil {
		return nil, err
	}
	return keyDeliveryForNode(resp, peerDID), nil
}

func keyDeliveryForNode(resp *control.MapResponse, nodeDID string) *dwncrypto.KeyDeliveryPublic {
	if resp == nil || nodeDID == "" {
		return nil
	}
	if resp.Node != nil && resp.Node.DID == nodeDID {
		return resp.Node.KeyDelivery
	}
	for _, peer := range resp.Peers {
		if peer != nil && peer.DID == nodeDID {
			return peer.KeyDelivery
		}
	}
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
	meta := resolveIdentityMetadata(flagProfile, identity.URI)
	fmt.Printf("  Local Node DID: %s\n", identity.URI)
	fmt.Printf("  Auth: %s\n", authDisplayName(meta.AuthType))
	if meta.OwnerDID != "" && meta.OwnerDID != identity.URI {
		fmt.Printf("  Wallet Owner DID: %s\n", meta.OwnerDID)
	}
	if meta.DelegateDID != "" {
		fmt.Printf("  Session Delegate DID: %s\n", meta.DelegateDID)
	}
	if meta.NodeDID != "" && meta.NodeDID != identity.URI {
		fmt.Printf("  Configured Node DID: %s\n", meta.NodeDID)
	}
	fmt.Printf("  State: %s\n", stateDir)
	if did.EncryptedExists(stateDir) {
		fmt.Printf("  Vault: encrypted\n")
	} else {
		fmt.Printf("  Vault: plaintext legacy\n")
	}
	if meta.AuthType == profile.AuthTypeWalletAuthorizedNode {
		if err := printWalletSessionStatus(stateDir, meta); err != nil {
			return err
		}
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
	selfNodeDID := networkNodeDID(ns, identity.URI)
	selfOwnerDID := networkOwnerDID(ns, firstNonEmpty(meta.OwnerDID, identity.URI))
	if selfNodeDID != "" {
		fmt.Printf("  Node DID: %s\n", selfNodeDID)
	}
	if selfOwnerDID != "" && selfOwnerDID != selfNodeDID {
		fmt.Printf("  Wallet Owner DID: %s\n", selfOwnerDID)
	}
	if ns.MeshIP != "" {
		fmt.Printf("  Mesh IP: %s\n", ns.MeshIP)
	}
	if ns.NodeExpiresAt != "" {
		fmt.Printf("  Membership Expires: %s\n", ns.NodeExpiresAt)
	}
	// WireGuard public key is derived from the node DID, not stored.
	if selfNodeDID != "" {
		wgPubKey, wgErr := mesh.WireGuardPubKeyFromDID(selfNodeDID)
		if wgErr == nil {
			fmt.Printf("  WireGuard Key: %s\n", wgPubKey)
		}
	}
	if ns.NodeRecordID != "" {
		fmt.Printf("  Node Record: %s\n", ns.NodeRecordID)
	}
	if ns.MemberRecordID != "" {
		fmt.Printf("  Member Record: %s\n", ns.MemberRecordID)
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

type doctorLevel string

const (
	doctorOK   doctorLevel = "ok"
	doctorWarn doctorLevel = "warn"
	doctorFail doctorLevel = "fail"
	doctorInfo doctorLevel = "info"
)

type doctorCheck struct {
	Level  doctorLevel
	Title  string
	Detail string
	Next   string
}

// cmdDoctor diagnoses local state and common runtime issues without mutating
// network or DWN state.
func cmdDoctor(ctx context.Context, args []string, flagProfile string) error {
	if len(args) > 0 {
		return fmt.Errorf("usage: meshd doctor")
	}

	fmt.Println("meshd doctor")
	checks := collectDoctorChecks(ctx, flagProfile)
	for _, check := range checks {
		printDoctorCheck(os.Stdout, check)
	}
	if doctorHasLevel(checks, doctorFail) {
		fmt.Println("\nResult: issues found. Follow the suggested next steps above.")
	} else if doctorHasLevel(checks, doctorWarn) {
		fmt.Println("\nResult: usable, with warnings.")
	} else {
		fmt.Println("\nResult: ready.")
	}
	return nil
}

func collectDoctorChecks(ctx context.Context, flagProfile string) []doctorCheck {
	var checks []doctorCheck

	stateDir, err := resolveStateDir(flagProfile)
	if err != nil {
		checks = append(checks, doctorCheck{
			Level:  doctorFail,
			Title:  "No active identity profile",
			Detail: err.Error(),
			Next:   "Run 'meshd auth connect' or select a profile with '--profile <name>'.",
		})
		return checks
	}
	checks = append(checks, doctorCheck{
		Level:  doctorInfo,
		Title:  "State directory",
		Detail: stateDir,
	})

	if !identityExists(stateDir) {
		checks = append(checks, doctorCheck{
			Level:  doctorFail,
			Title:  "Identity missing",
			Detail: "This profile has no local node identity.",
			Next:   "Run 'meshd auth connect' for wallet approval, or 'meshd auth login' for a local-vault profile.",
		})
		return checks
	}

	identity, err := loadIdentity(stateDir)
	if err != nil {
		checks = append(checks, doctorCheck{
			Level:  doctorFail,
			Title:  "Identity vault could not be opened",
			Detail: err.Error(),
			Next:   "Run 'meshd vault unlock' and check the vault password.",
		})
		return checks
	}
	meta := resolveIdentityMetadata(flagProfile, identity.URI)
	checks = append(checks, doctorCheck{
		Level:  doctorOK,
		Title:  "Identity loaded",
		Detail: fmt.Sprintf("node DID %s (%s)", firstNonEmpty(meta.NodeDID, identity.URI), authDisplayName(meta.AuthType)),
	})
	if did.EncryptedExists(stateDir) {
		checks = append(checks, doctorCheck{Level: doctorOK, Title: "Vault encrypted"})
	} else {
		checks = append(checks, doctorCheck{
			Level:  doctorWarn,
			Title:  "Legacy plaintext identity",
			Detail: "This profile is using the old plaintext identity file.",
			Next:   "Run 'meshd vault init' to encrypt it.",
		})
	}

	if meta.AuthType == profile.AuthTypeWalletAuthorizedNode {
		checks = append(checks, walletDoctorChecks(stateDir, meta)...)
	}

	ns, err := state.LoadNetworkState(stateDir)
	if err != nil {
		checks = append(checks, doctorCheck{
			Level:  doctorFail,
			Title:  "Network state could not be read",
			Detail: err.Error(),
			Next:   "Inspect network.json or run 'meshd network leave' before joining again.",
		})
		return checks
	}
	if ns == nil {
		checks = append(checks, doctorCheck{
			Level:  doctorWarn,
			Title:  "No network joined",
			Detail: "This profile has an identity but no mesh membership.",
			Next:   "Run 'meshd up' to use the setup wizard, create a network, or join an invite.",
		})
		return checks
	}

	selfNodeDID := networkNodeDID(ns, identity.URI)
	checks = append(checks, doctorCheck{
		Level:  doctorOK,
		Title:  "Network joined",
		Detail: fmt.Sprintf("%s (%s)", ns.NetworkName, ns.MeshCIDR),
	})
	if ns.AnchorEndpoint == "" || ns.AnchorDID == "" || ns.NetworkRecordID == "" {
		checks = append(checks, doctorCheck{
			Level:  doctorFail,
			Title:  "Network anchor metadata incomplete",
			Detail: fmt.Sprintf("anchor=%q endpoint=%q record=%q", ns.AnchorDID, ns.AnchorEndpoint, ns.NetworkRecordID),
			Next:   "Rejoin the network from a fresh invite or wallet approval.",
		})
	}
	if ns.MeshIP == "" {
		checks = append(checks, doctorCheck{
			Level: "fail",
			Title: "Mesh IP missing",
			Next:  "Run 'meshd up' again after the anchor approves this node.",
		})
	} else {
		checks = append(checks, doctorCheck{Level: doctorOK, Title: "Mesh IP assigned", Detail: ns.MeshIP})
	}
	if ns.NodeRecordID == "" {
		checks = append(checks, doctorCheck{
			Level:  doctorWarn,
			Title:  "Node record missing",
			Detail: "This usually means the join request is still waiting for anchor/wallet approval.",
			Next:   "Open the wallet admin panel or keep the anchor online, then run 'meshd up' again.",
		})
	}
	if meta.DelegateDID != "" && ns.DelegateDID != "" && meta.DelegateDID != ns.DelegateDID {
		checks = append(checks, doctorCheck{
			Level:  doctorFail,
			Title:  "Delegate mismatch",
			Detail: fmt.Sprintf("profile delegate %s, network delegate %s", meta.DelegateDID, ns.DelegateDID),
			Next:   "Reconnect this profile with 'meshd auth connect'.",
		})
	}

	live, daemonChecks := daemonDoctorChecks(ctx, ns)
	checks = append(checks, daemonChecks...)
	if live == nil {
		return checks
	}

	if live.TUNDevice == "" {
		checks = append(checks, doctorCheck{
			Level:  doctorWarn,
			Title:  "No TUN device",
			Detail: "The daemon is running in userspace/no-route mode. OS ping will not work in this mode.",
			Next:   "Run 'meshd down' and then 'meshd up' without '--no-tun'.",
		})
		return checks
	}

	checks = append(checks, interfaceDoctorChecks(ctx, live.TUNDevice, firstNonEmpty(live.MeshIP, ns.MeshIP))...)
	routeChecks := peerRouteDoctorChecks(ctx, stateDir, ns, identity, meta, selfNodeDID, live.TUNDevice)
	checks = append(checks, routeChecks...)
	return checks
}

func walletDoctorChecks(stateDir string, meta identityMetadata) []doctorCheck {
	if !state.WalletSessionExists(stateDir) {
		return []doctorCheck{{
			Level:  doctorFail,
			Title:  "Wallet session missing",
			Detail: "This profile is marked wallet-authorized but has no imported wallet grants.",
			Next:   "Run 'meshd auth connect'.",
		}}
	}
	status, err := loadWalletSessionStatus(stateDir, meta)
	if err != nil {
		return []doctorCheck{{
			Level:  doctorFail,
			Title:  "Wallet session could not be opened",
			Detail: err.Error(),
			Next:   "Run 'meshd vault unlock' and reconnect with 'meshd auth connect' if needed.",
		}}
	}
	if status == nil || !status.Exists {
		return []doctorCheck{{
			Level: doctorFail,
			Title: "Wallet session missing",
			Next:  "Run 'meshd auth connect'.",
		}}
	}
	checks := []doctorCheck{{
		Level:  doctorOK,
		Title:  "Wallet owner",
		Detail: status.OwnerDID,
	}}
	if status.DelegateDID == "" {
		checks = append(checks, doctorCheck{
			Level:  doctorWarn,
			Title:  "Delegate DID missing",
			Detail: "This looks like an older wallet session that granted directly to the node DID.",
			Next:   "Run 'meshd auth connect' to create a revocable local delegate.",
		})
	} else if _, err := verifyWalletDelegateIdentity(stateDir, status.DelegateDID); err != nil {
		checks = append(checks, doctorCheck{
			Level:  doctorFail,
			Title:  "Delegate vault mismatch",
			Detail: err.Error(),
			Next:   "Run 'meshd auth connect' again from this profile.",
		})
	} else {
		checks = append(checks, doctorCheck{
			Level:  doctorOK,
			Title:  "Delegate key loaded",
			Detail: status.DelegateDID,
		})
	}
	if status.OwnerDIDMismatch || status.NodeDIDMismatch {
		checks = append(checks, doctorCheck{
			Level:  doctorFail,
			Title:  "Wallet session identity mismatch",
			Detail: fmt.Sprintf("owner mismatch=%t node mismatch=%t", status.OwnerDIDMismatch, status.NodeDIDMismatch),
			Next:   "Reconnect this profile with 'meshd auth connect'.",
		})
	}
	if status.NodeRuntimeAccess {
		checks = append(checks, doctorCheck{Level: doctorOK, Title: "Runtime grants present"})
	} else {
		checks = append(checks, doctorCheck{
			Level:  doctorFail,
			Title:  "Runtime grants missing",
			Detail: "The daemon may not be able to read/write mesh control records.",
			Next:   "Run 'meshd auth connect' and approve node runtime access in the wallet.",
		})
	}
	if status.NodeContextKeyCount > 0 {
		checks = append(checks, doctorCheck{Level: doctorOK, Title: "Context keys cached", Detail: strconv.Itoa(status.NodeContextKeyCount)})
	} else {
		checks = append(checks, doctorCheck{
			Level:  doctorWarn,
			Title:  "No cached context key",
			Detail: "Non-anchor nodes need a delivered context key to decrypt mesh records.",
			Next:   "Approve the node in the wallet admin panel or run 'meshd peer approve <node-did>' on the anchor.",
		})
	}
	return checks
}

func daemonDoctorChecks(ctx context.Context, ns *state.NetworkState) (*daemon.Status, []doctorCheck) {
	client := daemon.NewClient(daemon.DefaultSocketPath())
	if !client.IsRunning() {
		return nil, []doctorCheck{{
			Level:  doctorFail,
			Title:  "Daemon not running",
			Detail: fmt.Sprintf("socket %s is not accepting connections", daemon.DefaultSocketPath()),
			Next:   "Run 'meshd up'.",
		}}
	}
	live, err := client.GetStatus(ctx)
	if err != nil {
		return nil, []doctorCheck{{
			Level:  doctorFail,
			Title:  "Daemon status unavailable",
			Detail: err.Error(),
			Next:   "Run 'meshd down' and then 'meshd up'.",
		}}
	}
	checks := []doctorCheck{{
		Level:  doctorOK,
		Title:  "Daemon running",
		Detail: fmt.Sprintf("pid %d, uptime %s", live.PID, live.Uptime),
	}}
	if ns != nil && ns.NetworkName != "" && live.Network != "" && live.Network != ns.NetworkName {
		checks = append(checks, doctorCheck{
			Level:  doctorWarn,
			Title:  "Daemon network differs from local state",
			Detail: fmt.Sprintf("daemon=%q local=%q", live.Network, ns.NetworkName),
			Next:   "Run 'meshd down' and then 'meshd up' for the active profile.",
		})
	}
	if ns != nil && ns.MeshIP != "" && live.MeshIP != "" && live.MeshIP != ns.MeshIP {
		checks = append(checks, doctorCheck{
			Level:  doctorWarn,
			Title:  "Daemon mesh IP differs from local state",
			Detail: fmt.Sprintf("daemon=%s local=%s", live.MeshIP, ns.MeshIP),
			Next:   "Run 'meshd down' and then 'meshd up'.",
		})
	}
	return live, checks
}

func interfaceDoctorChecks(ctx context.Context, tunName string, meshIP string) []doctorCheck {
	output, err := inspectInterface(ctx, tunName)
	if err != nil {
		return []doctorCheck{{
			Level:  doctorWarn,
			Title:  "TUN device could not be inspected",
			Detail: err.Error(),
			Next:   "Check the interface manually with 'ip addr' on Linux or 'ifconfig' on macOS.",
		}}
	}
	checks := []doctorCheck{{
		Level:  doctorOK,
		Title:  "TUN device exists",
		Detail: tunName,
	}}
	if meshIP != "" {
		if strings.Contains(output, meshIP) {
			checks = append(checks, doctorCheck{Level: doctorOK, Title: "TUN has mesh IP", Detail: meshIP})
		} else {
			checks = append(checks, doctorCheck{
				Level:  doctorWarn,
				Title:  "TUN mesh IP not visible",
				Detail: fmt.Sprintf("%s was not found in %s", meshIP, tunName),
				Next:   "Run 'meshd down' and then 'meshd up'.",
			})
		}
	}
	return checks
}

func peerRouteDoctorChecks(ctx context.Context, stateDir string, ns *state.NetworkState, identity *did.DID, meta identityMetadata, selfNodeDID string, tunName string) []doctorCheck {
	if ns == nil || identity == nil || tunName == "" {
		return nil
	}
	routeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	peerIP, peerCount, err := doctorPeerRouteTarget(routeCtx, stateDir, ns, identity, meta, selfNodeDID)
	if err != nil {
		return []doctorCheck{{
			Level:  doctorWarn,
			Title:  "Peer route check skipped",
			Detail: err.Error(),
			Next:   "Run 'meshd peer list' to verify peer discovery.",
		}}
	}
	if peerCount == 0 {
		return []doctorCheck{{
			Level:  doctorWarn,
			Title:  "No peers discovered",
			Detail: "The network map contains only this device.",
			Next:   "Join another device and approve it in the wallet admin panel.",
		}}
	}
	if peerIP == "" {
		return []doctorCheck{{
			Level:  doctorWarn,
			Title:  "No peer mesh IP available",
			Detail: fmt.Sprintf("%d peer records were found, but none had a usable mesh IP", peerCount),
			Next:   "Run 'meshd peer list' and check that peers have mesh IPs.",
		}}
	}
	output, err := routeForIP(ctx, peerIP)
	if err != nil {
		return []doctorCheck{{
			Level:  doctorWarn,
			Title:  "Peer route could not be inspected",
			Detail: err.Error(),
			Next:   "Check the route manually with 'ip route get <peer-ip>' on Linux or 'route -n get <peer-ip>' on macOS.",
		}}
	}
	if routeUsesInterface(output, tunName) {
		return []doctorCheck{{
			Level:  doctorOK,
			Title:  "Peer route uses meshd TUN",
			Detail: fmt.Sprintf("%s via %s", peerIP, tunName),
		}}
	}
	detected := routeInterface(output)
	detail := strings.TrimSpace(firstLine(output))
	if detected != "" {
		detail = fmt.Sprintf("%s routes via %s, not %s", peerIP, detected, tunName)
	}
	return []doctorCheck{{
		Level:  doctorFail,
		Title:  "Peer route does not use meshd TUN",
		Detail: detail,
		Next:   "Run 'meshd down' and then 'meshd up'. If another VPN owns this route, check its route table.",
	}}
}

func doctorPeerRouteTarget(ctx context.Context, stateDir string, ns *state.NetworkState, identity *did.DID, meta identityMetadata, selfNodeDID string) (string, int, error) {
	readGrantID, err := walletGrantIDForDWNOperation(stateDir, meta, dwn.InterfaceRecordsQuery, protocols.MeshProtocolURI, "", ns.NetworkRecordID, false)
	if err != nil {
		return "", 0, err
	}
	operationIdentity, err := loadDWNOperationIdentity(stateDir, meta, identity)
	if err != nil {
		return "", 0, err
	}
	encMgr := newEncryptionKeyManager(identity)
	if ns.AnchorDID != selfNodeDID {
		_, _, _ = loadLocalContextKeyForCLI(stateDir, ns, encMgr)
	}
	resp, err := loadControlStateForCLI(ctx, ns, identity, operationIdentity, encMgr, readGrantID)
	if err != nil {
		return "", 0, err
	}
	peerCount := 0
	for _, peer := range resp.Peers {
		if peer == nil || peer.DID == selfNodeDID {
			continue
		}
		peerCount++
		if peer.MeshIP.IsValid() {
			return peer.MeshIP.String(), peerCount, nil
		}
	}
	return "", peerCount, nil
}

func inspectInterface(ctx context.Context, name string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("interface name is empty")
	}
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "linux":
		cmd = exec.CommandContext(ctx, "ip", "addr", "show", "dev", name)
	case "darwin":
		cmd = exec.CommandContext(ctx, "ifconfig", name)
	default:
		return "", fmt.Errorf("interface inspection is not implemented for %s", runtime.GOOS)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return strings.TrimSpace(string(out)), fmt.Errorf("%s: %w", strings.Join(cmd.Args, " "), err)
	}
	return string(out), nil
}

func routeForIP(ctx context.Context, ip string) (string, error) {
	if ip == "" {
		return "", fmt.Errorf("peer IP is empty")
	}
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "linux":
		cmd = exec.CommandContext(ctx, "ip", "route", "get", ip)
	case "darwin":
		cmd = exec.CommandContext(ctx, "route", "-n", "get", ip)
	default:
		return "", fmt.Errorf("route inspection is not implemented for %s", runtime.GOOS)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return strings.TrimSpace(string(out)), fmt.Errorf("%s: %w", strings.Join(cmd.Args, " "), err)
	}
	return string(out), nil
}

func routeUsesInterface(output string, tunName string) bool {
	return tunName != "" && routeInterface(output) == tunName
}

func routeInterface(output string) string {
	fields := strings.Fields(output)
	for i, field := range fields {
		switch strings.TrimSuffix(field, ":") {
		case "dev", "interface":
			if i+1 < len(fields) {
				return strings.TrimSpace(fields[i+1])
			}
		}
	}
	return ""
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func printDoctorCheck(w io.Writer, check doctorCheck) {
	label := string(check.Level)
	if label == "" {
		label = string(doctorInfo)
	}
	fmt.Fprintf(w, "[%s] %s\n", label, check.Title)
	if check.Detail != "" {
		fmt.Fprintf(w, "     %s\n", check.Detail)
	}
	if check.Next != "" {
		fmt.Fprintf(w, "     Next: %s\n", check.Next)
	}
}

func doctorHasLevel(checks []doctorCheck, level doctorLevel) bool {
	for _, check := range checks {
		if check.Level == level {
			return true
		}
	}
	return false
}

// upFlags holds parsed flags for the `meshd up` command.
type upFlags struct {
	// Network setup flags.
	createNetwork string // --create <name>: create a new network
	endpoint      string // --endpoint <url>: DWN endpoint
	anchorDID     string // --anchor <did>: anchor DID for joining
	networkID     string // --network <id>: network record ID for joining
	ownerDID      string // --owner <did>: wallet owner DID for this node
	inviteURL     string // positional meshd://invite URL

	// Engine flags.
	tunName      string        // --tun [name]: TUN device name
	noTun        bool          // --no-tun: disable auto TUN
	listenPort   uint16        // --port <n>
	pollInterval time.Duration // --poll-interval <dur>
	foreground   bool          // --foreground: keep meshd up attached
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
		case "--owner", "--member":
			if i+1 < len(args) {
				f.ownerDID = args[i+1]
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
				f.tunName = defaultTUNName(runtime.GOOS)
			}
		case "--no-tun":
			f.noTun = true
		case "--foreground":
			f.foreground = true
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
		f.tunName = defaultTUNName(runtime.GOOS)
	}

	return f
}

func defaultTUNName(goos string) string {
	if goos == "darwin" {
		return "utun"
	}
	return "meshd0"
}

func supportsRealTUN(goos string) bool {
	return goos == "darwin" || goos == "linux"
}

func shouldReexecWithSudoForTun(f upFlags, uid int, goos string, stdinTTY bool) bool {
	if uid == 0 || f.noTun || !stdinTTY || !supportsRealTUN(goos) {
		return false
	}
	return true
}

func reexecUpWithSudo(args []string, flagProfile string) error {
	sudoPath, err := exec.LookPath("sudo")
	if err != nil {
		return fmt.Errorf("system routing requires administrator privileges, but sudo was not found; run meshd as root or use --no-tun")
	}

	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolving meshd executable for sudo handoff: %w", err)
	}

	sudoArgs := []string{"env"}
	sudoArgs = append(sudoArgs, sudoEnvironmentAssignments()...)
	sudoArgs = append(sudoArgs, exePath, "up")
	if flagProfile != "" {
		sudoArgs = append(sudoArgs, "--profile", flagProfile)
	}
	sudoArgs = append(sudoArgs, args...)

	fmt.Fprintln(os.Stderr, "meshd: system routing needs administrator privileges; asking sudo to start the tunnel.")

	cmd := exec.Command(sudoPath, sudoArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func startUpInBackground(ctx context.Context, args []string, flagProfile, stateDir string, needsSudo bool) error {
	socketPath := daemon.DefaultSocketPath()
	if daemon.NewClient(socketPath).IsRunning() {
		fmt.Println("meshd is already running.")
		fmt.Printf("  Socket: %s\n", socketPath)
		fmt.Println("Run 'meshd status' to inspect it or 'meshd down' to stop it.")
		return nil
	}

	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolving meshd executable: %w", err)
	}

	logPath := daemonLogPath(stateDir)
	if err := os.MkdirAll(filepath.Dir(logPath), 0o700); err != nil {
		return fmt.Errorf("creating daemon log directory: %w", err)
	}
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("opening daemon log: %w", err)
	}
	defer logFile.Close()

	cmdArgs := []string{exePath, "up"}
	if flagProfile != "" {
		cmdArgs = append(cmdArgs, "--profile", flagProfile)
	}
	cmdArgs = append(cmdArgs, args...)

	var cmd *exec.Cmd
	if needsSudo {
		sudoPath, err := exec.LookPath("sudo")
		if err != nil {
			return fmt.Errorf("system routing requires administrator privileges, but sudo was not found; run meshd as root or use --no-tun")
		}
		fmt.Fprintln(os.Stderr, "meshd: system routing needs administrator privileges; asking sudo to start the tunnel.")
		validate := exec.CommandContext(ctx, sudoPath, "-v")
		validate.Stdin = os.Stdin
		validate.Stdout = os.Stdout
		validate.Stderr = os.Stderr
		if err := validate.Run(); err != nil {
			return fmt.Errorf("sudo authentication failed: %w", err)
		}

		sudoArgs := []string{"-n", "env"}
		sudoArgs = append(sudoArgs, sudoEnvironmentAssignments()...)
		sudoArgs = append(sudoArgs, upBackgroundEnv+"=1")
		sudoArgs = append(sudoArgs, cmdArgs...)
		cmd = exec.Command(sudoPath, sudoArgs...)
	} else {
		cmd = exec.Command(cmdArgs[0], cmdArgs[1:]...)
		cmd.Env = append(os.Environ(), upBackgroundEnv+"=1")
	}
	cmd.Stdin = nil
	cmd.Stdout = logFile
	cmd.Stderr = logFile

	fmt.Println("Starting meshd in the background...")
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting background meshd: %w", err)
	}
	_ = cmd.Process.Release()

	status, err := waitForDaemonStart(ctx, socketPath, backgroundWait)
	if err != nil {
		return fmt.Errorf("%w; see %s", err, logPath)
	}

	fmt.Println("meshd is running.")
	if status.Network != "" {
		fmt.Printf("  Network: %s\n", status.Network)
	}
	if status.MeshIP != "" {
		fmt.Printf("  Mesh IP: %s\n", status.MeshIP)
	}
	if status.TUNDevice != "" {
		fmt.Printf("  TUN device: %s\n", status.TUNDevice)
	}
	fmt.Printf("  Socket: %s\n", socketPath)
	fmt.Printf("  Log: %s\n", logPath)
	fmt.Println("Run 'meshd status' to inspect it or 'meshd down' to stop it.")
	return nil
}

func waitForDaemonStart(ctx context.Context, socketPath string, timeout time.Duration) (*daemon.Status, error) {
	client := daemon.NewClient(socketPath)
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		status, err := client.GetStatus(ctx)
		if err == nil {
			return status, nil
		}
		lastErr = err
		time.Sleep(250 * time.Millisecond)
	}
	if lastErr != nil {
		return nil, fmt.Errorf("daemon did not start within %s: %w", timeout, lastErr)
	}
	return nil, fmt.Errorf("daemon did not start within %s", timeout)
}

func daemonLogPath(stateDir string) string {
	return filepath.Join(stateDir, daemonLogName)
}

func sudoEnvironmentAssignments() []string {
	assignments := []string{sudoChildEnv + "=1"}

	home := os.Getenv("HOME")
	if home == "" {
		if userHome, err := os.UserHomeDir(); err == nil {
			home = userHome
		}
	}
	if home != "" {
		assignments = append(assignments, "HOME="+home)
	}

	enboxHome := os.Getenv("ENBOX_HOME")
	if enboxHome == "" && home != "" {
		enboxHome = filepath.Join(home, ".enbox")
	}
	if enboxHome != "" {
		assignments = append(assignments, "ENBOX_HOME="+enboxHome)
	}

	if cacheDir := strings.TrimSpace(os.Getenv(vaultPasswordCacheDirEnv)); cacheDir != "" {
		assignments = append(assignments, vaultPasswordCacheDirEnv+"="+cacheDir)
	} else if cacheDir, err := vaultPasswordCacheDir(); err == nil && cacheDir != "" {
		assignments = append(assignments, vaultPasswordCacheDirEnv+"="+cacheDir)
	}

	for _, key := range []string{"PATH", "DWN_ENDPOINT", "ENBOX_PROFILE", "MESHD_STATE_DIR", vaultPasswordCacheTTLEnv, walletResponseEndpointEnv} {
		if value := os.Getenv(key); value != "" {
			assignments = append(assignments, key+"="+value)
		}
	}

	return assignments
}

func restoreSudoUserOwnership() {
	uid, gid, ok := sudoOriginalIDs()
	if !ok {
		return
	}

	for _, root := range sudoOwnershipRoots() {
		if root == "" {
			continue
		}
		_ = filepath.WalkDir(root, func(path string, _ os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			_ = os.Lchown(path, uid, gid)
			return nil
		})
	}
}

func sudoOriginalIDs() (uid int, gid int, ok bool) {
	uid64, uidErr := strconv.ParseInt(os.Getenv("SUDO_UID"), 10, 32)
	gid64, gidErr := strconv.ParseInt(os.Getenv("SUDO_GID"), 10, 32)
	if uidErr != nil || gidErr != nil || uid64 <= 0 || gid64 < 0 {
		return 0, 0, false
	}
	return int(uid64), int(gid64), true
}

func sudoOwnershipRoots() []string {
	home := os.Getenv("HOME")
	if home == "" {
		return nil
	}

	var candidates []string
	if stateDir := os.Getenv("MESHD_STATE_DIR"); stateDir != "" {
		candidates = append(candidates, stateDir)
	} else if enboxHome := os.Getenv("ENBOX_HOME"); enboxHome != "" {
		candidates = append(candidates, enboxHome)
	}

	roots := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		if isSafeSudoOwnershipRoot(candidate, home) {
			roots = append(roots, candidate)
		}
	}
	return roots
}

func isSafeSudoOwnershipRoot(root string, home string) bool {
	absRoot, rootErr := filepath.Abs(root)
	absHome, homeErr := filepath.Abs(home)
	if rootErr != nil || homeErr != nil {
		return false
	}
	if absRoot == absHome {
		return false
	}
	rel, err := filepath.Rel(absHome, absRoot)
	if err != nil || rel == "." {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// cmdUp starts the mesh agent daemon.
//
// This is the main entry point for meshd. It handles the full lifecycle:
//  1. Creates an identity profile if none exists
//  2. Creates or joins a network if not yet in one
//  3. Starts the WireGuard tunnel
//  4. Starts the mesh daemon in the background
//
// Flags like --create, --endpoint, --anchor, --network allow one-command
// setup. Without flags, it guides the user interactively.
func cmdUp(ctx context.Context, args []string, flagProfile string) error {
	f := parseUpFlags(args)
	backgroundChild := os.Getenv(upBackgroundEnv) == "1"
	if !backgroundChild && !f.foreground {
		socketPath := daemon.DefaultSocketPath()
		if daemon.NewClient(socketPath).IsRunning() {
			fmt.Println("meshd is already running.")
			fmt.Printf("  Socket: %s\n", socketPath)
			fmt.Println("Run 'meshd status' to inspect it or 'meshd down' to stop it.")
			return nil
		}
	}
	if os.Getenv(sudoChildEnv) == "1" {
		defer restoreSudoUserOwnership()
	}
	shouldElevate := shouldReexecWithSudoForTun(f, os.Getuid(), runtime.GOOS, stdinIsTerminal())

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

	createdFromInvite := false
	if ns == nil {
		// Not in a network. Use flags or prompt interactively.
		createdFromInvite = f.inviteURL != ""
		ns, err = ensureNetwork(ctx, f, stateDir, identity, flagProfile)
		if err != nil {
			return err
		}
	}
	if ns != nil && ns.NetworkRecordID == "" && ns.NodeRecordID == "" && ns.AnchorDID != "" {
		ns, err = refreshPendingOwnerApproval(ctx, stateDir, ns, identity)
		if err != nil {
			return err
		}
		if ns.NetworkRecordID == "" || ns.NodeRecordID == "" {
			printPendingOwnerApproval(ns)
			return nil
		}
	}
	if ns.NodeRecordID == "" && ns.AnchorDID != identity.URI {
		if createdFromInvite {
			return fmt.Errorf("join request is waiting for approval; approve it in the wallet admin panel or keep the anchor online, then run 'meshd up'")
		}
		ns, err = refreshPendingJoin(ctx, stateDir, ns, flagProfile, true)
		if err != nil {
			return err
		}
		if ns.NodeRecordID == "" {
			return fmt.Errorf("join request is waiting for approval; approve it in the wallet admin panel or keep the anchor online, then run 'meshd up'")
		}
	}
	selfNodeDID := networkNodeDID(ns, identity.URI)
	nodeIdentity, err := loadNodeIdentity(stateDir, selfNodeDID, identity)
	if err != nil {
		return err
	}
	if shouldElevate {
		if !backgroundChild && !f.foreground {
			return startUpInBackground(ctx, args, flagProfile, stateDir, true)
		}
		return reexecUpWithSudo(args, flagProfile)
	}
	if !backgroundChild && !f.foreground {
		return startUpInBackground(ctx, args, flagProfile, stateDir, false)
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

	meta := resolveIdentityMetadata(flagProfile, identity.URI)
	operationIdentity, err := loadDWNOperationIdentity(stateDir, meta, nodeIdentity)
	if err != nil {
		return err
	}
	signer := dwnSigner(operationIdentity)

	encMgr := newEncryptionKeyManager(nodeIdentity)

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
			contextKey, err := fetchContextKey(ctx, nodeIdentity, ns)
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
	wgKeys, err := mesh.WireGuardKeyFromIdentity(nodeIdentity.EncryptionPrivateKey)
	if err != nil {
		return fmt.Errorf("deriving WireGuard keys from identity: %w", err)
	}

	readGrantID, err := walletGrantIDForDWNOperation(stateDir, meta, dwn.InterfaceRecordsQuery, protocols.MeshProtocolURI, "", ns.NetworkRecordID, false)
	if err != nil {
		return err
	}
	if resp, refreshErr := loadControlStateForCLI(ctx, ns, nodeIdentity, operationIdentity, encMgr, readGrantID); refreshErr == nil {
		if refreshed, changed, saveErr := refreshLocalMembershipMetadataFromMap(stateDir, ns, resp); saveErr != nil {
			logger.Debug("membership metadata refresh save failed", slog.Any("error", saveErr))
		} else if changed {
			ns = refreshed
			fmt.Printf("  Membership metadata refreshed.\n")
		}
	} else {
		logger.Debug("membership metadata refresh skipped", slog.Any("error", refreshErr))
	}
	networkOwner := isNetworkOwnerProfile(meta, identity.URI, ns)
	endpointWriteGrantID, err := walletGrantIDForDWNOperation(stateDir, meta, dwn.InterfaceRecordsWrite, protocols.MeshProtocolURI, endpointProtocolPath(ns), ns.NetworkRecordID, false)
	if err != nil {
		return err
	}
	ownerWriteGrantID, err := walletGrantIDForDWNOperation(stateDir, meta, dwn.InterfaceRecordsWrite, protocols.MeshProtocolURI, "", ns.NetworkRecordID, false)
	if err != nil {
		return err
	}
	deleteGrantID, err := walletGrantIDForDWNOperation(stateDir, meta, dwn.InterfaceRecordsDelete, protocols.MeshProtocolURI, "", ns.NetworkRecordID, false)
	if err != nil {
		return err
	}
	keyDeliveryGrantID, err := walletGrantIDForDWNOperation(stateDir, meta, dwn.InterfaceRecordsWrite, protocols.KeyDeliveryProtocolURI, "", "", false)
	if err != nil {
		return err
	}
	ownerAutomation := ownerAutomationEnabled(ns, nodeIdentity.URI, networkOwner, readGrantID, ownerWriteGrantID, deleteGrantID, keyDeliveryGrantID)

	fmt.Printf("Starting meshd...\n")
	fmt.Printf("  Network: %s\n", ns.NetworkName)
	fmt.Printf("  DID: %s\n", nodeIdentity.URI)
	if operationIdentity.URI != nodeIdentity.URI {
		fmt.Printf("  DWN delegate: %s\n", operationIdentity.URI)
	}
	fmt.Printf("  Mesh IP: %s\n", ns.MeshIP)
	if ns.NodeExpiresAt != "" {
		fmt.Printf("  Membership Expires: %s\n", ns.NodeExpiresAt)
	}
	fmt.Printf("  Anchor: %s\n", ns.AnchorEndpoint)

	// Write/update endpoint record (encrypted) before starting the engine.
	if ns.NodeRecordID != "" {
		localEndpoints := mesh.DiscoverLocalEndpoints(f.listenPort)
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
			UseContextEncryption: useContextEncryption,
			PermissionGrantID:    endpointWriteGrantID,
		}
		err = mesh.WriteEndpoint(ctx, wpParams)
		if err != nil {
			logger.Warn("endpoint write failed (non-fatal)", slog.Any("error", err))
		} else {
			fmt.Printf("  Endpoint record updated (encrypted).\n")
		}
	}

	// If this profile has owner authority, enable automatic context key
	// delivery so new members get decryption keys without manual approval.
	var autoKeyDelivery *engine.AutoKeyDelivery
	if ownerAutomation && useContextEncryption {
		autoKeyDelivery = engine.NewAutoKeyDelivery(engine.AutoKeyDeliveryConfig{
			Endpoint:             ns.AnchorEndpoint,
			AnchorDID:            ns.AnchorDID,
			NetworkRecordID:      ns.NetworkRecordID,
			Signer:               signer,
			EncryptionKeyManager: encMgr,
			Logger:               logger,
			PermissionGrantID:    keyDeliveryGrantID,
		})
		if autoKeyDelivery != nil {
			fmt.Printf("  Auto key delivery: enabled (owner node)\n")
		}
	}
	if networkOwner && !ownerAutomation && ns.AnchorDID != nodeIdentity.URI {
		fmt.Printf("  Owner automation: disabled (use the wallet admin panel for approvals)\n")
	}
	if ownerAutomation {
		approvePreAuthRequests(ctx, ns, signer, encMgr, logger, readGrantID, ownerWriteGrantID, deleteGrantID, keyDeliveryGrantID, useContextEncryption)
	}

	// Determine the protocol role for DWN queries. The anchor reads as
	// author (no role needed). Non-anchor nodes use their node role.
	protocolRole := ""
	if ns.AnchorDID != nodeIdentity.URI {
		protocolRole = "network/node"
	}
	discoRegistry := engine.NewInMemoryDiscoRegistry()

	eng, err := engine.New(engine.Config{
		AnchorEndpoint:         ns.AnchorEndpoint,
		AnchorTenant:           ns.AnchorDID,
		NetworkRecordID:        ns.NetworkRecordID,
		SelfDID:                nodeIdentity.URI,
		Signer:                 signer,
		Resolver:               universalResolver{},
		EncryptionKeyManager:   encMgr,
		NodeRecordID:           ns.NodeRecordID,
		MemberRecordID:         ns.MemberRecordID,
		ProtocolRole:           protocolRole,
		PermissionGrantID:      readGrantID,
		WritePermissionGrantID: endpointWriteGrantID,
		AutoKeyDelivery:        autoKeyDelivery,
		UseContextEncryption:   useContextEncryption,
		WireGuardPrivateKey:    wgKeys.PrivateKey,
		DiscoKeyRegistry:       discoRegistry,
		TUNName:                f.tunName,
		Domain:                 ns.NetworkName,
		ListenPort:             f.listenPort,
		PollInterval:           f.pollInterval,
		Logger:                 logger,
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
	if ownerAutomation {
		stopPreAuthApproval = make(chan struct{})
		interval := f.pollInterval
		if interval == 0 {
			interval = 30 * time.Second
		}
		go runPreAuthApprovalLoop(ctx, stopPreAuthApproval, interval, ns, signer, encMgr, logger, readGrantID, ownerWriteGrantID, deleteGrantID, keyDeliveryGrantID, useContextEncryption)
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

func ensureDWNTenantRegistered(ctx context.Context, endpoint string, identity *did.DID) error {
	if endpoint == "" || identity == nil || identity.URI == "" {
		return nil
	}
	fmt.Printf("Registering DID with DWN...\n")
	if err := dwn.RegisterTenant(ctx, endpoint, identity.URI); err != nil {
		return fmt.Errorf("registering DID with DWN: %w", err)
	}
	fmt.Printf("  DWN tenant ready.\n")
	return nil
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
	case f.ownerDID != "":
		return setupOwnerNodeRequest(ctx, f, stateDir, identity, nil)
	default:
		return setupInteractive(ctx, f, stateDir, identity, flagProfile)
	}
}

// setupCreateNetwork creates a new mesh network (anchor mode).
// This is the --create flag path.
func setupCreateNetwork(ctx context.Context, f upFlags, stateDir string, identity *did.DID, flagProfile string) (*state.NetworkState, error) {
	walletOwned := isWalletAuthorizedNodeProfile(flagProfile)
	if f.endpoint == "" && !walletOwned {
		return nil, fmt.Errorf("--endpoint (or DWN_ENDPOINT env) is required to create a network")
	}
	if f.endpoint == "" && !stdinIsTerminal() {
		return nil, fmt.Errorf("wallet-owned network creation requires an interactive terminal; run 'meshd network create %s' first", f.createNetwork)
	}

	if f.endpoint == "" {
		fmt.Printf("Creating wallet-owned network %q...\n", f.createNetwork)
	} else {
		fmt.Printf("Creating network %q on %s...\n", f.createNetwork, f.endpoint)
	}

	// Delegate to the existing network create logic.
	createArgs := []string{f.createNetwork}
	if f.endpoint != "" {
		createArgs = append(createArgs, "--endpoint", f.endpoint)
	}
	err := cmdNetworkCreate(ctx, createArgs, flagProfile)
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

	joinArgs := []string{
		"--endpoint", f.endpoint,
		"--anchor", f.anchorDID,
		"--network", f.networkID,
	}
	if f.ownerDID != "" {
		joinArgs = append(joinArgs, "--owner", f.ownerDID)
	}

	err := cmdNetworkJoin(ctx, joinArgs, flagProfile)
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
	joinArgs := []string{f.inviteURL, "--no-start-hint"}
	if f.ownerDID != "" {
		joinArgs = append(joinArgs, "--owner", f.ownerDID)
	}
	if err := cmdJoin(ctx, joinArgs, flagProfile); err != nil {
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

func setupOwnerNodeRequest(ctx context.Context, f upFlags, stateDir string, identity *did.DID, scanner *bufio.Scanner) (*state.NetworkState, error) {
	ownerDID := strings.TrimSpace(f.ownerDID)
	var err error
	if ownerDID == "" {
		if scanner == nil {
			return nil, fmt.Errorf("--owner <did> is required")
		}
		ownerDID, err = promptRequired(scanner, "Owner DID")
		if err != nil {
			return nil, err
		}
	}

	endpoint, err := ownerDWNEndpointForRequest(ctx, ownerDID, f.endpoint, scanner)
	if err != nil {
		return nil, err
	}
	if state.HasNetwork(stateDir) {
		return nil, fmt.Errorf("already in a network. Use 'meshd network leave' first.")
	}
	if err := ensureDWNTenantRegistered(ctx, endpoint, identity); err != nil {
		return nil, err
	}

	label, _ := os.Hostname()
	nodeKeyDelivery, err := walletconnect.NewKeyDeliveryPublic(identity)
	if err != nil {
		return nil, fmt.Errorf("deriving node key-delivery public key: %w", err)
	}
	requestID, err := mesh.WriteOwnerNodeRequest(ctx, mesh.OwnerNodeRequestParams{
		OwnerEndpoint:   endpoint,
		OwnerDID:        ownerDID,
		NodeDID:         identity.URI,
		Signer:          dwnSigner(identity),
		Label:           label,
		SourceDWN:       endpoint,
		NodeKeyDelivery: nodeKeyDelivery,
	})
	if err != nil {
		ctx := adminContext{OwnerDID: ownerDID}
		return nil, fmt.Errorf("submitting owner approval request: %w\nOpen the dashboard once to initialize meshd for this owner:\n  %s\n  %s", err, adminDashboardCommand(ctx, true), buildAdminURL(defaultAdminDashboardURL, ctx))
	}

	ns := &state.NetworkState{
		AnchorDID:             ownerDID,
		AnchorEndpoint:        endpoint,
		NetworkName:           "pending approval",
		NodeDID:               identity.URI,
		OwnerDID:              ownerDID,
		MemberDID:             ownerDID,
		PendingOwnerRequestID: requestID,
		PendingOwnerRequestAt: time.Now().UTC().Format(time.RFC3339),
	}
	if err := state.SaveNetworkState(stateDir, ns); err != nil {
		return nil, fmt.Errorf("saving pending owner request: %w", err)
	}

	fmt.Printf("Node approval request submitted.\n")
	fmt.Printf("  Owner DID: %s\n", ownerDID)
	fmt.Printf("  Owner DWN: %s\n", endpoint)
	fmt.Printf("  Node DID:  %s\n", identity.URI)
	fmt.Printf("  Request:   %s\n", requestID)
	adminCtx := adminContext{OwnerDID: ownerDID}
	fmt.Printf("  Dashboard: %s\n", buildAdminURL(defaultAdminDashboardURL, adminCtx))
	fmt.Printf("  Admin command: %s\n", adminDashboardCommand(adminCtx, true))
	fmt.Printf("\nApprove this device in the dashboard, then run 'meshd up' again.\n")
	return ns, nil
}

func ownerDWNEndpointForRequest(ctx context.Context, ownerDID, explicitEndpoint string, scanner *bufio.Scanner) (string, error) {
	if strings.TrimSpace(explicitEndpoint) != "" {
		return ownerDWNEndpointFromInput(explicitEndpoint, "", nil, scanner, os.Stdout)
	}
	resolved, err := control.ResolvePeerDWNEndpoint(ctx, universalResolver{}, ownerDID, nil)
	return ownerDWNEndpointFromInput(explicitEndpoint, resolved, err, scanner, os.Stdout)
}

func ownerDWNEndpointFromInput(explicitEndpoint, resolvedEndpoint string, resolveErr error, scanner *bufio.Scanner, out io.Writer) (string, error) {
	endpoint := strings.TrimSpace(explicitEndpoint)
	if endpoint != "" {
		return strings.TrimRight(endpoint, "/"), nil
	}
	resolved := strings.TrimSpace(resolvedEndpoint)
	if resolved != "" {
		return strings.TrimRight(resolved, "/"), nil
	}
	fallback := strings.TrimRight(strings.TrimSpace(defaultOwnerRequestEndpoint), "/")
	if fallback == "" {
		return "", fmt.Errorf("default owner DWN endpoint is empty")
	}
	if scanner != nil {
		if resolveErr != nil {
			fmt.Fprintf(out, "Could not resolve an owner DWN endpoint automatically: %v\n", resolveErr)
		}
		fmt.Fprintf(out, "Owner DWN endpoint URL [%s]: ", fallback)
		if !scanner.Scan() {
			return "", fmt.Errorf("no input received")
		}
		if value := strings.TrimSpace(scanner.Text()); value != "" {
			return strings.TrimRight(value, "/"), nil
		}
		return fallback, nil
	}
	return fallback, nil
}

func refreshPendingOwnerApproval(ctx context.Context, stateDir string, ns *state.NetworkState, identity *did.DID) (*state.NetworkState, error) {
	if ns == nil {
		return nil, fmt.Errorf("network state is missing")
	}
	ownerDID := ns.EffectiveOwnerDID(ns.AnchorDID)
	nodeDID := ns.EffectiveNodeDID(identity.URI)
	fmt.Printf("Checking owner approval...\n")
	approval, approvalRecordID, err := mesh.FindOwnerNodeApproval(ctx, ns.AnchorEndpoint, ownerDID, nodeDID, dwnSigner(identity))
	if err != nil {
		return nil, err
	}
	if approval == nil {
		return ns, nil
	}
	if approval.ExpiresAt != "" {
		expiresAt, parseErr := time.Parse(time.RFC3339, approval.ExpiresAt)
		if parseErr != nil {
			return nil, fmt.Errorf("approval has invalid expiry %q", approval.ExpiresAt)
		}
		if time.Now().UTC().After(expiresAt) {
			return nil, fmt.Errorf("approval expired at %s; renew this node in the dashboard", approval.ExpiresAt)
		}
	}

	refreshed := &state.NetworkState{
		NetworkRecordID:   approval.NetworkRecordID,
		AnchorDID:         ownerDID,
		AnchorEndpoint:    firstNonEmpty(approval.AnchorEndpoint, ns.AnchorEndpoint),
		NetworkName:       firstNonEmpty(approval.NetworkName, "mesh"),
		MeshCIDR:          firstNonEmpty(approval.MeshCIDR, "10.200.0.0/16"),
		MeshIP:            approval.MeshIP,
		NodeExpiresAt:     approval.ExpiresAt,
		NodeDID:           nodeDID,
		OwnerDID:          ownerDID,
		MemberDID:         ownerDID,
		NodeRecordID:      approval.NodeRecordID,
		NodeDateCreated:   approval.NodeDateCreated,
		MemberRecordID:    approval.MemberRecordID,
		MemberDateCreated: approval.MemberDateCreated,
	}
	if err := state.SaveNetworkState(stateDir, refreshed); err != nil {
		return nil, fmt.Errorf("saving approved network state: %w", err)
	}
	fmt.Printf("Owner approval accepted.\n")
	fmt.Printf("  Network: %s\n", refreshed.NetworkName)
	fmt.Printf("  Mesh IP: %s\n", refreshed.MeshIP)
	if refreshed.NodeExpiresAt != "" {
		fmt.Printf("  Membership Expires: %s\n", refreshed.NodeExpiresAt)
	}
	if approvalRecordID != "" {
		fmt.Printf("  Approval: %s\n", approvalRecordID)
	}
	return refreshed, nil
}

func printPendingOwnerApproval(ns *state.NetworkState) {
	ownerDID := ""
	if ns != nil {
		ownerDID = ns.EffectiveOwnerDID(ns.AnchorDID)
	}
	fmt.Printf("Node approval is still pending.\n")
	if ownerDID != "" {
		fmt.Printf("  Owner DID: %s\n", ownerDID)
		adminCtx := adminContext{OwnerDID: ownerDID, NetworkRecordID: ns.NetworkRecordID}
		fmt.Printf("  Dashboard: %s\n", buildAdminURL(defaultAdminDashboardURL, adminCtx))
		fmt.Printf("  Admin command: %s\n", adminDashboardCommand(adminCtx, true))
	}
	fmt.Printf("\nApprove this device in the dashboard, then run 'meshd up' again.\n")
}

func refreshPendingJoin(ctx context.Context, stateDir string, ns *state.NetworkState, flagProfile string, noStartHint bool) (*state.NetworkState, error) {
	if ns == nil {
		return nil, fmt.Errorf("network state is missing")
	}
	previous := *ns

	fmt.Printf("Checking pending join approval...\n")
	if err := state.ClearNetworkState(stateDir); err != nil {
		return nil, fmt.Errorf("clearing pending network state: %w", err)
	}
	joinArgs := []string{
		"--endpoint", ns.AnchorEndpoint,
		"--anchor", ns.AnchorDID,
		"--network", ns.NetworkRecordID,
		"--preauth",
	}
	ownerDID := ns.EffectiveOwnerDID("")
	if ownerDID != "" && ownerDID != ns.NodeDID {
		joinArgs = append(joinArgs, "--owner", ownerDID)
	}
	if noStartHint {
		joinArgs = append(joinArgs, "--no-start-hint")
	}
	err := cmdNetworkJoin(ctx, joinArgs, flagProfile)
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

// setupInteractive prompts the user to request owner approval, create, or join
// a network.
func setupInteractive(ctx context.Context, f upFlags, stateDir string, identity *did.DID, flagProfile string) (*state.NetworkState, error) {
	fmt.Println("No network configured. What would you like to do?")
	fmt.Println()
	fmt.Println("  Paste an owner DID or invite URL, or choose:")
	fmt.Println()
	fmt.Println("  1) Request access from an owner DID")
	fmt.Println("  2) Create a new local-vault network")
	fmt.Println("  3) Join with an invite URL")
	fmt.Println()
	fmt.Print("Setup [owner DID/invite URL/1/2/3, default 1]: ")

	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		return nil, fmt.Errorf("no input received")
	}
	choice, pastedValue, err := parseInteractiveSetupChoice(scanner.Text())
	if err != nil {
		return nil, err
	}

	fmt.Println()

	switch choice {
	case interactiveSetupOwner:
		if pastedValue != "" {
			f.ownerDID = pastedValue
		}
		return setupOwnerNodeRequest(ctx, f, stateDir, identity, scanner)
	case interactiveSetupCreate:
		return interactiveCreate(ctx, f, stateDir, identity, flagProfile, scanner)
	case interactiveSetupJoin:
		if pastedValue != "" {
			f.inviteURL = pastedValue
			return setupJoinInvite(ctx, f, stateDir, identity, flagProfile)
		}
		return interactiveJoin(ctx, f, stateDir, identity, flagProfile, scanner)
	default:
		return nil, fmt.Errorf("invalid setup choice %q", choice)
	}
}

type interactiveSetupChoice string

const (
	interactiveSetupOwner  interactiveSetupChoice = "owner"
	interactiveSetupCreate interactiveSetupChoice = "create"
	interactiveSetupJoin   interactiveSetupChoice = "join"
)

func parseInteractiveSetupChoice(input string) (interactiveSetupChoice, string, error) {
	value := strings.TrimSpace(input)
	lower := strings.ToLower(value)
	switch lower {
	case "", "1", "owner", "request", "access":
		return interactiveSetupOwner, "", nil
	case "2", "create", "new":
		return interactiveSetupCreate, "", nil
	case "3", "join", "invite":
		return interactiveSetupJoin, "", nil
	}
	if strings.HasPrefix(value, invite.SchemePrefix) {
		return interactiveSetupJoin, value, nil
	}
	if strings.HasPrefix(lower, "did:") {
		return interactiveSetupOwner, value, nil
	}
	return "", "", fmt.Errorf("invalid choice %q (paste an owner DID, paste a meshd://invite URL, or choose 1, 2, or 3)", value)
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
	if endpoint == "" && !isWalletAuthorizedNodeProfile(flagProfile) {
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
	input, err := promptInteractiveJoin(scanner, f.endpoint)
	if err != nil {
		return nil, err
	}
	fmt.Println()
	if input.inviteURL != "" {
		f.inviteURL = input.inviteURL
		return setupJoinInvite(ctx, f, stateDir, identity, flagProfile)
	}
	f.endpoint = input.endpoint
	f.anchorDID = input.anchorDID
	f.networkID = input.networkID
	return setupJoinNetwork(ctx, f, stateDir, identity, flagProfile)
}

type interactiveJoinInput struct {
	inviteURL string
	endpoint  string
	anchorDID string
	networkID string
}

func promptInteractiveJoin(scanner *bufio.Scanner, defaultEndpoint string) (interactiveJoinInput, error) {
	fmt.Print("Invite URL (recommended; leave blank for manual details): ")
	if !scanner.Scan() {
		return interactiveJoinInput{}, fmt.Errorf("no input received")
	}
	inviteURL := strings.TrimSpace(scanner.Text())
	if inviteURL != "" {
		return interactiveJoinInput{inviteURL: inviteURL}, nil
	}

	endpoint := defaultEndpoint
	if endpoint == "" {
		fmt.Print("DWN endpoint URL: ")
		if !scanner.Scan() {
			return interactiveJoinInput{}, fmt.Errorf("no input received")
		}
		endpoint = strings.TrimSpace(scanner.Text())
		if endpoint == "" {
			return interactiveJoinInput{}, fmt.Errorf("endpoint URL is required")
		}
	}

	fmt.Print("Anchor DID: ")
	if !scanner.Scan() {
		return interactiveJoinInput{}, fmt.Errorf("no input received")
	}
	anchorDID := strings.TrimSpace(scanner.Text())
	if anchorDID == "" {
		return interactiveJoinInput{}, fmt.Errorf("anchor DID is required")
	}

	fmt.Print("Network ID: ")
	if !scanner.Scan() {
		return interactiveJoinInput{}, fmt.Errorf("no input received")
	}
	networkID := strings.TrimSpace(scanner.Text())
	if networkID == "" {
		return interactiveJoinInput{}, fmt.Errorf("network ID is required")
	}

	return interactiveJoinInput{
		endpoint:  endpoint,
		anchorDID: anchorDID,
		networkID: networkID,
	}, nil
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

const (
	vaultPasswordEnv           = "MESHD_VAULT_PASSWORD"
	vaultPasswordCacheTTLEnv   = "MESHD_VAULT_CACHE_TTL"
	vaultPasswordCacheDirEnv   = "MESHD_VAULT_CACHE_DIR"
	nodeIdentityVaultFile      = "node.identity.vault.json"
	delegateIdentityVaultFile  = "delegate.identity.vault.json"
	defaultVaultPasswordCache  = 5 * time.Minute
	vaultPasswordCacheFileMode = 0o600
	vaultPasswordCacheDirMode  = 0o700
)

var (
	cachedVaultPassword         string
	cachedVaultPasswordStateDir string
)

type vaultPasswordCacheEntry struct {
	Version  int       `json:"version"`
	StateDir string    `json:"stateDir"`
	Password string    `json:"password"`
	Expires  time.Time `json:"expires"`
}

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

type identityMetadata struct {
	AuthType    string
	OwnerDID    string
	DelegateDID string
	NodeDID     string
}

func authDisplayName(authType string) string {
	switch profile.NormalizeAuthType(authType) {
	case profile.AuthTypeLocalVault:
		return "local vault"
	case profile.AuthTypeWalletAuthorizedNode:
		return "wallet-authorized node"
	default:
		return authType
	}
}

func resolveIdentityMetadata(flagProfile string, fallbackDID string) identityMetadata {
	meta := identityMetadata{
		AuthType: profile.AuthTypeLocalVault,
		OwnerDID: fallbackDID,
		NodeDID:  fallbackDID,
	}
	if os.Getenv("MESHD_STATE_DIR") != "" {
		return meta
	}
	name, err := profile.Resolve(flagProfile)
	if err != nil {
		return meta
	}
	cfg, err := profile.ReadConfig()
	if err != nil || cfg.Profiles[name] == nil {
		return meta
	}
	entry := cfg.Profiles[name]
	meta.AuthType = entry.EffectiveAuthType()
	meta.OwnerDID = firstNonEmpty(entry.EffectiveOwnerDID(), fallbackDID)
	meta.DelegateDID = entry.DelegateDID
	meta.NodeDID = firstNonEmpty(entry.EffectiveNodeDID(), fallbackDID)
	return meta
}

func isWalletAuthorizedNodeProfile(flagProfile string) bool {
	if os.Getenv("MESHD_STATE_DIR") != "" {
		return false
	}
	name, err := profile.Resolve(flagProfile)
	if err != nil {
		return false
	}
	cfg, err := profile.ReadConfig()
	if err != nil || cfg.Profiles[name] == nil {
		return false
	}
	entry := cfg.Profiles[name]
	return entry.EffectiveAuthType() == profile.AuthTypeWalletAuthorizedNode &&
		entry.EffectiveOwnerDID() != "" &&
		entry.EffectiveOwnerDID() != entry.EffectiveNodeDID()
}

func isNetworkOwnerProfile(meta identityMetadata, identityDID string, ns *state.NetworkState) bool {
	if ns == nil || ns.AnchorDID == "" {
		return false
	}
	if ns.AnchorDID == identityDID {
		return true
	}
	return meta.AuthType == profile.AuthTypeWalletAuthorizedNode &&
		meta.OwnerDID != "" &&
		meta.OwnerDID == ns.AnchorDID
}

func ownerAutomationEnabled(ns *state.NetworkState, nodeDID string, networkOwner bool, readGrantID, writeGrantID, deleteGrantID, keyDeliveryWriteGrantID string) bool {
	if !networkOwner || ns == nil {
		return false
	}
	if ns.AnchorDID == nodeDID {
		return true
	}
	return readGrantID != "" && writeGrantID != "" && deleteGrantID != "" && keyDeliveryWriteGrantID != ""
}

func nodeInfoProtocolPath(ns *state.NetworkState) string {
	if ns != nil && ns.MemberRecordID != "" {
		return "network/member/node/nodeInfo"
	}
	return "network/node/nodeInfo"
}

func endpointProtocolPath(ns *state.NetworkState) string {
	if ns != nil && ns.MemberRecordID != "" {
		return "network/member/node/endpoint"
	}
	return "network/node/endpoint"
}

func requireNetworkOwnerProfile(flagProfile string, identity *did.DID, ns *state.NetworkState) (identityMetadata, bool, error) {
	if identity == nil {
		return identityMetadata{}, false, fmt.Errorf("identity is required")
	}
	meta := resolveIdentityMetadata(flagProfile, identity.URI)
	if !isNetworkOwnerProfile(meta, identity.URI, ns) {
		return meta, false, fmt.Errorf("only the network owner (%s) can perform this action", ns.AnchorDID)
	}
	return meta, ns.AnchorDID != identity.URI, nil
}

func prepareNetworkCommandEncryption(stateDir string, identity *did.DID, ns *state.NetworkState, useContextEncryption bool) (*dwncrypto.EncryptionKeyManager, error) {
	encMgr := newEncryptionKeyManager(identity)
	if !useContextEncryption {
		return encMgr, nil
	}
	_, loaded, err := loadLocalContextKeyForCLI(stateDir, ns, encMgr)
	if err != nil {
		return nil, err
	}
	if !loaded {
		return nil, fmt.Errorf("wallet-owned network is missing its local context key; reconnect this profile with 'meshd auth connect'")
	}
	return encMgr, nil
}

func walletGrantIDForDWNOperation(stateDir string, meta identityMetadata, messageType dwn.DwnInterface, protocolURI, protocolPath, contextID string, required bool) (string, error) {
	if meta.AuthType != profile.AuthTypeWalletAuthorizedNode {
		return "", nil
	}
	if !state.WalletSessionExists(stateDir) {
		if required {
			return "", fmt.Errorf("wallet-connected profile is missing an imported wallet session; run 'meshd auth connect --response <file>'")
		}
		return "", nil
	}
	password, err := vaultPasswordForUnlock(stateDir)
	if err != nil {
		return "", err
	}
	session, err := state.LoadWalletSession(stateDir, password)
	if err != nil {
		return "", err
	}
	if session == nil {
		if required {
			return "", fmt.Errorf("wallet-connected profile is missing an imported wallet session; run 'meshd auth connect --response <file>'")
		}
		return "", nil
	}
	sessionOwnerDID := session.EffectiveOwnerDID()
	if sessionOwnerDID != "" && meta.OwnerDID != "" && sessionOwnerDID != meta.OwnerDID {
		return "", fmt.Errorf("wallet session owner DID %s does not match profile owner DID %s", sessionOwnerDID, meta.OwnerDID)
	}
	if session.NodeDID != "" && meta.NodeDID != "" && session.NodeDID != meta.NodeDID {
		return "", fmt.Errorf("wallet session node DID %s does not match profile node DID %s", session.NodeDID, meta.NodeDID)
	}
	granteeDID, _ := walletSessionGrantGranteeDID(session, meta)
	grantID, err := dwn.FindPermissionGrantID(session.Grants, dwn.PermissionGrantMatch{
		Grantor:      firstNonEmpty(sessionOwnerDID, meta.OwnerDID),
		Grantee:      granteeDID,
		MessageType:  messageType,
		Protocol:     protocolURI,
		ProtocolPath: protocolPath,
		ContextID:    contextID,
		Now:          time.Now().UTC(),
	})
	if err != nil {
		return "", err
	}
	if grantID == "" && required {
		target := protocolURI
		if protocolPath != "" {
			target += " " + protocolPath
		}
		return "", fmt.Errorf("wallet session has no permission grant for %s %s; run 'meshd auth connect --admin' to approve admin control", messageType, target)
	}
	return grantID, nil
}

func walletSessionGrantGranteeDID(session *state.WalletSession, meta identityMetadata) (string, bool) {
	delegateDID := firstNonEmpty(session.DelegateDID, meta.DelegateDID)
	if delegateDID != "" {
		return delegateDID, true
	}
	return firstNonEmpty(session.NodeDID, meta.NodeDID), false
}

type walletSessionStatus struct {
	Exists                  bool
	OwnerDID                string
	NodeDID                 string
	WalletOrigin            string
	ExpiresAt               string
	DelegateDID             string
	GrantCount              int
	NodeContextKeyCount     int
	NodeProtocolCount       int
	NodeRuntimeAccess       bool
	AdminControlAccess      bool
	OwnerDIDMismatch        bool
	NodeDIDMismatch         bool
	LegacyDelegateKeyFields bool
}

func loadWalletSessionStatus(stateDir string, meta identityMetadata) (*walletSessionStatus, error) {
	status := &walletSessionStatus{}
	if !state.WalletSessionExists(stateDir) {
		return status, nil
	}
	password, err := vaultPasswordForUnlock(stateDir)
	if err != nil {
		return nil, err
	}
	session, err := state.LoadWalletSession(stateDir, password)
	if err != nil {
		return nil, err
	}
	if session == nil {
		return status, nil
	}
	status.Exists = true
	status.OwnerDID = session.EffectiveOwnerDID()
	status.NodeDID = session.NodeDID
	status.WalletOrigin = session.WalletOrigin
	status.ExpiresAt = session.ExpiresAt
	status.DelegateDID = session.DelegateDID
	status.GrantCount = len(session.Grants)
	status.NodeContextKeyCount = len(session.EffectiveNodeContextKeys())
	status.NodeProtocolCount = len(session.EffectiveNodeMultiPartyProtocols())
	status.NodeRuntimeAccess = walletSessionHasNodeRuntimeGrants(session, meta)
	status.AdminControlAccess = walletSessionHasAdminControlGrants(session, meta)
	status.LegacyDelegateKeyFields = len(session.NodeContextKeys) == 0 && len(session.DelegateContextKeys) > 0
	status.OwnerDIDMismatch = meta.OwnerDID != "" && status.OwnerDID != "" && meta.OwnerDID != status.OwnerDID
	status.NodeDIDMismatch = meta.NodeDID != "" && session.NodeDID != "" && meta.NodeDID != session.NodeDID
	return status, nil
}

func walletSessionHasNodeRuntimeGrants(session *state.WalletSession, meta identityMetadata) bool {
	if session == nil {
		return false
	}
	return walletSessionHasGrant(session, meta, dwn.InterfaceRecordsQuery, protocols.MeshProtocolURI, "") &&
		walletSessionHasGrant(session, meta, dwn.InterfaceRecordsWrite, protocols.MeshProtocolURI, "network/node/nodeInfo") &&
		walletSessionHasGrant(session, meta, dwn.InterfaceRecordsWrite, protocols.MeshProtocolURI, "network/node/endpoint") &&
		walletSessionHasGrant(session, meta, dwn.InterfaceRecordsWrite, protocols.MeshProtocolURI, "network/member/node/nodeInfo") &&
		walletSessionHasGrant(session, meta, dwn.InterfaceRecordsWrite, protocols.MeshProtocolURI, "network/member/node/endpoint") &&
		walletSessionHasGrant(session, meta, dwn.InterfaceRecordsQuery, protocols.KeyDeliveryProtocolURI, "")
}

func walletSessionHasAdminControlGrants(session *state.WalletSession, meta identityMetadata) bool {
	if session == nil {
		return false
	}
	return walletSessionHasGrant(session, meta, dwn.InterfaceRecordsQuery, protocols.MeshProtocolURI, "") &&
		walletSessionHasGrant(session, meta, dwn.InterfaceRecordsWrite, protocols.MeshProtocolURI, "") &&
		walletSessionHasGrant(session, meta, dwn.InterfaceRecordsDelete, protocols.MeshProtocolURI, "") &&
		walletSessionHasGrant(session, meta, dwn.InterfaceRecordsQuery, protocols.KeyDeliveryProtocolURI, "") &&
		walletSessionHasGrant(session, meta, dwn.InterfaceRecordsWrite, protocols.KeyDeliveryProtocolURI, "") &&
		walletSessionHasGrant(session, meta, dwn.InterfaceRecordsDelete, protocols.KeyDeliveryProtocolURI, "")
}

func walletSessionHasGrant(session *state.WalletSession, meta identityMetadata, messageType dwn.DwnInterface, protocolURI, protocolPath string) bool {
	if session == nil {
		return false
	}
	granteeDID, _ := walletSessionGrantGranteeDID(session, meta)
	grantID, err := dwn.FindPermissionGrantID(session.Grants, dwn.PermissionGrantMatch{
		Grantor:      firstNonEmpty(session.EffectiveOwnerDID(), meta.OwnerDID),
		Grantee:      granteeDID,
		MessageType:  messageType,
		Protocol:     protocolURI,
		ProtocolPath: protocolPath,
		Now:          time.Now().UTC(),
	})
	return err == nil && grantID != ""
}

func printWalletSessionStatus(stateDir string, meta identityMetadata) error {
	status, err := loadWalletSessionStatus(stateDir, meta)
	if err != nil {
		return err
	}
	fmt.Printf("  Wallet Session: ")
	if status == nil || !status.Exists {
		fmt.Printf("missing (run 'meshd auth connect')\n")
		return nil
	}
	fmt.Printf("imported\n")
	if status.WalletOrigin != "" {
		fmt.Printf("    Wallet: %s\n", status.WalletOrigin)
	}
	if status.OwnerDID != "" && status.OwnerDID != meta.OwnerDID {
		fmt.Printf("    Wallet Owner DID: %s\n", status.OwnerDID)
	}
	if status.NodeDID != "" && status.NodeDID != meta.NodeDID {
		fmt.Printf("    Node DID: %s\n", status.NodeDID)
	}
	if status.DelegateDID != "" {
		fmt.Printf("    Session Delegate DID: %s\n", status.DelegateDID)
	}
	fmt.Printf("    Grants: %d\n", status.GrantCount)
	if status.NodeRuntimeAccess {
		fmt.Printf("    Node Runtime Access: yes\n")
	} else {
		fmt.Printf("    Node Runtime Access: no\n")
	}
	if status.AdminControlAccess {
		fmt.Printf("    Admin Control Access: yes\n")
	} else {
		fmt.Printf("    Admin Control Access: no (run 'meshd auth connect --admin')\n")
	}
	fmt.Printf("    Node Context Keys: %d\n", status.NodeContextKeyCount)
	if status.NodeProtocolCount > 0 {
		fmt.Printf("    Node Protocols: %d\n", status.NodeProtocolCount)
	}
	if status.ExpiresAt != "" {
		fmt.Printf("    Expires: %s\n", status.ExpiresAt)
	}
	if status.OwnerDIDMismatch || status.NodeDIDMismatch {
		fmt.Printf("    Warning: session identity does not match profile metadata\n")
	}
	if status.LegacyDelegateKeyFields {
		fmt.Printf("    Compatibility: using legacy delegateContextKeys as node context keys\n")
	}
	return nil
}

func networkNodeDID(ns *state.NetworkState, fallbackDID string) string {
	if ns == nil {
		return fallbackDID
	}
	return ns.EffectiveNodeDID(fallbackDID)
}

func networkOwnerDID(ns *state.NetworkState, fallbackDID string) string {
	if ns == nil {
		return fallbackDID
	}
	return ns.EffectiveOwnerDID(fallbackDID)
}

func identityExists(stateDir string) bool {
	return did.EncryptedExists(stateDir) || did.Exists(stateDir)
}

func storeIdentityForCLI(identity *did.DID, stateDir string) error {
	password, err := vaultPasswordForCreate(stateDir)
	if err != nil {
		return err
	}
	return identity.StoreEncrypted(stateDir, password)
}

func vaultPasswordForUnlock(stateDir string) (string, error) {
	if password := os.Getenv(vaultPasswordEnv); password != "" {
		rememberVaultPassword(stateDir, password, true)
		return password, nil
	}
	if cachedVaultPassword != "" && cachedVaultPasswordStateDir == normalizeVaultStateDir(stateDir) {
		return cachedVaultPassword, nil
	}
	if password, ok := readVaultPasswordCache(stateDir); ok {
		rememberVaultPassword(stateDir, password, false)
		return password, nil
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
	rememberVaultPassword(stateDir, password, true)
	return password, nil
}

func vaultPasswordForCreate(stateDir string) (string, error) {
	if password := os.Getenv(vaultPasswordEnv); password != "" {
		rememberVaultPassword(stateDir, password, true)
		return password, nil
	}
	if cachedVaultPassword != "" && cachedVaultPasswordStateDir == normalizeVaultStateDir(stateDir) {
		return cachedVaultPassword, nil
	}
	if password, ok := readVaultPasswordCache(stateDir); ok {
		rememberVaultPassword(stateDir, password, false)
		return password, nil
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
	rememberVaultPassword(stateDir, password, true)
	return password, nil
}

func rememberVaultPassword(stateDir, password string, persist bool) {
	if password == "" {
		return
	}
	normalized := normalizeVaultStateDir(stateDir)
	cachedVaultPassword = password
	cachedVaultPasswordStateDir = normalized
	if persist {
		writeVaultPasswordCache(normalized, password)
	}
}

func forgetVaultPassword(stateDir string) {
	normalized := normalizeVaultStateDir(stateDir)
	if cachedVaultPasswordStateDir == normalized {
		cachedVaultPassword = ""
		cachedVaultPasswordStateDir = ""
	}
	removeVaultPasswordCache(normalized)
}

func normalizeVaultStateDir(stateDir string) string {
	if abs, err := filepath.Abs(stateDir); err == nil {
		return filepath.Clean(abs)
	}
	return filepath.Clean(stateDir)
}

func vaultPasswordCacheTTL() time.Duration {
	raw := strings.TrimSpace(os.Getenv(vaultPasswordCacheTTLEnv))
	if raw == "" {
		return defaultVaultPasswordCache
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return defaultVaultPasswordCache
	}
	if d < 0 {
		return 0
	}
	return d
}

func vaultPasswordCacheDir() (string, error) {
	if dir := strings.TrimSpace(os.Getenv(vaultPasswordCacheDirEnv)); dir != "" {
		return dir, nil
	}
	if dir := strings.TrimSpace(os.Getenv("XDG_RUNTIME_DIR")); dir != "" {
		return filepath.Join(dir, "meshd"), nil
	}
	if runtime.GOOS == "linux" {
		runUser := filepath.Join("/run/user", strconv.Itoa(os.Getuid()))
		if info, err := os.Stat(runUser); err == nil && info.IsDir() {
			return filepath.Join(runUser, "meshd"), nil
		}
	}
	return filepath.Join(os.TempDir(), fmt.Sprintf("meshd-%d", os.Getuid())), nil
}

func vaultPasswordCachePath(stateDir string) (string, error) {
	dir, err := vaultPasswordCacheDir()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(normalizeVaultStateDir(stateDir)))
	name := hex.EncodeToString(sum[:]) + ".json"
	return filepath.Join(dir, "vault", name), nil
}

func readVaultPasswordCache(stateDir string) (string, bool) {
	if vaultPasswordCacheTTL() <= 0 {
		return "", false
	}
	normalized := normalizeVaultStateDir(stateDir)
	path, err := vaultPasswordCachePath(normalized)
	if err != nil {
		return "", false
	}
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return "", false
	}
	if info.Mode().Perm()&0o077 != 0 {
		_ = os.Remove(path)
		return "", false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	var entry vaultPasswordCacheEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		_ = os.Remove(path)
		return "", false
	}
	if entry.Version != 1 || entry.StateDir != normalized || entry.Password == "" {
		_ = os.Remove(path)
		return "", false
	}
	if !entry.Expires.After(time.Now()) {
		_ = os.Remove(path)
		return "", false
	}
	return entry.Password, true
}

func writeVaultPasswordCache(stateDir, password string) {
	ttl := vaultPasswordCacheTTL()
	if ttl <= 0 {
		return
	}
	normalized := normalizeVaultStateDir(stateDir)
	path, err := vaultPasswordCachePath(normalized)
	if err != nil {
		return
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, vaultPasswordCacheDirMode); err != nil {
		return
	}
	_ = os.Chmod(dir, vaultPasswordCacheDirMode)
	entry := vaultPasswordCacheEntry{
		Version:  1,
		StateDir: normalized,
		Password: password,
		Expires:  time.Now().Add(ttl),
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return
	}
	tmp, err := os.CreateTemp(dir, ".vault-cache-*")
	if err != nil {
		return
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return
	}
	if err := os.Chmod(tmpName, vaultPasswordCacheFileMode); err != nil {
		_ = os.Remove(tmpName)
		return
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return
	}
	_ = os.Chmod(path, vaultPasswordCacheFileMode)
}

func removeVaultPasswordCache(stateDir string) {
	path, err := vaultPasswordCachePath(stateDir)
	if err == nil {
		_ = os.Remove(path)
	}
}

// loadIdentity loads the DID identity, or returns an error if not initialized.
func loadIdentity(stateDir string) (*did.DID, error) {
	if did.EncryptedExists(stateDir) {
		password, err := vaultPasswordForUnlock(stateDir)
		if err != nil {
			return nil, err
		}
		identity, err := did.LoadEncrypted(stateDir, password)
		if err != nil {
			forgetVaultPassword(stateDir)
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

func loadNodeIdentity(stateDir string, nodeDID string, fallback *did.DID) (*did.DID, error) {
	if fallback == nil {
		return nil, fmt.Errorf("fallback identity is required")
	}
	if nodeDID == "" || nodeDID == fallback.URI {
		return fallback, nil
	}
	if !did.EncryptedExistsAs(stateDir, nodeIdentityVaultFile) {
		return nil, fmt.Errorf("node identity %s is recorded, but %s is missing", nodeDID, nodeIdentityVaultFile)
	}
	password, err := vaultPasswordForUnlock(stateDir)
	if err != nil {
		return nil, err
	}
	nodeIdentity, err := did.LoadEncryptedAs(stateDir, nodeIdentityVaultFile, password)
	if err != nil {
		return nil, fmt.Errorf("unlocking node identity vault: %w", err)
	}
	if nodeIdentity == nil {
		return nil, fmt.Errorf("node identity vault is missing")
	}
	if nodeIdentity.URI != nodeDID {
		return nil, fmt.Errorf("node identity vault DID %s does not match network node DID %s", nodeIdentity.URI, nodeDID)
	}
	return nodeIdentity, nil
}

func loadLocalContextKeyForCLI(stateDir string, ns *state.NetworkState, encMgr *dwncrypto.EncryptionKeyManager) (string, bool, error) {
	if ns == nil || ns.NetworkRecordID == "" {
		return "", false, nil
	}

	if did.EncryptedExists(stateDir) {
		password, err := vaultPasswordForUnlock(stateDir)
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
		password, err := vaultPasswordForUnlock(stateDir)
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
		password, err := vaultPasswordForUnlock(stateDir)
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

	return mesh.FetchContextKey(ctx, mesh.FetchContextKeyParams{
		AnchorEndpoint:       ns.AnchorEndpoint,
		AnchorDID:            ns.AnchorDID,
		SelfDID:              identity.URI,
		ContextID:            ns.NetworkRecordID,
		Signer:               signer,
		EncryptionKeyManager: newEncryptionKeyManager(identity),
	})
}

func ensureWalletDelegateIdentity(stateDir string) (*did.DID, error) {
	password, err := vaultPasswordForUnlock(stateDir)
	if err != nil {
		return nil, err
	}
	if did.EncryptedExistsAs(stateDir, delegateIdentityVaultFile) {
		delegateIdentity, err := did.LoadEncryptedAs(stateDir, delegateIdentityVaultFile, password)
		if err != nil {
			return nil, fmt.Errorf("unlocking delegate identity vault: %w", err)
		}
		if delegateIdentity == nil {
			return nil, fmt.Errorf("delegate identity vault is missing")
		}
		return delegateIdentity, nil
	}
	delegateIdentity, err := did.Generate()
	if err != nil {
		return nil, fmt.Errorf("generating delegate DID: %w", err)
	}
	if err := delegateIdentity.StoreEncryptedAs(stateDir, delegateIdentityVaultFile, password); err != nil {
		return nil, fmt.Errorf("storing delegate identity: %w", err)
	}
	return delegateIdentity, nil
}

func verifyWalletDelegateIdentity(stateDir string, delegateDID string) (*did.DID, error) {
	delegateDID = strings.TrimSpace(delegateDID)
	if delegateDID == "" {
		return nil, nil
	}
	if !did.EncryptedExistsAs(stateDir, delegateIdentityVaultFile) {
		return nil, fmt.Errorf("wallet response grants to delegate DID %s, but the local delegate vault is missing; rerun 'meshd auth connect' from this profile", delegateDID)
	}
	password, err := vaultPasswordForUnlock(stateDir)
	if err != nil {
		return nil, err
	}
	delegateIdentity, err := did.LoadEncryptedAs(stateDir, delegateIdentityVaultFile, password)
	if err != nil {
		return nil, fmt.Errorf("unlocking delegate identity vault: %w", err)
	}
	if delegateIdentity == nil {
		return nil, fmt.Errorf("delegate identity vault is missing")
	}
	if delegateIdentity.URI != delegateDID {
		return nil, fmt.Errorf("delegate identity vault DID %s does not match wallet response delegate DID %s", delegateIdentity.URI, delegateDID)
	}
	return delegateIdentity, nil
}

func requireWalletResponseDelegateIdentity(stateDir string, delegateDID string, nodeDID string, responseLabel string) (*did.DID, error) {
	delegateDID = strings.TrimSpace(delegateDID)
	nodeDID = strings.TrimSpace(nodeDID)
	if responseLabel == "" {
		responseLabel = "wallet response"
	}
	if delegateDID == "" {
		return nil, nil
	}
	if nodeDID != "" && delegateDID == nodeDID {
		return nil, fmt.Errorf("%s delegate DID must be distinct from node DID %s", responseLabel, nodeDID)
	}
	return verifyWalletDelegateIdentity(stateDir, delegateDID)
}

func loadDWNOperationIdentity(stateDir string, meta identityMetadata, fallback *did.DID) (*did.DID, error) {
	if fallback == nil {
		return nil, fmt.Errorf("fallback identity is required")
	}
	if meta.AuthType != profile.AuthTypeWalletAuthorizedNode || meta.DelegateDID == "" || meta.DelegateDID == fallback.URI {
		return fallback, nil
	}
	return verifyWalletDelegateIdentity(stateDir, meta.DelegateDID)
}

func dwnSigner(identity *did.DID) *dwn.Signer {
	if identity == nil {
		return nil
	}
	return &dwn.Signer{
		DID:        identity.URI,
		PrivateKey: identity.SigningKey,
	}
}

func approvePreAuthRequests(ctx context.Context, ns *state.NetworkState, signer *dwn.Signer, encMgr *dwncrypto.EncryptionKeyManager, logger *slog.Logger, readGrantID, writeGrantID, deleteGrantID, keyDeliveryGrantID string, useContextEncryption bool) {
	result, err := mesh.ApprovePreAuthRequests(ctx, mesh.ApprovePreAuthRequestsParams{
		AnchorEndpoint:          ns.AnchorEndpoint,
		AnchorDID:               ns.AnchorDID,
		NetworkRecordID:         ns.NetworkRecordID,
		MeshCIDR:                ns.MeshCIDR,
		Signer:                  signer,
		EncryptionKeyManager:    encMgr,
		ReadPermissionGrantID:   readGrantID,
		WritePermissionGrantID:  writeGrantID,
		DeletePermissionGrantID: deleteGrantID,
		KeyDeliveryGrantID:      keyDeliveryGrantID,
		UseContextEncryption:    useContextEncryption,
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

func runPreAuthApprovalLoop(ctx context.Context, stop <-chan struct{}, interval time.Duration, ns *state.NetworkState, signer *dwn.Signer, encMgr *dwncrypto.EncryptionKeyManager, logger *slog.Logger, readGrantID, writeGrantID, deleteGrantID, keyDeliveryGrantID string, useContextEncryption bool) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-stop:
			return
		case <-ticker.C:
			approvePreAuthRequests(ctx, ns, signer, encMgr, logger, readGrantID, writeGrantID, deleteGrantID, keyDeliveryGrantID, useContextEncryption)
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

type authConnectOptions struct {
	profileName string
	requestOut  string
	responseIn  string
	walletURL   string
	noWait      bool
	admin       bool
}

// cmdAuthConnect creates or imports a wallet connection for a CLI profile.
//
// Usage:
//
//	meshd auth connect [name] [--admin] [--request-out <file>] [--wallet <url>] [--no-wait]
//	meshd auth connect [name] --response <file>
func cmdAuthConnect(ctx context.Context, args []string, flagProfile string) error {
	opts, err := parseAuthConnectArgs(args)
	if err != nil {
		return err
	}
	profileFlag := firstNonEmpty(opts.profileName, flagProfile)

	if opts.responseIn != "" {
		return importAuthConnectResponse(ctx, profileFlag, opts.responseIn)
	}
	return createAuthConnectRequest(ctx, profileFlag, opts)
}

func parseAuthConnectArgs(args []string) (authConnectOptions, error) {
	opts := authConnectOptions{
		walletURL: "https://wallet.enbox.id",
	}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--request-out":
			if i+1 >= len(args) {
				return opts, fmt.Errorf("--request-out requires a path")
			}
			opts.requestOut = args[i+1]
			i++
		case "--response":
			if i+1 >= len(args) {
				return opts, fmt.Errorf("--response requires a path")
			}
			opts.responseIn = args[i+1]
			i++
		case "--wallet":
			if i+1 >= len(args) {
				return opts, fmt.Errorf("--wallet requires a URL")
			}
			opts.walletURL = args[i+1]
			i++
		case "--no-wait":
			opts.noWait = true
		case "--admin":
			opts.admin = true
		default:
			if strings.HasPrefix(args[i], "-") {
				return opts, fmt.Errorf("unknown auth connect flag %q", args[i])
			}
			if opts.profileName == "" {
				opts.profileName = args[i]
			} else {
				return opts, fmt.Errorf("unexpected argument %q", args[i])
			}
		}
	}
	return opts, nil
}

func createAuthConnectRequest(ctx context.Context, profileFlag string, opts authConnectOptions) error {
	stateDir, identity, err := ensureIdentityForCommand(ctx, profileFlag, "")
	if err != nil {
		return err
	}
	var callback *walletResponseCallback
	if shouldWaitForWalletResponse(opts.walletURL, opts.requestOut, opts.noWait) {
		callback, err = startWalletResponseCallback()
		if err != nil {
			return err
		}
		defer callback.close()
	}
	var relay *walletResponseRelay
	if shouldUseWalletResponseRelay(opts.walletURL, opts.requestOut, opts.noWait) {
		relay, err = setupWalletResponseRelay(ctx, walletResponseEndpoint(""), identity)
		if err != nil {
			fmt.Printf("  Warning: wallet response handoff unavailable: %v\n", err)
			relay = nil
		}
	}
	profileName := profileNameForWrite(profileFlag)
	delegateIdentity, err := ensureWalletDelegateIdentity(stateDir)
	if err != nil {
		return err
	}
	req, err := walletconnect.NewRequest(profileName, identity, delegateIdentity)
	if err != nil {
		return err
	}
	if opts.admin {
		req.Permissions = appendUniqueStrings(req.Permissions, "mesh-admin")
	}
	if callback != nil {
		req.CallbackURL = callback.url
	}
	if relay != nil {
		req.ResponseEndpoint = relay.endpoint
		req.ResponseToken = relay.token
	}
	if err := walletconnect.SignRequest(identity, &req); err != nil {
		return err
	}
	requestURL, err := walletconnect.EncodeRequest(req)
	if err != nil {
		return err
	}
	if opts.requestOut != "" {
		data, err := json.MarshalIndent(req, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal wallet request: %w", err)
		}
		if err := os.WriteFile(opts.requestOut, data, 0600); err != nil {
			return fmt.Errorf("write wallet request: %w", err)
		}
	}

	fmt.Println("Wallet connect request created.")
	fmt.Printf("  Profile: %s\n", profileName)
	fmt.Printf("  Node DID: %s\n", identity.URI)
	fmt.Printf("  Delegate DID: %s\n", delegateIdentity.URI)
	if opts.admin {
		fmt.Printf("  Access: node runtime + admin control\n")
	} else {
		fmt.Printf("  Access: node runtime\n")
	}
	fmt.Printf("  State: %s\n", stateDir)
	if opts.requestOut != "" {
		fmt.Printf("  Request: %s\n", opts.requestOut)
	}
	if relay != nil {
		fmt.Printf("  Response handoff: %s\n", relay.endpoint)
	}
	fmt.Printf("\nRequest URL:\n  %s\n", requestURL)
	if opts.walletURL != "" {
		walletURL := strings.TrimRight(opts.walletURL, "/") + "/meshd/connect?request=" + url.QueryEscape(requestURL)
		printWalletURL(walletURL, callback != nil, relay != nil)
	}
	if callback == nil && relay == nil {
		fmt.Printf("\nAfter wallet approval, save the response JSON and run:\n")
		fmt.Printf("  meshd auth connect %s --response <response.json>\n", profileName)
		return nil
	}
	fmt.Printf("\nWaiting for wallet approval...\n")
	data, err := waitForWalletDelivery(ctx, callback, relay, identity)
	if err != nil {
		return err
	}
	return importAuthConnectResponseData(ctx, profileFlag, data)
}

func importAuthConnectResponse(ctx context.Context, profileFlag string, responsePath string) error {
	var data []byte
	var err error
	if responsePath == "-" {
		data, err = io.ReadAll(os.Stdin)
	} else {
		data, err = os.ReadFile(responsePath)
	}
	if err != nil {
		return fmt.Errorf("read wallet response: %w", err)
	}
	return importAuthConnectResponseData(ctx, profileFlag, data)
}

func importAuthConnectResponseData(ctx context.Context, profileFlag string, data []byte) error {
	var resp walletconnect.Response
	if err := json.Unmarshal(data, &resp); err != nil {
		return fmt.Errorf("parse wallet response: %w", err)
	}
	if err := resp.Validate(); err != nil {
		return err
	}
	resp.NormalizeOwnerDID()
	ownerDID := resp.EffectiveOwnerDID()
	profileFlag = firstNonEmpty(profileFlag, resp.ProfileName)
	stateDir, identity, err := ensureIdentityForCommand(ctx, profileFlag, "")
	if err != nil {
		return err
	}
	if resp.NodeDID != identity.URI {
		return fmt.Errorf("wallet response node DID %s does not match local node DID %s", resp.NodeDID, identity.URI)
	}

	password, err := vaultPasswordForUnlock(stateDir)
	if err != nil {
		return err
	}
	if _, err := requireWalletResponseDelegateIdentity(stateDir, resp.DelegateDID, resp.NodeDID, "wallet response"); err != nil {
		return err
	}
	nodeContextKeys := resp.EffectiveNodeContextKeys()
	nodeProtocols := resp.EffectiveNodeMultiPartyProtocols()
	session := &state.WalletSession{
		Version:                 1,
		OwnerDID:                ownerDID,
		ConnectedDID:            ownerDID,
		DelegateDID:             resp.DelegateDID,
		NodeDID:                 resp.NodeDID,
		WalletOrigin:            resp.WalletOrigin,
		ExpiresAt:               resp.ExpiresAt,
		Grants:                  resp.Grants,
		NodeContextKeys:         nodeContextKeys,
		NodeMultiPartyProtocols: nodeProtocols,
		DelegateDecryptionKeys:  resp.DelegateDecryptionKeys,
	}
	if err := state.StoreWalletSession(stateDir, password, session); err != nil {
		return err
	}
	importedContextKeys, err := storeWalletNodeContextKeys(stateDir, password, nodeContextKeys)
	if err != nil {
		return err
	}

	if os.Getenv("MESHD_STATE_DIR") == "" {
		profileName := profileNameForWrite(profileFlag)
		if err := profile.UpsertProfileEntry(&profile.Entry{
			Name:         profileName,
			DID:          identity.URI,
			AuthType:     profile.AuthTypeWalletAuthorizedNode,
			OwnerDID:     ownerDID,
			ConnectedDID: ownerDID,
			DelegateDID:  resp.DelegateDID,
			NodeDID:      identity.URI,
			WalletOrigin: resp.WalletOrigin,
			ExpiresAt:    resp.ExpiresAt,
		}); err != nil {
			return fmt.Errorf("saving wallet-connected profile: %w", err)
		}
	}

	fmt.Println("Wallet connection imported.")
	fmt.Printf("  Wallet Owner DID: %s\n", ownerDID)
	if resp.DelegateDID != "" {
		fmt.Printf("  Session Delegate DID: %s\n", resp.DelegateDID)
	}
	fmt.Printf("  Node DID: %s\n", resp.NodeDID)
	fmt.Printf("  Session: encrypted\n")
	if importedContextKeys > 0 {
		fmt.Printf("  Context keys: %d imported\n", importedContextKeys)
	}
	return nil
}

func storeWalletNodeContextKeys(stateDir string, password string, rawKeys []json.RawMessage) (int, error) {
	imported := 0
	for _, raw := range rawKeys {
		var entry struct {
			Protocol          string          `json:"protocol"`
			ContextID         string          `json:"contextId"`
			DerivedPrivateKey json.RawMessage `json:"derivedPrivateKey"`
		}
		if err := json.Unmarshal(raw, &entry); err != nil {
			return imported, fmt.Errorf("parse node context key: %w", err)
		}
		if entry.Protocol != protocols.MeshProtocolURI || entry.ContextID == "" {
			continue
		}
		contextKey, err := dwncrypto.ParseDerivedPrivateJwk(entry.DerivedPrivateKey)
		if err != nil {
			return imported, fmt.Errorf("parse mesh context key %s: %w", entry.ContextID, err)
		}
		privateKey, err := contextKey.PrivateKeyBytes()
		if err != nil {
			return imported, fmt.Errorf("decode mesh context key %s: %w", entry.ContextID, err)
		}
		if err := state.StoreContextKey(stateDir, password, entry.ContextID, privateKey); err != nil {
			return imported, err
		}
		imported++
	}
	return imported, nil
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
		fmt.Printf("    Node:    %s\n", entry.EffectiveNodeDID())
		fmt.Printf("    Auth:    %s\n", authDisplayName(entry.EffectiveAuthType()))
		if ownerDID := entry.EffectiveOwnerDID(); ownerDID != "" && ownerDID != entry.DID {
			fmt.Printf("    Owner:   %s\n", ownerDID)
		}
		if entry.DelegateDID != "" {
			fmt.Printf("    Session: %s\n", entry.DelegateDID)
		}
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

	meta, useContextEncryption, err := requireNetworkOwnerProfile(flagProfile, identity, ns)
	if err != nil {
		return err
	}

	operationIdentity, err := loadDWNOperationIdentity(stateDir, meta, identity)
	if err != nil {
		return err
	}
	signer := dwnSigner(operationIdentity)
	encMgr, err := prepareNetworkCommandEncryption(stateDir, identity, ns, useContextEncryption)
	if err != nil {
		return err
	}
	writeGrantID, err := walletGrantIDForDWNOperation(stateDir, meta, dwn.InterfaceRecordsWrite, protocols.MeshProtocolURI, "", ns.NetworkRecordID, useContextEncryption)
	if err != nil {
		return err
	}

	if err := mesh.WriteACLPolicy(ctx, mesh.WriteACLPolicyParams{
		AnchorEndpoint:       ns.AnchorEndpoint,
		AnchorDID:            ns.AnchorDID,
		NetworkRecordID:      ns.NetworkRecordID,
		Signer:               signer,
		EncryptionKeyManager: encMgr,
		PermissionGrantID:    writeGrantID,
		UseContextEncryption: useContextEncryption,
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

	meta := resolveIdentityMetadata(flagProfile, identity.URI)
	operationIdentity, err := loadDWNOperationIdentity(stateDir, meta, identity)
	if err != nil {
		return err
	}
	signer := dwnSigner(operationIdentity)
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
	readGrantID, err := walletGrantIDForDWNOperation(stateDir, meta, dwn.InterfaceRecordsQuery, protocols.MeshProtocolURI, "", ns.NetworkRecordID, false)
	if err != nil {
		return err
	}

	client := control.NewDWNClient(
		ns.AnchorEndpoint,
		ns.AnchorDID,
		ns.NetworkRecordID,
		identity.URI,
		signer,
		control.WithEncryptionKeyManager(encMgr),
		control.WithProtocolRole(aclQueryRole),
		control.WithPermissionGrantID(readGrantID),
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

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func appendUniqueStrings(values []string, next ...string) []string {
	for _, candidate := range next {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		exists := false
		for _, value := range values {
			if value == candidate {
				exists = true
				break
			}
		}
		if !exists {
			values = append(values, candidate)
		}
	}
	return values
}
