package engine_test

// TestE2EEnboxConnectTwoNodeMesh proves the wallet-delegate MVP end to end:
//
//  1. Two devices each onboard through the REAL enbox connect relay flow
//     (POST /connect/par → wallet URI → PIN-bound encrypted response), with
//     the headless approver (scripts/e2e/approver.ts) standing in for the
//     Enbox wallet. Both approvals come from the SAME persistent owner.
//  2. Device A creates a wallet-owned network directly as a delegate —
//     writing the network record with a delegated grant and eagerly
//     provisioning the sealed role-audience keys.
//  3. Device B joins the same network as a delegate — no dashboard
//     approval round-trip.
//  4. Both devices run real engines (UserspaceEngine + netstack), discover
//     each other through encrypted DWN records (wrapped grant keys +
//     sealed role audiences), and exchange TCP traffic over their
//     WireGuard mesh IPs.
//
// Requirements (skipped otherwise):
//   - DWN_ENDPOINT: an @enbox/dwn-server with the /connect relay
//     (e.g. http://localhost:3000 via `bun run dev` in the enbox monorepo)
//   - bun on PATH and the enbox monorepo checkout (ENBOX_REPO, default
//     ~/src/enboxorg/enbox) for the approver script.

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/enboxorg/meshd/internal/control"
	"github.com/enboxorg/meshd/internal/did"
	"github.com/enboxorg/meshd/internal/dwn"
	dwncrypto "github.com/enboxorg/meshd/internal/dwn/crypto"
	"github.com/enboxorg/meshd/internal/enboxconnect"
	"github.com/enboxorg/meshd/internal/engine"
	"github.com/enboxorg/meshd/internal/mesh"
	"github.com/enboxorg/meshd/protocols"

	"github.com/enboxorg/meshnet/derp/derpserver"
	"github.com/enboxorg/meshnet/types/key"
)

func TestE2EEnboxConnectTwoNodeMesh(t *testing.T) {
	endpoint := os.Getenv("DWN_ENDPOINT")
	if endpoint == "" {
		t.Skip("DWN_ENDPOINT not set, skipping enbox-connect e2e test")
	}
	bunPath, err := exec.LookPath("bun")
	if err != nil {
		t.Skip("bun not on PATH, skipping enbox-connect e2e test")
	}
	enboxRepo := os.Getenv("ENBOX_REPO")
	if enboxRepo == "" {
		home, _ := os.UserHomeDir()
		enboxRepo = filepath.Join(home, "src", "enboxorg", "enbox")
	}
	if _, err := os.Stat(enboxRepo); err != nil {
		t.Skipf("enbox monorepo not found at %s (set ENBOX_REPO), skipping", enboxRepo)
	}
	approverScript, err := filepath.Abs(filepath.Join("..", "..", "scripts", "e2e", "approver.ts"))
	if err != nil || fileMissing(approverScript) {
		t.Fatalf("approver script not found at %s", approverScript)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// The approver keeps one persistent owner identity across both
	// approvals: one wallet owner, two devices.
	ownerDir := filepath.Join(t.TempDir(), "approver-owner")

	// ── Device A: connect, then create the network as a delegate ──
	nodeA := generateIdentity(t)
	delegateA := generateIdentity(t)
	t.Logf("device A: node=%s delegate=%s", short(nodeA.URI), short(delegateA.URI))

	resA := connectViaApprover(t, ctx, connectParams{
		endpoint: endpoint, bun: bunPath, script: approverScript,
		enboxRepo: enboxRepo, ownerDir: ownerDir, delegate: delegateA,
	})
	ownerDID := resA.OwnerDID
	t.Logf("device A connected: owner=%s grants=%d revocations=%d",
		short(ownerDID), len(resA.Grants), len(resA.SessionRevocations))

	sessA, err := mesh.NewDelegateSession(ctx, mesh.DelegateSessionParams{
		Endpoint:           endpoint,
		OwnerDID:           ownerDID,
		DelegateSigner:     &dwn.Signer{DID: delegateA.URI, PrivateKey: delegateA.SigningKey},
		DelegateX25519Priv: delegateA.EncryptionPrivateKey,
		Grants:             resA.Grants,
	})
	if err != nil {
		t.Fatalf("device A delegate session: %v", err)
	}

	network, err := mesh.CreateNetworkAsDelegate(ctx, mesh.CreateNetworkParams{
		Session:     sessA,
		NetworkName: "enbox-e2e",
		NodeDID:     nodeA.URI,
		Label:       "device-a",
		Hostname:    "device-a",
	})
	if err != nil {
		t.Fatalf("device A network create: %v", err)
	}
	t.Logf("network created: id=%s meshIP(A)=%s", short(network.NetworkRecordID), network.MeshIP)

	// ── Device B: connect (same owner), then join as a delegate ──
	nodeB := generateIdentity(t)
	delegateB := generateIdentity(t)
	t.Logf("device B: node=%s delegate=%s", short(nodeB.URI), short(delegateB.URI))

	resB := connectViaApprover(t, ctx, connectParams{
		endpoint: endpoint, bun: bunPath, script: approverScript,
		enboxRepo: enboxRepo, ownerDir: ownerDir, delegate: delegateB,
	})
	if resB.OwnerDID != ownerDID {
		t.Fatalf("device B connected to a different owner: %s != %s", resB.OwnerDID, ownerDID)
	}

	sessB, err := mesh.NewDelegateSession(ctx, mesh.DelegateSessionParams{
		Endpoint:           endpoint,
		OwnerDID:           ownerDID,
		DelegateSigner:     &dwn.Signer{DID: delegateB.URI, PrivateKey: delegateB.SigningKey},
		DelegateX25519Priv: delegateB.EncryptionPrivateKey,
		Grants:             resB.Grants,
	})
	if err != nil {
		t.Fatalf("device B delegate session: %v", err)
	}

	joined, err := mesh.JoinNetworkAsDelegate(ctx, mesh.JoinNetworkParams{
		Session:         sessB,
		NetworkRecordID: network.NetworkRecordID,
		NodeDID:         nodeB.URI,
		Label:           "device-b",
		Hostname:        "device-b",
	})
	if err != nil {
		t.Fatalf("device B network join: %v", err)
	}
	t.Logf("device B joined: meshIP(B)=%s node=%s", joined.MeshIP, short(joined.NodeRecordID))

	// ── Engines: real UserspaceEngine + netstack, no root needed ──
	derpMap, stopDERP := startLocalTestDERP(t)
	defer stopDERP()
	discoReg := engine.NewInMemoryDiscoRegistry()

	engA := startDelegateEngine(t, ctx, engineParams{
		endpoint: endpoint, owner: ownerDID, network: network.NetworkRecordID,
		node: nodeA, sess: sessA, nodeRecordID: network.NodeRecordID,
		derpMap: derpMap, disco: discoReg, domain: "enbox-e2e",
	})
	defer engA.Stop()
	engB := startDelegateEngine(t, ctx, engineParams{
		endpoint: endpoint, owner: ownerDID, network: network.NetworkRecordID,
		node: nodeB, sess: sessB, nodeRecordID: joined.NodeRecordID,
		derpMap: derpMap, disco: discoReg, domain: "enbox-e2e",
	})
	defer engB.Stop()

	// ── Wait for mutual discovery through encrypted DWN records ──
	waitForPeer(t, engA, joined.MeshIP, "device A sees B")
	waitForPeer(t, engB, network.MeshIP, "device B sees A")

	// ── TCP echo through the WireGuard tunnel ──
	nsA := engA.Netstack()
	nsB := engB.Netstack()
	if nsA == nil || nsB == nil {
		t.Fatal("netstack is nil on one or both engines")
	}

	listener, err := nsA.ListenTCP("tcp4", "0.0.0.0:9999")
	if err != nil {
		t.Fatalf("device A netstack listen: %v", err)
	}
	defer listener.Close()

	echoDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			echoDone <- fmt.Errorf("accept: %w", err)
			return
		}
		defer conn.Close()
		buf := make([]byte, 256)
		n, err := conn.Read(buf)
		if err != nil {
			echoDone <- fmt.Errorf("read: %w", err)
			return
		}
		if _, err := conn.Write(buf[:n]); err != nil {
			echoDone <- fmt.Errorf("write: %w", err)
			return
		}
		echoDone <- nil
	}()

	dialCtx, dialCancel := context.WithTimeout(ctx, 60*time.Second)
	defer dialCancel()
	dst := netip.AddrPortFrom(netip.MustParseAddr(network.MeshIP), 9999)
	conn, err := nsB.DialContextTCP(dialCtx, dst)
	if err != nil {
		t.Fatalf("device B dial %s through the mesh: %v", dst, err)
	}
	defer conn.Close()

	const testMsg = "hello through the wallet-delegate mesh"
	if _, err := conn.Write([]byte(testMsg)); err != nil {
		t.Fatalf("device B write: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("device B read echo: %v", err)
	}
	if string(buf[:n]) != testMsg {
		t.Fatalf("echo mismatch: got %q want %q", buf[:n], testMsg)
	}
	if err := <-echoDone; err != nil {
		t.Fatalf("device A echo server: %v", err)
	}

	t.Log("e2e OK: enbox connect onboarding → delegate network create/join → sealed-encrypted coordination → WireGuard TCP echo")
}

// connectParams configures one device's connect-via-approver round.
type connectParams struct {
	endpoint  string
	bun       string
	script    string
	enboxRepo string
	ownerDir  string
	delegate  *did.DID
}

// connectViaApprover drives enboxconnect.Connect against the real relay,
// launching the headless approver when the wallet URI is ready and feeding
// its PIN back to the client.
func connectViaApprover(t *testing.T, ctx context.Context, p connectParams) *enboxconnect.Result {
	t.Helper()

	pinCh := make(chan string, 1)
	approverErr := make(chan error, 1)
	meshDef := json.RawMessage(protocols.MeshProtocolJSON)

	res, err := enboxconnect.Connect(ctx, enboxconnect.Options{
		AppName:          "meshd e2e",
		WalletURL:        "https://wallet.invalid", // approver only reads the URI query params
		ConnectServerURL: strings.TrimRight(p.endpoint, "/") + "/connect",
		DelegateDID:      p.delegate.URI,
		PermissionRequests: []enboxconnect.PermissionRequest{{
			ProtocolDefinition: meshDef,
			Permissions:        []string{"read", "write", "delete"},
		}},
		OnWalletURI: func(uri string) {
			go runApprover(t, ctx, p, uri, pinCh, approverErr)
		},
		PINPrompt: func() (string, error) {
			select {
			case pin := <-pinCh:
				return pin, nil
			case err := <-approverErr:
				return "", fmt.Errorf("approver failed before delivering a PIN: %w", err)
			case <-ctx.Done():
				return "", ctx.Err()
			}
		},
		PollInterval: 500 * time.Millisecond,
		Timeout:      2 * time.Minute,
	})
	if err != nil {
		t.Fatalf("enbox connect: %v", err)
	}
	return res
}

// runApprover executes the headless approver for one wallet URI and sends
// the PIN it prints back to the connect flow.
func runApprover(t *testing.T, ctx context.Context, p connectParams, uri string, pinCh chan<- string, errCh chan<- error) {
	cmd := exec.CommandContext(ctx, p.bun, p.script,
		"--uri", uri,
		"--data", p.ownerDir,
		"--endpoint", p.endpoint,
		"--password", "meshd-e2e-approver",
	)
	cmd.Env = append(os.Environ(), "ENBOX_REPO="+p.enboxRepo)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		errCh <- err
		return
	}
	cmd.Stderr = &testLogWriter{t: t, prefix: "[approver] "}
	if err := cmd.Start(); err != nil {
		errCh <- fmt.Errorf("starting approver: %w", err)
		return
	}

	scanner := bufio.NewScanner(stdout)
	pinSent := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		t.Logf("[approver] %s", line)
		if pin, ok := strings.CutPrefix(line, "PIN="); ok && !pinSent {
			pinSent = true
			pinCh <- pin
		}
	}
	if err := cmd.Wait(); err != nil {
		errCh <- fmt.Errorf("approver exited: %w", err)
		return
	}
	if !pinSent {
		errCh <- fmt.Errorf("approver completed without printing a PIN")
	}
}

// engineParams configures one device's engine.
type engineParams struct {
	endpoint     string
	owner        string
	network      string
	node         *did.DID
	sess         *mesh.DelegateSession
	nodeRecordID string
	derpMap      *control.DERPMap
	disco        engine.DiscoKeyRegistry
	domain       string
}

// startDelegateEngine builds and starts a real engine for a wallet-delegate
// device: the delegate signs control-plane messages with delegated grants,
// grant keys decrypt the mesh records, and the node identity provides the
// WireGuard keys.
func startDelegateEngine(t *testing.T, ctx context.Context, p engineParams) *engine.Engine {
	t.Helper()

	wgKeys, err := mesh.WireGuardKeyFromIdentity(p.node.EncryptionPrivateKey)
	if err != nil {
		t.Fatalf("deriving WireGuard keys: %v", err)
	}

	eng, err := engine.New(engine.Config{
		AnchorEndpoint:  p.endpoint,
		AnchorTenant:    p.owner,
		NetworkRecordID: p.network,
		SelfDID:         p.node.URI,
		Signer:          p.sess.Signer,
		EncryptionKeyManager: &dwncrypto.EncryptionKeyManager{
			RootPrivateKey: p.node.EncryptionPrivateKey,
			RootKeyID:      p.node.EncryptionKeyID(),
			ProtocolURI:    protocols.MeshProtocolURI,
		},
		NodeRecordID:        p.nodeRecordID,
		DelegatedGrant:      p.sess.ReadGrant,
		WriteDelegatedGrant: p.sess.WriteGrant,
		GrantKeys:           p.sess.GrantKeys,
		AudienceSource:      p.sess.AudienceSource,
		ProtocolDefinition:  p.sess.ProtocolDefinition,
		WireGuardPrivateKey: wgKeys.PrivateKey,
		DiscoKeyRegistry:    p.disco,
		DERPMap:             p.derpMap,
		Domain:              p.domain,
		ListenPort:          0,
		PollInterval:        2 * time.Second,
	})
	if err != nil {
		t.Fatalf("creating engine: %v", err)
	}
	if err := eng.Start(ctx); err != nil {
		t.Fatalf("starting engine: %v", err)
	}
	return eng
}

// waitForPeer polls the engine's netmap until a peer with the given mesh IP
// appears (with any endpoint or disco key), or fails after a deadline.
func waitForPeer(t *testing.T, eng *engine.Engine, peerIP string, what string) {
	t.Helper()
	want := netip.MustParseAddr(peerIP)
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		nm := eng.Backend().NetMap()
		if nm != nil {
			for _, p := range nm.Peers {
				for i := 0; i < p.Addresses().Len(); i++ {
					if p.Addresses().At(i).Addr() == want {
						t.Logf("%s: peer %s visible", what, peerIP)
						return
					}
				}
			}
		}
		time.Sleep(1 * time.Second)
	}
	t.Fatalf("%s: peer %s never appeared in the netmap", what, peerIP)
}

// startLocalTestDERP runs an in-process DERP relay so two loopback engines
// have a deterministic relay path (no external infrastructure).
func startLocalTestDERP(t *testing.T) (*control.DERPMap, func()) {
	t.Helper()

	derpKey := key.NewNode()
	logf := func(format string, args ...any) {}
	ds := derpserver.New(derpKey, logf)

	mux := http.NewServeMux()
	mux.Handle("/derp", derpserver.Handler(ds))
	mux.HandleFunc("/derp/probe", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
	})
	mux.HandleFunc("/derp/latency-check", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
	})
	mux.HandleFunc("/generate_204", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	ts := httptest.NewTLSServer(mux)
	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatalf("parsing local DERP URL: %v", err)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatalf("parsing local DERP port: %v", err)
	}

	dm := &control.DERPMap{
		Regions: map[int]*control.DERPRegion{
			1: {
				RegionID:   1,
				RegionCode: "test",
				RegionName: "Local Test",
				Nodes: []control.DERPNode{{
					Name:             "1a",
					RegionID:         1,
					HostName:         u.Hostname(),
					DERPPort:         port,
					InsecureForTests: true,
				}},
			},
		},
	}

	return dm, func() {
		ds.Close()
		ts.Close()
	}
}

func generateIdentity(t *testing.T) *did.DID {
	t.Helper()
	id, err := did.Generate()
	if err != nil {
		t.Fatalf("generating identity: %v", err)
	}
	return id
}

func short(s string) string {
	if len(s) > 24 {
		return s[:24] + "…"
	}
	return s
}

func fileMissing(path string) bool {
	_, err := os.Stat(path)
	return err != nil
}

// testLogWriter forwards subprocess output lines to the test log.
type testLogWriter struct {
	t      *testing.T
	prefix string
}

func (w *testLogWriter) Write(p []byte) (int, error) {
	for _, line := range strings.Split(strings.TrimRight(string(p), "\n"), "\n") {
		if strings.TrimSpace(line) != "" {
			w.t.Logf("%s%s", w.prefix, line)
		}
	}
	return len(p), nil
}

var _ io.Writer = (*testLogWriter)(nil)
