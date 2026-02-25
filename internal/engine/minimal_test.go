package engine

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/enboxorg/meshd/internal/control"

	"github.com/enboxorg/meshnet/control/controlclient"
	"github.com/enboxorg/meshnet/derp/derpserver"
	"github.com/enboxorg/meshnet/ipn"
	"github.com/enboxorg/meshnet/ipn/ipnlocal"
	"github.com/enboxorg/meshnet/ipn/store/mem"
	"github.com/enboxorg/meshnet/net/netmon"
	"github.com/enboxorg/meshnet/net/tsdial"
	"github.com/enboxorg/meshnet/tsd"
	"github.com/enboxorg/meshnet/types/key"
	"github.com/enboxorg/meshnet/types/logid"
	"github.com/enboxorg/meshnet/types/logger"
	"github.com/enboxorg/meshnet/types/netmap"
	"github.com/enboxorg/meshnet/wgengine"
	"github.com/enboxorg/meshnet/wgengine/netstack"
)

// TestMinimalTwoEngineConnectivity creates two full meshnet stacks with
// hard-coded NetworkMaps (no DWN, no DID, no encryption) and tests TCP
// connectivity through the WireGuard tunnel. This isolates the data plane
// from the DWN control plane for fast debugging (~5s vs ~50s).
//
// Run with: go test ./internal/engine/ -run TestMinimalTwoEngineConnectivity -v -count=1 -timeout 60s
func TestMinimalTwoEngineConnectivity(t *testing.T) {
	// Use verbose logging so we can see meshnet internals.
	logLevel := slog.LevelDebug
	if os.Getenv("VERBOSE_MESHNET") != "" {
		logLevel = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel}))

	// Generate WireGuard key pairs for both nodes.
	wgKeyA := key.NewNode()
	wgKeyB := key.NewNode()
	pubA := wgKeyA.Public()
	pubB := wgKeyB.Public()
	t.Logf("Node A: pubKey=%s", pubA.ShortString())
	t.Logf("Node B: pubKey=%s", pubB.ShortString())

	// Mesh IPs.
	// IMPORTANT: 10.200.0.1 is TailscaleServiceIP in the meshnet fork — do NOT use it
	// as a node address. shouldSendToHost() treats traffic from serviceIP as
	// host-bound, which prevents SYN-ACKs from going through WireGuard.
	ipA := netip.MustParseAddr("10.200.0.2")
	ipB := netip.MustParseAddr("10.200.0.3")

	// Shared disco key registry — both engines publish and look up disco keys here.
	discoReg := NewInMemoryDiscoRegistry()

	// Local DERP server — avoids reliance on Tailscale's public DERP servers.
	derpMap, derpCleanup := startLocalDERP(t)
	defer derpCleanup()

	// ================================================================
	// MapResponseFunc for Node A: self=A, peer=B
	// ================================================================
	mapFuncA := func(ctx context.Context) (*netmap.NetworkMap, error) {
		resp := control.BuildStaticMapResponse(
			&control.Node{
				ID:            1,
				Name:          "node-a",
				DID:           "did:test:a",
				Key:           pubKeyToBase64(pubA),
				MeshIP:        ipA,
				PreferredDERP: 900,
				Online:        true,
			},
			[]*control.Node{
				{
					ID:            2,
					Name:          "node-b",
					DID:           "did:test:b",
					Key:           pubKeyToBase64(pubB),
					MeshIP:        ipB,
					PreferredDERP: 900,
					Online:        true,
				},
			},
			derpMap,
		)
		converter := NewConverter("minimal-test")
		return converter.Convert(resp)
	}

	// ================================================================
	// MapResponseFunc for Node B: self=B, peer=A
	// ================================================================
	mapFuncB := func(ctx context.Context) (*netmap.NetworkMap, error) {
		resp := control.BuildStaticMapResponse(
			&control.Node{
				ID:            2,
				Name:          "node-b",
				DID:           "did:test:b",
				Key:           pubKeyToBase64(pubB),
				MeshIP:        ipB,
				PreferredDERP: 900,
				Online:        true,
			},
			[]*control.Node{
				{
					ID:            1,
					Name:          "node-a",
					DID:           "did:test:a",
					Key:           pubKeyToBase64(pubA),
					MeshIP:        ipA,
					PreferredDERP: 900,
					Online:        true,
				},
			},
			derpMap,
		)
		converter := NewConverter("minimal-test")
		return converter.Convert(resp)
	}

	// ================================================================
	// Create Engine A
	// ================================================================
	t.Log("Creating engine A")
	stackA, err := newMinimalStack(t, logger, wgKeyA, mapFuncA, discoReg)
	if err != nil {
		t.Fatalf("creating stack A: %v", err)
	}
	defer stackA.close()

	// ================================================================
	// Create Engine B
	// ================================================================
	t.Log("Creating engine B")
	stackB, err := newMinimalStack(t, logger, wgKeyB, mapFuncB, discoReg)
	if err != nil {
		t.Fatalf("creating stack B: %v", err)
	}
	defer stackB.close()

	// ================================================================
	// Start both engines
	// ================================================================
	t.Log("Starting engines")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if err := stackA.start(ctx); err != nil {
		t.Fatalf("starting A: %v", err)
	}
	if err := stackB.start(ctx); err != nil {
		t.Fatalf("starting B: %v", err)
	}

	// ================================================================
	// Wait for peer discovery (netmap population)
	// ================================================================
	t.Log("Waiting for engines to discover peers in netmap")

	// Wait for both engines to have peers in their netmap.
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		nmA := stackA.backend.NetMap()
		nmB := stackB.backend.NetMap()

		if nmA != nil && nmB != nil && len(nmA.Peers) > 0 && len(nmB.Peers) > 0 {
			t.Logf("  Engine A: selfKey=%s, peers=%d", nmA.NodeKey.ShortString(), len(nmA.Peers))
			t.Logf("  Engine B: selfKey=%s, peers=%d", nmB.NodeKey.ShortString(), len(nmB.Peers))

			// Check disco keys are present on peers.
			for i, p := range nmA.Peers {
				t.Logf("    A peer %d: key=%s disco=%s homeDERP=%d",
					i, p.Key().ShortString(), p.DiscoKey().ShortString(), p.HomeDERP())
			}
			for i, p := range nmB.Peers {
				t.Logf("    B peer %d: key=%s disco=%s homeDERP=%d",
					i, p.Key().ShortString(), p.DiscoKey().ShortString(), p.HomeDERP())
			}
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	// Log full status for debugging.
	logStatus(t, "A", stackA.backend)
	logStatus(t, "B", stackB.backend)

	// ================================================================
	// TCP connectivity test: B dials A
	// ================================================================
	// The TCP dial triggers the WireGuard handshake and disco discovery.
	// WireGuard only initiates a handshake when there is data to send,
	// so the dial itself is what starts the whole process.
	t.Log("Testing TCP connectivity through WireGuard mesh (dial triggers WG handshake + disco)")

	// Node A listens on port 9999.
	listener, err := stackA.ns.ListenTCP("tcp4", "0.0.0.0:9999")
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	defer listener.Close()

	// Server goroutine: echo.
	serverDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverDone <- fmt.Errorf("accept: %w", err)
			return
		}
		defer conn.Close()

		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil && err != io.EOF {
			serverDone <- fmt.Errorf("read: %w", err)
			return
		}
		if _, err := conn.Write(buf[:n]); err != nil {
			serverDone <- fmt.Errorf("write: %w", err)
			return
		}
		serverDone <- nil
	}()

	// Node B dials Node A. This triggers the WireGuard handshake + disco.
	// Give it enough time for DERP relay discovery and handshake.
	dialCtx, dialCancel := context.WithTimeout(ctx, 30*time.Second)
	defer dialCancel()

	dst := netip.AddrPortFrom(ipA, 9999)
	conn, err := stackB.ns.DialContextTCP(dialCtx, dst)
	if err != nil {
		t.Fatalf("DialContextTCP to %s: %v", dst, err)
	}
	defer conn.Close()

	testMsg := []byte("hello from minimal test!")
	if _, err := conn.Write(testMsg); err != nil {
		t.Fatalf("write: %v", err)
	}

	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read echo: %v", err)
	}

	if string(buf[:n]) != string(testMsg) {
		t.Fatalf("echo mismatch: got %q, want %q", buf[:n], testMsg)
	}

	t.Logf("TCP echo verified: %q", string(buf[:n]))

	// Log post-connectivity status showing the handshake succeeded.
	logStatus(t, "A (post-connect)", stackA.backend)
	logStatus(t, "B (post-connect)", stackB.backend)

	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatalf("server error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not finish within 5s")
	}

	t.Log("=== Minimal Two-Engine Connectivity Test PASSED ===")
}

// minimalStack holds the meshnet components for a single node.
type minimalStack struct {
	backend *ipnlocal.LocalBackend
	ns      *netstack.Impl
	eng     wgengine.Engine
	nm      *netmon.Monitor
	sys     *tsd.System
	dialer  *tsdial.Dialer
}

func (s *minimalStack) start(ctx context.Context) error {
	return s.backend.Start(ipn.Options{
		UpdatePrefs: &ipn.Prefs{
			WantRunning: true,
		},
	})
}

func (s *minimalStack) close() {
	s.backend.Shutdown()
	if s.nm != nil {
		s.nm.Close()
	}
}

// newMinimalStack creates a full meshnet stack (UserspaceEngine + netstack +
// LocalBackend) with the given MapResponseFunc. This mirrors engine.New() but
// skips all DWN-related setup.
func newMinimalStack(
	t *testing.T,
	l *slog.Logger,
	nodeKey key.NodePrivate,
	mapFn func(context.Context) (*netmap.NetworkMap, error),
	discoReg controlclient.DiscoKeyRegistry,
) (*minimalStack, error) {
	t.Helper()

	// Use info-level logging so we can see meshnet's [v1] messages.
	logf := minimalLogf(l)

	sys := tsd.NewSystem()
	sys.Set(&mem.Store{})

	// Disable lazy WireGuard peer config — without this, inactive peers
	// are trimmed from the WG device, preventing the initial handshake.
	sys.ControlKnobs().KeepFullWGConfig.Store(true)

	nm, err := netmon.New(sys.Bus.Get(), logf)
	if err != nil {
		return nil, fmt.Errorf("creating network monitor: %w", err)
	}

	dial := &tsdial.Dialer{Logf: logf}
	dial.SetBus(sys.Bus.Get())

	eng, err := wgengine.NewUserspaceEngine(logf, wgengine.Config{
		Tun:           nil, // fake TUN
		EventBus:      sys.Bus.Get(),
		ListenPort:    0, // auto
		NetMon:        nm,
		Dialer:        dial,
		SetSubsystem:  sys.Set,
		ControlKnobs:  sys.ControlKnobs(),
		HealthTracker: sys.HealthTracker.Get(),
		Metrics:       sys.UserMetricsRegistry(),
	})
	if err != nil {
		nm.Close()
		return nil, fmt.Errorf("creating WireGuard engine: %w", err)
	}
	sys.Set(eng)

	ns, err := netstack.Create(
		logf,
		sys.Tun.Get(),
		eng,
		sys.MagicSock.Get(),
		dial,
		sys.DNSManager.Get(),
		sys.ProxyMapper(),
	)
	if err != nil {
		eng.Close()
		nm.Close()
		return nil, fmt.Errorf("creating netstack: %w", err)
	}
	sys.Tun.Get().Start()
	sys.Set(ns)

	ns.ProcessLocalIPs = true
	ns.ProcessSubnets = true

	dial.UseNetstackForIP = func(ip netip.Addr) bool {
		_, ok := eng.PeerForIP(ip)
		return ok
	}
	dial.NetstackDialTCP = func(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
		return ns.DialContextTCP(ctx, dst)
	}

	lb, err := ipnlocal.NewLocalBackend(
		logf,
		logid.PublicID{},
		sys,
		controlclient.LoginDefault|controlclient.LocalBackendStartKeyOSNeutral,
	)
	if err != nil {
		eng.Close()
		nm.Close()
		return nil, fmt.Errorf("creating LocalBackend: %w", err)
	}

	if err := ns.Start(lb); err != nil {
		lb.Shutdown()
		eng.Close()
		nm.Close()
		return nil, fmt.Errorf("starting netstack: %w", err)
	}

	// Wire DWNControl with hard-coded map and disco registry.
	dwnCfg := &controlclient.DWNControlConfig{
		MapResponseFunc: mapFn,
		PollInterval:    30 * time.Second, // slow polling — initial push is enough for static config
		NodePrivateKey:  nodeKey,
		DiscoKeyRegistry: discoReg,
		Logf:            logf,
	}

	lb.SetControlClientGetterForTesting(
		controlclient.NewDWNControlFactory(dwnCfg),
	)

	return &minimalStack{
		backend: lb,
		ns:      ns,
		eng:     eng,
		nm:      nm,
		sys:     sys,
		dialer:  dial,
	}, nil
}

// minimalLogf logs meshnet messages at Info level so we can see important
// messages like authReconfigLocked, SetPrivateKey, disco, DERP connections.
// The production slogToLogf maps everything to Debug, which suppresses these.
func minimalLogf(l *slog.Logger) logger.Logf {
	if l == nil {
		l = slog.Default()
	}
	return func(format string, args ...any) {
		msg := fmt.Sprintf(format, args...)
		l.Info(msg, slog.String("source", "meshnet"))
	}
}

// pubKeyToBase64 converts a key.NodePublic to the standard base64 encoding
// used in DWN records (same as WireGuardKeyPair.PublicKeyBase64).
func pubKeyToBase64(k key.NodePublic) string {
	raw := k.Raw32()
	return base64.StdEncoding.EncodeToString(raw[:])
}

// startLocalDERP starts a local DERP server and returns its DERP map and a
// cleanup function. Using a local DERP avoids reliance on Tailscale's public
// DERP servers, which may not relay data for unknown clients.
func startLocalDERP(t *testing.T) (*control.DERPMap, func()) {
	t.Helper()

	// Create a DERP server with a fresh key.
	derpKey := key.NewNode()
	logf := func(format string, args ...any) {
		t.Logf("[derp] "+format, args...)
	}
	ds := derpserver.New(derpKey, logf)

	// Wrap it in an HTTP test server.
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

	// Use TLS server — the DERP HTTP client always speaks TLS for region-based
	// connections. InsecureForTests=true makes it skip certificate verification.
	ts := httptest.NewTLSServer(mux)
	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatalf("parsing test server URL: %v", err)
	}
	port, _ := strconv.Atoi(u.Port())

	t.Logf("Local DERP server running at %s (port %d)", ts.URL, port)

	dm := &control.DERPMap{
		Regions: map[int]*control.DERPRegion{
			900: {
				RegionID:   900,
				RegionCode: "test",
				RegionName: "Local Test",
				Nodes: []control.DERPNode{
					{
						Name:     "900a",
						RegionID: 900,
						HostName: u.Hostname(),
						DERPPort: port,
					// Self-signed TLS — InsecureForTests skips cert verification.
					InsecureForTests: true,
					},
				},
			},
		},
	}

	return dm, func() {
		ds.Close()
		ts.Close()
	}
}

// logStatus logs the full status of a backend for debugging.
func logStatus(t *testing.T, label string, lb *ipnlocal.LocalBackend) {
	t.Helper()
	status := lb.Status()
	if status == nil {
		t.Logf("  %s: status is nil", label)
		return
	}
	t.Logf("  %s: state=%s self=%+v", label, status.BackendState, status.Self)
	for k, peer := range status.Peer {
		t.Logf("    Peer %s: relay=%s curAddr=%s active=%v lastHandshake=%v rxBytes=%d txBytes=%d",
			k.ShortString(), peer.Relay, peer.CurAddr, peer.Active, peer.LastHandshake,
			peer.RxBytes, peer.TxBytes)
	}
}

// Ensure imports are used.
var _ net.Conn
