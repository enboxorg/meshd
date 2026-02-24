package engine

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/enboxorg/dwn-mesh/internal/control"
	"github.com/enboxorg/dwn-mesh/internal/dwn"
	dwncrypto "github.com/enboxorg/dwn-mesh/internal/dwn/crypto"

	"github.com/enboxorg/meshnet/control/controlclient"
	"github.com/enboxorg/meshnet/ipn"
	"github.com/enboxorg/meshnet/ipn/ipnlocal"
	"github.com/enboxorg/meshnet/ipn/store/mem"
	"github.com/enboxorg/meshnet/net/netmon"
	"github.com/enboxorg/meshnet/net/tsdial"
	"github.com/enboxorg/meshnet/tsd"
	"github.com/enboxorg/meshnet/types/logid"
	"github.com/enboxorg/meshnet/types/logger"
	"github.com/enboxorg/meshnet/wgengine"
	"github.com/enboxorg/meshnet/wgengine/netstack"
)

// Engine orchestrates the full dwn-mesh stack:
//   - DWNClient reads mesh state from DWN records
//   - Converter transforms it into meshnet NetworkMap
//   - meshnet's LocalBackend runs WireGuard with the DWN-backed control client
//
// Engine is the core of `dwn-mesh up`.
type Engine struct {
	dwnClient       *control.DWNClient
	converter       *Converter
	backend         *ipnlocal.LocalBackend
	sys             *tsd.System
	netMon          *netmon.Monitor
	dialer          *tsdial.Dialer
	ns              *netstack.Impl
	autoKeyDelivery *AutoKeyDelivery
	logger          *slog.Logger

	mu      sync.Mutex
	running bool
	cancel  context.CancelFunc
}

// Config holds the configuration for creating an Engine.
type Config struct {
	// AnchorEndpoint is the DWN server URL for the network anchor.
	AnchorEndpoint string

	// AnchorTenant is the DID of the anchor DWN (network creator's DID).
	AnchorTenant string

	// NetworkRecordID is the record ID of the network root record.
	NetworkRecordID string

	// SelfDID is this node's DID URI.
	SelfDID string

	// Signer signs DWN messages for this node.
	Signer *dwn.Signer

	// Resolver resolves peer DIDs to discover their DWN endpoints and keys.
	// If nil, peer DID resolution is disabled.
	Resolver control.Resolver

	// Domain is the mesh domain name for DNS.
	Domain string

	// MagicDNSSuffix overrides the default "mesh.local" DNS suffix.
	MagicDNSSuffix string

	// ListenPort is the WireGuard UDP port. 0 = auto-select.
	ListenPort uint16

	// PollInterval is how often to re-read DWN state. Default: 30s.
	PollInterval time.Duration

	// EncryptionKeyManager manages derived encryption keys for decrypting
	// protocol records. If nil, encrypted records cannot be read.
	EncryptionKeyManager *dwncrypto.EncryptionKeyManager

	// AutoKeyDelivery enables automatic context key delivery to new members.
	// Only active when this node is the anchor and has the root private key.
	// If nil, auto delivery is disabled.
	AutoKeyDelivery *AutoKeyDelivery

	// Logger is the structured logger. Nil = default.
	Logger *slog.Logger
}

// New creates a new Engine from the given config.
//
// Call [Engine.Start] to bring up the WireGuard tunnel, and [Engine.Stop] to
// tear it down. The engine is safe for concurrent use.
func New(cfg Config) (*Engine, error) {
	if cfg.AnchorEndpoint == "" {
		return nil, fmt.Errorf("AnchorEndpoint is required")
	}
	if cfg.AnchorTenant == "" {
		return nil, fmt.Errorf("AnchorTenant is required")
	}
	if cfg.NetworkRecordID == "" {
		return nil, fmt.Errorf("NetworkRecordID is required")
	}
	if cfg.SelfDID == "" {
		return nil, fmt.Errorf("SelfDID is required")
	}
	if cfg.Signer == nil {
		return nil, fmt.Errorf("Signer is required")
	}

	l := cfg.Logger
	if l == nil {
		l = slog.Default()
	}

	pollInterval := cfg.PollInterval
	if pollInterval == 0 {
		pollInterval = 30 * time.Second
	}

	magicDNS := cfg.MagicDNSSuffix
	if magicDNS == "" {
		magicDNS = "mesh.local"
	}

	domain := cfg.Domain
	if domain == "" {
		domain = "dwn-mesh"
	}

	// Create the DWN control client that reads mesh state.
	controlOpts := []control.Option{control.WithLogger(l)}
	if cfg.Resolver != nil {
		controlOpts = append(controlOpts, control.WithResolver(cfg.Resolver))
	}
	if cfg.EncryptionKeyManager != nil {
		controlOpts = append(controlOpts, control.WithEncryptionKeyManager(cfg.EncryptionKeyManager))
	}
	dwnClient := control.NewDWNClient(
		cfg.AnchorEndpoint,
		cfg.AnchorTenant,
		cfg.NetworkRecordID,
		cfg.SelfDID,
		cfg.Signer,
		controlOpts...,
	)

	// Create the converter that bridges dwn-mesh types to meshnet types.
	converter := NewConverter(domain, WithConverterLogger(l))
	converter.MagicDNSSuffix = magicDNS

	// Create the meshnet system container.
	sys := tsd.NewSystem()
	sys.Set(&mem.Store{})

	// Logging adapter: meshnet uses printf-style logging.
	logf := slogToLogf(l)

	// Create network monitor for detecting connectivity changes.
	nm, err := netmon.New(sys.Bus.Get(), logf)
	if err != nil {
		return nil, fmt.Errorf("creating network monitor: %w", err)
	}

	// Create the dialer that routes through netstack.
	dial := &tsdial.Dialer{Logf: logf}
	dial.SetBus(sys.Bus.Get())

	// Create the real userspace WireGuard engine.
	// Tun: nil triggers fake-TUN mode — no real TUN device, no root required.
	// magicsock is still real: UDP hole punching, DERP relay, STUN all work.
	eng, err := wgengine.NewUserspaceEngine(logf, wgengine.Config{
		Tun:           nil, // fake TUN; netstack handles all packets in userspace
		EventBus:      sys.Bus.Get(),
		ListenPort:    cfg.ListenPort,
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

	// Create netstack — gVisor userspace TCP/IP stack that processes all
	// WireGuard tunnel packets without needing a real TUN device.
	ns, err := netstack.Create(
		logf,
		sys.Tun.Get(),      // the tstun.Wrapper created by the engine
		eng,                 // wgengine.Engine
		sys.MagicSock.Get(), // magicsock.Conn for direct connections
		dial,                // tsdial.Dialer
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

	// With fake TUN (no real device), netstack handles everything:
	// - ProcessLocalIPs: packets destined for our mesh IP
	// - ProcessSubnets: packets destined for other mesh nodes
	ns.ProcessLocalIPs = true
	ns.ProcessSubnets = true

	// Wire the dialer through netstack so outbound connections from the
	// dwn-mesh process go through the WireGuard tunnel.
	dial.UseNetstackForIP = func(ip netip.Addr) bool {
		_, ok := eng.PeerForIP(ip)
		return ok
	}
	dial.NetstackDialTCP = func(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
		return ns.DialContextTCP(ctx, dst)
	}

	// Create the LocalBackend.
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

	// Start netstack with the LocalBackend so it can resolve peer IPs.
	if err := ns.Start(lb); err != nil {
		lb.Shutdown()
		eng.Close()
		nm.Close()
		return nil, fmt.Errorf("starting netstack: %w", err)
	}

	// Wire the DWN control client into the LocalBackend.
	// MapResponseFunc closes over our DWNClient and Converter to produce
	// NetworkMaps from DWN records. If auto key delivery is configured,
	// it also triggers key delivery to new members after each poll.
	mapFn := MapResponseFunc(dwnClient, converter, cfg.AutoKeyDelivery)
	dwnControlConfig := &controlclient.DWNControlConfig{
		MapResponseFunc: mapFn,
		PollInterval:    pollInterval,
		Logf:            logf,
	}
	lb.SetControlClientGetterForTesting(
		controlclient.NewDWNControlFactory(dwnControlConfig),
	)

	return &Engine{
		dwnClient:       dwnClient,
		converter:       converter,
		backend:         lb,
		sys:             sys,
		netMon:          nm,
		dialer:          dial,
		ns:              ns,
		autoKeyDelivery: cfg.AutoKeyDelivery,
		logger:          l,
	}, nil
}

// Start brings up the WireGuard tunnel.
//
// It starts the meshnet LocalBackend, which will:
//  1. Call the DWN MapResponseFunc to load initial mesh state
//  2. Configure WireGuard peers from the NetworkMap
//  3. Begin polling DWN for state changes
func (e *Engine) Start(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.running {
		return fmt.Errorf("engine already running")
	}

	_, cancel := context.WithCancel(ctx)
	e.cancel = cancel

	e.logger.InfoContext(ctx, "starting dwn-mesh engine")

	err := e.backend.Start(ipn.Options{
		UpdatePrefs: &ipn.Prefs{
			WantRunning: true,
		},
	})
	if err != nil {
		cancel()
		return fmt.Errorf("starting backend: %w", err)
	}

	e.running = true
	e.logger.InfoContext(ctx, "dwn-mesh engine started")
	return nil
}

// Stop tears down the WireGuard tunnel and releases all resources.
func (e *Engine) Stop() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if !e.running {
		return nil
	}

	e.logger.Info("stopping dwn-mesh engine")

	if e.cancel != nil {
		e.cancel()
	}

	// Shutdown order matters: backend first (stops control polling),
	// then network monitor.
	e.backend.Shutdown()

	if e.netMon != nil {
		e.netMon.Close()
	}

	e.running = false
	e.logger.Info("dwn-mesh engine stopped")
	return nil
}

// Running reports whether the engine is currently active.
func (e *Engine) Running() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.running
}

// Backend returns the underlying meshnet LocalBackend for advanced use.
// Most callers should use the Engine methods instead.
func (e *Engine) Backend() *ipnlocal.LocalBackend {
	return e.backend
}

// slogToLogf adapts a *slog.Logger to meshnet's printf-style logger.Logf.
func slogToLogf(l *slog.Logger) logger.Logf {
	if l == nil {
		l = slog.Default()
	}
	return func(format string, args ...any) {
		msg := fmt.Sprintf(format, args...)
		l.Debug(msg, slog.String("source", "meshnet"))
	}
}

// init registers the slogToLogf adapter.
func init() {
	// Suppress the default log.Printf prefix when meshnet logs through us.
	log.SetFlags(0)
}
