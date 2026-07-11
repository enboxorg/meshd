// Package engine — DWN-backed control client for meshnet.
//
// DWNControl replaces Tailscale's HTTP-based control plane with a generic
// callback-driven control client. The networking engine (WireGuard, magicsock,
// DERP) doesn't know or care where the NetworkMap comes from — it just
// receives Status updates via the Observer interface.
//
// This was previously in the meshnet vendor tree (controlclient/dwn.go) but
// moved here because meshnet shouldn't know about DWN. All the types it
// depends on (Client, Observer, Options, Status) are exported from meshnet.
package engine

import (
	"context"
	"fmt"
	"log"
	"math/rand/v2"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/enboxorg/meshnet/control/controlclient"
	"github.com/enboxorg/meshnet/tailcfg"
	"github.com/enboxorg/meshnet/types/key"
	"github.com/enboxorg/meshnet/types/logger"
	"github.com/enboxorg/meshnet/types/netmap"
	"github.com/enboxorg/meshnet/types/persist"
)

// DWNControlConfig holds the configuration for a DWN-backed control client.
//
// Instead of talking to a centralized Tailscale control plane, this client
// reads mesh state from DWN records and constructs NetworkMap snapshots.
type DWNControlConfig struct {
	// MapResponseFunc is called to obtain the current network state.
	// The DWN control integration implements this by reading DWN records
	// and building a NetworkMap.
	//
	// Calls are serialized and coalesced by RefreshCoordinator.
	MapResponseFunc func(ctx context.Context) (*netmap.NetworkMap, error)

	// OnMapResult observes every completed map load. It is called after the
	// control-client observer has received the result, and is useful for
	// reconciling host routing readiness with the exact map that was loaded.
	// A nil map and nil error means the load completed without usable state.
	OnMapResult func(ctx context.Context, nm *netmap.NetworkMap, err error)

	// EndpointUpdateFunc is called when magicsock discovers new endpoints
	// (via STUN, local interface enumeration, etc). The implementation
	// should write these back to the anchor DWN so peers can discover
	// this node's reachable addresses.
	//
	// If nil, endpoint updates are not published.
	EndpointUpdateFunc func(ctx context.Context, endpoints []tailcfg.Endpoint)

	// PollInterval is the fallback reconciliation interval while authoritative
	// subscription coverage is incomplete or unhealthy. Default: 30 seconds.
	PollInterval time.Duration

	// HealthyPollInterval is the slow anti-entropy interval while topology and
	// delivery streams are both live and repaired. Default: 5 minutes.
	HealthyPollInterval time.Duration

	// RefreshTimeout bounds one complete DWN state rebuild. Default: 2 minutes.
	RefreshTimeout time.Duration

	// StartupSubscriptionWait gives asynchronous subscription handshakes a
	// bounded chance to establish before the initial full rebuild.
	StartupSubscriptionWait time.Duration

	// NodePrivateKey, if set, overrides the auto-generated WireGuard node
	// key with the given key. This is essential when the WireGuard key has
	// already been published to a coordination store (e.g. DWN records) and
	// the engine must use the same key so peers can route to it.
	NodePrivateKey key.NodePrivate

	// DiscoKeyRegistry, if set, is used to publish this node's disco key and
	// to look up peer disco keys. When magicsock generates a disco key,
	// DWNControl publishes it via SetDisco. When building network maps, the
	// MapResponseFunc should call GetDisco on peers to populate their disco
	// keys, enabling DERP relay and hole punching.
	//
	// If nil, disco keys are not exchanged and peers must use WireGuardOnly
	// mode (direct endpoints only, no DERP relay).
	DiscoKeyRegistry DiscoKeyRegistry

	// OnCreated is called after the DWNControl instance is created but
	// before the poll loop starts. This lets the caller capture a reference
	// to the DWNControl for calling Notify() from subscription handlers.
	//
	// If nil, no callback is made.
	OnCreated func(cc *DWNControl)

	// Logf is the logging function. If nil, log.Printf is used.
	Logf logger.Logf
}

// DiscoKeyRegistry enables disco key exchange between DWN-backed engines.
// In normal Tailscale, the control server distributes disco keys. In DWN mode,
// this registry fills that role.
type DiscoKeyRegistry interface {
	// SetDisco publishes the disco key for a node (identified by its public key).
	SetDisco(nodeKey key.NodePublic, disco key.DiscoPublic)
	// GetDisco returns the disco key for a node, or a zero key if unknown.
	GetDisco(nodeKey key.NodePublic) key.DiscoPublic
}

// DWNControl is a controlclient.Client backed by DWN records.
//
// It replaces Tailscale's HTTP-based control plane with a DWN-based one.
// The networking engine (WireGuard, magicsock, DERP) doesn't know or care
// where the NetworkMap comes from — it just receives Status updates via
// the Observer interface, same as with the upstream Auto client.
//
// Usage:
//
//	config := &engine.DWNControlConfig{
//	    MapResponseFunc: myDWNMapFunc,
//	    PollInterval:    30 * time.Second,
//	}
//	factory := engine.NewDWNControlFactory(config)
//	localBackend.SetControlClientGetterForTesting(factory)
type DWNControl struct {
	config   DWNControlConfig
	observer controlclient.Observer
	persist  *persist.Persist
	logf     logger.Logf
	clientID int64

	mu                sync.Mutex
	disco             key.DiscoPublic
	shutdownOnce      sync.Once
	cancel            context.CancelFunc
	coordinator       *RefreshCoordinator
	initialMapApplied atomic.Bool
}

// NewDWNControlFactory returns a factory function suitable for
// LocalBackend.SetControlClientGetterForTesting.
//
// This is the main entry point for wiring DWN-based control into meshnet.
func NewDWNControlFactory(config *DWNControlConfig) func(controlclient.Options) (controlclient.Client, error) {
	return func(opts controlclient.Options) (controlclient.Client, error) {
		return NewDWNControl(config, opts)
	}
}

// NewDWNControl creates a new DWN-backed control client.
func NewDWNControl(config *DWNControlConfig, opts controlclient.Options) (*DWNControl, error) {
	if config == nil {
		return nil, fmt.Errorf("DWN control config is required")
	}
	if config.MapResponseFunc == nil {
		return nil, fmt.Errorf("DWN control map response function is required")
	}
	if config.RefreshTimeout < 0 || config.StartupSubscriptionWait < 0 {
		return nil, fmt.Errorf("DWN control timeouts must not be negative")
	}
	logf := config.Logf
	if logf == nil {
		logf = log.Printf
	}

	pollInterval := config.PollInterval
	if pollInterval == 0 {
		pollInterval = 30 * time.Second
	}
	healthyPollInterval := config.HealthyPollInterval
	if healthyPollInterval == 0 {
		healthyPollInterval = 5 * time.Minute
	}
	refreshTimeout := config.RefreshTimeout
	if refreshTimeout == 0 {
		refreshTimeout = 2 * time.Minute
	}

	p := opts.Persist.Clone()
	if p == nil {
		p = &persist.Persist{}
	}

	// Use the provided WireGuard key if set, otherwise generate one.
	if !config.NodePrivateKey.IsZero() {
		logf("dwn-control: using provided WireGuard node key")
		p.PrivateNodeKey = config.NodePrivateKey
	} else if p.PrivateNodeKey.IsZero() {
		logf("dwn-control: generating new node key")
		p.PrivateNodeKey = key.NewNode()
	}

	ctx, cancel := context.WithCancel(context.Background())

	cc := &DWNControl{
		config: DWNControlConfig{
			MapResponseFunc:         config.MapResponseFunc,
			OnMapResult:             config.OnMapResult,
			EndpointUpdateFunc:      config.EndpointUpdateFunc,
			PollInterval:            pollInterval,
			HealthyPollInterval:     healthyPollInterval,
			RefreshTimeout:          refreshTimeout,
			StartupSubscriptionWait: config.StartupSubscriptionWait,
			NodePrivateKey:          config.NodePrivateKey,
			DiscoKeyRegistry:        config.DiscoKeyRegistry,
			Logf:                    logf,
		},
		observer: opts.Observer,
		persist:  p,
		logf:     logf,
		clientID: rand.Int64(),
		cancel:   cancel,
	}
	coordinator, err := NewRefreshCoordinator(RefreshCoordinatorConfig{
		Refresh:          cc.refreshControlState,
		FallbackInterval: pollInterval,
		HealthyInterval:  healthyPollInterval,
		RetryBackoff:     time.Second,
		Debounce:         250 * time.Millisecond,
		MaxDebounce:      time.Second,
		MaxRetryBackoff:  time.Minute,
	})
	if err != nil {
		cancel()
		return nil, err
	}
	cc.coordinator = coordinator

	cc.disco = opts.DiscoPublicKey

	// Publish the initial disco key to the registry so peers can discover
	// it immediately. In normal Tailscale, the control server distributes
	// disco keys. In DWN mode, the registry fills that role.
	// SetDiscoPublicKey is only called on explicit key rotation, so we
	// must publish the initial key here.
	if !cc.disco.IsZero() && cc.config.DiscoKeyRegistry != nil {
		cc.config.DiscoKeyRegistry.SetDisco(cc.persist.PrivateNodeKey.Public(), cc.disco)
		logf("dwn-control: published initial disco key %s for nodeKey %s", cc.disco.ShortString(), cc.persist.PrivateNodeKey.Public().ShortString())
	}

	// Notify the caller so it can capture a reference for calling Notify().
	if config.OnCreated != nil {
		config.OnCreated(cc)
	}

	if !opts.SkipStartForTests {
		go cc.pollLoop(ctx)
	}

	return cc, nil
}

// pollLoop gives the LocalBackend event bus time to initialize, then starts
// the single-owner refresh coordinator.
func (cc *DWNControl) pollLoop(ctx context.Context) {
	select {
	case <-ctx.Done():
		return
	case <-time.After(50 * time.Millisecond):
	}
	cc.waitForStartupSubscriptions(ctx, cc.config.StartupSubscriptionWait)
	if err := cc.coordinator.Start(ctx); err != nil && ctx.Err() == nil {
		cc.logf("dwn-control: starting refresh coordinator: %v", err)
	}
}

func (cc *DWNControl) waitForStartupSubscriptions(ctx context.Context, maximum time.Duration) {
	if maximum <= 0 {
		return
	}
	deadline := time.NewTimer(maximum)
	defer deadline.Stop()
	poll := time.NewTicker(25 * time.Millisecond)
	defer poll.Stop()
	for {
		if refreshStreamsReadyForStartup(cc.coordinator.Health()) {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-deadline.C:
			return
		case <-poll.C:
		}
	}
}

func refreshStreamsReadyForStartup(health RefreshCoordinatorHealth) bool {
	covered := 0
	for _, stream := range []RefreshStream{RefreshStreamTopology, RefreshStreamDelivery} {
		state := health.Streams[stream]
		if !state.Covered {
			continue
		}
		covered++
		if !state.Live {
			return false
		}
	}
	return covered > 0
}

// refreshControlState performs one bounded remote rebuild. The first usable
// map is applied locally a second time after the event bus has observed its peer
// views; this preserves the startup ordering workaround without a second DWN load.
func (cc *DWNControl) refreshControlState(ctx context.Context, _ RefreshBatch) error {
	refreshCtx := ctx
	cancel := func() {}
	if cc.config.RefreshTimeout > 0 {
		refreshCtx, cancel = context.WithTimeout(ctx, cc.config.RefreshTimeout)
	}
	defer cancel()

	replay, err := cc.loadAndPush(refreshCtx)
	if err != nil {
		return err
	}
	if replay == nil || !cc.initialMapApplied.CompareAndSwap(false, true) || cc.observer == nil {
		return nil
	}
	if !waitForRefreshContext(ctx, 200*time.Millisecond) {
		return ctx.Err()
	}
	cc.pushNetMap(replay)
	return nil
}

// loadAndPush reads DWN state, applies it once, and returns an observer-safe
// clone for the one-time startup replay.
func (cc *DWNControl) loadAndPush(ctx context.Context) (*netmap.NetworkMap, error) {
	if cc.config.MapResponseFunc == nil {
		cc.logf("dwn-control: no MapResponseFunc configured")
		return nil, nil
	}

	nm, err := cc.config.MapResponseFunc(ctx)
	if err != nil {
		cc.logf("dwn-control: MapResponseFunc error: %v", err)
		if cc.observer != nil {
			cc.observer.SetControlClientStatus(cc, controlclient.Status{
				Err:     err,
				Persist: cc.persist.View(),
			})
		}
		if cc.config.OnMapResult != nil {
			cc.config.OnMapResult(ctx, nil, err)
		}
		return nil, err
	}

	if nm == nil {
		if cc.config.OnMapResult != nil {
			cc.config.OnMapResult(ctx, nil, nil)
		}
		return nil, nil
	}

	cc.prepareNetMap(nm)
	replay := cloneNetMapForReplay(nm)
	cc.pushNetMap(nm)
	if cc.config.OnMapResult != nil {
		cc.config.OnMapResult(ctx, nm, nil)
	}
	return replay, nil
}

func (cc *DWNControl) prepareNetMap(nm *netmap.NetworkMap) {
	nm.NodeKey = cc.persist.PrivateNodeKey.Public()
	if cc.config.DiscoKeyRegistry == nil {
		return
	}
	cc.mu.Lock()
	selfDisco := cc.disco
	cc.mu.Unlock()
	if !selfDisco.IsZero() && nm.SelfNode.Valid() {
		sn := nm.SelfNode.AsStruct()
		sn.DiscoKey = selfDisco
		nm.SelfNode = sn.View()
	}
	for i, peer := range nm.Peers {
		if peer.Key().IsZero() {
			continue
		}
		disco := cc.config.DiscoKeyRegistry.GetDisco(peer.Key())
		if disco.IsZero() {
			continue
		}
		copy := peer.AsStruct()
		copy.DiscoKey = disco
		nm.Peers[i] = copy.View()
	}
}

func (cc *DWNControl) pushNetMap(nm *netmap.NetworkMap) {
	if cc.observer == nil || nm == nil {
		return
	}
	cc.observer.SetControlClientStatus(cc, controlclient.Status{
		LoggedIn:  true,
		InMapPoll: true,
		NetMap:    nm,
		Persist:   cc.persist.View(),
	})
}

func cloneNetMapForReplay(nm *netmap.NetworkMap) *netmap.NetworkMap {
	if nm == nil {
		return nil
	}
	clone := *nm
	clone.Peers = slices.Clone(nm.Peers)
	return &clone
}

func waitForRefreshContext(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// Notify records a manual invalidation without blocking the caller.
func (cc *DWNControl) Notify() {
	cc.coordinator.Notify(RefreshReasonManual)
}

// RefreshHealth returns a deep-copied view of refresh scheduling and stream health.
func (cc *DWNControl) RefreshHealth() RefreshCoordinatorHealth {
	return cc.coordinator.Health()
}

//
// --- controlclient.Client interface ---
//

func (cc *DWNControl) Shutdown() {
	cc.shutdownOnce.Do(func() {
		cc.cancel()
		cc.coordinator.Stop()
	})
}

func (cc *DWNControl) Login(flags controlclient.LoginFlags) {
	// DWN has no interactive login. The coordinator always queues startup, so
	// treating LocalBackend login feedback as another invalidation would cause
	// a redundant rebuild after every successful map application.
}

func (cc *DWNControl) Logout(ctx context.Context) error {
	// DWN-based control doesn't have a server-side session to revoke.
	if cc.observer != nil {
		cc.observer.SetControlClientStatus(cc, controlclient.Status{
			Persist: cc.persist.View(),
		})
	}
	return nil
}

func (cc *DWNControl) SetPaused(paused bool) {
	cc.coordinator.SetPaused(paused)
}

func (cc *DWNControl) AuthCantContinue() bool {
	// DWN doesn't have an interactive auth flow.
	return false
}

func (cc *DWNControl) SetHostinfo(hi *tailcfg.Hostinfo) {
	// Not used in DWN-based control. Hostinfo is derived from the node record.
}

func (cc *DWNControl) SetNetInfo(ni *tailcfg.NetInfo) {
	// Not used in DWN-based control. NetInfo is part of local state.
}

func (cc *DWNControl) SetTKAHead(headHash string) {
	// TKA (Tailnet Key Authority) is not used in DWN-based control.
}

func (cc *DWNControl) UpdateEndpoints(endpoints []tailcfg.Endpoint) {
	if cc.config.EndpointUpdateFunc != nil {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			cc.config.EndpointUpdateFunc(ctx, endpoints)
			// Coalesce the local write with its subscription echo.
			cc.coordinator.Notify(RefreshReasonEndpoint)
		}()
	}
}

func (cc *DWNControl) SetDiscoPublicKey(k key.DiscoPublic) {
	cc.mu.Lock()
	cc.disco = k
	cc.mu.Unlock()

	// Publish disco key so peers can discover it.
	if cc.config.DiscoKeyRegistry != nil {
		cc.config.DiscoKeyRegistry.SetDisco(cc.persist.PrivateNodeKey.Public(), k)
		cc.logf("dwn-control: published disco key %s for nodeKey %s", k.ShortString(), cc.persist.PrivateNodeKey.Public().ShortString())
	}
}

func (cc *DWNControl) ClientID() int64 {
	return cc.clientID
}

// Compile-time assertion that DWNControl implements controlclient.Client.
var _ controlclient.Client = (*DWNControl)(nil)
