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
	"log"
	"math/rand/v2"
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
	// This is called:
	//   - Once on Login (initial state load)
	//   - Periodically at PollInterval
	//   - When explicitly triggered via Notify()
	MapResponseFunc func(ctx context.Context) (*netmap.NetworkMap, error)

	// EndpointUpdateFunc is called when magicsock discovers new endpoints
	// (via STUN, local interface enumeration, etc). The implementation
	// should write these back to the anchor DWN so peers can discover
	// this node's reachable addresses.
	//
	// If nil, endpoint updates are not published.
	EndpointUpdateFunc func(ctx context.Context, endpoints []tailcfg.Endpoint)

	// PollInterval is how often to re-read DWN state.
	// Default: 30 seconds.
	PollInterval time.Duration

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

	mu        sync.Mutex
	hostinfo  *tailcfg.Hostinfo
	netinfo   *tailcfg.NetInfo
	disco     key.DiscoPublic
	endpoints []tailcfg.Endpoint
	paused    atomic.Bool
	shutdown  chan struct{}
	cancel    context.CancelFunc
	notify    chan struct{} // signal to re-poll immediately
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
	logf := config.Logf
	if logf == nil {
		logf = log.Printf
	}

	pollInterval := config.PollInterval
	if pollInterval == 0 {
		pollInterval = 30 * time.Second
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
			MapResponseFunc:    config.MapResponseFunc,
			EndpointUpdateFunc: config.EndpointUpdateFunc,
			PollInterval:       pollInterval,
			NodePrivateKey:     config.NodePrivateKey,
			DiscoKeyRegistry:   config.DiscoKeyRegistry,
			Logf:               logf,
		},
		observer: opts.Observer,
		persist:  p,
		logf:     logf,
		clientID: rand.Int64(),
		shutdown: make(chan struct{}),
		cancel:   cancel,
		notify:   make(chan struct{}, 1),
	}

	if opts.Hostinfo != nil {
		cc.hostinfo = opts.Hostinfo
	}
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

// pollLoop periodically reads DWN state and pushes NetworkMap updates.
func (cc *DWNControl) pollLoop(ctx context.Context) {
	// Brief startup delay to let the LocalBackend's event bus fully
	// initialize before we send the first NetworkMap. Without this, the
	// first SetControlClientStatus triggers authReconfigLocked which calls
	// Reconfig → ParseEndpoint before magicsock has processed the
	// NodeViewsUpdate event, causing "unknown peer" errors.
	select {
	case <-ctx.Done():
		return
	case <-time.After(50 * time.Millisecond):
	}

	// Initial login: load state and report logged-in.
	cc.loadAndPush(ctx, true)

	// Allow the event bus to propagate the initial NodeViewsUpdate to
	// magicsock before any subsequent Reconfig from the notify feedback
	// loop. The first loadAndPush publishes the netmap to the event bus
	// (via setNetMapLocked), but authReconfigLocked runs before magicsock
	// processes it. This sleep gives the event bus time to deliver.
	select {
	case <-ctx.Done():
		return
	case <-time.After(200 * time.Millisecond):
	}
	// Drain any queued notifications from the startup burst.
	select {
	case <-cc.notify:
	default:
	}
	// Re-push now that magicsock knows about our peers.
	cc.loadAndPush(ctx, false)

	ticker := time.NewTicker(cc.config.PollInterval)
	defer ticker.Stop()

	// Minimum interval between polls to avoid a feedback loop where
	// SetControlClientStatus triggers Login/Notify, causing another
	// loadAndPush immediately.
	const minPollInterval = 250 * time.Millisecond
	lastPoll := time.Now()

	for {
		select {
		case <-ctx.Done():
			return
		case <-cc.shutdown:
			return
		case <-ticker.C:
			if cc.paused.Load() {
				continue
			}
			cc.loadAndPush(ctx, false)
			lastPoll = time.Now()
		case <-cc.notify:
			if cc.paused.Load() {
				continue
			}
			// Debounce: ensure minimum interval between polls.
			if elapsed := time.Since(lastPoll); elapsed < minPollInterval {
				time.Sleep(minPollInterval - elapsed)
			}
			// Drain any queued notifications that accumulated during the sleep.
			select {
			case <-cc.notify:
			default:
			}
			cc.loadAndPush(ctx, false)
			lastPoll = time.Now()
		}
	}
}

// loadAndPush reads DWN state and pushes a Status to the observer.
func (cc *DWNControl) loadAndPush(ctx context.Context, loginFinished bool) {
	if cc.config.MapResponseFunc == nil {
		cc.logf("dwn-control: no MapResponseFunc configured")
		return
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
		return
	}

	if nm == nil {
		return
	}

	// Inject our node key into the NetworkMap.
	nm.NodeKey = cc.persist.PrivateNodeKey.Public()

	// If a disco key registry is available, inject disco keys into the
	// network map. This replaces the role of the Tailscale control server
	// which normally distributes disco keys to peers.
	if cc.config.DiscoKeyRegistry != nil {
		// Inject our own disco key into SelfNode.
		cc.mu.Lock()
		selfDisco := cc.disco
		cc.mu.Unlock()
		if !selfDisco.IsZero() && nm.SelfNode.Valid() {
			sn := nm.SelfNode.AsStruct()
			sn.DiscoKey = selfDisco
			nm.SelfNode = sn.View()
		}
		// Inject peer disco keys.
		for i, p := range nm.Peers {
			if !p.Key().IsZero() {
				dk := cc.config.DiscoKeyRegistry.GetDisco(p.Key())
				if !dk.IsZero() {
					ps := p.AsStruct()
					ps.DiscoKey = dk
					nm.Peers[i] = ps.View()
				}
			}
		}
	}

	if cc.observer != nil {
		s := controlclient.Status{
			LoggedIn:  true,
			InMapPoll: true,
			NetMap:    nm,
			Persist:   cc.persist.View(),
		}
		cc.observer.SetControlClientStatus(cc, s)
	}
}

// Notify triggers an immediate re-read of DWN state.
// This is called by the DWN subscription handler when records change.
func (cc *DWNControl) Notify() {
	select {
	case cc.notify <- struct{}{}:
	default:
		// Already a pending notification.
	}
}

//
// --- controlclient.Client interface ---
//

func (cc *DWNControl) Shutdown() {
	cc.cancel()
	close(cc.shutdown)
}

func (cc *DWNControl) Login(flags controlclient.LoginFlags) {
	// DWN doesn't need interactive login — the DID is the identity.
	// Trigger an immediate state load which will report LoggedIn.
	cc.Notify()
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
	cc.paused.Store(paused)
	if !paused {
		// Unpause: trigger immediate refresh.
		cc.Notify()
	}
}

func (cc *DWNControl) AuthCantContinue() bool {
	// DWN doesn't have an interactive auth flow.
	return false
}

func (cc *DWNControl) SetHostinfo(hi *tailcfg.Hostinfo) {
	cc.mu.Lock()
	cc.hostinfo = hi
	cc.mu.Unlock()
	// TODO: publish hostinfo to DWN as a nodeInfo record update.
}

func (cc *DWNControl) SetNetInfo(ni *tailcfg.NetInfo) {
	cc.mu.Lock()
	cc.netinfo = ni
	cc.mu.Unlock()
	// TODO: publish netinfo to DWN.
}

func (cc *DWNControl) SetTKAHead(headHash string) {
	// TKA (Tailnet Key Authority) is not used in DWN-based control.
}

func (cc *DWNControl) UpdateEndpoints(endpoints []tailcfg.Endpoint) {
	cc.mu.Lock()
	cc.endpoints = endpoints
	cc.mu.Unlock()

	if cc.config.EndpointUpdateFunc != nil {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			cc.config.EndpointUpdateFunc(ctx, endpoints)
			// Trigger re-poll so peers pick up the new endpoints.
			cc.Notify()
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
