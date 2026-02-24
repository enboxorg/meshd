// Copyright (c) Enbox contributors
// SPDX-License-Identifier: BSD-3-Clause

package controlclient

import (
	"context"
	"log"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"time"

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
	// The DWN control integration (in dwn-mesh) implements this by
	// reading DWN records and building a NetworkMap.
	//
	// This is called:
	//   - Once on Login (initial state load)
	//   - Periodically at PollInterval
	//   - When explicitly triggered via Notify()
	MapResponseFunc func(ctx context.Context) (*netmap.NetworkMap, error)

	// EndpointUpdateFunc is called when magicsock discovers new endpoints
	// (via STUN, local interface enumeration, etc). The DWN control
	// integration should write these back to the anchor DWN so peers
	// can discover this node's reachable addresses.
	//
	// If nil, endpoint updates are not published.
	EndpointUpdateFunc func(ctx context.Context, endpoints []tailcfg.Endpoint)

	// PollInterval is how often to re-read DWN state.
	// Default: 30 seconds.
	PollInterval time.Duration

	// Logf is the logging function. If nil, log.Printf is used.
	Logf logger.Logf
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
//	config := &controlclient.DWNControlConfig{
//	    MapResponseFunc: myDWNMapFunc,
//	    PollInterval:    30 * time.Second,
//	}
//	factory := controlclient.NewDWNControlFactory(config)
//	localBackend.SetControlClientGetterForTesting(factory)
type DWNControl struct {
	config   DWNControlConfig
	observer Observer
	persist  *persist.Persist
	logf     logger.Logf
	clientID int64

	mu       sync.Mutex
	hostinfo *tailcfg.Hostinfo
	netinfo  *tailcfg.NetInfo
	disco    key.DiscoPublic
	endpoints []tailcfg.Endpoint
	paused   atomic.Bool
	shutdown chan struct{}
	cancel   context.CancelFunc
	notify   chan struct{} // signal to re-poll immediately
}

// NewDWNControlFactory returns a factory function suitable for
// LocalBackend.SetControlClientGetterForTesting.
//
// This is the main entry point for wiring DWN-based control into meshnet.
func NewDWNControlFactory(config *DWNControlConfig) func(Options) (Client, error) {
	return func(opts Options) (Client, error) {
		return NewDWNControl(config, opts)
	}
}

// NewDWNControl creates a new DWN-backed control client.
func NewDWNControl(config *DWNControlConfig, opts Options) (*DWNControl, error) {
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

	// Ensure we have a node key.
	if p.PrivateNodeKey.IsZero() {
		logf("dwn-control: generating new node key")
		p.PrivateNodeKey = key.NewNode()
	}

	ctx, cancel := context.WithCancel(context.Background())

	cc := &DWNControl{
		config: DWNControlConfig{
			MapResponseFunc: config.MapResponseFunc,
			PollInterval:    pollInterval,
			Logf:            logf,
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

	if !opts.SkipStartForTests {
		go cc.pollLoop(ctx)
	}

	return cc, nil
}

// pollLoop periodically reads DWN state and pushes NetworkMap updates.
func (cc *DWNControl) pollLoop(ctx context.Context) {
	// Initial login: load state and report logged-in.
	cc.loadAndPush(ctx, true)

	ticker := time.NewTicker(cc.config.PollInterval)
	defer ticker.Stop()

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
		case <-cc.notify:
			if cc.paused.Load() {
				continue
			}
			cc.loadAndPush(ctx, false)
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
			cc.observer.SetControlClientStatus(cc, Status{
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

	if cc.observer != nil {
		s := Status{
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

func (cc *DWNControl) Login(flags LoginFlags) {
	// DWN doesn't need interactive login — the DID is the identity.
	// Trigger an immediate state load which will report LoggedIn.
	cc.Notify()
}

func (cc *DWNControl) Logout(ctx context.Context) error {
	// DWN-based control doesn't have a server-side session to revoke.
	if cc.observer != nil {
		cc.observer.SetControlClientStatus(cc, Status{
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
	// TODO: publish disco key to DWN.
}

func (cc *DWNControl) ClientID() int64 {
	return cc.clientID
}

// Compile-time assertion that DWNControl implements Client.
var _ Client = (*DWNControl)(nil)
