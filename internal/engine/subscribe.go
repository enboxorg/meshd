// Package engine — subscription watcher for real-time DWN updates.
//
// Instead of polling every 30 seconds, the SubscriptionWatcher opens a
// WebSocket subscription to the anchor DWN and triggers an immediate
// re-poll whenever mesh records change (nodeInfo, endpoints, members).
//
// The watcher subscribes to all records under the wireguard-mesh protocol
// within the network's contextId. When an event arrives, it calls
// DWNControl.Notify() which wakes the poll loop for an immediate
// loadAndPush cycle.
package engine

import (
	"context"
	"log/slog"
	"sync"

	"github.com/enboxorg/meshd/internal/dwn"
)

// SubscriptionWatcher subscribes to DWN record changes and triggers
// engine re-polls via DWNControl.Notify().
//
// This replaces pure 30-second polling with event-driven updates,
// reducing peer discovery latency from up to 30s to near-instant.
// The poll timer remains as a fallback for missed events.
type SubscriptionWatcher struct {
	endpoint        string
	anchorTenant    string
	networkRecordID string
	signer          *dwn.Signer
	logger          *slog.Logger

	mu      sync.Mutex
	manager *dwn.SubscriptionManager
	cancel  context.CancelFunc
	done    chan struct{}

	// dwnControl is set via the OnCreated callback from DWNControlConfig.
	// It's nil until the control client is created by the LocalBackend.
	controlMu  sync.Mutex
	dwnControl *DWNControl
}

// SubscriptionWatcherConfig holds the configuration for creating a
// SubscriptionWatcher.
type SubscriptionWatcherConfig struct {
	// AnchorEndpoint is the DWN server URL.
	AnchorEndpoint string

	// AnchorTenant is the DID of the anchor DWN owner.
	AnchorTenant string

	// NetworkRecordID is the contextId for the network.
	NetworkRecordID string

	// Signer signs subscription requests.
	Signer *dwn.Signer

	// Logger is the structured logger.
	Logger *slog.Logger
}

// NewSubscriptionWatcher creates a new watcher but does not start it.
// Call Start() to begin subscribing.
func NewSubscriptionWatcher(cfg SubscriptionWatcherConfig) *SubscriptionWatcher {
	l := cfg.Logger
	if l == nil {
		l = slog.Default()
	}

	return &SubscriptionWatcher{
		endpoint:        cfg.AnchorEndpoint,
		anchorTenant:    cfg.AnchorTenant,
		networkRecordID: cfg.NetworkRecordID,
		signer:          cfg.Signer,
		logger:          l.With(slog.String("component", "subscription-watcher")),
	}
}

// SetDWNControl is called by the DWNControlConfig.OnCreated callback
// to provide the DWNControl reference for triggering Notify().
func (w *SubscriptionWatcher) SetDWNControl(cc *DWNControl) {
	w.controlMu.Lock()
	defer w.controlMu.Unlock()
	w.dwnControl = cc
}

// notify triggers an immediate re-poll on the DWNControl if available.
func (w *SubscriptionWatcher) notify() {
	w.controlMu.Lock()
	cc := w.dwnControl
	w.controlMu.Unlock()

	if cc != nil {
		cc.Notify()
	}
}

// Start begins subscribing to DWN record changes. It subscribes to all
// records under the wireguard-mesh protocol within the network context.
//
// The subscription automatically reconnects on failure (handled by
// SubscriptionManager). When any record changes, it triggers an
// immediate engine re-poll.
func (w *SubscriptionWatcher) Start(ctx context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.cancel != nil {
		return nil // already started
	}

	subCtx, cancel := context.WithCancel(ctx)
	w.cancel = cancel
	w.done = make(chan struct{})

	w.manager = dwn.NewSubscriptionManager(w.endpoint, w.logger)

	// Subscribe to all records under the wireguard-mesh protocol for
	// this network. This catches nodeInfo, endpoint, member, and relay
	// record changes in a single subscription.
	filter := dwn.RecordsFilter{
		Protocol:  "https://enbox.org/protocols/wireguard-mesh",
		ContextID: w.networkRecordID,
	}

	handler := func(event *dwn.SubscriptionMessage) {
		if event == nil {
			return
		}

		switch event.Type {
		case "event":
			w.logger.Debug("DWN record changed, triggering re-poll",
				slog.String("cursor", event.Cursor),
			)
			w.notify()
		case "eose":
			// End-of-stored-events: initial backfill is done.
			// No action needed — the poll loop already loaded initial state.
			w.logger.Debug("subscription caught up to live events")
		}
	}

	_, err := w.manager.Subscribe(
		subCtx,
		w.anchorTenant,
		w.signer,
		filter,
		handler,
	)
	if err != nil {
		cancel()
		w.cancel = nil
		return err
	}

	w.logger.Info("subscription watcher started",
		slog.String("endpoint", w.endpoint),
		slog.String("network", w.networkRecordID),
	)

	// Monitor context cancellation to close the done channel.
	go func() {
		<-subCtx.Done()
		w.manager.CloseAll()
		close(w.done)
	}()

	return nil
}

// Stop cancels all subscriptions and waits for cleanup.
func (w *SubscriptionWatcher) Stop() {
	w.mu.Lock()
	cancel := w.cancel
	done := w.done
	w.cancel = nil
	w.mu.Unlock()

	if cancel != nil {
		cancel()
		if done != nil {
			<-done
		}
	}

	w.logger.Info("subscription watcher stopped")
}
