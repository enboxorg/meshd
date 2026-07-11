// Package engine — subscription watcher for real-time DWN updates.
//
// Instead of polling every 30 seconds, the SubscriptionWatcher opens a
// WebSocket subscription to the anchor DWN and triggers an immediate
// re-poll whenever mesh records change (nodes, endpoints).
//
// The watcher subscribes to all records under the wireguard-mesh protocol
// within the network's contextId. When an event arrives, it calls
// DWNControl.Notify() which wakes the poll loop for an immediate
// loadAndPush cycle.
package engine

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/enboxorg/meshd/internal/dwn"
	dwncrypto "github.com/enboxorg/meshd/internal/dwn/crypto"
	"github.com/enboxorg/meshd/protocols"
)

type subscriptionManager interface {
	SubscribeWithAuthAndLifecycle(
		context.Context,
		string,
		*dwn.Signer,
		dwn.RecordsFilter,
		dwn.MessageAuth,
		dwn.EventHandler,
		dwn.SubscriptionLifecycleHandler,
	) (*dwn.Subscription, error)
	CloseAll()
}

type subscriptionManagerFactory func(string, *slog.Logger) subscriptionManager

type subscriptionSourceState struct {
	live  bool
	dirty bool
}

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
	selfDID         string
	signer          *dwn.Signer
	readAuth        dwn.MessageAuth
	logger          *slog.Logger
	newManager      subscriptionManagerFactory

	mu      sync.Mutex
	manager subscriptionManager
	cancel  context.CancelFunc
	done    chan struct{}

	// dwnControl is set via the OnCreated callback from DWNControlConfig.
	// It's nil until the control client is created by the LocalBackend.
	controlMu  sync.Mutex
	dwnControl *DWNControl

	sourceMu sync.Mutex
	sources  map[string]subscriptionSourceState
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

	// SelfDID is the device DID. Delivery-key records addressed to this DID
	// are watched separately from the network-context subscription because
	// delivery records are scoped by tags rather than descriptor contextId.
	SelfDID string

	// Signer signs subscription requests.
	Signer *dwn.Signer

	// ReadAuth is the authorization used for control-plane record reads. Read
	// grants authorize RecordsSubscribe; a role-only reader needs path-scoped
	// subscriptions and therefore keeps polling for topology changes.
	ReadAuth dwn.MessageAuth

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
		selfDID:         cfg.SelfDID,
		signer:          cfg.Signer,
		readAuth:        cloneMessageAuth(cfg.ReadAuth),
		logger:          l.With(slog.String("component", "subscription-watcher")),
		newManager: func(endpoint string, logger *slog.Logger) subscriptionManager {
			return dwn.NewSubscriptionManager(endpoint, logger)
		},
		sources: make(map[string]subscriptionSourceState),
	}
}

func cloneMessageAuth(auth dwn.MessageAuth) dwn.MessageAuth {
	auth.DelegatedGrant = append([]byte(nil), auth.DelegatedGrant...)
	return auth
}

func broadSubscriptionAuth(readAuth dwn.MessageAuth) (dwn.MessageAuth, bool) {
	auth := cloneMessageAuth(readAuth)
	if auth.PermissionGrantID != "" || len(auth.DelegatedGrant) != 0 {
		// Grant authorization supplies the broad RecordsSubscribe permission;
		// invoking a protocol role as well would force path-scoped validation.
		auth.ProtocolRole = ""
		return auth, true
	}
	return auth, auth.ProtocolRole == ""
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

// handleSubscriptionMessage translates DWN events and lifecycle signals into
// cache invalidations. DWNControl.Notify coalesces repeated signals, so an EOSE
// following a burst of events schedules at most one additional refresh.
func (w *SubscriptionWatcher) handleSubscriptionMessage(source string, message *dwn.SubscriptionMessage) error {
	if message == nil {
		return nil
	}

	invalidates := false
	switch message.Type {
	case "event":
		w.logger.Debug("DWN record changed",
			slog.String("source", source),
			slog.Any("cursor", message.Cursor),
		)
		invalidates = true
	case "eose":
		// EOSE is only a replay barrier. A replayed event already marked the
		// source dirty; an empty replay must not force an expensive rebuild.
		w.logger.Debug("subscription caught up to live events",
			slog.String("source", source),
			slog.Any("cursor", message.Cursor),
		)
	case "error":
		w.logger.Warn("subscription reported an error",
			slog.String("source", source),
			slog.Any("cursor", message.Cursor),
			slog.Any("error", message.Error),
		)
		invalidates = true
	default:
		w.logger.Debug("ignoring unknown subscription message",
			slog.String("source", source),
			slog.String("type", message.Type),
		)
	}
	if invalidates && w.recordSourceInvalidation(source) {
		w.notify()
	}
	return nil
}

// recordSourceInvalidation marks replay frames dirty until their subscription
// is established. Once live, each frame invalidates immediately; DWNControl's
// size-one notify channel coalesces bursts.
func (w *SubscriptionWatcher) recordSourceInvalidation(source string) bool {
	w.sourceMu.Lock()
	defer w.sourceMu.Unlock()
	state := w.sources[source]
	if !state.live {
		state.dirty = true
		w.sources[source] = state
		return false
	}
	return true
}

func (w *SubscriptionWatcher) handleSubscriptionLifecycle(source string, event dwn.SubscriptionLifecycleEvent) {
	switch event.Kind {
	case dwn.SubscriptionLifecycleEstablished:
		w.logger.Debug("subscription established",
			slog.String("source", source),
			slog.Bool("needsFullRefresh", event.NeedsFullRefresh),
		)
		w.sourceMu.Lock()
		state := w.sources[source]
		shouldRefresh := event.NeedsFullRefresh || state.dirty
		state.live = true
		state.dirty = false
		w.sources[source] = state
		w.sourceMu.Unlock()
		if shouldRefresh {
			w.notify()
		}
	case dwn.SubscriptionLifecycleProgressGap:
		// Wait for the fresh replacement stream before rebuilding. This keeps
		// the subscribe-before-repair invariant and avoids racing cursor reset.
		w.logger.Warn("subscription progress gap; waiting for fresh stream",
			slog.String("source", source),
			slog.Any("gap", event.Gap),
		)
		w.markSourceNotLive(source)
	case dwn.SubscriptionLifecycleRetrying:
		// The periodic poll remains the fallback while the stream reconnects.
		w.logger.Debug("subscription retrying",
			slog.String("source", source),
			slog.Int("attempt", event.Attempt),
			slog.Any("error", event.Err),
		)
		w.markSourceNotLive(source)
	case dwn.SubscriptionLifecycleTerminal:
		w.logger.Warn("subscription terminated; triggering reconciliation before polling fallback",
			slog.String("source", source),
			slog.Any("error", event.Err),
		)
		w.markSourceNotLive(source)
		w.notify()
	default:
		w.logger.Debug("ignoring unknown subscription lifecycle event",
			slog.String("source", source),
			slog.String("kind", string(event.Kind)),
		)
	}
}

func (w *SubscriptionWatcher) markSourceNotLive(source string) {
	w.sourceMu.Lock()
	defer w.sourceMu.Unlock()
	state := w.sources[source]
	state.live = false
	w.sources[source] = state
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
	if w.selfDID == "" {
		return fmt.Errorf("subscription watcher requires a self DID")
	}

	subCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	manager := w.newManager(w.endpoint, w.logger)
	w.sourceMu.Lock()
	clear(w.sources)
	w.sourceMu.Unlock()

	// Subscribe to all records under the wireguard-mesh protocol for
	// this network. This catches node, endpoint, and relay
	// record changes in a single subscription. Read grants authorize
	// RecordsSubscribe broadly. A role-only invocation cannot use this filter:
	// production DWN requires protocolPath and direct-parent scoping.
	meshAuth, topologySupported := broadSubscriptionAuth(w.readAuth)
	if topologySupported {
		filter := dwn.RecordsFilter{
			Protocol:  protocols.MeshProtocolURI,
			ContextID: w.networkRecordID,
		}
		if _, err := manager.SubscribeWithAuthAndLifecycle(
			subCtx,
			w.anchorTenant,
			w.signer,
			filter,
			meshAuth,
			func(message *dwn.SubscriptionMessage) error {
				return w.handleSubscriptionMessage("mesh", message)
			},
			func(event dwn.SubscriptionLifecycleEvent) {
				w.handleSubscriptionLifecycle("mesh", event)
			},
		); err != nil {
			cancel()
			manager.CloseAll()
			return fmt.Errorf("subscribing to mesh records: %w", err)
		}
	} else {
		w.logger.Warn("broad mesh subscription disabled for protocol-role reads; using polling until path-scoped subscriptions are available",
			slog.String("protocolRole", w.readAuth.ProtocolRole),
		)
	}

	// Delivery records do not carry the network contextId in their descriptor,
	// so they are not covered by the mesh subscription above. Subscribe by the
	// recipient and the control-record tags used by delivery lookups. These
	// records are recipient-readable and must not invoke the mesh read role or
	// grant.
	deliveryFilter := dwn.RecordsFilter{
		Protocol:     protocols.MeshProtocolURI,
		ProtocolPath: dwncrypto.EncryptionControlDeliveryPath,
		Recipient:    w.selfDID,
		Tags: map[string]any{
			"protocol":  protocols.MeshProtocolURI,
			"contextId": w.networkRecordID,
		},
	}
	if _, err := manager.SubscribeWithAuthAndLifecycle(
		subCtx,
		w.anchorTenant,
		w.signer,
		deliveryFilter,
		dwn.MessageAuth{},
		func(message *dwn.SubscriptionMessage) error {
			return w.handleSubscriptionMessage("delivery", message)
		},
		func(event dwn.SubscriptionLifecycleEvent) {
			w.handleSubscriptionLifecycle("delivery", event)
		},
	); err != nil {
		cancel()
		manager.CloseAll()
		return fmt.Errorf("subscribing to delivery records: %w", err)
	}

	w.cancel = cancel
	w.done = done
	w.manager = manager

	w.logger.Info("subscription watcher started",
		slog.String("endpoint", w.endpoint),
		slog.String("network", w.networkRecordID),
	)

	// Monitor context cancellation to close the done channel.
	go func() {
		<-subCtx.Done()
		manager.CloseAll()
		close(done)
	}()

	return nil
}

// Stop cancels all subscriptions and waits for cleanup.
func (w *SubscriptionWatcher) Stop() {
	w.mu.Lock()
	cancel := w.cancel
	done := w.done
	if cancel != nil {
		cancel()
		if done != nil {
			<-done
		}
	}
	w.cancel = nil
	w.done = nil
	w.manager = nil
	w.mu.Unlock()

	w.logger.Info("subscription watcher stopped")
}
