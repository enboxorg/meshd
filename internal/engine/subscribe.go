// Package engine — subscription watcher for real-time DWN updates.
//
// Instead of polling every 30 seconds, the SubscriptionWatcher opens a
// WebSocket subscription to the anchor DWN and invalidates the local
// control-plane snapshot whenever mesh records change (nodes, endpoints).
//
// The watcher subscribes to all records under the wireguard-mesh protocol
// within the network's contextId. The refresh coordinator coalesces events and
// serializes the resulting full rebuilds.
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

type subscriptionWatcherStreamState struct {
	covered bool
	live    bool
}

type subscriptionRefreshCoordinator interface {
	SetStreamCovered(RefreshStream, bool)
	SetStreamLive(RefreshStream, bool, bool)
	InvalidateStream(RefreshStream, RefreshReason)
	Notify(RefreshReason)
}

// SubscriptionWatcher subscribes to DWN record changes and reports stream
// health and invalidations to the engine's refresh coordinator.
//
// This replaces pure 30-second polling with event-driven updates,
// reducing peer discovery latency from up to 30s to near-instant.
// The poll timer remains as a fallback for missed events.
type SubscriptionWatcher struct {
	endpoint              string
	anchorTenant          string
	networkRecordID       string
	selfDID               string
	signer                *dwn.Signer
	readAuth              dwn.MessageAuth
	topologyHandler       func(*dwn.SubscriptionMessage) error
	topologyRepairHandler func()
	logger                *slog.Logger
	newManager            subscriptionManagerFactory

	mu      sync.Mutex
	manager subscriptionManager
	cancel  context.CancelFunc
	done    chan struct{}

	coordinatorMu sync.RWMutex
	coordinator   subscriptionRefreshCoordinator

	streams           map[RefreshStream]subscriptionWatcherStreamState
	streamsConfigured bool
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

	// TopologyEventHandler applies topology event frames to local materialized
	// state before the refresh coordinator is invalidated. It runs
	// synchronously; returning an error prevents invalidation and propagates to
	// the subscription so the event cursor is not acknowledged.
	TopologyEventHandler func(*dwn.SubscriptionMessage) error

	// TopologyRepairHandler marks local topology state as requiring an
	// authoritative rebuild. It runs before coordinator lifecycle actions can
	// release or schedule a topology repair.
	TopologyRepairHandler func()

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
		endpoint:              cfg.AnchorEndpoint,
		anchorTenant:          cfg.AnchorTenant,
		networkRecordID:       cfg.NetworkRecordID,
		selfDID:               cfg.SelfDID,
		signer:                cfg.Signer,
		readAuth:              cloneMessageAuth(cfg.ReadAuth),
		topologyHandler:       cfg.TopologyEventHandler,
		topologyRepairHandler: cfg.TopologyRepairHandler,
		logger:                l.With(slog.String("component", "subscription-watcher")),
		newManager: func(endpoint string, logger *slog.Logger) subscriptionManager {
			return dwn.NewSubscriptionManager(endpoint, logger)
		},
		streams: map[RefreshStream]subscriptionWatcherStreamState{
			RefreshStreamTopology: {},
			RefreshStreamDelivery: {},
		},
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

// SetRefreshCoordinator supplies the refresh coordinator that owns stream
// health, invalidation coalescing, and serialized control-plane rebuilds.
// If LocalBackend replaces its control client while subscriptions remain live,
// their current coverage is replayed and forced through one repair.
func (w *SubscriptionWatcher) SetRefreshCoordinator(coordinator subscriptionRefreshCoordinator) {
	w.coordinatorMu.Lock()
	defer w.coordinatorMu.Unlock()
	if coordinator != nil && w.streamsConfigured {
		for _, stream := range []RefreshStream{RefreshStreamTopology, RefreshStreamDelivery} {
			coordinator.SetStreamCovered(stream, w.streams[stream].covered)
		}
		for _, stream := range []RefreshStream{RefreshStreamTopology, RefreshStreamDelivery} {
			state := w.streams[stream]
			coordinator.SetStreamLive(stream, state.live, state.live)
		}
	}
	w.coordinator = coordinator
}

func (w *SubscriptionWatcher) invalidateStream(stream RefreshStream, reason RefreshReason) {
	w.coordinatorMu.RLock()
	defer w.coordinatorMu.RUnlock()
	if w.coordinator != nil {
		w.coordinator.InvalidateStream(stream, reason)
	}
}

func (w *SubscriptionWatcher) notify(reason RefreshReason) {
	w.coordinatorMu.RLock()
	defer w.coordinatorMu.RUnlock()
	if w.coordinator != nil {
		w.coordinator.Notify(reason)
	}
}

func (w *SubscriptionWatcher) setStreamLive(stream RefreshStream, live, needsFullRefresh bool) {
	w.coordinatorMu.Lock()
	state := w.streams[stream]
	state.live = live
	w.streams[stream] = state
	if w.coordinator != nil {
		w.coordinator.SetStreamLive(stream, live, needsFullRefresh)
	}
	w.coordinatorMu.Unlock()
}

// handleSubscriptionMessage translates DWN events into cache invalidations.
// The coordinator retains and coalesces invalidations; EOSE remains a barrier
// only and is reflected by the established lifecycle callback.
func (w *SubscriptionWatcher) handleSubscriptionMessage(stream RefreshStream, message *dwn.SubscriptionMessage) error {
	if message == nil {
		return nil
	}

	switch message.Type {
	case "event":
		if stream == RefreshStreamTopology && w.topologyHandler != nil {
			if err := w.topologyHandler(message); err != nil {
				return fmt.Errorf("handling topology event: %w", err)
			}
		}
		w.logger.Debug("DWN record changed",
			slog.String("source", string(stream)),
			slog.Any("cursor", message.Cursor),
		)
		w.invalidateStream(stream, reasonForStream(stream))
	case "eose":
		// EOSE is only a replay barrier. The lifecycle callback establishes the
		// stream after replay and lets the coordinator release pending repairs.
		w.logger.Debug("subscription caught up to live events",
			slog.String("source", string(stream)),
			slog.Any("cursor", message.Cursor),
		)
	case "error":
		w.logger.Warn("subscription reported an error",
			slog.String("source", string(stream)),
			slog.Any("cursor", message.Cursor),
			slog.Any("error", message.Error),
		)
	default:
		w.logger.Debug("ignoring unknown subscription message",
			slog.String("source", string(stream)),
			slog.String("type", message.Type),
		)
	}
	return nil
}

func (w *SubscriptionWatcher) handleSubscriptionLifecycle(stream RefreshStream, event dwn.SubscriptionLifecycleEvent) {
	switch event.Kind {
	case dwn.SubscriptionLifecycleEstablished:
		w.logger.Debug("subscription established",
			slog.String("source", string(stream)),
			slog.Bool("needsFullRefresh", event.NeedsFullRefresh),
		)
		if stream == RefreshStreamTopology && event.NeedsFullRefresh && w.topologyRepairHandler != nil {
			w.topologyRepairHandler()
		}
		w.setStreamLive(stream, true, event.NeedsFullRefresh)
	case dwn.SubscriptionLifecycleProgressGap:
		// Wait for the fresh replacement stream before rebuilding. This keeps
		// the subscribe-before-repair invariant and avoids racing cursor reset.
		w.logger.Warn("subscription progress gap; waiting for fresh stream",
			slog.String("source", string(stream)),
			slog.Any("gap", event.Gap),
		)
		if stream == RefreshStreamTopology && w.topologyRepairHandler != nil {
			w.topologyRepairHandler()
		}
		w.setStreamLive(stream, false, true)
	case dwn.SubscriptionLifecycleRetrying:
		// The coordinator switches to the fallback cadence while reconnecting.
		w.logger.Debug("subscription retrying",
			slog.String("source", string(stream)),
			slog.Int("attempt", event.Attempt),
			slog.Any("error", event.Err),
		)
		w.setStreamLive(stream, false, false)
	case dwn.SubscriptionLifecycleTerminal:
		w.logger.Warn("subscription terminated; triggering reconciliation before polling fallback",
			slog.String("source", string(stream)),
			slog.Any("error", event.Err),
		)
		if stream == RefreshStreamTopology && w.topologyRepairHandler != nil {
			w.topologyRepairHandler()
		}
		w.setStreamLive(stream, false, false)
		w.notify(reasonForStream(stream))
	default:
		w.logger.Debug("ignoring unknown subscription lifecycle event",
			slog.String("source", string(stream)),
			slog.String("kind", string(event.Kind)),
		)
	}
}

func (w *SubscriptionWatcher) initializeStreamCoverage(topologyCovered bool) {
	w.coordinatorMu.Lock()
	defer w.coordinatorMu.Unlock()
	w.streamsConfigured = true
	w.streams[RefreshStreamTopology] = subscriptionWatcherStreamState{covered: topologyCovered}
	w.streams[RefreshStreamDelivery] = subscriptionWatcherStreamState{covered: true}
	if w.coordinator == nil {
		return
	}
	w.coordinator.SetStreamLive(RefreshStreamTopology, false, false)
	w.coordinator.SetStreamLive(RefreshStreamDelivery, false, false)
	w.coordinator.SetStreamCovered(RefreshStreamTopology, topologyCovered)
	w.coordinator.SetStreamCovered(RefreshStreamDelivery, true)
}

func (w *SubscriptionWatcher) clearStreamCoverage() {
	w.coordinatorMu.Lock()
	defer w.coordinatorMu.Unlock()
	w.streamsConfigured = false
	w.streams[RefreshStreamTopology] = subscriptionWatcherStreamState{}
	w.streams[RefreshStreamDelivery] = subscriptionWatcherStreamState{}
	if w.coordinator == nil {
		return
	}
	w.coordinator.SetStreamLive(RefreshStreamTopology, false, false)
	w.coordinator.SetStreamLive(RefreshStreamDelivery, false, false)
	w.coordinator.SetStreamCovered(RefreshStreamTopology, false)
	w.coordinator.SetStreamCovered(RefreshStreamDelivery, false)
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

	// Subscribe to all records under the wireguard-mesh protocol for
	// this network. This catches node, endpoint, and relay
	// record changes in a single subscription. Read grants authorize
	// RecordsSubscribe broadly. A role-only invocation cannot use this filter:
	// production DWN requires protocolPath and direct-parent scoping.
	meshAuth, topologySupported := broadSubscriptionAuth(w.readAuth)
	w.initializeStreamCoverage(topologySupported)
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
				return w.handleSubscriptionMessage(RefreshStreamTopology, message)
			},
			func(event dwn.SubscriptionLifecycleEvent) {
				w.handleSubscriptionLifecycle(RefreshStreamTopology, event)
			},
		); err != nil {
			w.clearStreamCoverage()
			cancel()
			manager.CloseAll()
			w.clearStreamCoverage()
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
	// Context IDs differ for owner nodes and member-associated nodes, so the
	// recipient-scoped stream deliberately omits an exact contextId tag.
	deliveryFilter := dwn.RecordsFilter{
		Protocol:     protocols.MeshProtocolURI,
		ProtocolPath: dwncrypto.EncryptionControlDeliveryPath,
		Recipient:    w.selfDID,
		Tags: map[string]any{
			"protocol": protocols.MeshProtocolURI,
		},
	}
	if _, err := manager.SubscribeWithAuthAndLifecycle(
		subCtx,
		w.anchorTenant,
		w.signer,
		deliveryFilter,
		dwn.MessageAuth{},
		func(message *dwn.SubscriptionMessage) error {
			return w.handleSubscriptionMessage(RefreshStreamDelivery, message)
		},
		func(event dwn.SubscriptionLifecycleEvent) {
			w.handleSubscriptionLifecycle(RefreshStreamDelivery, event)
		},
	); err != nil {
		w.clearStreamCoverage()
		cancel()
		manager.CloseAll()
		w.clearStreamCoverage()
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
		w.clearStreamCoverage()
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
		w.clearStreamCoverage()
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
