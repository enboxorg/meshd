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
	"errors"
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
	SubscribeMessagesWithLifecycle(
		context.Context,
		string,
		*dwn.Signer,
		dwn.MessagesSubscribeOptions,
		dwn.EventHandler,
		dwn.SubscriptionLifecycleHandler,
	) (*dwn.Subscription, error)
	CheckHealth(context.Context)
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
	SetDegradedReason(string)
}

// feedAuthDegradedReason is surfaced through the daemon status when the feed
// subscription dies terminally with the delivery-authorization sentinel.
const feedAuthDegradedReason = "wallet session grants expired or revoked — run 'meshd auth connect' to refresh them"

// SubscriptionWatcher subscribes to DWN record changes and reports stream
// health and invalidations to the engine's refresh coordinator.
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

	// feedMode replaces the two Records streams with the single Messages
	// replication-feed stream. feedSync (optional) persists the resume
	// cursor across restarts.
	feedMode     bool
	feedGrantIDs []string
	feedSync     *feedSyncRecorder

	// streamNames is the fixed stream set this watcher reports on:
	// [feed] in feed mode, [topology, delivery] otherwise.
	streamNames []RefreshStream

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

	// FeedMode runs the single Messages replication-feed stream instead of
	// the two Records streams. The server's core-protocol shadow filters make
	// that one stream carry $encryption/delivery and mesh-tagged permission
	// records too. Requires the anchor owner signing identity or active
	// protocol-root Messages.Read grants.
	FeedMode bool

	// FeedGrantIDs is the canonical permissionGrantIds list invoked on the
	// feed subscription. Empty for the anchor owner (tenant bypass).
	FeedGrantIDs []string

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

	streamNames := []RefreshStream{RefreshStreamTopology, RefreshStreamDelivery}
	if cfg.FeedMode {
		streamNames = []RefreshStream{RefreshStreamFeed}
	}
	streams := make(map[RefreshStream]subscriptionWatcherStreamState, len(streamNames))
	for _, stream := range streamNames {
		streams[stream] = subscriptionWatcherStreamState{}
	}

	return &SubscriptionWatcher{
		endpoint:        cfg.AnchorEndpoint,
		anchorTenant:    cfg.AnchorTenant,
		networkRecordID: cfg.NetworkRecordID,
		selfDID:         cfg.SelfDID,
		signer:          cfg.Signer,
		readAuth:        cloneMessageAuth(cfg.ReadAuth),
		feedMode:        cfg.FeedMode,
		feedGrantIDs:    append([]string(nil), cfg.FeedGrantIDs...),
		streamNames:     streamNames,
		logger:          l.With(slog.String("component", "subscription-watcher")),
		newManager: func(endpoint string, logger *slog.Logger) subscriptionManager {
			return dwn.NewSubscriptionManager(endpoint, logger)
		},
		streams: streams,
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
		for _, stream := range w.streamNames {
			coordinator.SetStreamCovered(stream, w.streams[stream].covered)
		}
		for _, stream := range w.streamNames {
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
		w.setStreamLive(stream, true, event.NeedsFullRefresh)
	case dwn.SubscriptionLifecycleProgressGap:
		// Wait for the fresh replacement stream before rebuilding. This keeps
		// the subscribe-before-repair invariant and avoids racing cursor reset.
		w.logger.Warn("subscription progress gap; waiting for fresh stream",
			slog.String("source", string(stream)),
			slog.Any("gap", event.Gap),
		)
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
		w.setStreamLive(stream, false, false)
		w.notify(reasonForStream(stream))
	default:
		w.logger.Debug("ignoring unknown subscription lifecycle event",
			slog.String("source", string(stream)),
			slog.String("kind", string(event.Kind)),
		)
	}
}

func (w *SubscriptionWatcher) initializeStreamCoverage(coverage map[RefreshStream]bool) {
	w.coordinatorMu.Lock()
	defer w.coordinatorMu.Unlock()
	w.streamsConfigured = true
	for _, stream := range w.streamNames {
		w.streams[stream] = subscriptionWatcherStreamState{covered: coverage[stream]}
	}
	if w.coordinator == nil {
		return
	}
	// Fresh coverage supersedes any terminal degradation from a previous run.
	w.coordinator.SetDegradedReason("")
	for _, stream := range w.streamNames {
		w.coordinator.SetStreamLive(stream, false, false)
	}
	for _, stream := range w.streamNames {
		w.coordinator.SetStreamCovered(stream, coverage[stream])
	}
}

func (w *SubscriptionWatcher) clearStreamCoverage() {
	w.coordinatorMu.Lock()
	defer w.coordinatorMu.Unlock()
	w.streamsConfigured = false
	for _, stream := range w.streamNames {
		w.streams[stream] = subscriptionWatcherStreamState{}
	}
	if w.coordinator == nil {
		return
	}
	for _, stream := range w.streamNames {
		w.coordinator.SetStreamLive(stream, false, false)
	}
	for _, stream := range w.streamNames {
		w.coordinator.SetStreamCovered(stream, false)
	}
}

// setStreamUncovered drops one stream out of coverage after a terminal
// authorization failure and records the operator-facing reason. The
// coordinator falls back to the polling cadence.
func (w *SubscriptionWatcher) setStreamUncovered(stream RefreshStream, reason string) {
	w.coordinatorMu.Lock()
	defer w.coordinatorMu.Unlock()
	state := w.streams[stream]
	state.covered = false
	state.live = false
	w.streams[stream] = state
	if w.coordinator == nil {
		return
	}
	w.coordinator.SetStreamLive(stream, false, false)
	w.coordinator.SetStreamCovered(stream, false)
	w.coordinator.SetDegradedReason(reason)
}

// startRecordsSubscriptions opens the two Records streams: the broad
// mesh-protocol topology stream and the recipient-scoped delivery stream.
func (w *SubscriptionWatcher) startRecordsSubscriptions(subCtx context.Context, manager subscriptionManager) error {
	// Subscribe to all records under the wireguard-mesh protocol for
	// this network. This catches node, endpoint, and relay
	// record changes in a single subscription. Read grants authorize
	// RecordsSubscribe broadly. A role-only invocation cannot use this filter:
	// production DWN requires protocolPath and direct-parent scoping.
	meshAuth, topologySupported := broadSubscriptionAuth(w.readAuth)
	w.initializeStreamCoverage(map[RefreshStream]bool{
		RefreshStreamTopology: topologySupported,
		RefreshStreamDelivery: true,
	})
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
		return fmt.Errorf("subscribing to delivery records: %w", err)
	}
	return nil
}

// startFeedSubscription opens the single Messages replication-feed stream.
// The server's core-protocol shadow filters make a protocol-scoped feed
// subscription also carry the $encryption/delivery control records and the
// mesh-tagged permission records, so this one stream subsumes both Records
// streams. Events remain invalidation-only wake hints.
func (w *SubscriptionWatcher) startFeedSubscription(subCtx context.Context, manager subscriptionManager) error {
	// The feed stream is always authorized: the anchor owner bypasses grants
	// and delegates hold protocol-root Messages.Read grants (feed mode is not
	// selected otherwise).
	w.initializeStreamCoverage(map[RefreshStream]bool{RefreshStreamFeed: true})

	opts := dwn.MessagesSubscribeOptions{
		Filters:            []dwn.MessagesFilter{{Protocol: protocols.MeshProtocolURI}},
		PermissionGrantIDs: append([]string(nil), w.feedGrantIDs...),
		Cursor:             w.feedSync.resumeCursor(),
	}
	if _, err := manager.SubscribeMessagesWithLifecycle(
		subCtx,
		w.anchorTenant,
		w.signer,
		opts,
		w.handleFeedMessage,
		w.handleFeedLifecycle,
	); err != nil {
		return fmt.Errorf("subscribing to replication feed: %w", err)
	}
	return nil
}

// handleFeedMessage records cursor progress for resume and translates feed
// events into invalidations. Events are never checkpoint evidence for the
// control-plane state — only the cursor advances; repairs still require a
// full refresh.
func (w *SubscriptionWatcher) handleFeedMessage(message *dwn.SubscriptionMessage) error {
	if message == nil {
		return nil
	}
	switch message.Type {
	case dwn.SubscriptionEventType:
		w.feedSync.recordCursor(message.Cursor)
	case dwn.SubscriptionEOSEType:
		w.feedSync.flushCursor(message.Cursor)
	}
	return w.handleSubscriptionMessage(RefreshStreamFeed, message)
}

func (w *SubscriptionWatcher) handleFeedLifecycle(event dwn.SubscriptionLifecycleEvent) {
	switch event.Kind {
	case dwn.SubscriptionLifecycleProgressGap:
		// The server can no longer resume the persisted cursor. Discard it so
		// the reconnect replays from scratch; the lifecycle handler below
		// holds the repair until the fresh stream is live.
		w.feedSync.clearCursor()
	case dwn.SubscriptionLifecycleTerminal:
		if errors.Is(event.Err, dwn.ErrSubscriptionAuthorizationRevoked) {
			// Grants revoked or expired mid-stream: the subscription cannot be
			// re-established with the current session. Drop to uncovered
			// polling fallback and surface the reason to `meshd status`.
			w.logger.Warn("feed subscription authorization revoked; falling back to polling",
				slog.Any("error", event.Err),
			)
			w.setStreamUncovered(RefreshStreamFeed, feedAuthDegradedReason)
			w.notify(RefreshReasonFeed)
			return
		}
	}
	w.handleSubscriptionLifecycle(RefreshStreamFeed, event)
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

	var subscribeErr error
	if w.feedMode {
		subscribeErr = w.startFeedSubscription(subCtx, manager)
	} else {
		subscribeErr = w.startRecordsSubscriptions(subCtx, manager)
	}
	if subscribeErr != nil {
		w.clearStreamCoverage()
		cancel()
		manager.CloseAll()
		w.clearStreamCoverage()
		return subscribeErr
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

// CheckHealth forces an immediate liveness probe on every active
// subscription stream (feed, or topology+delivery) — the daemon analog of
// the browser online/visibility wake listeners. Dead sockets are detected
// and force-closed right away, triggering cursor-resumed resubscription,
// and streams parked in reconnect backoff have that wait fast-forwarded.
// Safe no-op while the watcher is not running.
func (w *SubscriptionWatcher) CheckHealth() {
	w.mu.Lock()
	manager := w.manager
	w.mu.Unlock()
	if manager == nil {
		return
	}
	// Each probe is bounded by its own pong deadline, so an unbounded
	// context cannot hang the caller.
	manager.CheckHealth(context.Background())
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
