package engine

import (
	"log/slog"
	"sync"
	"time"

	"github.com/enboxorg/meshd/internal/dwn"
	"github.com/enboxorg/meshd/internal/state"
	"github.com/enboxorg/meshd/protocols"
)

// feedCursorPersistDebounce coalesces cursor persistence during event bursts.
// EOSE, progress gaps, and fingerprint updates persist immediately.
const feedCursorPersistDebounce = 2 * time.Second

// feedSyncRecorder owns the in-memory replication-feed checkpoint (resume
// cursor + last-verified fingerprint) and serializes its persistence through
// the caller-supplied save hook. The subscription watcher records cursor
// advances; the control client records fingerprints. Neither learns where the
// checkpoint is stored.
type feedSyncRecorder struct {
	linkKey  string
	save     func(state.FeedSyncState) error
	debounce time.Duration
	logger   *slog.Logger

	mu          sync.Mutex
	cursor      *dwn.ProgressToken
	fingerprint string
	dirty       bool
	timer       *time.Timer
	closed      bool
}

func newFeedSyncRecorder(linkKey string, save func(state.FeedSyncState) error, logger *slog.Logger) *feedSyncRecorder {
	if logger == nil {
		logger = slog.Default()
	}
	return &feedSyncRecorder{
		linkKey:  linkKey,
		save:     save,
		debounce: feedCursorPersistDebounce,
		logger:   logger.With(slog.String("component", "feed-sync")),
	}
}

// adopt restores a persisted checkpoint. Checkpoints from a different link
// key (grant churn, endpoint change, scope change) are discarded: their
// cursor belongs to a stream the current authorization epoch cannot resume.
func (r *feedSyncRecorder) adopt(loaded *state.FeedSyncState) {
	if r == nil || loaded == nil || loaded.LinkKey != r.linkKey {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if loaded.Cursor.Valid() {
		r.cursor = cloneProgressToken(loaded.Cursor)
	}
	r.fingerprint = loaded.Fingerprint
}

// resumeCursor returns the cursor the initial feed subscribe should resume
// from, or nil to replay from scratch.
func (r *feedSyncRecorder) resumeCursor() *dwn.ProgressToken {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return cloneProgressToken(r.cursor)
}

// recordCursor notes an event-delivered cursor advance and schedules a
// debounced persist.
func (r *feedSyncRecorder) recordCursor(cursor *dwn.ProgressToken) {
	if r == nil || !cursor.Valid() {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	r.cursor = cloneProgressToken(cursor)
	r.dirty = true
	if r.timer == nil {
		r.timer = time.AfterFunc(r.debounce, r.persistDebounced)
	}
}

// flushCursor persists a cursor immediately (EOSE barrier).
func (r *feedSyncRecorder) flushCursor(cursor *dwn.ProgressToken) {
	if r == nil || !cursor.Valid() {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	r.cursor = cloneProgressToken(cursor)
	r.dirty = true
	r.stopTimerLocked()
	r.persistLocked()
}

// clearCursor discards the persisted cursor after a 410 progress gap so the
// reconnect replays from scratch. The fingerprint is retained: it describes
// feed contents, not log positions.
func (r *feedSyncRecorder) clearCursor() {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	r.cursor = nil
	r.dirty = true
	r.stopTimerLocked()
	r.persistLocked()
}

// storedFingerprint returns the fingerprint recorded before the last
// successful full state load, or "" when unknown.
func (r *feedSyncRecorder) storedFingerprint() string {
	if r == nil {
		return ""
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.fingerprint
}

// recordFingerprint persists the fingerprint observed immediately before a
// successful full state load. An empty value marks the fingerprint unknown
// and disables periodic skipping until the next full load.
func (r *feedSyncRecorder) recordFingerprint(fingerprint string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	r.fingerprint = fingerprint
	r.dirty = true
	r.persistLocked()
}

// close flushes any pending cursor advance and stops further persistence.
func (r *feedSyncRecorder) close() {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	r.closed = true
	r.stopTimerLocked()
	if r.dirty {
		r.persistLocked()
	}
}

func (r *feedSyncRecorder) persistDebounced() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.timer = nil
	if r.closed || !r.dirty {
		return
	}
	r.persistLocked()
}

func (r *feedSyncRecorder) stopTimerLocked() {
	if r.timer != nil {
		r.timer.Stop()
		r.timer = nil
	}
}

func (r *feedSyncRecorder) persistLocked() {
	if r.save == nil {
		r.dirty = false
		return
	}
	err := r.save(state.FeedSyncState{
		LinkKey:     r.linkKey,
		Cursor:      cloneProgressToken(r.cursor),
		Fingerprint: r.fingerprint,
	})
	if err != nil {
		r.logger.Warn("persisting feed sync state failed", slog.Any("error", err))
		return
	}
	r.dirty = false
}

func cloneProgressToken(token *dwn.ProgressToken) *dwn.ProgressToken {
	if token == nil {
		return nil
	}
	clone := *token
	return &clone
}

// feedModeEnabled reports whether the engine converges via the Messages
// replication feed: the anchor owner signs Messages operations tenant-side
// (grant bypass), and wallet delegates need active protocol-root
// Messages.Read grants. Everyone else keeps the two Records streams.
func feedModeEnabled(cfg Config) bool {
	if cfg.Signer == nil {
		return false
	}
	if cfg.Signer.DID != "" && cfg.Signer.DID == cfg.AnchorTenant {
		return true
	}
	return len(cfg.FeedGrantIDs) > 0
}

// feedLinkKey derives the replication link identity of the engine's feed
// subscription: (tenant, endpoint, projectionId, authorizationEpoch). Grant
// churn or expiry changes the authorization epoch, which invalidates any
// persisted cursor recorded under the previous link key.
func feedLinkKey(cfg Config) (string, error) {
	scope, err := dwn.ProtocolSetSyncScope([]string{protocols.MeshProtocolURI})
	if err != nil {
		return "", err
	}
	projectionID, err := dwn.ComputeProjectionID(cfg.AnchorTenant, scope)
	if err != nil {
		return "", err
	}
	var epoch string
	if cfg.Signer.DID == cfg.AnchorTenant {
		epoch = dwn.ComputeOwnerAuthorizationEpoch()
	} else {
		epoch, err = dwn.ComputeDelegateAuthorizationEpoch(cfg.Signer.DID, cfg.FeedGrants)
		if err != nil {
			return "", err
		}
	}
	return dwn.BuildLinkKey(cfg.AnchorTenant, cfg.AnchorEndpoint, projectionID, epoch), nil
}
