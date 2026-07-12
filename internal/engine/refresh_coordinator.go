package engine

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"sort"
	"sync"
	"time"

	"github.com/enboxorg/meshd/internal/dwn"
)

// RefreshReason identifies a source of control-plane invalidation. Reasons are
// retained until a refresh succeeds, and duplicate reasons are coalesced.
type RefreshReason string

const (
	RefreshReasonStartup  RefreshReason = "startup"
	RefreshReasonPeriodic RefreshReason = "periodic"
	RefreshReasonTopology RefreshReason = "topology"
	RefreshReasonExpiry   RefreshReason = "expiry"
	RefreshReasonDelivery RefreshReason = "delivery"
	RefreshReasonEndpoint RefreshReason = "endpoint"
	RefreshReasonManual   RefreshReason = "manual"
)

// RefreshStream identifies an authoritative subscription stream.
type RefreshStream string

const (
	RefreshStreamTopology RefreshStream = "topology"
	RefreshStreamDelivery RefreshStream = "delivery"
)

// RefreshBatch is the immutable set of invalidations represented by one
// refresh attempt. Attempt starts at one and increases across consecutive
// failures. Sequence is monotonically increasing within a coordinator.
type RefreshBatch struct {
	Reasons   []RefreshReason
	Sequence  uint64
	Attempt   int
	StartedAt time.Time
}

// RefreshFunc rebuilds and publishes the complete control-plane view.
type RefreshFunc func(context.Context, RefreshBatch) error

// RefreshTimer is the small timer surface used by RefreshCoordinator. It is
// exported so deterministic clocks can be supplied by users and tests.
type RefreshTimer interface {
	C() <-chan time.Time
	Stop() bool
}

// RefreshClock supplies time and timers to RefreshCoordinator.
type RefreshClock interface {
	Now() time.Time
	NewTimer(time.Duration) RefreshTimer
}

// RefreshCoordinatorConfig configures a single refresh worker.
type RefreshCoordinatorConfig struct {
	Refresh RefreshFunc

	// FallbackInterval is used whenever either required stream is uncovered,
	// disconnected, or has not yet been repaired. Default: 30 seconds.
	FallbackInterval time.Duration

	// HealthyInterval is the anti-entropy interval when both topology and
	// delivery streams are covered, live, and repaired. Default: 5 minutes.
	HealthyInterval time.Duration

	// Debounce waits for a quiet window after event invalidations. MaxDebounce
	// caps the total coalescing delay so a hot stream cannot starve refreshes.
	// Zero Debounce disables both.
	Debounce    time.Duration
	MaxDebounce time.Duration

	// RetryBackoff and MaxRetryBackoff bound exponential retry delays.
	// Defaults: 1 second and 30 seconds.
	RetryBackoff    time.Duration
	MaxRetryBackoff time.Duration

	// Jitter transforms periodic intervals. A nil function applies random
	// plus or minus 10 percent jitter.
	Jitter func(time.Duration) time.Duration

	// RetryJitter transforms retry delays. The result is clamped so it can
	// never schedule earlier than exponential backoff or Retry-After. A nil
	// function adds random zero to 20 percent delay.
	RetryJitter func(time.Duration) time.Duration

	// Clock defaults to the system clock.
	Clock RefreshClock
}

// RefreshMode describes the current anti-entropy cadence.
type RefreshMode string

const (
	RefreshModeFallback RefreshMode = "fallback"
	RefreshModeHealthy  RefreshMode = "healthy"
)

// RefreshStreamHealth is an immutable view of one subscription source.
type RefreshStreamHealth struct {
	Covered  bool
	Live     bool
	Repaired bool
}

// RefreshCoordinatorHealth is a point-in-time, deep-copied scheduler view.
type RefreshCoordinatorHealth struct {
	Running             bool
	Paused              bool
	InFlight            bool
	Mode                RefreshMode
	StreamsHealthy      bool
	Streams             map[RefreshStream]RefreshStreamHealth
	PendingReasons      []RefreshReason
	ConsecutiveFailures int
	LastAttemptAt       time.Time
	LastSuccessAt       time.Time
	LastReasons         []RefreshReason
	LastDuration        time.Duration
	LastError           string
	RetryNotBefore      time.Time
	NextPeriodicAt      time.Time
	NextAttemptAt       time.Time
}

type refreshPending struct {
	sequence uint64
}

type refreshStreamState struct {
	covered        bool
	live           bool
	repaired       bool
	repairSequence uint64
}

// RefreshCoordinator serializes full control-plane refreshes while preserving
// every invalidation until a successful rebuild. Its wake channel is only a
// hint; durable pending work is always owned by mu.
type RefreshCoordinator struct {
	refresh          RefreshFunc
	fallbackInterval time.Duration
	healthyInterval  time.Duration
	retryBackoff     time.Duration
	maxRetryBackoff  time.Duration
	debounce         time.Duration
	maxDebounce      time.Duration
	jitter           func(time.Duration) time.Duration
	retryJitter      func(time.Duration) time.Duration
	clock            RefreshClock

	mu      sync.Mutex
	pending map[RefreshReason]refreshPending
	streams map[RefreshStream]refreshStreamState
	wake    chan struct{}

	sequence            uint64
	started             bool
	stopped             bool
	running             bool
	paused              bool
	inFlight            bool
	consecutiveFailures int
	lastAttemptAt       time.Time
	lastSuccessAt       time.Time
	lastReasons         []RefreshReason
	lastDuration        time.Duration
	lastError           string
	retryNotBefore      time.Time
	debounceStartedAt   time.Time
	debounceNotBefore   time.Time
	nextPeriodicAt      time.Time
	cancel              context.CancelFunc
	done                chan struct{}
}

// NewRefreshCoordinator constructs a coordinator. Call Start exactly once to
// launch its worker.
func NewRefreshCoordinator(cfg RefreshCoordinatorConfig) (*RefreshCoordinator, error) {
	if cfg.Refresh == nil {
		return nil, fmt.Errorf("refresh coordinator requires a refresh function")
	}

	fallbackInterval := cfg.FallbackInterval
	if fallbackInterval == 0 {
		fallbackInterval = 30 * time.Second
	}
	healthyInterval := cfg.HealthyInterval
	if healthyInterval == 0 {
		healthyInterval = 5 * time.Minute
	}
	retryBackoff := cfg.RetryBackoff
	if retryBackoff == 0 {
		retryBackoff = time.Second
	}
	maxRetryBackoff := cfg.MaxRetryBackoff
	if maxRetryBackoff == 0 {
		maxRetryBackoff = 30 * time.Second
	}
	maxDebounce := cfg.MaxDebounce
	if cfg.Debounce > 0 && maxDebounce == 0 {
		maxDebounce = cfg.Debounce
	}
	if fallbackInterval < 0 || healthyInterval < 0 || retryBackoff < 0 || maxRetryBackoff < 0 || cfg.Debounce < 0 || maxDebounce < 0 {
		return nil, fmt.Errorf("refresh coordinator durations must be positive")
	}
	if maxRetryBackoff < retryBackoff {
		return nil, fmt.Errorf("refresh coordinator max retry backoff must be at least retry backoff")
	}
	if cfg.Debounce > 0 && maxDebounce < cfg.Debounce {
		return nil, fmt.Errorf("refresh coordinator max debounce must be at least debounce")
	}

	clock := cfg.Clock
	if clock == nil {
		clock = systemRefreshClock{}
	}
	jitter := cfg.Jitter
	if jitter == nil {
		jitter = defaultRefreshJitter
	}
	retryJitter := cfg.RetryJitter
	if retryJitter == nil {
		retryJitter = defaultRefreshRetryJitter
	}

	return &RefreshCoordinator{
		refresh:          cfg.Refresh,
		fallbackInterval: fallbackInterval,
		healthyInterval:  healthyInterval,
		retryBackoff:     retryBackoff,
		maxRetryBackoff:  maxRetryBackoff,
		debounce:         cfg.Debounce,
		maxDebounce:      maxDebounce,
		jitter:           jitter,
		retryJitter:      retryJitter,
		clock:            clock,
		pending:          make(map[RefreshReason]refreshPending),
		streams: map[RefreshStream]refreshStreamState{
			RefreshStreamTopology: {},
			RefreshStreamDelivery: {},
		},
		wake: make(chan struct{}, 1),
	}, nil
}

// Start launches the sole refresh worker and queues the initial rebuild. A
// coordinator cannot be restarted after Stop or parent-context cancellation.
func (c *RefreshCoordinator) Start(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("refresh coordinator requires a context")
	}

	c.mu.Lock()
	if c.started {
		c.mu.Unlock()
		return fmt.Errorf("refresh coordinator already started")
	}
	if c.stopped {
		c.mu.Unlock()
		return fmt.Errorf("refresh coordinator cannot be restarted")
	}
	runCtx, cancel := context.WithCancel(ctx)
	c.started = true
	c.running = true
	c.cancel = cancel
	c.done = make(chan struct{})
	c.enqueueLocked(RefreshReasonStartup)
	c.resetPeriodicLocked(c.clock.Now())
	done := c.done
	c.mu.Unlock()

	go c.run(runCtx, done)
	c.signal()
	return nil
}

// Stop cancels the worker and waits for the in-flight refresh to observe
// cancellation and return. Stop is idempotent.
func (c *RefreshCoordinator) Stop() {
	c.mu.Lock()
	if c.stopped {
		done := c.done
		c.mu.Unlock()
		if done != nil {
			<-done
		}
		return
	}
	c.stopped = true
	cancel := c.cancel
	done := c.done
	c.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	c.signal()
	if done != nil {
		<-done
	}
}

// Notify records non-stream work and wakes the worker without blocking.
func (c *RefreshCoordinator) Notify(reason RefreshReason) {
	if reason == "" {
		reason = RefreshReasonManual
	}
	c.mu.Lock()
	if c.stopped {
		c.mu.Unlock()
		return
	}
	c.enqueueLocked(reason)
	c.deferPendingLocked()
	c.mu.Unlock()
	c.signal()
}

// SetPaused suspends refresh attempts without discarding pending work.
// Unpausing wakes the worker immediately.
func (c *RefreshCoordinator) SetPaused(paused bool) {
	c.mu.Lock()
	if c.stopped {
		c.mu.Unlock()
		return
	}
	wasPaused := c.paused
	changed := wasPaused != paused
	c.paused = paused
	if wasPaused && !paused {
		c.enqueueLocked(RefreshReasonManual)
		c.deferPendingLocked()
	}
	c.mu.Unlock()
	if changed {
		c.signal()
	}
}

// SetStreamCovered reports whether an authoritative subscription exists for a
// required source. Newly covered streams require a successful repair after
// they become live. Coverage changes reset the adaptive periodic timer.
func (c *RefreshCoordinator) SetStreamCovered(stream RefreshStream, covered bool) {
	c.mu.Lock()
	if c.stopped {
		c.mu.Unlock()
		return
	}
	state := c.streams[stream]
	if state.covered == covered {
		c.mu.Unlock()
		return
	}
	state.covered = covered
	if !covered {
		state.live = false
		state.repaired = false
		state.repairSequence = 0
		delete(c.pending, reasonForStream(stream))
		if len(c.pending) == 0 {
			c.debounceStartedAt = time.Time{}
			c.debounceNotBefore = time.Time{}
		}
	} else {
		c.sequence++
		state.repaired = false
		state.repairSequence = c.sequence
		if state.live {
			c.enqueueAtLocked(reasonForStream(stream), state.repairSequence)
		}
	}
	c.streams[stream] = state
	c.resetPeriodicLocked(c.clock.Now())
	c.mu.Unlock()
	c.signal()
}

// SetStreamLive reports a lifecycle transition. A non-live stream is marked
// stale when needsFullRefresh is true, but repair is deliberately held until a
// fresh stream is live (subscribe-before-repair). A live unrepaired stream
// queues one source-specific rebuild.
func (c *RefreshCoordinator) SetStreamLive(stream RefreshStream, live, needsFullRefresh bool) {
	c.mu.Lock()
	if c.stopped {
		c.mu.Unlock()
		return
	}
	state := c.streams[stream]
	wasLive := state.live
	changed := wasLive != live
	state.live = live
	if needsFullRefresh {
		c.sequence++
		state.repaired = false
		state.repairSequence = c.sequence
		changed = true
		if !live {
			delete(c.pending, reasonForStream(stream))
			if len(c.pending) == 0 {
				c.debounceStartedAt = time.Time{}
				c.debounceNotBefore = time.Time{}
			}
		}
	}
	if live && state.covered && !state.repaired {
		// Crossing the replay barrier receives a new revision even if the
		// underlying invalidation predates an in-flight refresh. That older
		// refresh must not be allowed to mark this stream repaired.
		if !wasLive || state.repairSequence == 0 {
			c.sequence++
			state.repairSequence = c.sequence
		}
		c.enqueueAtLocked(reasonForStream(stream), state.repairSequence)
	}
	c.streams[stream] = state
	if changed {
		c.resetPeriodicLocked(c.clock.Now())
	}
	c.mu.Unlock()
	c.signal()
}

// InvalidateStream marks a subscription source stale. Replay events received
// while the source is not live remain pending but do not trigger a rebuild
// until SetStreamLive reports the replay barrier.
func (c *RefreshCoordinator) InvalidateStream(stream RefreshStream, reason RefreshReason) {
	if reason == "" {
		reason = reasonForStream(stream)
	}
	c.mu.Lock()
	if c.stopped {
		c.mu.Unlock()
		return
	}
	state := c.streams[stream]
	c.sequence++
	state.repaired = false
	state.repairSequence = c.sequence
	c.streams[stream] = state
	if state.covered && state.live {
		c.enqueueAtLocked(reason, state.repairSequence)
		c.deferPendingLocked()
	}
	c.resetPeriodicLocked(c.clock.Now())
	c.mu.Unlock()
	c.signal()
}

// Health returns a deep copy. Mutating its maps or slices cannot affect the
// coordinator.
func (c *RefreshCoordinator) Health() RefreshCoordinatorHealth {
	c.mu.Lock()
	defer c.mu.Unlock()

	healthy := c.streamsHealthyLocked()
	h := RefreshCoordinatorHealth{
		Running:             c.running,
		Paused:              c.paused,
		InFlight:            c.inFlight,
		Mode:                modeForHealth(healthy),
		StreamsHealthy:      healthy,
		Streams:             make(map[RefreshStream]RefreshStreamHealth, len(c.streams)),
		PendingReasons:      sortedPendingReasons(c.pending),
		ConsecutiveFailures: c.consecutiveFailures,
		LastAttemptAt:       c.lastAttemptAt,
		LastSuccessAt:       c.lastSuccessAt,
		LastReasons:         append([]RefreshReason(nil), c.lastReasons...),
		LastDuration:        c.lastDuration,
		LastError:           c.lastError,
		RetryNotBefore:      c.retryNotBefore,
		NextPeriodicAt:      c.nextPeriodicAt,
	}
	for source, state := range c.streams {
		h.Streams[source] = RefreshStreamHealth{
			Covered:  state.covered,
			Live:     state.live,
			Repaired: state.repaired,
		}
	}
	if c.running && !c.paused && !c.inFlight {
		now := c.clock.Now()
		if len(c.pending) > 0 {
			h.NextAttemptAt = now
			if c.retryNotBefore.After(h.NextAttemptAt) {
				h.NextAttemptAt = c.retryNotBefore
			}
			if c.debounceNotBefore.After(h.NextAttemptAt) {
				h.NextAttemptAt = c.debounceNotBefore
			}
		} else {
			h.NextAttemptAt = c.nextPeriodicAt
		}
	}
	return h
}

type refreshWork struct {
	batch   RefreshBatch
	pending map[RefreshReason]refreshPending
	reasons []RefreshReason
}

func (c *RefreshCoordinator) run(ctx context.Context, done chan struct{}) {
	defer func() {
		c.mu.Lock()
		c.running = false
		c.inFlight = false
		c.stopped = true
		c.mu.Unlock()
		close(done)
	}()

	for {
		if ctx.Err() != nil {
			return
		}

		now := c.clock.Now()
		c.mu.Lock()
		work, ready := c.takeWorkLocked(now)
		deadline := c.nextDeadlineLocked(now)
		c.mu.Unlock()

		if ready {
			err := c.refresh(ctx, work.batch)
			c.finishWork(work, err)
			continue
		}

		wait := deadline.Sub(c.clock.Now())
		if wait < 0 {
			wait = 0
		}
		timer := c.clock.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-c.wake:
			timer.Stop()
		case <-timer.C():
			c.handleTimer(c.clock.Now())
		}
	}
}

func (c *RefreshCoordinator) takeWorkLocked(now time.Time) (refreshWork, bool) {
	if c.paused || c.inFlight || len(c.pending) == 0 || c.retryNotBefore.After(now) || c.debounceNotBefore.After(now) {
		return refreshWork{}, false
	}
	pending := c.pending
	c.pending = make(map[RefreshReason]refreshPending)
	c.debounceStartedAt = time.Time{}
	c.debounceNotBefore = time.Time{}
	c.inFlight = true
	c.lastAttemptAt = now

	var sequence uint64
	for _, item := range pending {
		if item.sequence > sequence {
			sequence = item.sequence
		}
	}
	reasons := sortedPendingReasons(pending)
	return refreshWork{
		batch: RefreshBatch{
			Reasons:   append([]RefreshReason(nil), reasons...),
			Sequence:  sequence,
			Attempt:   c.consecutiveFailures + 1,
			StartedAt: now,
		},
		pending: pending,
		reasons: reasons,
	}, true
}

func (c *RefreshCoordinator) finishWork(work refreshWork, err error) {
	now := c.clock.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.inFlight = false
	c.lastReasons = append(c.lastReasons[:0], work.reasons...)
	c.lastDuration = now.Sub(work.batch.StartedAt)
	if c.lastDuration < 0 {
		c.lastDuration = 0
	}
	if err != nil {
		for reason, item := range work.pending {
			c.enqueueAtLocked(reason, item.sequence)
		}
		c.consecutiveFailures++
		c.lastError = err.Error()
		minimumDelay := exponentialBackoff(c.retryBackoff, c.maxRetryBackoff, c.consecutiveFailures)
		var rateLimit *dwn.RateLimitError
		if errors.As(err, &rateLimit) && rateLimit.RetryAfter > minimumDelay {
			minimumDelay = rateLimit.RetryAfter
		}
		delay := c.retryJitter(minimumDelay)
		if delay < minimumDelay {
			delay = minimumDelay
		}
		c.retryNotBefore = now.Add(delay)
		return
	}

	c.consecutiveFailures = 0
	c.lastSuccessAt = now
	c.lastError = ""
	c.retryNotBefore = time.Time{}
	for source, state := range c.streams {
		if state.covered && state.live && !state.repaired && state.repairSequence != 0 && state.repairSequence <= work.batch.Sequence {
			state.repaired = true
			c.streams[source] = state
		}
	}
	c.resetPeriodicLocked(now)
}

func (c *RefreshCoordinator) nextDeadlineLocked(now time.Time) time.Time {
	deadline := c.nextPeriodicAt
	if deadline.IsZero() {
		deadline = now.Add(c.currentIntervalLocked())
	}
	if !c.paused && len(c.pending) > 0 {
		attemptAt := now
		if c.retryNotBefore.After(attemptAt) {
			attemptAt = c.retryNotBefore
		}
		if c.debounceNotBefore.After(attemptAt) {
			attemptAt = c.debounceNotBefore
		}
		if deadline.IsZero() || attemptAt.Before(deadline) {
			deadline = attemptAt
		}
	}
	return deadline
}

func (c *RefreshCoordinator) handleTimer(now time.Time) {
	c.mu.Lock()
	if !c.nextPeriodicAt.IsZero() && !now.Before(c.nextPeriodicAt) {
		c.enqueueLocked(RefreshReasonPeriodic)
		c.resetPeriodicLocked(now)
	}
	c.mu.Unlock()
}

func (c *RefreshCoordinator) deferPendingLocked() {
	if c.debounce <= 0 || len(c.pending) == 0 {
		return
	}
	now := c.clock.Now()
	if c.debounceStartedAt.IsZero() {
		c.debounceStartedAt = now
	}
	deadline := now.Add(c.debounce)
	if c.maxDebounce > 0 {
		maximum := c.debounceStartedAt.Add(c.maxDebounce)
		if deadline.After(maximum) {
			deadline = maximum
		}
	}
	if deadline.Before(now) {
		deadline = now
	}
	c.debounceNotBefore = deadline
}

func (c *RefreshCoordinator) enqueueLocked(reason RefreshReason) {
	c.sequence++
	c.enqueueAtLocked(reason, c.sequence)
}

func (c *RefreshCoordinator) enqueueAtLocked(reason RefreshReason, sequence uint64) {
	if reason == "" {
		reason = RefreshReasonManual
	}
	current, ok := c.pending[reason]
	if !ok || sequence > current.sequence {
		c.pending[reason] = refreshPending{sequence: sequence}
	}
}

func (c *RefreshCoordinator) resetPeriodicLocked(now time.Time) {
	interval := c.jitter(c.currentIntervalLocked())
	if interval < 0 {
		interval = 0
	}
	c.nextPeriodicAt = now.Add(interval)
}

func (c *RefreshCoordinator) currentIntervalLocked() time.Duration {
	if c.streamsHealthyLocked() {
		return c.healthyInterval
	}
	return c.fallbackInterval
}

func (c *RefreshCoordinator) streamsHealthyLocked() bool {
	for _, source := range []RefreshStream{RefreshStreamTopology, RefreshStreamDelivery} {
		state := c.streams[source]
		if !state.covered || !state.live || !state.repaired {
			return false
		}
	}
	return true
}

func (c *RefreshCoordinator) signal() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

func reasonForStream(stream RefreshStream) RefreshReason {
	switch stream {
	case RefreshStreamTopology:
		return RefreshReasonTopology
	case RefreshStreamDelivery:
		return RefreshReasonDelivery
	default:
		return RefreshReason(stream)
	}
}

func sortedPendingReasons(pending map[RefreshReason]refreshPending) []RefreshReason {
	reasons := make([]RefreshReason, 0, len(pending))
	for reason := range pending {
		reasons = append(reasons, reason)
	}
	sort.Slice(reasons, func(i, j int) bool { return reasons[i] < reasons[j] })
	return reasons
}

func modeForHealth(healthy bool) RefreshMode {
	if healthy {
		return RefreshModeHealthy
	}
	return RefreshModeFallback
}

func exponentialBackoff(base, maximum time.Duration, failures int) time.Duration {
	if failures <= 1 {
		return base
	}
	delay := base
	for i := 1; i < failures; i++ {
		if delay >= maximum || delay > maximum/2 {
			return maximum
		}
		delay *= 2
	}
	if delay > maximum {
		return maximum
	}
	return delay
}

func defaultRefreshJitter(interval time.Duration) time.Duration {
	if interval <= 0 {
		return interval
	}
	span := interval / 5 // total width is 20 percent.
	if span <= 0 {
		return interval
	}
	return interval - span/2 + time.Duration(rand.Int64N(int64(span)+1))
}

func defaultRefreshRetryJitter(delay time.Duration) time.Duration {
	if delay <= 0 {
		return delay
	}
	span := delay / 5
	if span <= 0 {
		return delay
	}
	extra := time.Duration(rand.Int64N(int64(span) + 1))
	const maxDuration = time.Duration(1<<63 - 1)
	if delay > maxDuration-extra {
		return maxDuration
	}
	return delay + extra
}

type systemRefreshClock struct{}

func (systemRefreshClock) Now() time.Time { return time.Now() }

func (systemRefreshClock) NewTimer(delay time.Duration) RefreshTimer {
	return systemRefreshTimer{timer: time.NewTimer(delay)}
}

type systemRefreshTimer struct {
	timer *time.Timer
}

func (t systemRefreshTimer) C() <-chan time.Time { return t.timer.C }
func (t systemRefreshTimer) Stop() bool          { return t.timer.Stop() }
