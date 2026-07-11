package engine

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/enboxorg/meshd/internal/dwn"
)

func TestRefreshCoordinatorCoalescesAndRunsOneTrailingRefresh(t *testing.T) {
	clock := newCoordinatorFakeClock()
	started := make(chan RefreshBatch, 4)
	release := make(chan error, 4)
	var active atomic.Int32
	var maximum atomic.Int32

	coordinator := newTestRefreshCoordinator(t, clock, func(ctx context.Context, batch RefreshBatch) error {
		current := active.Add(1)
		defer active.Add(-1)
		for {
			old := maximum.Load()
			if current <= old || maximum.CompareAndSwap(old, current) {
				break
			}
		}
		started <- batch
		select {
		case err := <-release:
			return err
		case <-ctx.Done():
			return ctx.Err()
		}
	})

	if err := coordinator.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(coordinator.Stop)
	first := receiveBatch(t, started)
	assertReasons(t, first, RefreshReasonStartup)

	for range 100 {
		coordinator.Notify(RefreshReasonTopology)
	}
	assertNoBatch(t, started)
	release <- nil

	second := receiveBatch(t, started)
	assertReasons(t, second, RefreshReasonTopology)
	for range 100 {
		coordinator.Notify(RefreshReasonDelivery)
	}
	assertNoBatch(t, started)
	release <- nil

	third := receiveBatch(t, started)
	assertReasons(t, third, RefreshReasonDelivery)
	release <- nil
	waitCoordinator(t, func() bool { return !coordinator.Health().InFlight })
	assertNoBatch(t, started)
	if got := maximum.Load(); got != 1 {
		t.Fatalf("maximum concurrent refreshes = %d, want 1", got)
	}

	health := coordinator.Health()
	if !reflect.DeepEqual(health.LastReasons, []RefreshReason{RefreshReasonDelivery}) {
		t.Fatalf("last reasons = %v", health.LastReasons)
	}
	health.LastReasons[0] = RefreshReasonManual
	if got := coordinator.Health().LastReasons[0]; got != RefreshReasonDelivery {
		t.Fatalf("mutating Health.LastReasons changed coordinator: %q", got)
	}
}

func TestRefreshCoordinatorDebouncesBurstWithHardCap(t *testing.T) {
	clock := newCoordinatorFakeClock()
	started := make(chan RefreshBatch, 4)
	coordinator, err := NewRefreshCoordinator(RefreshCoordinatorConfig{
		Refresh: func(_ context.Context, batch RefreshBatch) error {
			started <- batch
			return nil
		},
		FallbackInterval: 100 * time.Second,
		HealthyInterval:  200 * time.Second,
		RetryBackoff:     time.Second,
		MaxRetryBackoff:  time.Second,
		Debounce:         2 * time.Second,
		MaxDebounce:      5 * time.Second,
		Jitter:           identityRefreshJitter,
		RetryJitter:      identityRefreshJitter,
		Clock:            clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(coordinator.Stop)
	receiveBatch(t, started)
	waitCoordinator(t, func() bool { return !coordinator.Health().InFlight })

	coordinator.Notify(RefreshReasonTopology)
	assertNoBatch(t, started)
	clock.Advance(time.Second)
	coordinator.Notify(RefreshReasonDelivery)
	clock.Advance(time.Second)
	coordinator.Notify(RefreshReasonEndpoint)
	clock.Advance(time.Second)
	coordinator.Notify(RefreshReasonTopology)
	clock.Advance(time.Second)
	coordinator.Notify(RefreshReasonDelivery)
	assertNoBatch(t, started)

	health := coordinator.Health()
	wantDeadline := clock.Now().Add(time.Second)
	if !health.NextAttemptAt.Equal(wantDeadline) {
		t.Fatalf("next attempt = %v, want hard-cap deadline %v", health.NextAttemptAt, wantDeadline)
	}
	clock.Advance(time.Second - time.Nanosecond)
	assertNoBatch(t, started)
	clock.Advance(time.Nanosecond)
	batch := receiveBatch(t, started)
	assertReasons(t, batch, RefreshReasonDelivery, RefreshReasonEndpoint, RefreshReasonTopology)
	waitCoordinator(t, func() bool { return !coordinator.Health().InFlight })
	assertNoBatch(t, started)
}

func TestRefreshCoordinatorUnpauseQueuesRefreshWithoutPriorPendingWork(t *testing.T) {
	clock := newCoordinatorFakeClock()
	started := make(chan RefreshBatch, 3)
	coordinator := newTestRefreshCoordinator(t, clock, func(_ context.Context, batch RefreshBatch) error {
		started <- batch
		return nil
	})
	if err := coordinator.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(coordinator.Stop)
	receiveBatch(t, started)
	waitCoordinator(t, func() bool { return !coordinator.Health().InFlight })

	coordinator.SetPaused(true)
	coordinator.SetPaused(false)
	batch := receiveBatch(t, started)
	assertReasons(t, batch, RefreshReasonManual)
}

func TestRefreshCoordinatorRetriesFailedBatchWithRateLimitAndBackoff(t *testing.T) {
	clock := newCoordinatorFakeClock()
	started := make(chan RefreshBatch, 4)
	results := make(chan error, 4)
	coordinator := newTestRefreshCoordinator(t, clock, func(ctx context.Context, batch RefreshBatch) error {
		started <- batch
		select {
		case err := <-results:
			return err
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	if err := coordinator.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(coordinator.Stop)

	first := receiveBatch(t, started)
	if first.Attempt != 1 {
		t.Fatalf("first attempt = %d", first.Attempt)
	}
	clock.Advance(2 * time.Second)
	results <- fmt.Errorf("query failed: %w", &dwn.RateLimitError{RetryAfter: 10 * time.Second, Detail: "slow down"})
	waitCoordinator(t, func() bool { return coordinator.Health().ConsecutiveFailures == 1 })

	health := coordinator.Health()
	wantNotBefore := clock.Now().Add(10 * time.Second)
	if !health.RetryNotBefore.Equal(wantNotBefore) {
		t.Fatalf("retry not before = %v, want %v", health.RetryNotBefore, wantNotBefore)
	}
	if health.LastDuration != 2*time.Second {
		t.Fatalf("last duration = %v, want 2s", health.LastDuration)
	}
	assertReasonsSlice(t, health.PendingReasons, RefreshReasonStartup)
	coordinator.Notify(RefreshReasonEndpoint)
	clock.Advance(9 * time.Second)
	assertNoBatch(t, started)
	clock.Advance(time.Second)

	second := receiveBatch(t, started)
	if second.Attempt != 2 {
		t.Fatalf("second attempt = %d", second.Attempt)
	}
	assertReasons(t, second, RefreshReasonEndpoint, RefreshReasonPeriodic, RefreshReasonStartup)
	results <- errors.New("still unavailable")
	waitCoordinator(t, func() bool { return coordinator.Health().ConsecutiveFailures == 2 })
	wantNotBefore = clock.Now().Add(2 * time.Second)
	if got := coordinator.Health().RetryNotBefore; !got.Equal(wantNotBefore) {
		t.Fatalf("second retry not before = %v, want %v", got, wantNotBefore)
	}
	clock.Advance(time.Second)
	assertNoBatch(t, started)
	clock.Advance(time.Second)

	third := receiveBatch(t, started)
	if third.Attempt != 3 {
		t.Fatalf("third attempt = %d", third.Attempt)
	}
	results <- nil
	waitCoordinator(t, func() bool {
		health := coordinator.Health()
		return !health.InFlight && health.ConsecutiveFailures == 0 && health.LastError == ""
	})
	if got := coordinator.Health().PendingReasons; len(got) != 0 {
		t.Fatalf("pending reasons after success = %v", got)
	}
}

func TestRefreshCoordinatorPauseRetainsPendingWork(t *testing.T) {
	clock := newCoordinatorFakeClock()
	started := make(chan RefreshBatch, 2)
	coordinator := newTestRefreshCoordinator(t, clock, func(_ context.Context, batch RefreshBatch) error {
		started <- batch
		return nil
	})
	coordinator.SetPaused(true)
	coordinator.Notify(RefreshReasonEndpoint)
	if err := coordinator.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(coordinator.Stop)
	assertNoBatch(t, started)

	health := coordinator.Health()
	if !health.Paused || !health.NextAttemptAt.IsZero() {
		t.Fatalf("paused health = %+v", health)
	}
	assertReasonsSlice(t, health.PendingReasons, RefreshReasonEndpoint, RefreshReasonStartup)
	coordinator.SetPaused(false)
	batch := receiveBatch(t, started)
	assertReasons(t, batch, RefreshReasonEndpoint, RefreshReasonManual, RefreshReasonStartup)
	waitCoordinator(t, func() bool { return !coordinator.Health().InFlight })
}

func TestRefreshCoordinatorStreamRepairGatingAndAdaptiveCadence(t *testing.T) {
	clock := newCoordinatorFakeClock()
	started := make(chan RefreshBatch, 8)
	coordinator := newTestRefreshCoordinator(t, clock, func(_ context.Context, batch RefreshBatch) error {
		started <- batch
		return nil
	})
	coordinator.SetStreamCovered(RefreshStreamTopology, true)
	coordinator.SetStreamCovered(RefreshStreamDelivery, true)
	coordinator.SetStreamLive(RefreshStreamTopology, true, true)
	coordinator.SetStreamLive(RefreshStreamDelivery, true, true)
	if err := coordinator.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(coordinator.Stop)

	initial := receiveBatch(t, started)
	assertReasons(t, initial, RefreshReasonDelivery, RefreshReasonStartup, RefreshReasonTopology)
	waitCoordinator(t, func() bool { return coordinator.Health().StreamsHealthy })
	health := coordinator.Health()
	if health.Mode != RefreshModeHealthy {
		t.Fatalf("mode = %q, want healthy", health.Mode)
	}
	if want := clock.Now().Add(100 * time.Second); !health.NextPeriodicAt.Equal(want) {
		t.Fatalf("healthy periodic = %v, want %v", health.NextPeriodicAt, want)
	}

	coordinator.SetPaused(true)
	coordinator.InvalidateStream(RefreshStreamTopology, RefreshReasonTopology)
	coordinator.SetStreamLive(RefreshStreamTopology, false, true)
	coordinator.SetPaused(false)
	resumed := receiveBatch(t, started)
	assertReasons(t, resumed, RefreshReasonManual)
	waitCoordinator(t, func() bool { return !coordinator.Health().InFlight })
	health = coordinator.Health()
	if health.Mode != RefreshModeFallback || health.Streams[RefreshStreamTopology].Repaired {
		t.Fatalf("gap health = %+v", health)
	}
	if want := clock.Now().Add(10 * time.Second); !health.NextPeriodicAt.Equal(want) {
		t.Fatalf("fallback periodic = %v, want %v", health.NextPeriodicAt, want)
	}
	clock.Advance(10 * time.Second)
	fallback := receiveBatch(t, started)
	assertReasons(t, fallback, RefreshReasonPeriodic)
	waitCoordinator(t, func() bool { return !coordinator.Health().InFlight })
	if coordinator.Health().Streams[RefreshStreamTopology].Repaired {
		t.Fatal("fallback anti-entropy incorrectly repaired a non-live stream")
	}

	coordinator.SetStreamLive(RefreshStreamTopology, true, false)
	repair := receiveBatch(t, started)
	assertReasons(t, repair, RefreshReasonTopology)
	waitCoordinator(t, func() bool { return coordinator.Health().StreamsHealthy })
	if want := clock.Now().Add(100 * time.Second); !coordinator.Health().NextPeriodicAt.Equal(want) {
		t.Fatalf("repaired periodic = %v, want %v", coordinator.Health().NextPeriodicAt, want)
	}

	clock.Advance(99 * time.Second)
	assertNoBatch(t, started)
	clock.Advance(time.Second)
	periodic := receiveBatch(t, started)
	assertReasons(t, periodic, RefreshReasonPeriodic)
}

func TestRefreshCoordinatorDoesNotRepairMidFlightInvalidation(t *testing.T) {
	clock := newCoordinatorFakeClock()
	started := make(chan RefreshBatch, 4)
	release := make(chan struct{}, 4)
	coordinator := newTestRefreshCoordinator(t, clock, func(ctx context.Context, batch RefreshBatch) error {
		started <- batch
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	coordinator.SetStreamCovered(RefreshStreamTopology, true)
	coordinator.SetStreamCovered(RefreshStreamDelivery, true)
	coordinator.SetStreamLive(RefreshStreamTopology, true, true)
	coordinator.SetStreamLive(RefreshStreamDelivery, true, true)
	if err := coordinator.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(coordinator.Stop)
	receiveBatch(t, started)

	coordinator.InvalidateStream(RefreshStreamTopology, RefreshReasonTopology)
	release <- struct{}{}
	trailing := receiveBatch(t, started)
	assertReasons(t, trailing, RefreshReasonTopology)
	if coordinator.Health().Streams[RefreshStreamTopology].Repaired {
		t.Fatal("mid-flight invalidation was incorrectly marked repaired")
	}
	release <- struct{}{}
	waitCoordinator(t, func() bool { return coordinator.Health().StreamsHealthy })
}

func TestRefreshCoordinatorHealthIsDeepCopied(t *testing.T) {
	clock := newCoordinatorFakeClock()
	coordinator := newTestRefreshCoordinator(t, clock, func(context.Context, RefreshBatch) error { return nil })
	coordinator.SetPaused(true)
	coordinator.Notify(RefreshReasonEndpoint)
	first := coordinator.Health()
	first.PendingReasons[0] = RefreshReasonManual
	first.Streams[RefreshStreamTopology] = RefreshStreamHealth{Covered: true, Live: true, Repaired: true}
	second := coordinator.Health()
	assertReasonsSlice(t, second.PendingReasons, RefreshReasonEndpoint)
	if second.Streams[RefreshStreamTopology].Covered {
		t.Fatal("mutating returned stream map changed coordinator")
	}
}

func TestRefreshCoordinatorCallbackCannotMutateLastReasons(t *testing.T) {
	clock := newCoordinatorFakeClock()
	coordinator := newTestRefreshCoordinator(t, clock, func(_ context.Context, batch RefreshBatch) error {
		batch.Reasons[0] = RefreshReasonManual
		return nil
	})
	if err := coordinator.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(coordinator.Stop)
	waitCoordinator(t, func() bool { return !coordinator.Health().LastSuccessAt.IsZero() })
	assertReasonsSlice(t, coordinator.Health().LastReasons, RefreshReasonStartup)
}

func TestRefreshCoordinatorContextShutdownStopsAcceptingWork(t *testing.T) {
	clock := newCoordinatorFakeClock()
	started := make(chan struct{}, 1)
	ctx, cancel := context.WithCancel(context.Background())
	coordinator := newTestRefreshCoordinator(t, clock, func(ctx context.Context, _ RefreshBatch) error {
		started <- struct{}{}
		<-ctx.Done()
		return ctx.Err()
	})
	if err := coordinator.Start(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("refresh did not start")
	}
	cancel()
	waitCoordinator(t, func() bool { return !coordinator.Health().Running })
	before := append([]RefreshReason(nil), coordinator.Health().PendingReasons...)
	coordinator.Notify(RefreshReasonManual)
	if after := coordinator.Health().PendingReasons; !reflect.DeepEqual(after, before) {
		t.Fatalf("work accepted after context shutdown: before=%v after=%v", before, after)
	}
	coordinator.Stop()
}

func TestRefreshCoordinatorConcurrentOperations(t *testing.T) {
	var active atomic.Int32
	var maximum atomic.Int32
	coordinator, err := NewRefreshCoordinator(RefreshCoordinatorConfig{
		Refresh: func(context.Context, RefreshBatch) error {
			current := active.Add(1)
			defer active.Add(-1)
			for {
				old := maximum.Load()
				if current <= old || maximum.CompareAndSwap(old, current) {
					break
				}
			}
			time.Sleep(time.Microsecond)
			return nil
		},
		FallbackInterval: time.Hour,
		HealthyInterval:  time.Hour,
		Jitter:           identityRefreshJitter,
		RetryJitter:      identityRefreshJitter,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Start(context.Background()); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	for worker := range 8 {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := range 200 {
				coordinator.Notify(RefreshReasonManual)
				coordinator.InvalidateStream(RefreshStreamTopology, RefreshReasonTopology)
				coordinator.SetStreamCovered(RefreshStreamTopology, (worker+i)%2 == 0)
				coordinator.SetStreamLive(RefreshStreamTopology, i%2 == 0, i%7 == 0)
				coordinator.SetPaused(i%11 == 0)
				_ = coordinator.Health()
			}
		}(worker)
	}
	wg.Wait()
	coordinator.SetPaused(false)
	coordinator.Stop()
	if got := maximum.Load(); got > 1 {
		t.Fatalf("maximum concurrent refreshes = %d", got)
	}
}

func TestNewRefreshCoordinatorValidation(t *testing.T) {
	if _, err := NewRefreshCoordinator(RefreshCoordinatorConfig{}); err == nil {
		t.Fatal("nil refresh function was accepted")
	}
	refresh := func(context.Context, RefreshBatch) error { return nil }
	if _, err := NewRefreshCoordinator(RefreshCoordinatorConfig{Refresh: refresh, RetryBackoff: 2 * time.Second, MaxRetryBackoff: time.Second}); err == nil {
		t.Fatal("inverted retry bounds were accepted")
	}
	coordinator := newTestRefreshCoordinator(t, newCoordinatorFakeClock(), refresh)
	if err := coordinator.Start(nil); err == nil {
		t.Fatal("nil start context was accepted")
	}
	if err := coordinator.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Start(context.Background()); err == nil {
		t.Fatal("second Start was accepted")
	}
	coordinator.Stop()
}

func TestRefreshCoordinatorRetryJitterRespectsFloor(t *testing.T) {
	clock := newCoordinatorFakeClock()
	coordinator, err := NewRefreshCoordinator(RefreshCoordinatorConfig{
		Refresh: func(context.Context, RefreshBatch) error {
			return errors.New("unavailable")
		},
		FallbackInterval: time.Hour,
		HealthyInterval:  time.Hour,
		RetryBackoff:     time.Second,
		MaxRetryBackoff:  time.Second,
		Jitter:           identityRefreshJitter,
		RetryJitter: func(delay time.Duration) time.Duration {
			return delay + 500*time.Millisecond
		},
		Clock: clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(coordinator.Stop)
	waitCoordinator(t, func() bool { return coordinator.Health().ConsecutiveFailures == 1 })
	if got, want := coordinator.Health().RetryNotBefore, clock.Now().Add(1500*time.Millisecond); !got.Equal(want) {
		t.Fatalf("retry deadline = %v, want jittered %v", got, want)
	}
}

func TestDefaultRefreshRetryJitterNeverShortens(t *testing.T) {
	const delay = 10 * time.Second
	for range 100 {
		got := defaultRefreshRetryJitter(delay)
		if got < delay || got > 12*time.Second {
			t.Fatalf("retry jitter = %v, want in [%v,%v]", got, delay, 12*time.Second)
		}
	}
}

func TestRefreshCoordinatorExponentialBackoffCaps(t *testing.T) {
	for _, test := range []struct {
		failures int
		want     time.Duration
	}{
		{failures: 0, want: time.Second},
		{failures: 1, want: time.Second},
		{failures: 2, want: 2 * time.Second},
		{failures: 3, want: 4 * time.Second},
		{failures: 4, want: 8 * time.Second},
		{failures: 40, want: 8 * time.Second},
	} {
		if got := exponentialBackoff(time.Second, 8*time.Second, test.failures); got != test.want {
			t.Fatalf("failures %d: backoff = %v, want %v", test.failures, got, test.want)
		}
	}
}

func newTestRefreshCoordinator(t *testing.T, clock RefreshClock, refresh RefreshFunc) *RefreshCoordinator {
	t.Helper()
	coordinator, err := NewRefreshCoordinator(RefreshCoordinatorConfig{
		Refresh:          refresh,
		FallbackInterval: 10 * time.Second,
		HealthyInterval:  100 * time.Second,
		RetryBackoff:     time.Second,
		MaxRetryBackoff:  8 * time.Second,
		Jitter:           identityRefreshJitter,
		RetryJitter:      identityRefreshJitter,
		Clock:            clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	return coordinator
}

func identityRefreshJitter(interval time.Duration) time.Duration { return interval }

func receiveBatch(t *testing.T, batches <-chan RefreshBatch) RefreshBatch {
	t.Helper()
	select {
	case batch := <-batches:
		return batch
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for refresh")
		return RefreshBatch{}
	}
}

func assertNoBatch(t *testing.T, batches <-chan RefreshBatch) {
	t.Helper()
	select {
	case batch := <-batches:
		t.Fatalf("unexpected refresh: %+v", batch)
	case <-time.After(20 * time.Millisecond):
	}
}

func assertReasons(t *testing.T, batch RefreshBatch, reasons ...RefreshReason) {
	t.Helper()
	assertReasonsSlice(t, batch.Reasons, reasons...)
}

func assertReasonsSlice(t *testing.T, got []RefreshReason, reasons ...RefreshReason) {
	t.Helper()
	want := append([]RefreshReason(nil), reasons...)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("reasons = %v, want %v", got, want)
	}
}

func waitCoordinator(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for coordinator state")
		}
		time.Sleep(time.Millisecond)
	}
}

type coordinatorFakeClock struct {
	mu     sync.Mutex
	now    time.Time
	timers map[*coordinatorFakeTimer]struct{}
}

func newCoordinatorFakeClock() *coordinatorFakeClock {
	return &coordinatorFakeClock{
		now:    time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC),
		timers: make(map[*coordinatorFakeTimer]struct{}),
	}
}

func (c *coordinatorFakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *coordinatorFakeClock) NewTimer(delay time.Duration) RefreshTimer {
	c.mu.Lock()
	defer c.mu.Unlock()
	timer := &coordinatorFakeTimer{
		clock:    c,
		deadline: c.now.Add(delay),
		ch:       make(chan time.Time, 1),
	}
	c.timers[timer] = struct{}{}
	if delay <= 0 {
		timer.fired = true
		delete(c.timers, timer)
		timer.ch <- c.now
	}
	return timer
}

func (c *coordinatorFakeClock) Advance(delta time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(delta)
	now := c.now
	var due []*coordinatorFakeTimer
	for timer := range c.timers {
		if !timer.deadline.After(now) {
			timer.fired = true
			delete(c.timers, timer)
			due = append(due, timer)
		}
	}
	c.mu.Unlock()
	for _, timer := range due {
		timer.ch <- now
	}
}

type coordinatorFakeTimer struct {
	clock    *coordinatorFakeClock
	deadline time.Time
	ch       chan time.Time
	fired    bool
	stopped  bool
}

func (t *coordinatorFakeTimer) C() <-chan time.Time { return t.ch }

func (t *coordinatorFakeTimer) Stop() bool {
	t.clock.mu.Lock()
	defer t.clock.mu.Unlock()
	if t.fired || t.stopped {
		return false
	}
	t.stopped = true
	delete(t.clock.timers, t)
	return true
}
