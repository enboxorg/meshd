package engine

import (
	"context"
	"errors"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/enboxorg/meshnet/control/controlclient"
	"github.com/enboxorg/meshnet/tailcfg"
	"github.com/enboxorg/meshnet/types/netmap"
)

func TestDWNControlRejectsInvalidCoordinatorConfig(t *testing.T) {
	valid := func() *DWNControlConfig {
		return &DWNControlConfig{
			MapResponseFunc: func(context.Context) (*netmap.NetworkMap, error) { return nil, nil },
		}
	}
	tests := []struct {
		name string
		cfg  func() *DWNControlConfig
	}{
		{name: "nil config", cfg: func() *DWNControlConfig { return nil }},
		{name: "missing loader", cfg: func() *DWNControlConfig { return &DWNControlConfig{} }},
		{name: "negative refresh timeout", cfg: func() *DWNControlConfig {
			cfg := valid()
			cfg.RefreshTimeout = -time.Second
			return cfg
		}},
		{name: "negative startup wait", cfg: func() *DWNControlConfig {
			cfg := valid()
			cfg.StartupSubscriptionWait = -time.Second
			return cfg
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if cc, err := NewDWNControl(tc.cfg(), controlclient.Options{SkipStartForTests: true}); err == nil {
				cc.Shutdown()
				t.Fatal("NewDWNControl unexpectedly succeeded")
			}
		})
	}
}

func TestDWNControlCoordinatorFirstSuccessReplaysLoadedMap(t *testing.T) {
	var loads atomic.Int32
	var mapResults atomic.Int32
	var applies atomic.Int32
	peerValid := make(chan bool, 2)

	observer := dwnControlObserverFunc(func(client controlclient.Client, status controlclient.Status) {
		if status.NetMap == nil {
			return
		}
		call := applies.Add(1)
		valid := len(status.NetMap.Peers) == 1 && status.NetMap.Peers[0].Valid()
		if call == 1 {
			// Mutate the backing slice, not just its header. The startup replay
			// must own an independent slice captured before this callback.
			status.NetMap.Peers[0] = tailcfg.NodeView{}
		}
		peerValid <- valid
		// LocalBackend feeds Login back to a control client while applying
		// status. DWN login is intentionally a no-op: startup already queued
		// the load, and feedback must not create a trailing remote rebuild.
		client.Login(0)
	})

	cc, err := NewDWNControl(&DWNControlConfig{
		MapResponseFunc: func(context.Context) (*netmap.NetworkMap, error) {
			loads.Add(1)
			return routingTestNetMap(), nil
		},
		OnMapResult: func(context.Context, *netmap.NetworkMap, error) {
			mapResults.Add(1)
		},
		PollInterval: time.Hour,
		Logf:         func(string, ...any) {},
	}, controlclient.Options{Observer: observer, SkipStartForTests: true})
	if err != nil {
		t.Fatalf("NewDWNControl: %v", err)
	}
	defer cc.Shutdown()

	if err := cc.coordinator.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	waitForDWNControlCondition(t, func() bool {
		health := cc.RefreshHealth()
		return !health.InFlight && len(health.PendingReasons) == 0 && !health.LastSuccessAt.IsZero()
	})
	if got := loads.Load(); got != 1 {
		t.Fatalf("remote loads = %d, want 1", got)
	}
	if got := applies.Load(); got != 2 {
		t.Fatalf("observer applies = %d, want 2", got)
	}
	if got := mapResults.Load(); got != 1 {
		t.Fatalf("map-result callbacks = %d, want 1", got)
	}
	for apply := 1; apply <= 2; apply++ {
		select {
		case valid := <-peerValid:
			if !valid {
				t.Fatalf("apply %d received mutated peer slice", apply)
			}
		case <-time.After(time.Second):
			t.Fatalf("timed out waiting for observer apply %d", apply)
		}
	}
}

func TestDWNControlCoordinatorCancellationSuppressesReplay(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var applies atomic.Int32
	var mapResults atomic.Int32
	observer := dwnControlObserverFunc(func(_ controlclient.Client, status controlclient.Status) {
		if status.NetMap != nil {
			applies.Add(1)
			cancel()
		}
	})

	cc, err := NewDWNControl(&DWNControlConfig{
		MapResponseFunc: func(context.Context) (*netmap.NetworkMap, error) {
			return routingTestNetMap(), nil
		},
		OnMapResult: func(context.Context, *netmap.NetworkMap, error) {
			mapResults.Add(1)
		},
		PollInterval: time.Hour,
		Logf:         func(string, ...any) {},
	}, controlclient.Options{Observer: observer, SkipStartForTests: true})
	if err != nil {
		t.Fatalf("NewDWNControl: %v", err)
	}
	defer cc.Shutdown()

	err = cc.refreshControlState(ctx, RefreshBatch{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("refreshControlState error = %v, want context canceled", err)
	}
	if got := applies.Load(); got != 1 {
		t.Fatalf("observer applies = %d, want only the initial apply", got)
	}
	if got := mapResults.Load(); got != 1 {
		t.Fatalf("map-result callbacks = %d, want 1", got)
	}
}

func TestDWNControlCoordinatorRetriesDirtyFirstLoadThenReplaysSuccess(t *testing.T) {
	loadErr := errors.New("initial DWN load failed")
	var loads atomic.Int32
	var mapResults atomic.Int32
	statuses := make(chan controlclient.Status, 3)
	observer := dwnControlObserverFunc(func(_ controlclient.Client, status controlclient.Status) {
		statuses <- status
	})

	cc, err := NewDWNControl(&DWNControlConfig{
		MapResponseFunc: func(context.Context) (*netmap.NetworkMap, error) {
			if loads.Add(1) == 1 {
				return nil, loadErr
			}
			return routingTestNetMap(), nil
		},
		OnMapResult: func(context.Context, *netmap.NetworkMap, error) {
			mapResults.Add(1)
		},
		PollInterval: time.Hour,
		Logf:         func(string, ...any) {},
	}, controlclient.Options{Observer: observer, SkipStartForTests: true})
	if err != nil {
		t.Fatalf("NewDWNControl: %v", err)
	}
	defer cc.Shutdown()

	clock := newCoordinatorFakeClock()
	cc.coordinator, err = NewRefreshCoordinator(RefreshCoordinatorConfig{
		Refresh:          cc.refreshControlState,
		FallbackInterval: time.Hour,
		HealthyInterval:  2 * time.Hour,
		RetryBackoff:     time.Second,
		MaxRetryBackoff:  time.Second,
		Jitter:           identityRefreshJitter,
		RetryJitter:      identityRefreshJitter,
		Clock:            clock,
	})
	if err != nil {
		t.Fatalf("NewRefreshCoordinator: %v", err)
	}
	if err := cc.coordinator.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}

	first := receiveDWNControlStatus(t, statuses)
	if !errors.Is(first.Err, loadErr) {
		t.Fatalf("first observer error = %v, want %v", first.Err, loadErr)
	}
	waitForDWNControlCondition(t, func() bool {
		return cc.RefreshHealth().ConsecutiveFailures == 1
	})
	health := cc.RefreshHealth()
	if !reflect.DeepEqual(health.PendingReasons, []RefreshReason{RefreshReasonStartup}) {
		t.Fatalf("pending reasons after failure = %v, want startup", health.PendingReasons)
	}
	if !health.RetryNotBefore.Equal(clock.Now().Add(time.Second)) {
		t.Fatalf("retry deadline = %v, want %v", health.RetryNotBefore, clock.Now().Add(time.Second))
	}

	clock.Advance(time.Second)
	for apply := 1; apply <= 2; apply++ {
		status := receiveDWNControlStatus(t, statuses)
		if status.Err != nil || status.NetMap == nil {
			t.Fatalf("successful apply %d = %+v", apply, status)
		}
	}
	waitForDWNControlCondition(t, func() bool {
		health := cc.RefreshHealth()
		return !health.InFlight && health.ConsecutiveFailures == 0 && health.LastError == ""
	})
	if got := loads.Load(); got != 2 {
		t.Fatalf("remote loads = %d, want 2", got)
	}
	if got := mapResults.Load(); got != 2 {
		t.Fatalf("map-result callbacks = %d, want 2", got)
	}
	if got := cc.RefreshHealth().PendingReasons; len(got) != 0 {
		t.Fatalf("pending reasons after success = %v", got)
	}
}

func TestDWNControlCoordinatorBoundsRefreshWithTimeout(t *testing.T) {
	observerErrors := make(chan error, 1)
	resultErrors := make(chan error, 1)
	observer := dwnControlObserverFunc(func(_ controlclient.Client, status controlclient.Status) {
		if status.Err != nil {
			observerErrors <- status.Err
		}
	})

	cc, err := NewDWNControl(&DWNControlConfig{
		MapResponseFunc: func(ctx context.Context) (*netmap.NetworkMap, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
		OnMapResult: func(_ context.Context, _ *netmap.NetworkMap, err error) {
			resultErrors <- err
		},
		PollInterval:   time.Hour,
		RefreshTimeout: 20 * time.Millisecond,
		Logf:           func(string, ...any) {},
	}, controlclient.Options{Observer: observer, SkipStartForTests: true})
	if err != nil {
		t.Fatalf("NewDWNControl: %v", err)
	}
	defer cc.Shutdown()

	err = cc.refreshControlState(context.Background(), RefreshBatch{})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("refreshControlState error = %v, want deadline exceeded", err)
	}
	if got := receiveDWNControlError(t, observerErrors); !errors.Is(got, context.DeadlineExceeded) {
		t.Fatalf("observer error = %v, want deadline exceeded", got)
	}
	if got := receiveDWNControlError(t, resultErrors); !errors.Is(got, context.DeadlineExceeded) {
		t.Fatalf("map-result error = %v, want deadline exceeded", got)
	}
}

func TestDWNControlCoordinatorCoalescesPreStartAndMidFlightNotify(t *testing.T) {
	var loads atomic.Int32
	var applies atomic.Int32
	var mapResults atomic.Int32
	started := make(chan int32, 2)
	releaseFirst := make(chan struct{})
	observer := dwnControlObserverFunc(func(_ controlclient.Client, status controlclient.Status) {
		if status.NetMap != nil {
			applies.Add(1)
		}
	})

	cc, err := NewDWNControl(&DWNControlConfig{
		MapResponseFunc: func(ctx context.Context) (*netmap.NetworkMap, error) {
			call := loads.Add(1)
			started <- call
			if call == 1 {
				select {
				case <-releaseFirst:
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
			return routingTestNetMap(), nil
		},
		OnMapResult: func(context.Context, *netmap.NetworkMap, error) {
			mapResults.Add(1)
		},
		PollInterval: time.Hour,
		Logf:         func(string, ...any) {},
	}, controlclient.Options{Observer: observer, SkipStartForTests: true})
	if err != nil {
		t.Fatalf("NewDWNControl: %v", err)
	}
	defer cc.Shutdown()

	cc.Notify()
	cc.Notify()
	if err := cc.coordinator.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if call := receiveDWNControlLoad(t, started); call != 1 {
		t.Fatalf("first load number = %d, want 1", call)
	}
	cc.Notify()
	cc.Notify()
	close(releaseFirst)
	if call := receiveDWNControlLoad(t, started); call != 2 {
		t.Fatalf("trailing load number = %d, want 2", call)
	}

	waitForDWNControlCondition(t, func() bool {
		health := cc.RefreshHealth()
		return !health.InFlight && len(health.PendingReasons) == 0 && !health.LastSuccessAt.IsZero()
	})
	if got := loads.Load(); got != 2 {
		t.Fatalf("remote loads = %d, want one initial and one trailing load", got)
	}
	if got := applies.Load(); got != 3 {
		t.Fatalf("observer applies = %d, want initial, replay, and trailing", got)
	}
	if got := mapResults.Load(); got != 2 {
		t.Fatalf("map-result callbacks = %d, want 2", got)
	}
}

func TestDWNControlCoordinatorPauseRetainsPendingUntilOneUnpausedLoad(t *testing.T) {
	var loads atomic.Int32
	started := make(chan struct{}, 1)
	cc, err := NewDWNControl(&DWNControlConfig{
		MapResponseFunc: func(context.Context) (*netmap.NetworkMap, error) {
			loads.Add(1)
			started <- struct{}{}
			return nil, nil
		},
		PollInterval: time.Hour,
		Logf:         func(string, ...any) {},
	}, controlclient.Options{SkipStartForTests: true})
	if err != nil {
		t.Fatalf("NewDWNControl: %v", err)
	}
	defer cc.Shutdown()

	cc.SetPaused(true)
	cc.Notify()
	cc.Notify()
	if err := cc.coordinator.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	waitForDWNControlCondition(t, func() bool {
		health := cc.RefreshHealth()
		return health.Running && health.Paused
	})
	if got := loads.Load(); got != 0 {
		t.Fatalf("loads while paused = %d, want 0", got)
	}
	if got := cc.RefreshHealth().PendingReasons; !reflect.DeepEqual(got, []RefreshReason{RefreshReasonManual, RefreshReasonStartup}) {
		t.Fatalf("pending reasons while paused = %v, want manual and startup", got)
	}

	cc.SetPaused(false)
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for unpaused refresh")
	}
	waitForDWNControlCondition(t, func() bool {
		health := cc.RefreshHealth()
		return !health.InFlight && len(health.PendingReasons) == 0 && !health.LastSuccessAt.IsZero()
	})
	if got := loads.Load(); got != 1 {
		t.Fatalf("loads after unpause = %d, want 1", got)
	}
}

func TestDWNControlPollLoopWaitsForLiveStreamsBeforeStartupLoad(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	loads := make(chan struct{}, 2)
	cc, err := NewDWNControl(&DWNControlConfig{
		MapResponseFunc: func(context.Context) (*netmap.NetworkMap, error) {
			loads <- struct{}{}
			return nil, nil
		},
		PollInterval:            time.Hour,
		StartupSubscriptionWait: time.Second,
		Logf:                    func(string, ...any) {},
	}, controlclient.Options{SkipStartForTests: true})
	if err != nil {
		t.Fatalf("NewDWNControl: %v", err)
	}
	defer cc.Shutdown()

	cc.coordinator.SetStreamCovered(RefreshStreamTopology, true)
	cc.coordinator.SetStreamCovered(RefreshStreamDelivery, true)
	go cc.pollLoop(ctx)

	select {
	case <-loads:
		t.Fatal("startup loaded before covered streams became live")
	case <-time.After(100 * time.Millisecond):
	}

	cc.coordinator.SetStreamLive(RefreshStreamTopology, true, true)
	cc.coordinator.SetStreamLive(RefreshStreamDelivery, true, true)
	select {
	case <-loads:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for post-subscribe startup load")
	}
	waitForDWNControlCondition(t, func() bool {
		health := cc.RefreshHealth()
		return !health.InFlight && health.StreamsHealthy
	})
	select {
	case <-loads:
		t.Fatal("post-subscribe startup performed a duplicate remote load")
	case <-time.After(100 * time.Millisecond):
	}
}

func TestRefreshStreamsReadyForStartup(t *testing.T) {
	tests := []struct {
		name    string
		streams map[RefreshStream]RefreshStreamHealth
		want    bool
	}{
		{name: "unconfigured", streams: map[RefreshStream]RefreshStreamHealth{}, want: false},
		{name: "role delivery live", streams: map[RefreshStream]RefreshStreamHealth{
			RefreshStreamDelivery: {Covered: true, Live: true},
		}, want: true},
		{name: "covered delivery connecting", streams: map[RefreshStream]RefreshStreamHealth{
			RefreshStreamDelivery: {Covered: true},
		}, want: false},
		{name: "both live", streams: map[RefreshStream]RefreshStreamHealth{
			RefreshStreamTopology: {Covered: true, Live: true},
			RefreshStreamDelivery: {Covered: true, Live: true},
		}, want: true},
		{name: "topology connecting", streams: map[RefreshStream]RefreshStreamHealth{
			RefreshStreamTopology: {Covered: true},
			RefreshStreamDelivery: {Covered: true, Live: true},
		}, want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := refreshStreamsReadyForStartup(RefreshCoordinatorHealth{Streams: tc.streams}); got != tc.want {
				t.Fatalf("ready = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestDWNControlCoordinatorUsesConfiguredRefreshIntervals(t *testing.T) {
	const (
		fallback = 17 * time.Second
		healthy  = 91 * time.Second
		timeout  = 3 * time.Second
		startup  = 4 * time.Second
	)
	cc, err := NewDWNControl(&DWNControlConfig{
		MapResponseFunc:         func(context.Context) (*netmap.NetworkMap, error) { return nil, nil },
		PollInterval:            fallback,
		HealthyPollInterval:     healthy,
		RefreshTimeout:          timeout,
		StartupSubscriptionWait: startup,
		Logf:                    func(string, ...any) {},
	}, controlclient.Options{SkipStartForTests: true})
	if err != nil {
		t.Fatalf("NewDWNControl: %v", err)
	}
	defer cc.Shutdown()

	if got := cc.config.PollInterval; got != fallback {
		t.Fatalf("control fallback interval = %v, want %v", got, fallback)
	}
	if got := cc.config.HealthyPollInterval; got != healthy {
		t.Fatalf("control healthy interval = %v, want %v", got, healthy)
	}
	if got := cc.config.RefreshTimeout; got != timeout {
		t.Fatalf("control refresh timeout = %v, want %v", got, timeout)
	}
	if got := cc.config.StartupSubscriptionWait; got != startup {
		t.Fatalf("control startup subscription wait = %v, want %v", got, startup)
	}
	if got := cc.coordinator.fallbackInterval; got != fallback {
		t.Fatalf("coordinator fallback interval = %v, want %v", got, fallback)
	}
	if got := cc.coordinator.healthyInterval; got != healthy {
		t.Fatalf("coordinator healthy interval = %v, want %v", got, healthy)
	}
	if got := cc.coordinator.debounce; got != 250*time.Millisecond {
		t.Fatalf("coordinator debounce = %v, want 250ms", got)
	}
	if got := cc.coordinator.maxDebounce; got != time.Second {
		t.Fatalf("coordinator max debounce = %v, want 1s", got)
	}
}

type dwnControlObserverFunc func(controlclient.Client, controlclient.Status)

func (f dwnControlObserverFunc) SetControlClientStatus(client controlclient.Client, status controlclient.Status) {
	f(client, status)
}

func receiveDWNControlStatus(t *testing.T, statuses <-chan controlclient.Status) controlclient.Status {
	t.Helper()
	select {
	case status := <-statuses:
		return status
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for control status")
		return controlclient.Status{}
	}
}

func receiveDWNControlError(t *testing.T, errors <-chan error) error {
	t.Helper()
	select {
	case err := <-errors:
		return err
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for control error")
		return nil
	}
}

func receiveDWNControlLoad(t *testing.T, loads <-chan int32) int32 {
	t.Helper()
	select {
	case load := <-loads:
		return load
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for control load")
		return 0
	}
}

func waitForDWNControlCondition(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for DWN control condition")
		}
		time.Sleep(time.Millisecond)
	}
}
