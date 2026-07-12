package engine

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/enboxorg/meshd/internal/control"
	"github.com/enboxorg/meshnet/control/controlclient"
	"github.com/enboxorg/meshnet/tailcfg"
	"github.com/enboxorg/meshnet/types/netmap"
)

func TestPeerExpirySchedulerSchedulesNearestFuturePeer(t *testing.T) {
	clock := newCoordinatorFakeClock()
	now := clock.Now()
	notified := make(chan struct{}, 1)
	scheduler := newPeerExpiryScheduler(clock, func() { notified <- struct{}{} })
	t.Cleanup(scheduler.Stop)

	expired := &tailcfg.Node{KeyExpiry: now.Add(5 * time.Minute), Expired: true}
	scheduler.Schedule(&netmap.NetworkMap{
		SelfNode: (&tailcfg.Node{KeyExpiry: now.Add(time.Hour)}).View(),
		Peers: []tailcfg.NodeView{
			(&tailcfg.Node{}).View(),
			(&tailcfg.Node{KeyExpiry: now.Add(-time.Minute)}).View(),
			(&tailcfg.Node{KeyExpiry: now}).View(),
			expired.View(),
			(&tailcfg.Node{KeyExpiry: now.Add(20 * time.Minute)}).View(),
			(&tailcfg.Node{KeyExpiry: now.Add(10 * time.Minute)}).View(),
		},
	})

	timer, _ := activePeerExpiryTimer(t, scheduler)
	if got, want := timer.deadline, now.Add(10*time.Minute); !got.Equal(want) {
		t.Fatalf("deadline = %v, want nearest peer expiry %v", got, want)
	}

	clock.Advance(10 * time.Minute)
	receivePeerExpiryNotification(t, notified)
	if timer, _ := currentPeerExpiryTimer(scheduler); timer != nil {
		t.Fatal("fired timer remains active")
	}
}

func TestPeerExpirySchedulerDefersToSelfExpiry(t *testing.T) {
	clock := newCoordinatorFakeClock()
	now := clock.Now()
	var calls atomic.Int32
	scheduler := newPeerExpiryScheduler(clock, func() { calls.Add(1) })
	t.Cleanup(scheduler.Stop)

	tests := []struct {
		name string
		nm   *netmap.NetworkMap
	}{
		{
			name: "self only",
			nm:   expiryTestNetMap(now.Add(10 * time.Minute)),
		},
		{
			name: "peer at self deadline",
			nm:   expiryTestNetMap(now.Add(10*time.Minute), now.Add(10*time.Minute)),
		},
		{
			name: "peer after self",
			nm:   expiryTestNetMap(now.Add(10*time.Minute), now.Add(20*time.Minute)),
		},
		{
			name: "self already expired",
			nm:   expiryTestNetMap(now.Add(-time.Minute), now.Add(20*time.Minute)),
		},
		{
			name: "self expires now",
			nm:   expiryTestNetMap(now, now.Add(20*time.Minute)),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			scheduler.Schedule(test.nm)
			if timer, _ := currentPeerExpiryTimer(scheduler); timer != nil {
				t.Fatalf("scheduled peer projection after terminal self expiry: %#v", timer)
			}
		})
	}

	clock.Advance(time.Hour)
	if got := calls.Load(); got != 0 {
		t.Fatalf("self expiry queued %d local refreshes, want 0", got)
	}

	scheduler.Schedule(expiryTestNetMap(now.Add(2*time.Hour), clock.Now().Add(10*time.Minute)))
	timer, _ := activePeerExpiryTimer(t, scheduler)
	if got, want := timer.deadline, clock.Now().Add(10*time.Minute); !got.Equal(want) {
		t.Fatalf("renewed schedule deadline = %v, want %v", got, want)
	}
}

func TestPeerExpirySchedulerReplacementCancelsAndFencesStaleCallback(t *testing.T) {
	clock := newCoordinatorFakeClock()
	now := clock.Now()
	notified := make(chan struct{}, 1)
	scheduler := newPeerExpiryScheduler(clock, func() { notified <- struct{}{} })
	t.Cleanup(scheduler.Stop)

	scheduler.Schedule(expiryTestNetMap(time.Time{}, now.Add(10*time.Minute)))
	oldTimer, oldGeneration := activePeerExpiryTimer(t, scheduler)
	scheduler.mu.Lock()
	oldCancel := scheduler.cancel
	scheduler.mu.Unlock()

	scheduler.Schedule(expiryTestNetMap(time.Time{}, now.Add(20*time.Minute)))
	newTimer, newGeneration := activePeerExpiryTimer(t, scheduler)
	if newGeneration == oldGeneration || newTimer == oldTimer {
		t.Fatalf("replacement did not create a new generation: old=%d new=%d", oldGeneration, newGeneration)
	}
	if !fakeTimerStopped(clock, oldTimer) {
		t.Fatal("replaced timer was not stopped")
	}
	select {
	case <-oldCancel:
	default:
		t.Fatal("replaced timer waiter was not canceled")
	}

	// Model an AfterFunc-style callback that was already runnable when Stop
	// won. The generation and active-timer fence must reject it.
	scheduler.fire(oldGeneration)
	assertNoPeerExpiryNotification(t, notified)

	clock.Advance(20 * time.Minute)
	receivePeerExpiryNotification(t, notified)
}

func TestPeerExpirySchedulerStopCancelsAndPreventsReschedule(t *testing.T) {
	clock := newCoordinatorFakeClock()
	now := clock.Now()
	notified := make(chan struct{}, 1)
	scheduler := newPeerExpiryScheduler(clock, func() { notified <- struct{}{} })

	scheduler.Schedule(expiryTestNetMap(time.Time{}, now.Add(10*time.Minute)))
	timer, generation := activePeerExpiryTimer(t, scheduler)
	scheduler.mu.Lock()
	cancel := scheduler.cancel
	scheduler.mu.Unlock()

	scheduler.Stop()
	scheduler.Stop()
	if !fakeTimerStopped(clock, timer) {
		t.Fatal("shutdown did not stop active expiry timer")
	}
	select {
	case <-cancel:
	default:
		t.Fatal("shutdown did not cancel expiry waiter")
	}

	scheduler.fire(generation)
	scheduler.Schedule(expiryTestNetMap(time.Time{}, now.Add(20*time.Minute)))
	if timer, _ := currentPeerExpiryTimer(scheduler); timer != nil {
		t.Fatal("stopped scheduler accepted a new deadline")
	}
	assertNoPeerExpiryNotification(t, notified)
}

func TestDWNControlReplacesPeerExpiryScheduleAndStopsItOnShutdown(t *testing.T) {
	clock := newCoordinatorFakeClock()
	now := clock.Now()
	maps := []*netmap.NetworkMap{
		expiryTestNetMap(time.Time{}, now.Add(10*time.Minute)),
		expiryTestNetMap(time.Time{}, now.Add(20*time.Minute)),
	}
	var loads atomic.Int32
	observer := dwnControlObserverFunc(func(controlclient.Client, controlclient.Status) {})

	cc, err := NewDWNControl(&DWNControlConfig{
		MapResponseFunc: func(context.Context) (*netmap.NetworkMap, error) {
			index := int(loads.Add(1)) - 1
			return maps[index], nil
		},
		ExpiryClock: clock,
		Logf:        func(string, ...any) {},
	}, controlclient.Options{Observer: observer, SkipStartForTests: true})
	if err != nil {
		t.Fatalf("NewDWNControl: %v", err)
	}

	if _, err := cc.loadAndPush(context.Background(), RefreshBatch{Reasons: []RefreshReason{RefreshReasonStartup}}); err != nil {
		t.Fatalf("first loadAndPush: %v", err)
	}
	first, firstGeneration := activePeerExpiryTimer(t, cc.peerExpiry)
	if got, want := first.deadline, now.Add(10*time.Minute); !got.Equal(want) {
		t.Fatalf("first deadline = %v, want %v", got, want)
	}

	if _, err := cc.loadAndPush(context.Background(), RefreshBatch{Reasons: []RefreshReason{RefreshReasonPeriodic}}); err != nil {
		t.Fatalf("second loadAndPush: %v", err)
	}
	second, secondGeneration := activePeerExpiryTimer(t, cc.peerExpiry)
	if secondGeneration == firstGeneration || !fakeTimerStopped(clock, first) {
		t.Fatalf("successful replacement did not cancel first schedule: generations %d -> %d", firstGeneration, secondGeneration)
	}
	if got, want := second.deadline, now.Add(20*time.Minute); !got.Equal(want) {
		t.Fatalf("second deadline = %v, want %v", got, want)
	}

	cc.Shutdown()
	if !fakeTimerStopped(clock, second) {
		t.Fatal("DWNControl shutdown did not stop expiry schedule")
	}
	cc.peerExpiry.mu.Lock()
	stopped := cc.peerExpiry.stopped
	cc.peerExpiry.mu.Unlock()
	if !stopped {
		t.Fatal("DWNControl shutdown did not stop expiry scheduler")
	}
}

func TestDWNControlSelfOnlyExpiryQueuesNoRefresh(t *testing.T) {
	clock := newCoordinatorFakeClock()
	now := clock.Now()
	var loads atomic.Int32
	cc, err := NewDWNControl(&DWNControlConfig{
		MapResponseFunc: func(context.Context) (*netmap.NetworkMap, error) {
			loads.Add(1)
			return expiryTestNetMap(now.Add(10 * time.Minute)), nil
		},
		ExpiryClock: clock,
		Logf:        func(string, ...any) {},
	}, controlclient.Options{
		Observer:          dwnControlObserverFunc(func(controlclient.Client, controlclient.Status) {}),
		SkipStartForTests: true,
	})
	if err != nil {
		t.Fatalf("NewDWNControl: %v", err)
	}
	defer cc.Shutdown()

	if _, err := cc.loadAndPush(context.Background(), RefreshBatch{Reasons: []RefreshReason{RefreshReasonStartup}}); err != nil {
		t.Fatalf("loadAndPush: %v", err)
	}
	if timer, _ := currentPeerExpiryTimer(cc.peerExpiry); timer != nil {
		t.Fatal("self-only expiry created a coordinator timer")
	}
	clock.Advance(time.Hour)
	if got := loads.Load(); got != 1 {
		t.Fatalf("self-only expiry caused %d loads, want initial load only", got)
	}
	if pending := cc.RefreshHealth().PendingReasons; len(pending) != 0 {
		t.Fatalf("self-only expiry queued refresh reasons: %v", pending)
	}
}

func TestExpiryOnlyRefreshUsesLocalMaterializer(t *testing.T) {
	response := &control.MapResponse{}
	loader := &recordingControlStateLoader{
		applyResponse: response,
		loadError:     errors.New("full load must not run"),
	}
	fn := refreshMapResponseFunc(loader, NewConverter("mesh.test"), nil)

	if _, err := fn(context.Background(), RefreshBatch{Reasons: []RefreshReason{RefreshReasonExpiry}}); err != nil {
		t.Fatalf("expiry refresh: %v", err)
	}
	if len(loader.calls) != 1 || loader.calls[0] != "apply" {
		t.Fatalf("loader calls = %v, want [apply]", loader.calls)
	}
}

func TestExpiryRepairSentinelFallsBackToFullReconciliation(t *testing.T) {
	loader := &recordingControlStateLoader{
		applyError:   control.ErrFullReconciliationRequired,
		loadResponse: &control.MapResponse{},
	}
	fn := refreshMapResponseFunc(loader, NewConverter("mesh.test"), nil)

	if _, err := fn(context.Background(), RefreshBatch{Reasons: []RefreshReason{RefreshReasonExpiry}}); err != nil {
		t.Fatalf("expiry repair refresh: %v", err)
	}
	if len(loader.calls) != 2 || loader.calls[0] != "apply" || loader.calls[1] != "load" {
		t.Fatalf("loader calls = %v, want [apply load]", loader.calls)
	}
}

func expiryTestNetMap(selfExpiry time.Time, peerExpiries ...time.Time) *netmap.NetworkMap {
	nm := &netmap.NetworkMap{SelfNode: (&tailcfg.Node{KeyExpiry: selfExpiry}).View()}
	for _, expiry := range peerExpiries {
		nm.Peers = append(nm.Peers, (&tailcfg.Node{KeyExpiry: expiry}).View())
	}
	return nm
}

func activePeerExpiryTimer(t *testing.T, scheduler *peerExpiryScheduler) (*coordinatorFakeTimer, uint64) {
	t.Helper()
	timer, generation := currentPeerExpiryTimer(scheduler)
	if timer == nil {
		t.Fatal("no active peer expiry timer")
	}
	return timer, generation
}

func currentPeerExpiryTimer(scheduler *peerExpiryScheduler) (*coordinatorFakeTimer, uint64) {
	scheduler.mu.Lock()
	defer scheduler.mu.Unlock()
	if scheduler.timer == nil {
		return nil, scheduler.generation
	}
	return scheduler.timer.(*coordinatorFakeTimer), scheduler.generation
}

func fakeTimerStopped(clock *coordinatorFakeClock, timer *coordinatorFakeTimer) bool {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return timer.stopped
}

func receivePeerExpiryNotification(t *testing.T, notified <-chan struct{}) {
	t.Helper()
	select {
	case <-notified:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for peer expiry notification")
	}
}

func assertNoPeerExpiryNotification(t *testing.T, notified <-chan struct{}) {
	t.Helper()
	select {
	case <-notified:
		t.Fatal("unexpected peer expiry notification")
	default:
	}
}

func TestDWNControlPeerExpiryQueuesOnlyLocalReason(t *testing.T) {
	clock := newCoordinatorFakeClock()
	now := clock.Now()
	var loads atomic.Int32
	cc, err := NewDWNControl(&DWNControlConfig{
		MapResponseFunc: func(context.Context) (*netmap.NetworkMap, error) {
			loads.Add(1)
			return expiryTestNetMap(time.Time{}, now.Add(10*time.Minute)), nil
		},
		ExpiryClock: clock,
		Logf:        func(string, ...any) {},
	}, controlclient.Options{
		Observer:          dwnControlObserverFunc(func(controlclient.Client, controlclient.Status) {}),
		SkipStartForTests: true,
	})
	if err != nil {
		t.Fatalf("NewDWNControl: %v", err)
	}
	defer cc.Shutdown()

	if _, err := cc.loadAndPush(context.Background(), RefreshBatch{Reasons: []RefreshReason{RefreshReasonStartup}}); err != nil {
		t.Fatalf("loadAndPush: %v", err)
	}
	_, generation := activePeerExpiryTimer(t, cc.peerExpiry)
	before := cc.RefreshHealth()
	cc.peerExpiry.fire(generation)
	after := cc.RefreshHealth()

	if len(after.PendingReasons) != 1 || after.PendingReasons[0] != RefreshReasonExpiry {
		t.Fatalf("pending reasons = %v, want [%s]", after.PendingReasons, RefreshReasonExpiry)
	}
	for _, stream := range []RefreshStream{RefreshStreamTopology, RefreshStreamDelivery} {
		if after.Streams[stream] != before.Streams[stream] {
			t.Fatalf("%s stream health changed on local expiry: before=%+v after=%+v", stream, before.Streams[stream], after.Streams[stream])
		}
	}
	if got := loads.Load(); got != 1 {
		t.Fatalf("expiry notification ran %d loads before coordinator execution, want initial load only", got)
	}
}
