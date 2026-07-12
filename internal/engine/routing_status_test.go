package engine

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/enboxorg/meshnet/control/controlclient"
	"github.com/enboxorg/meshnet/tailcfg"
	"github.com/enboxorg/meshnet/types/netmap"
	"github.com/enboxorg/meshnet/wgengine/router"
)

func TestRoutingStatusUserspaceReady(t *testing.T) {
	eng := newRoutingTestEngine(false, nil, discardRoutingLogger())
	ctx := context.Background()
	want := RoutingStatus{Ready: true, Phase: RoutingPhaseUserspace}
	if got := eng.RoutingStatus(); got != want {
		t.Fatalf("RoutingStatus() = %+v, want %+v", got, want)
	}
	if err := eng.reconcileTUNRoutes(ctx); err != nil {
		t.Fatalf("userspace reconcile = %v, want nil", err)
	}
	eng.handleControlMapResult(ctx, nil, errors.New("control unavailable"))
	if got := eng.RoutingStatus(); got != want {
		t.Fatalf("userspace status after control error = %+v, want %+v", got, want)
	}
}

func TestRoutingStatusWaitsForUsableNetworkMap(t *testing.T) {
	rtr := &scriptedRoutingRouter{}
	eng := newRoutingTestEngine(true, rtr, discardRoutingLogger())
	assertRoutingStatus(t, eng, RoutingStatus{Required: true, Phase: RoutingPhaseSyncing})

	eng.handleControlMapResult(context.Background(), nil, nil)
	status := eng.RoutingStatus()
	if !status.Required || status.Ready || status.Phase != RoutingPhaseSyncing ||
		status.LastError != "no usable network map addresses yet" {
		t.Fatalf("status without network map = %+v", status)
	}
	if calls := rtr.SetCalls(); calls != 0 {
		t.Fatalf("router Set calls without network map = %d, want 0", calls)
	}

	eng.handleControlMapResult(context.Background(), routingTestNetMap(), nil)
	assertRoutingStatus(t, eng, RoutingStatus{Required: true, Ready: true, Phase: RoutingPhaseReady})
	if calls := rtr.SetCalls(); calls != 1 {
		t.Fatalf("router Set calls = %d, want 1", calls)
	}
}

func TestRoutingStatusControlFailureThenRecovery(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	eng := newRoutingTestEngine(true, &scriptedRoutingRouter{}, logger)
	ctx := context.Background()
	mapErr := errors.New("DWN rate limited")

	eng.handleControlMapResult(ctx, nil, mapErr)
	eng.handleControlMapResult(ctx, nil, mapErr)
	status := eng.RoutingStatus()
	if status.Ready || status.Phase != RoutingPhaseError ||
		status.LastError != "loading control map: DWN rate limited" {
		t.Fatalf("status after control failure = %+v", status)
	}
	if got := strings.Count(logs.String(), `"msg":"mesh control map load failed"`); got != 1 {
		t.Fatalf("control warning log count = %d, want 1; logs:\n%s", got, logs.String())
	}

	eng.handleControlMapResult(ctx, routingTestNetMap(), nil)
	assertRoutingStatus(t, eng, RoutingStatus{Required: true, Ready: true, Phase: RoutingPhaseReady})
	if got := strings.Count(logs.String(), `"msg":"mesh routing recovered"`); got != 1 {
		t.Fatalf("recovery log count = %d, want 1; logs:\n%s", got, logs.String())
	}
}

func TestRoutingStatusRouterFailureRetriesWithoutWarningSpam(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	rtr := &scriptedRoutingRouter{setErrors: []error{
		errors.New("route command failed"),
		errors.New("route command failed differently"),
		nil,
	}}
	eng := newRoutingTestEngine(true, rtr, logger)
	ctx := context.Background()
	nm := routingTestNetMap()

	eng.handleControlMapResult(ctx, nm, nil)
	status := eng.RoutingStatus()
	if status.Ready || status.Phase != RoutingPhaseError ||
		!strings.Contains(status.LastError, "configuring OS routes: route command failed") {
		t.Fatalf("status after router failure = %+v", status)
	}
	eng.handleControlMapResult(ctx, nm, nil)
	if got := eng.RoutingStatus().LastError; !strings.Contains(got, "failed differently") {
		t.Fatalf("retry error = %q, want latest router error", got)
	}
	eng.handleControlMapResult(ctx, nm, nil)
	assertRoutingStatus(t, eng, RoutingStatus{Required: true, Ready: true, Phase: RoutingPhaseReady})

	if got := strings.Count(logs.String(), `"level":"WARN"`); got != 1 {
		t.Fatalf("warning log count = %d, want 1; logs:\n%s", got, logs.String())
	}
	if got := strings.Count(logs.String(), `"msg":"mesh routing recovered"`); got != 1 {
		t.Fatalf("recovery log count = %d, want 1; logs:\n%s", got, logs.String())
	}
}

func TestRoutingStatusWarnsForDistinctControlAndRouterFailures(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	rtr := &scriptedRoutingRouter{setErrors: []error{
		errors.New("route command failed"),
		nil,
	}}
	eng := newRoutingTestEngine(true, rtr, logger)
	ctx := context.Background()

	eng.handleControlMapResult(ctx, nil, errors.New("control unavailable"))
	eng.handleControlMapResult(ctx, routingTestNetMap(), nil)
	eng.handleControlMapResult(ctx, routingTestNetMap(), nil)

	if got := strings.Count(logs.String(), `"level":"WARN"`); got != 2 {
		t.Fatalf("warning log count = %d, want separate control and router warnings; logs:\n%s", got, logs.String())
	}
	if got := strings.Count(logs.String(), `"msg":"mesh routing recovered"`); got != 1 {
		t.Fatalf("recovery log count = %d, want 1; logs:\n%s", got, logs.String())
	}
}

func TestRoutingStatusCachedRetryDoesNotHideControlError(t *testing.T) {
	eng := newRoutingTestEngine(true, &scriptedRoutingRouter{}, discardRoutingLogger())
	ctx := context.Background()
	nm := routingTestNetMap()

	eng.handleControlMapResult(ctx, nm, nil)
	eng.handleControlMapResult(ctx, nil, errors.New("control refresh failed"))
	if err := eng.reconcileTUNRoutes(ctx); err != nil {
		t.Fatalf("cached route retry: %v", err)
	}
	status := eng.RoutingStatus()
	if !status.Ready || status.Phase != RoutingPhaseError ||
		status.LastError != "loading control map: control refresh failed" {
		t.Fatalf("status after cached retry = %+v", status)
	}

	eng.handleControlMapResult(ctx, nm, nil)
	assertRoutingStatus(t, eng, RoutingStatus{Required: true, Ready: true, Phase: RoutingPhaseReady})
}

func TestRoutingStatusConcurrentSnapshots(t *testing.T) {
	eng := newRoutingTestEngine(true, &scriptedRoutingRouter{}, discardRoutingLogger())
	ctx := context.Background()
	nm := routingTestNetMap()

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			eng.handleControlMapResult(ctx, nil, errors.New("control retry"))
			eng.handleControlMapResult(ctx, nm, nil)
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				_ = eng.RoutingStatus()
			}
		}()
	}
	wg.Wait()
	eng.handleControlMapResult(ctx, nm, nil)
	if status := eng.RoutingStatus(); !status.Ready || status.Phase != RoutingPhaseReady {
		t.Fatalf("final routing status = %+v", status)
	}
}

func TestDWNControlReportsMapResults(t *testing.T) {
	wantMap := routingTestNetMap()
	mapErr := errors.New("map load failed")
	var loads int
	type result struct {
		nm  *netmap.NetworkMap
		err error
	}
	var results []result

	cc, err := NewDWNControl(&DWNControlConfig{
		MapResponseFunc: func(context.Context) (*netmap.NetworkMap, error) {
			loads++
			switch loads {
			case 1:
				return nil, mapErr
			case 2:
				return nil, nil
			default:
				return wantMap, nil
			}
		},
		OnMapResult: func(_ context.Context, nm *netmap.NetworkMap, err error) {
			results = append(results, result{nm: nm, err: err})
		},
		PollInterval: time.Hour,
		Logf:         func(string, ...any) {},
	}, controlclient.Options{SkipStartForTests: true})
	if err != nil {
		t.Fatalf("NewDWNControl: %v", err)
	}
	defer cc.Shutdown()

	ctx := context.Background()
	cc.loadAndPush(ctx, RefreshBatch{})
	cc.loadAndPush(ctx, RefreshBatch{})
	cc.loadAndPush(ctx, RefreshBatch{})
	if len(results) != 3 {
		t.Fatalf("map result callbacks = %d, want 3", len(results))
	}
	if results[0].nm != nil || !errors.Is(results[0].err, mapErr) {
		t.Fatalf("error result = %+v", results[0])
	}
	if results[1].nm != nil || results[1].err != nil {
		t.Fatalf("nil result = %+v", results[1])
	}
	if results[2].nm != wantMap || results[2].err != nil {
		t.Fatalf("map result = %+v, want map %p", results[2], wantMap)
	}
}

func TestHandleControlMapResultRevokedSelfRemovesPeerRoutes(t *testing.T) {
	routerRecorder := &recordingRoutingRouter{}
	eng := newRoutingTestEngine(true, routerRecorder, discardRoutingLogger())
	ctx := context.Background()

	eng.handleControlMapResult(ctx, routingTestNetMap(), nil)
	selfAddress := netip.MustParsePrefix("10.200.70.205/32")
	revoked := &netmap.NetworkMap{SelfNode: (&tailcfg.Node{
		Addresses: []netip.Prefix{selfAddress},
		KeyExpiry: time.Now().Add(-time.Second),
	}).View()}
	eng.handleControlMapResult(ctx, revoked, nil)

	configs := routerRecorder.Configs()
	if len(configs) != 2 {
		t.Fatalf("router configs = %d, want 2", len(configs))
	}
	if len(configs[0].Routes) != 1 {
		t.Fatalf("initial routes = %v, want peer route", configs[0].Routes)
	}
	if len(configs[1].Routes) != 0 {
		t.Fatalf("revoked routes = %v, want none", configs[1].Routes)
	}
	if len(configs[1].LocalAddrs) != 1 || configs[1].LocalAddrs[0] != selfAddress {
		t.Fatalf("revoked local addresses = %v, want %v", configs[1].LocalAddrs, selfAddress)
	}
}

type recordingRoutingRouter struct {
	mu      sync.Mutex
	configs []*router.Config
}

func (r *recordingRoutingRouter) Up() error    { return nil }
func (r *recordingRoutingRouter) Close() error { return nil }
func (r *recordingRoutingRouter) Set(cfg *router.Config) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	owned := *cfg
	owned.LocalAddrs = append([]netip.Prefix(nil), cfg.LocalAddrs...)
	owned.Routes = append([]netip.Prefix(nil), cfg.Routes...)
	r.configs = append(r.configs, &owned)
	return nil
}
func (r *recordingRoutingRouter) Configs() []*router.Config {
	r.mu.Lock()
	defer r.mu.Unlock()
	configs := make([]*router.Config, len(r.configs))
	for i, cfg := range r.configs {
		owned := *cfg
		owned.LocalAddrs = append([]netip.Prefix(nil), cfg.LocalAddrs...)
		owned.Routes = append([]netip.Prefix(nil), cfg.Routes...)
		configs[i] = &owned
	}
	return configs
}

type scriptedRoutingRouter struct {
	mu        sync.Mutex
	setErrors []error
	setCalls  int
}

func (r *scriptedRoutingRouter) Up() error    { return nil }
func (r *scriptedRoutingRouter) Close() error { return nil }

func (r *scriptedRoutingRouter) Set(*router.Config) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	call := r.setCalls
	r.setCalls++
	if call < len(r.setErrors) {
		return r.setErrors[call]
	}
	return nil
}

func (r *scriptedRoutingRouter) SetCalls() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.setCalls
}

func newRoutingTestEngine(required bool, r router.Router, logger *slog.Logger) *Engine {
	eng := &Engine{logger: logger}
	if r != nil {
		eng.osRouter = newSynchronizedRouter(r)
	}
	eng.initializeRoutingStatus(required)
	return eng
}

func discardRoutingLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func routingTestNetMap() *netmap.NetworkMap {
	self := (&tailcfg.Node{
		Addresses: []netip.Prefix{netip.MustParsePrefix("10.200.70.205/32")},
	}).View()
	peer := (&tailcfg.Node{
		Addresses:  []netip.Prefix{netip.MustParsePrefix("10.200.176.93/32")},
		AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.200.176.93/32")},
	}).View()
	return &netmap.NetworkMap{SelfNode: self, Peers: []tailcfg.NodeView{peer}}
}

func assertRoutingStatus(t *testing.T, eng *Engine, want RoutingStatus) {
	t.Helper()
	if got := eng.RoutingStatus(); got != want {
		t.Fatalf("RoutingStatus() = %+v, want %+v", got, want)
	}
}
