package engine

import (
	"context"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/enboxorg/meshd/internal/dwn"

	"github.com/enboxorg/meshnet/net/netmon"
)

func TestWakeProberDebouncesAndFiltersLinkChanges(t *testing.T) {
	var calls atomic.Int32
	current := time.Unix(1000, 0)
	prober := newWakeProber(time.Second, func() { calls.Add(1) })
	prober.now = func() time.Time { return current }

	prober.OnNetworkChange(nil)
	prober.OnNetworkChange(&netmon.ChangeDelta{})
	if got := calls.Load(); got != 0 {
		t.Fatalf("probes after minor deltas = %d, want 0", got)
	}

	prober.OnNetworkChange(&netmon.ChangeDelta{RebindLikelyRequired: true})
	if got := calls.Load(); got != 1 {
		t.Fatalf("probes after major delta = %d, want 1", got)
	}

	current = current.Add(500 * time.Millisecond)
	prober.OnNetworkChange(&netmon.ChangeDelta{RebindLikelyRequired: true})
	prober.OnNetworkChange(&netmon.ChangeDelta{TimeJumped: true})
	if got := calls.Load(); got != 1 {
		t.Fatalf("probes after flapping within debounce window = %d, want 1", got)
	}

	current = current.Add(time.Second)
	prober.OnNetworkChange(&netmon.ChangeDelta{TimeJumped: true})
	if got := calls.Load(); got != 2 {
		t.Fatalf("probes after wall-clock jump past the window = %d, want 2", got)
	}
}

func TestSubscriptionWatcherCheckHealthProbesActiveManagerOnly(t *testing.T) {
	manager := &recordingSubscriptionManager{}
	w := NewSubscriptionWatcher(SubscriptionWatcherConfig{
		AnchorEndpoint:  "https://example.com",
		AnchorTenant:    "did:dht:anchor",
		NetworkRecordID: "network-record",
		SelfDID:         "did:dht:self",
		Signer:          &dwn.Signer{DID: "did:dht:self"},
	})
	w.newManager = func(_ string, _ *slog.Logger) subscriptionManager { return manager }

	// Not started yet: probing must be a safe no-op.
	w.CheckHealth()
	if got := manager.healthChecks.Load(); got != 0 {
		t.Fatalf("health checks before Start = %d, want 0", got)
	}

	if err := w.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	w.CheckHealth()
	w.CheckHealth()
	if got := manager.healthChecks.Load(); got != 2 {
		t.Fatalf("health checks while running = %d, want 2", got)
	}

	w.Stop()
	// Stopped: the manager is gone, probing must be a safe no-op again.
	w.CheckHealth()
	if got := manager.healthChecks.Load(); got != 2 {
		t.Fatalf("health checks after Stop = %d, want 2", got)
	}
}
