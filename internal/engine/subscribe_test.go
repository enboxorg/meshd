package engine

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/enboxorg/meshd/internal/dwn"

	"github.com/enboxorg/meshnet/control/controlclient"
	"github.com/enboxorg/meshnet/types/netmap"
)

func TestNewSubscriptionWatcher(t *testing.T) {
	w := NewSubscriptionWatcher(SubscriptionWatcherConfig{
		AnchorEndpoint:  "https://example.com",
		AnchorTenant:    "did:dht:anchor",
		NetworkRecordID: "record123",
		Signer:          &dwn.Signer{DID: "did:dht:self"},
	})

	if w == nil {
		t.Fatal("watcher is nil")
	}
	if w.endpoint != "https://example.com" {
		t.Errorf("endpoint = %q, want %q", w.endpoint, "https://example.com")
	}
	if w.anchorTenant != "did:dht:anchor" {
		t.Errorf("anchorTenant = %q, want %q", w.anchorTenant, "did:dht:anchor")
	}
	if w.networkRecordID != "record123" {
		t.Errorf("networkRecordID = %q, want %q", w.networkRecordID, "record123")
	}
}

func TestSubscriptionWatcherStopBeforeStart(t *testing.T) {
	w := NewSubscriptionWatcher(SubscriptionWatcherConfig{
		AnchorEndpoint:  "https://example.com",
		AnchorTenant:    "did:dht:anchor",
		NetworkRecordID: "record123",
		Signer:          &dwn.Signer{DID: "did:dht:self"},
	})

	// Stop before Start should not panic.
	w.Stop()
}

func TestSubscriptionWatcherDoubleStop(t *testing.T) {
	w := NewSubscriptionWatcher(SubscriptionWatcherConfig{
		AnchorEndpoint:  "https://example.com",
		AnchorTenant:    "did:dht:anchor",
		NetworkRecordID: "record123",
		Signer:          &dwn.Signer{DID: "did:dht:self"},
	})

	// Double stop should not panic.
	w.Stop()
	w.Stop()
}

func TestSubscriptionWatcherSetDWNControl(t *testing.T) {
	w := NewSubscriptionWatcher(SubscriptionWatcherConfig{
		AnchorEndpoint:  "https://example.com",
		AnchorTenant:    "did:dht:anchor",
		NetworkRecordID: "record123",
		Signer:          &dwn.Signer{DID: "did:dht:self"},
	})

	// Before setting, notify should not panic (no-op).
	w.notify()

	// Create a DWNControl with SkipStartForTests to avoid the poll loop.
	cc, err := NewDWNControl(
		&DWNControlConfig{
			MapResponseFunc: func(ctx context.Context) (*netmap.NetworkMap, error) {
				return nil, nil
			},
			PollInterval: time.Hour,
		},
		controlclient.Options{SkipStartForTests: true},
	)
	if err != nil {
		t.Fatalf("NewDWNControl: %v", err)
	}
	defer cc.Shutdown()

	// Set the DWNControl on the watcher.
	w.SetDWNControl(cc)

	// Now notify should trigger the DWNControl's notify channel.
	// This is a smoke test — we just verify it doesn't panic.
	w.notify()
}

func TestSubscriptionWatcherOnCreatedCallback(t *testing.T) {
	w := NewSubscriptionWatcher(SubscriptionWatcherConfig{
		AnchorEndpoint:  "https://example.com",
		AnchorTenant:    "did:dht:anchor",
		NetworkRecordID: "record123",
		Signer:          &dwn.Signer{DID: "did:dht:self"},
	})

	// Simulate the factory calling OnCreated.
	var called atomic.Bool
	config := &DWNControlConfig{
		MapResponseFunc: func(ctx context.Context) (*netmap.NetworkMap, error) {
			return nil, nil
		},
		PollInterval: time.Hour,
		OnCreated: func(cc *DWNControl) {
			called.Store(true)
			w.SetDWNControl(cc)
		},
	}

	cc, err := NewDWNControl(
		config,
		controlclient.Options{SkipStartForTests: true},
	)
	if err != nil {
		t.Fatalf("NewDWNControl: %v", err)
	}
	defer cc.Shutdown()

	if !called.Load() {
		t.Error("OnCreated callback was not called")
	}

	// The watcher should now have the DWNControl reference.
	w.controlMu.Lock()
	hasControl := w.dwnControl != nil
	w.controlMu.Unlock()

	if !hasControl {
		t.Error("watcher does not have DWNControl reference after OnCreated")
	}
}

func TestSubscriptionWatcherStartFailsGracefully(t *testing.T) {
	w := NewSubscriptionWatcher(SubscriptionWatcherConfig{
		// Use a deliberately unreachable endpoint.
		AnchorEndpoint:  "ws://127.0.0.1:1",
		AnchorTenant:    "did:dht:anchor",
		NetworkRecordID: "record123",
		Signer:          &dwn.Signer{DID: "did:dht:self"},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Start should succeed — the subscription runs asynchronously and
	// reconnects on failure. The SubscriptionManager.Subscribe returns
	// immediately (the WebSocket dial happens in a goroutine).
	err := w.Start(ctx)
	if err != nil {
		// Some setups might fail synchronously — that's also acceptable.
		t.Logf("Start returned error (acceptable): %v", err)
	}

	w.Stop()
}

func TestSubscriptionWatcherStartIdempotent(t *testing.T) {
	w := NewSubscriptionWatcher(SubscriptionWatcherConfig{
		AnchorEndpoint:  "ws://127.0.0.1:1",
		AnchorTenant:    "did:dht:anchor",
		NetworkRecordID: "record123",
		Signer:          &dwn.Signer{DID: "did:dht:self"},
	})

	ctx := context.Background()

	// First start.
	_ = w.Start(ctx)

	// Second start should be a no-op (already started).
	err := w.Start(ctx)
	if err != nil {
		t.Fatalf("second Start should be no-op, got: %v", err)
	}

	w.Stop()
}

func TestEngineCreatesSubscriptionWatcher(t *testing.T) {
	cfg := Config{
		AnchorEndpoint:  "https://example.com",
		AnchorTenant:    "did:dht:anchor",
		NetworkRecordID: "record123",
		SelfDID:         "did:dht:self",
		Signer:          &dwn.Signer{DID: "did:dht:self"},
	}

	eng, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer eng.Stop()

	if eng.subWatcher == nil {
		t.Error("engine should have a subscription watcher")
	}
}
