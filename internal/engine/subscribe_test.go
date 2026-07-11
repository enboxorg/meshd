package engine

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/enboxorg/meshd/internal/dwn"
	dwncrypto "github.com/enboxorg/meshd/internal/dwn/crypto"
	"github.com/enboxorg/meshd/protocols"

	"github.com/enboxorg/meshnet/control/controlclient"
	"github.com/enboxorg/meshnet/types/key"
	"github.com/enboxorg/meshnet/types/netmap"
)

type recordedSubscription struct {
	target    string
	signer    *dwn.Signer
	filter    dwn.RecordsFilter
	auth      dwn.MessageAuth
	handler   dwn.EventHandler
	lifecycle dwn.SubscriptionLifecycleHandler
}

type recordingSubscriptionManager struct {
	mu        sync.Mutex
	calls     []recordedSubscription
	failCall  int
	closeCall atomic.Int32
}

func (m *recordingSubscriptionManager) SubscribeWithAuthAndLifecycle(
	_ context.Context,
	target string,
	signer *dwn.Signer,
	filter dwn.RecordsFilter,
	auth dwn.MessageAuth,
	handler dwn.EventHandler,
	lifecycle dwn.SubscriptionLifecycleHandler,
) (*dwn.Subscription, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	callNumber := len(m.calls) + 1
	if m.failCall == callNumber {
		return nil, errors.New("subscribe failed")
	}
	filter.Tags = cloneTags(filter.Tags)
	m.calls = append(m.calls, recordedSubscription{
		target:    target,
		signer:    signer,
		filter:    filter,
		auth:      cloneMessageAuth(auth),
		handler:   handler,
		lifecycle: lifecycle,
	})
	return nil, nil
}

func (m *recordingSubscriptionManager) CloseAll() {
	m.closeCall.Add(1)
}

type blockingCloseSubscriptionManager struct {
	recordingSubscriptionManager
	closeStarted chan struct{}
	releaseClose chan struct{}
	startOnce    sync.Once
}

func (m *blockingCloseSubscriptionManager) CloseAll() {
	m.startOnce.Do(func() { close(m.closeStarted) })
	<-m.releaseClose
	m.recordingSubscriptionManager.CloseAll()
}

func cloneTags(tags map[string]any) map[string]any {
	if tags == nil {
		return nil
	}
	clone := make(map[string]any, len(tags))
	for key, value := range tags {
		clone[key] = value
	}
	return clone
}

func TestNewSubscriptionWatcher(t *testing.T) {
	w := NewSubscriptionWatcher(SubscriptionWatcherConfig{
		AnchorEndpoint:  "https://example.com",
		AnchorTenant:    "did:dht:anchor",
		NetworkRecordID: "record123",
		SelfDID:         "did:dht:self",
		Signer:          &dwn.Signer{DID: "did:dht:self"},
		ReadAuth:        dwn.MessageAuth{PermissionGrantID: "read-grant"},
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
	if w.selfDID != "did:dht:self" {
		t.Errorf("selfDID = %q, want %q", w.selfDID, "did:dht:self")
	}
	if w.readAuth.PermissionGrantID != "read-grant" {
		t.Errorf("read grant = %q, want read-grant", w.readAuth.PermissionGrantID)
	}
}

func TestSubscriptionWatcherStopBeforeStart(t *testing.T) {
	w := NewSubscriptionWatcher(SubscriptionWatcherConfig{
		AnchorEndpoint:  "https://example.com",
		AnchorTenant:    "did:dht:anchor",
		NetworkRecordID: "record123",
		SelfDID:         "did:dht:self",
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
		SelfDID:         "did:dht:self",
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
		SelfDID:         "did:dht:self",
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
		SelfDID:         "did:dht:self",
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

func TestDWNControlPublishesInitialDiscoKey(t *testing.T) {
	nodeKey := key.NewNode()
	disco := key.NewDisco().Public()
	registry := NewInMemoryDiscoRegistry()

	cc, err := NewDWNControl(
		&DWNControlConfig{
			MapResponseFunc: func(ctx context.Context) (*netmap.NetworkMap, error) {
				return nil, nil
			},
			PollInterval:     time.Hour,
			NodePrivateKey:   nodeKey,
			DiscoKeyRegistry: registry,
		},
		controlclient.Options{
			DiscoPublicKey:    disco,
			SkipStartForTests: true,
		},
	)
	if err != nil {
		t.Fatalf("NewDWNControl: %v", err)
	}
	defer cc.Shutdown()

	if got := registry.GetDisco(nodeKey.Public()); got != disco {
		t.Fatalf("registry disco = %v, want %v", got, disco)
	}
}

func TestEffectiveControlReadAuth(t *testing.T) {
	delegated := json.RawMessage(`{"recordId":"delegated-read"}`)
	tests := []struct {
		name string
		cfg  Config
		want dwn.MessageAuth
	}{
		{
			name: "owner reads as author",
			cfg:  Config{AnchorTenant: "did:owner", SelfDID: "did:owner"},
			want: dwn.MessageAuth{},
		},
		{
			name: "non-owner defaults to node role",
			cfg:  Config{AnchorTenant: "did:owner", SelfDID: "did:node"},
			want: dwn.MessageAuth{ProtocolRole: "network/node"},
		},
		{
			name: "plain query grant retains effective read role",
			cfg: Config{
				AnchorTenant:      "did:owner",
				SelfDID:           "did:node",
				PermissionGrantID: "query-grant",
			},
			want: dwn.MessageAuth{
				ProtocolRole:      "network/node",
				PermissionGrantID: "query-grant",
			},
		},
		{
			name: "delegated author never invokes role",
			cfg: Config{
				AnchorTenant:      "did:owner",
				SelfDID:           "did:node",
				ProtocolRole:      "network/member",
				PermissionGrantID: "ignored-plain-grant",
				DelegatedGrant:    delegated,
			},
			want: dwn.MessageAuth{DelegatedGrant: delegated},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := effectiveControlReadAuth(test.cfg); !reflect.DeepEqual(got, test.want) {
				t.Fatalf("effectiveControlReadAuth() = %#v, want %#v", got, test.want)
			}
		})
	}
}

func TestBroadSubscriptionAuth(t *testing.T) {
	delegated := json.RawMessage(`{"recordId":"delegated-read"}`)
	tests := []struct {
		name      string
		readAuth  dwn.MessageAuth
		want      dwn.MessageAuth
		supported bool
	}{
		{name: "owner", supported: true},
		{
			name: "plain read grant strips role invocation",
			readAuth: dwn.MessageAuth{
				ProtocolRole:      "network/node",
				PermissionGrantID: "query-grant",
			},
			want:      dwn.MessageAuth{PermissionGrantID: "query-grant"},
			supported: true,
		},
		{
			name:      "delegated read grant strips role invocation",
			readAuth:  dwn.MessageAuth{ProtocolRole: "network/member", DelegatedGrant: delegated},
			want:      dwn.MessageAuth{DelegatedGrant: delegated},
			supported: true,
		},
		{
			name:      "role only needs path-scoped subscriptions",
			readAuth:  dwn.MessageAuth{ProtocolRole: "network/node"},
			want:      dwn.MessageAuth{ProtocolRole: "network/node"},
			supported: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, supported := broadSubscriptionAuth(test.readAuth)
			if supported != test.supported {
				t.Fatalf("supported = %v, want %v", supported, test.supported)
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("auth = %#v, want %#v", got, test.want)
			}
		})
	}
}

func TestSubscriptionWatcherStartUsesReadGrantAndRecipientDeliveryFilter(t *testing.T) {
	signer := &dwn.Signer{DID: "did:dht:self"}
	manager := &recordingSubscriptionManager{}
	w := NewSubscriptionWatcher(SubscriptionWatcherConfig{
		AnchorEndpoint:  "https://example.com",
		AnchorTenant:    "did:dht:anchor",
		NetworkRecordID: "network-record",
		SelfDID:         "did:dht:self",
		Signer:          signer,
		ReadAuth: dwn.MessageAuth{
			ProtocolRole:      "network/node",
			PermissionGrantID: "query-grant",
		},
	})
	w.newManager = func(_ string, _ *slog.Logger) subscriptionManager { return manager }

	if err := w.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer w.Stop()

	if len(manager.calls) != 2 {
		t.Fatalf("subscription calls = %d, want 2", len(manager.calls))
	}
	meshCall := manager.calls[0]
	if meshCall.target != "did:dht:anchor" || meshCall.signer != signer {
		t.Fatalf("mesh target/signer = %q/%p", meshCall.target, meshCall.signer)
	}
	wantMeshFilter := dwn.RecordsFilter{
		Protocol:  protocols.MeshProtocolURI,
		ContextID: "network-record",
	}
	if !reflect.DeepEqual(meshCall.filter, wantMeshFilter) {
		t.Fatalf("mesh filter = %#v, want %#v", meshCall.filter, wantMeshFilter)
	}
	if want := (dwn.MessageAuth{PermissionGrantID: "query-grant"}); !reflect.DeepEqual(meshCall.auth, want) {
		t.Fatalf("mesh auth = %#v, want %#v", meshCall.auth, want)
	}
	if meshCall.handler == nil || meshCall.lifecycle == nil {
		t.Fatal("mesh handlers were not installed")
	}

	deliveryCall := manager.calls[1]
	wantDeliveryFilter := dwn.RecordsFilter{
		Protocol:     protocols.MeshProtocolURI,
		ProtocolPath: dwncrypto.EncryptionControlDeliveryPath,
		Recipient:    "did:dht:self",
		Tags: map[string]any{
			"protocol":  protocols.MeshProtocolURI,
			"contextId": "network-record",
		},
	}
	if !reflect.DeepEqual(deliveryCall.filter, wantDeliveryFilter) {
		t.Fatalf("delivery filter = %#v, want %#v", deliveryCall.filter, wantDeliveryFilter)
	}
	if !reflect.DeepEqual(deliveryCall.auth, dwn.MessageAuth{}) {
		t.Fatalf("delivery auth = %#v, want recipient-readable empty auth", deliveryCall.auth)
	}
	if deliveryCall.handler == nil || deliveryCall.lifecycle == nil {
		t.Fatal("delivery handlers were not installed")
	}
}

func TestSubscriptionWatcherRoleOnlyUsesDeliveryAndPolling(t *testing.T) {
	manager := &recordingSubscriptionManager{}
	w := NewSubscriptionWatcher(SubscriptionWatcherConfig{
		AnchorEndpoint:  "https://example.com",
		AnchorTenant:    "did:dht:anchor",
		NetworkRecordID: "network-record",
		SelfDID:         "did:dht:self",
		Signer:          &dwn.Signer{DID: "did:dht:self"},
		ReadAuth:        dwn.MessageAuth{ProtocolRole: "network/node"},
	})
	w.newManager = func(_ string, _ *slog.Logger) subscriptionManager { return manager }

	if err := w.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer w.Stop()

	if len(manager.calls) != 1 {
		t.Fatalf("subscription calls = %d, want delivery only", len(manager.calls))
	}
	if manager.calls[0].filter.ProtocolPath != dwncrypto.EncryptionControlDeliveryPath {
		t.Fatalf("only subscription path = %q, want delivery", manager.calls[0].filter.ProtocolPath)
	}
}

func TestSubscriptionWatcherSetupFailureClosesPartialSubscriptions(t *testing.T) {
	manager := &recordingSubscriptionManager{failCall: 2}
	w := NewSubscriptionWatcher(SubscriptionWatcherConfig{
		AnchorEndpoint:  "https://example.com",
		AnchorTenant:    "did:dht:anchor",
		NetworkRecordID: "network-record",
		SelfDID:         "did:dht:self",
		Signer:          &dwn.Signer{DID: "did:dht:self"},
	})
	w.newManager = func(_ string, _ *slog.Logger) subscriptionManager { return manager }

	if err := w.Start(context.Background()); err == nil {
		t.Fatal("Start succeeded despite delivery subscription failure")
	}
	if manager.closeCall.Load() != 1 {
		t.Fatalf("CloseAll calls = %d, want 1", manager.closeCall.Load())
	}
	if w.cancel != nil || w.manager != nil || w.done != nil {
		t.Fatal("failed Start retained running watcher state")
	}
}

func newWatcherTestControl(t *testing.T) *DWNControl {
	t.Helper()
	cc, err := NewDWNControl(
		&DWNControlConfig{
			MapResponseFunc: func(context.Context) (*netmap.NetworkMap, error) {
				return nil, nil
			},
			PollInterval: time.Hour,
		},
		controlclient.Options{SkipStartForTests: true},
	)
	if err != nil {
		t.Fatalf("NewDWNControl: %v", err)
	}
	t.Cleanup(cc.Shutdown)
	return cc
}

func expectWatcherNotification(t *testing.T, cc *DWNControl, want bool) {
	t.Helper()
	select {
	case <-cc.notify:
		if !want {
			t.Fatal("unexpected refresh notification")
		}
	default:
		if want {
			t.Fatal("refresh notification was not queued")
		}
	}
}

func TestSubscriptionWatcherDefersReplayUntilEstablished(t *testing.T) {
	w := NewSubscriptionWatcher(SubscriptionWatcherConfig{})
	cc := newWatcherTestControl(t)
	w.SetDWNControl(cc)

	if err := w.handleSubscriptionMessage("mesh", &dwn.SubscriptionMessage{Type: "event"}); err != nil {
		t.Fatalf("pre-establishment event: %v", err)
	}
	if err := w.handleSubscriptionMessage("mesh", &dwn.SubscriptionMessage{Type: "eose"}); err != nil {
		t.Fatalf("pre-establishment EOSE: %v", err)
	}
	expectWatcherNotification(t, cc, false)

	w.handleSubscriptionLifecycle("mesh", dwn.SubscriptionLifecycleEvent{
		Kind:             dwn.SubscriptionLifecycleEstablished,
		NeedsFullRefresh: false,
	})
	expectWatcherNotification(t, cc, true)

	if err := w.handleSubscriptionMessage("mesh", &dwn.SubscriptionMessage{Type: "event"}); err != nil {
		t.Fatalf("live event: %v", err)
	}
	expectWatcherNotification(t, cc, true)

	w.handleSubscriptionLifecycle("mesh", dwn.SubscriptionLifecycleEvent{
		Kind:    dwn.SubscriptionLifecycleRetrying,
		Attempt: 1,
	})
	if err := w.handleSubscriptionMessage("mesh", &dwn.SubscriptionMessage{Type: "event"}); err != nil {
		t.Fatalf("replay event: %v", err)
	}
	expectWatcherNotification(t, cc, false)
	w.handleSubscriptionLifecycle("mesh", dwn.SubscriptionLifecycleEvent{
		Kind:             dwn.SubscriptionLifecycleEstablished,
		NeedsFullRefresh: false,
	})
	expectWatcherNotification(t, cc, true)
}

func TestSubscriptionWatcherEOSEBarrierRefreshesOnlyAfterReplay(t *testing.T) {
	tests := []struct {
		name        string
		replayEvent bool
		wantRefresh bool
	}{
		{name: "empty replay", wantRefresh: false},
		{name: "replayed event", replayEvent: true, wantRefresh: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			w := NewSubscriptionWatcher(SubscriptionWatcherConfig{})
			cc := newWatcherTestControl(t)
			w.SetDWNControl(cc)

			if test.replayEvent {
				if err := w.handleSubscriptionMessage("mesh", &dwn.SubscriptionMessage{Type: dwn.SubscriptionEventType}); err != nil {
					t.Fatalf("replay event: %v", err)
				}
			}
			if err := w.handleSubscriptionMessage("mesh", &dwn.SubscriptionMessage{Type: dwn.SubscriptionEOSEType}); err != nil {
				t.Fatalf("EOSE: %v", err)
			}
			expectWatcherNotification(t, cc, false)

			w.handleSubscriptionLifecycle("mesh", dwn.SubscriptionLifecycleEvent{
				Kind:             dwn.SubscriptionLifecycleEstablished,
				NeedsFullRefresh: false,
			})
			expectWatcherNotification(t, cc, test.wantRefresh)
			// Replay event + EOSE is one invalidation batch, never two.
			expectWatcherNotification(t, cc, false)
		})
	}
}

func TestSubscriptionWatcherGapWaitsForFreshEstablishment(t *testing.T) {
	w := NewSubscriptionWatcher(SubscriptionWatcherConfig{})
	cc := newWatcherTestControl(t)
	w.SetDWNControl(cc)

	w.handleSubscriptionLifecycle("delivery", dwn.SubscriptionLifecycleEvent{
		Kind:             dwn.SubscriptionLifecycleEstablished,
		NeedsFullRefresh: false,
	})
	expectWatcherNotification(t, cc, false)
	w.handleSubscriptionLifecycle("delivery", dwn.SubscriptionLifecycleEvent{
		Kind: dwn.SubscriptionLifecycleProgressGap,
		Gap:  &dwn.ProgressGapInfo{Reason: "compacted"},
	})
	expectWatcherNotification(t, cc, false)
	w.handleSubscriptionLifecycle("delivery", dwn.SubscriptionLifecycleEvent{
		Kind:             dwn.SubscriptionLifecycleEstablished,
		NeedsFullRefresh: true,
	})
	expectWatcherNotification(t, cc, true)
}

func TestSubscriptionWatcherLiveErrorAndTerminalReconcile(t *testing.T) {
	w := NewSubscriptionWatcher(SubscriptionWatcherConfig{})
	cc := newWatcherTestControl(t)
	w.SetDWNControl(cc)

	w.handleSubscriptionLifecycle("mesh", dwn.SubscriptionLifecycleEvent{
		Kind:             dwn.SubscriptionLifecycleEstablished,
		NeedsFullRefresh: false,
	})
	if err := w.handleSubscriptionMessage("mesh", &dwn.SubscriptionMessage{
		Type:  "error",
		Error: &dwn.SubscriptionError{Code: "SubscriptionFailed", Detail: "closed"},
	}); err != nil {
		t.Fatalf("live error: %v", err)
	}
	expectWatcherNotification(t, cc, true)

	w.handleSubscriptionLifecycle("mesh", dwn.SubscriptionLifecycleEvent{
		Kind: dwn.SubscriptionLifecycleTerminal,
		Err:  errors.New("stream terminated"),
	})
	expectWatcherNotification(t, cc, true)
}

func TestSubscriptionWatcherStartFailsGracefully(t *testing.T) {
	w := NewSubscriptionWatcher(SubscriptionWatcherConfig{
		// Use a deliberately unreachable endpoint.
		AnchorEndpoint:  "ws://127.0.0.1:1",
		AnchorTenant:    "did:dht:anchor",
		NetworkRecordID: "record123",
		SelfDID:         "did:dht:self",
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
		SelfDID:         "did:dht:self",
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

func TestSubscriptionWatcherStartWaitsForConcurrentStop(t *testing.T) {
	oldManager := &blockingCloseSubscriptionManager{
		closeStarted: make(chan struct{}),
		releaseClose: make(chan struct{}),
	}
	newManager := &recordingSubscriptionManager{}
	var factoryCalls atomic.Int32

	w := NewSubscriptionWatcher(SubscriptionWatcherConfig{
		AnchorEndpoint:  "https://example.com",
		AnchorTenant:    "did:dht:anchor",
		NetworkRecordID: "network-record",
		SelfDID:         "did:dht:self",
		Signer:          &dwn.Signer{DID: "did:dht:self"},
	})
	w.newManager = func(_ string, _ *slog.Logger) subscriptionManager {
		if factoryCalls.Add(1) == 1 {
			return oldManager
		}
		return newManager
	}
	if err := w.Start(context.Background()); err != nil {
		t.Fatalf("initial Start: %v", err)
	}

	stopDone := make(chan struct{})
	go func() {
		w.Stop()
		close(stopDone)
	}()
	select {
	case <-oldManager.closeStarted:
	case <-time.After(time.Second):
		t.Fatal("old manager did not begin CloseAll")
	}

	startAttempted := make(chan struct{})
	startResult := make(chan error, 1)
	go func() {
		close(startAttempted)
		startResult <- w.Start(context.Background())
	}()
	<-startAttempted

	select {
	case err := <-startResult:
		t.Fatalf("concurrent Start completed before old CloseAll: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if got := factoryCalls.Load(); got != 1 {
		t.Fatalf("manager factory calls before old CloseAll = %d, want 1", got)
	}

	close(oldManager.releaseClose)
	select {
	case <-stopDone:
	case <-time.After(time.Second):
		t.Fatal("Stop did not complete after old CloseAll")
	}
	select {
	case err := <-startResult:
		if err != nil {
			t.Fatalf("replacement Start: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("replacement Start remained blocked after Stop")
	}
	if got := factoryCalls.Load(); got != 2 {
		t.Fatalf("manager factory calls after replacement Start = %d, want 2", got)
	}

	w.Stop()
	if got := oldManager.closeCall.Load(); got != 1 {
		t.Fatalf("old manager CloseAll calls = %d, want 1", got)
	}
	if got := newManager.closeCall.Load(); got != 1 {
		t.Fatalf("new manager CloseAll calls = %d, want 1", got)
	}
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
	if eng.subWatcher.selfDID != cfg.SelfDID {
		t.Fatalf("watcher self DID = %q, want %q", eng.subWatcher.selfDID, cfg.SelfDID)
	}
	if eng.subWatcher.readAuth.ProtocolRole != "network/node" {
		t.Fatalf("watcher read role = %q, want network/node", eng.subWatcher.readAuth.ProtocolRole)
	}
}
