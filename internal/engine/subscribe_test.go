package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/enboxorg/meshd/internal/dwn"
	dwncrypto "github.com/enboxorg/meshd/internal/dwn/crypto"
	"github.com/enboxorg/meshd/internal/state"
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

type recordedMessagesSubscription struct {
	target    string
	signer    *dwn.Signer
	opts      dwn.MessagesSubscribeOptions
	handler   dwn.EventHandler
	lifecycle dwn.SubscriptionLifecycleHandler
}

type recordingSubscriptionManager struct {
	mu            sync.Mutex
	calls         []recordedSubscription
	messagesCalls []recordedMessagesSubscription
	failCall      int
	closeHook     func()
	closeCall     atomic.Int32
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
	callNumber := len(m.calls) + len(m.messagesCalls) + 1
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

func (m *recordingSubscriptionManager) SubscribeMessagesWithLifecycle(
	_ context.Context,
	target string,
	signer *dwn.Signer,
	opts dwn.MessagesSubscribeOptions,
	handler dwn.EventHandler,
	lifecycle dwn.SubscriptionLifecycleHandler,
) (*dwn.Subscription, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	callNumber := len(m.calls) + len(m.messagesCalls) + 1
	if m.failCall == callNumber {
		return nil, errors.New("subscribe failed")
	}
	m.messagesCalls = append(m.messagesCalls, recordedMessagesSubscription{
		target:    target,
		signer:    signer,
		opts:      opts,
		handler:   handler,
		lifecycle: lifecycle,
	})
	return nil, nil
}

func (m *recordingSubscriptionManager) CloseAll() {
	if m.closeHook != nil {
		m.closeHook()
	}
	m.closeCall.Add(1)
}

type refreshCoordinatorCall struct {
	method           string
	stream           RefreshStream
	covered          bool
	live             bool
	needsFullRefresh bool
	reason           RefreshReason
	degradedReason   string
}

type recordingRefreshCoordinator struct {
	mu      sync.Mutex
	calls   []refreshCoordinatorCall
	streams map[RefreshStream]RefreshStreamHealth
}

func newRecordingRefreshCoordinator() *recordingRefreshCoordinator {
	return &recordingRefreshCoordinator{streams: make(map[RefreshStream]RefreshStreamHealth)}
}

func (c *recordingRefreshCoordinator) SetStreamCovered(stream RefreshStream, covered bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	health := c.streams[stream]
	health.Covered = covered
	if !covered {
		health.Live = false
	}
	c.streams[stream] = health
	c.calls = append(c.calls, refreshCoordinatorCall{method: "covered", stream: stream, covered: covered})
}

func (c *recordingRefreshCoordinator) SetStreamLive(stream RefreshStream, live, needsFullRefresh bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	health := c.streams[stream]
	health.Live = live
	c.streams[stream] = health
	c.calls = append(c.calls, refreshCoordinatorCall{
		method:           "live",
		stream:           stream,
		live:             live,
		needsFullRefresh: needsFullRefresh,
	})
}

func (c *recordingRefreshCoordinator) InvalidateStream(stream RefreshStream, reason RefreshReason) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls = append(c.calls, refreshCoordinatorCall{method: "invalidate", stream: stream, reason: reason})
}

func (c *recordingRefreshCoordinator) Notify(reason RefreshReason) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls = append(c.calls, refreshCoordinatorCall{method: "notify", reason: reason})
}

func (c *recordingRefreshCoordinator) SetDegradedReason(reason string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls = append(c.calls, refreshCoordinatorCall{method: "degraded", degradedReason: reason})
}

func (c *recordingRefreshCoordinator) takeCalls() []refreshCoordinatorCall {
	c.mu.Lock()
	defer c.mu.Unlock()
	calls := append([]refreshCoordinatorCall(nil), c.calls...)
	c.calls = nil
	return calls
}

func (c *recordingRefreshCoordinator) streamHealth(stream RefreshStream) RefreshStreamHealth {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.streams[stream]
}

type blockingReplacementCoordinator struct {
	*recordingRefreshCoordinator
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func newBlockingReplacementCoordinator() *blockingReplacementCoordinator {
	return &blockingReplacementCoordinator{
		recordingRefreshCoordinator: newRecordingRefreshCoordinator(),
		entered:                     make(chan struct{}),
		release:                     make(chan struct{}),
	}
}

func (c *blockingReplacementCoordinator) SetStreamCovered(stream RefreshStream, covered bool) {
	c.once.Do(func() {
		close(c.entered)
		<-c.release
	})
	c.recordingRefreshCoordinator.SetStreamCovered(stream, covered)
}

type blockingInvalidationCoordinator struct {
	*recordingRefreshCoordinator
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func newBlockingInvalidationCoordinator() *blockingInvalidationCoordinator {
	return &blockingInvalidationCoordinator{
		recordingRefreshCoordinator: newRecordingRefreshCoordinator(),
		entered:                     make(chan struct{}),
		release:                     make(chan struct{}),
	}
}

func (c *blockingInvalidationCoordinator) InvalidateStream(stream RefreshStream, reason RefreshReason) {
	c.once.Do(func() {
		close(c.entered)
		<-c.release
	})
	c.recordingRefreshCoordinator.InvalidateStream(stream, reason)
}

func requireRefreshCoordinatorCalls(t *testing.T, coordinator *recordingRefreshCoordinator, want []refreshCoordinatorCall) {
	t.Helper()
	if got := coordinator.takeCalls(); !reflect.DeepEqual(got, want) {
		t.Fatalf("coordinator calls = %#v, want %#v", got, want)
	}
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

func TestSubscriptionWatcherSetRefreshCoordinator(t *testing.T) {
	w := NewSubscriptionWatcher(SubscriptionWatcherConfig{})

	// Callbacks are harmless until engine startup supplies a coordinator.
	if err := w.handleSubscriptionMessage(RefreshStreamTopology, &dwn.SubscriptionMessage{Type: "event"}); err != nil {
		t.Fatalf("event without coordinator: %v", err)
	}

	coordinator := newRecordingRefreshCoordinator()
	w.SetRefreshCoordinator(coordinator)
	if err := w.handleSubscriptionMessage(RefreshStreamTopology, &dwn.SubscriptionMessage{Type: "event"}); err != nil {
		t.Fatalf("event with coordinator: %v", err)
	}
	requireRefreshCoordinatorCalls(t, coordinator, []refreshCoordinatorCall{{
		method: "invalidate", stream: RefreshStreamTopology, reason: RefreshReasonTopology,
	}})
}

func TestSubscriptionWatcherReplacementCoordinatorReplaysLiveCoverage(t *testing.T) {
	w := NewSubscriptionWatcher(SubscriptionWatcherConfig{})
	first := newRecordingRefreshCoordinator()
	w.SetRefreshCoordinator(first)
	w.initializeStreamCoverage(map[RefreshStream]bool{RefreshStreamTopology: true, RefreshStreamDelivery: true})
	w.handleSubscriptionLifecycle(RefreshStreamTopology, dwn.SubscriptionLifecycleEvent{
		Kind: dwn.SubscriptionLifecycleEstablished,
	})
	w.handleSubscriptionLifecycle(RefreshStreamDelivery, dwn.SubscriptionLifecycleEvent{
		Kind: dwn.SubscriptionLifecycleEstablished,
	})
	first.takeCalls()

	replacement := newRecordingRefreshCoordinator()
	w.SetRefreshCoordinator(replacement)
	requireRefreshCoordinatorCalls(t, replacement, []refreshCoordinatorCall{
		{method: "covered", stream: RefreshStreamTopology, covered: true},
		{method: "covered", stream: RefreshStreamDelivery, covered: true},
		{method: "live", stream: RefreshStreamTopology, live: true, needsFullRefresh: true},
		{method: "live", stream: RefreshStreamDelivery, live: true, needsFullRefresh: true},
	})
}

func TestSubscriptionWatcherReplacementHandoffDoesNotOverwriteConcurrentDisconnect(t *testing.T) {
	w := NewSubscriptionWatcher(SubscriptionWatcherConfig{})
	first := newRecordingRefreshCoordinator()
	w.SetRefreshCoordinator(first)
	w.initializeStreamCoverage(map[RefreshStream]bool{RefreshStreamTopology: true, RefreshStreamDelivery: true})
	w.handleSubscriptionLifecycle(RefreshStreamTopology, dwn.SubscriptionLifecycleEvent{
		Kind: dwn.SubscriptionLifecycleEstablished,
	})
	w.handleSubscriptionLifecycle(RefreshStreamDelivery, dwn.SubscriptionLifecycleEvent{
		Kind: dwn.SubscriptionLifecycleEstablished,
	})

	replacement := newBlockingReplacementCoordinator()
	handoffDone := make(chan struct{})
	go func() {
		w.SetRefreshCoordinator(replacement)
		close(handoffDone)
	}()
	<-replacement.entered

	disconnectDone := make(chan struct{})
	go func() {
		w.handleSubscriptionLifecycle(RefreshStreamTopology, dwn.SubscriptionLifecycleEvent{
			Kind: dwn.SubscriptionLifecycleRetrying,
		})
		close(disconnectDone)
	}()
	select {
	case <-disconnectDone:
		t.Fatal("disconnect interleaved with an incomplete coordinator handoff")
	case <-time.After(50 * time.Millisecond):
	}

	close(replacement.release)
	select {
	case <-handoffDone:
	case <-time.After(time.Second):
		t.Fatal("coordinator handoff did not finish")
	}
	select {
	case <-disconnectDone:
	case <-time.After(time.Second):
		t.Fatal("disconnect did not reach replacement coordinator")
	}
	if got := replacement.streamHealth(RefreshStreamTopology); got.Live {
		t.Fatalf("replacement topology health = %+v, want disconnected", got)
	}
}

func TestSubscriptionWatcherEventIsFencedByCoordinatorHandoff(t *testing.T) {
	w := NewSubscriptionWatcher(SubscriptionWatcherConfig{})
	first := newBlockingInvalidationCoordinator()
	w.SetRefreshCoordinator(first)
	w.initializeStreamCoverage(map[RefreshStream]bool{RefreshStreamTopology: true, RefreshStreamDelivery: true})
	w.handleSubscriptionLifecycle(RefreshStreamTopology, dwn.SubscriptionLifecycleEvent{
		Kind: dwn.SubscriptionLifecycleEstablished,
	})
	w.handleSubscriptionLifecycle(RefreshStreamDelivery, dwn.SubscriptionLifecycleEvent{
		Kind: dwn.SubscriptionLifecycleEstablished,
	})
	first.takeCalls()

	eventDone := make(chan struct{})
	go func() {
		_ = w.handleSubscriptionMessage(RefreshStreamTopology, &dwn.SubscriptionMessage{Type: "event"})
		close(eventDone)
	}()
	<-first.entered

	replacement := newRecordingRefreshCoordinator()
	handoffDone := make(chan struct{})
	go func() {
		w.SetRefreshCoordinator(replacement)
		close(handoffDone)
	}()
	select {
	case <-handoffDone:
		t.Fatal("coordinator handoff interleaved with event invalidation")
	case <-time.After(50 * time.Millisecond):
	}

	close(first.release)
	select {
	case <-eventDone:
	case <-time.After(time.Second):
		t.Fatal("event invalidation did not finish")
	}
	select {
	case <-handoffDone:
	case <-time.After(time.Second):
		t.Fatal("coordinator handoff did not finish")
	}
	requireRefreshCoordinatorCalls(t, first.recordingRefreshCoordinator, []refreshCoordinatorCall{{
		method: "invalidate", stream: RefreshStreamTopology, reason: RefreshReasonTopology,
	}})
	requireRefreshCoordinatorCalls(t, replacement, []refreshCoordinatorCall{
		{method: "covered", stream: RefreshStreamTopology, covered: true},
		{method: "covered", stream: RefreshStreamDelivery, covered: true},
		{method: "live", stream: RefreshStreamTopology, live: true, needsFullRefresh: true},
		{method: "live", stream: RefreshStreamDelivery, live: true, needsFullRefresh: true},
	})
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
	coordinator := newRecordingRefreshCoordinator()
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
	w.SetRefreshCoordinator(coordinator)

	if err := w.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer w.Stop()
	requireRefreshCoordinatorCalls(t, coordinator, []refreshCoordinatorCall{
		{method: "degraded"},
		{method: "live", stream: RefreshStreamTopology},
		{method: "live", stream: RefreshStreamDelivery},
		{method: "covered", stream: RefreshStreamTopology, covered: true},
		{method: "covered", stream: RefreshStreamDelivery, covered: true},
	})

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
			"protocol": protocols.MeshProtocolURI,
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
	coordinator := newRecordingRefreshCoordinator()
	w := NewSubscriptionWatcher(SubscriptionWatcherConfig{
		AnchorEndpoint:  "https://example.com",
		AnchorTenant:    "did:dht:anchor",
		NetworkRecordID: "network-record",
		SelfDID:         "did:dht:self",
		Signer:          &dwn.Signer{DID: "did:dht:self"},
		ReadAuth:        dwn.MessageAuth{ProtocolRole: "network/node"},
	})
	w.newManager = func(_ string, _ *slog.Logger) subscriptionManager { return manager }
	w.SetRefreshCoordinator(coordinator)

	if err := w.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer w.Stop()
	requireRefreshCoordinatorCalls(t, coordinator, []refreshCoordinatorCall{
		{method: "degraded"},
		{method: "live", stream: RefreshStreamTopology},
		{method: "live", stream: RefreshStreamDelivery},
		{method: "covered", stream: RefreshStreamTopology, covered: false},
		{method: "covered", stream: RefreshStreamDelivery, covered: true},
	})

	if len(manager.calls) != 1 {
		t.Fatalf("subscription calls = %d, want delivery only", len(manager.calls))
	}
	if manager.calls[0].filter.ProtocolPath != dwncrypto.EncryptionControlDeliveryPath {
		t.Fatalf("only subscription path = %q, want delivery", manager.calls[0].filter.ProtocolPath)
	}
}

func TestSubscriptionWatcherSetupFailureClosesPartialSubscriptions(t *testing.T) {
	manager := &recordingSubscriptionManager{failCall: 2}
	coordinator := newRecordingRefreshCoordinator()
	w := NewSubscriptionWatcher(SubscriptionWatcherConfig{
		AnchorEndpoint:  "https://example.com",
		AnchorTenant:    "did:dht:anchor",
		NetworkRecordID: "network-record",
		SelfDID:         "did:dht:self",
		Signer:          &dwn.Signer{DID: "did:dht:self"},
	})
	w.newManager = func(_ string, _ *slog.Logger) subscriptionManager { return manager }
	w.SetRefreshCoordinator(coordinator)
	manager.closeHook = func() {
		manager.mu.Lock()
		lifecycle := manager.calls[0].lifecycle
		manager.mu.Unlock()
		lifecycle(dwn.SubscriptionLifecycleEvent{Kind: dwn.SubscriptionLifecycleEstablished})
	}

	if err := w.Start(context.Background()); err == nil {
		t.Fatal("Start succeeded despite delivery subscription failure")
	}
	if manager.closeCall.Load() != 1 {
		t.Fatalf("CloseAll calls = %d, want 1", manager.closeCall.Load())
	}
	if w.cancel != nil || w.manager != nil || w.done != nil {
		t.Fatal("failed Start retained running watcher state")
	}
	for _, stream := range []RefreshStream{RefreshStreamTopology, RefreshStreamDelivery} {
		health := coordinator.streamHealth(stream)
		if health.Covered || health.Live {
			t.Fatalf("%s stream remained available after failed Start: %#v", stream, health)
		}
	}
}

func TestSubscriptionWatcherMessageCallbacks(t *testing.T) {
	tests := []struct {
		name    string
		stream  RefreshStream
		message *dwn.SubscriptionMessage
		want    []refreshCoordinatorCall
	}{
		{name: "nil message", stream: RefreshStreamTopology},
		{
			name:    "topology event",
			stream:  RefreshStreamTopology,
			message: &dwn.SubscriptionMessage{Type: dwn.SubscriptionEventType},
			want: []refreshCoordinatorCall{{
				method: "invalidate", stream: RefreshStreamTopology, reason: RefreshReasonTopology,
			}},
		},
		{
			name:    "delivery event",
			stream:  RefreshStreamDelivery,
			message: &dwn.SubscriptionMessage{Type: dwn.SubscriptionEventType},
			want: []refreshCoordinatorCall{{
				method: "invalidate", stream: RefreshStreamDelivery, reason: RefreshReasonDelivery,
			}},
		},
		{
			name:    "end of stored events",
			stream:  RefreshStreamTopology,
			message: &dwn.SubscriptionMessage{Type: dwn.SubscriptionEOSEType},
		},
		{
			name:   "error frame is lifecycle owned",
			stream: RefreshStreamTopology,
			message: &dwn.SubscriptionMessage{
				Type:  "error",
				Error: &dwn.SubscriptionError{Code: "SubscriptionFailed", Detail: "closed"},
			},
		},
		{name: "unknown frame", stream: RefreshStreamDelivery, message: &dwn.SubscriptionMessage{Type: "future"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			coordinator := newRecordingRefreshCoordinator()
			w := NewSubscriptionWatcher(SubscriptionWatcherConfig{})
			w.SetRefreshCoordinator(coordinator)
			if err := w.handleSubscriptionMessage(test.stream, test.message); err != nil {
				t.Fatalf("handleSubscriptionMessage: %v", err)
			}
			requireRefreshCoordinatorCalls(t, coordinator, test.want)
		})
	}
}

func TestSubscriptionWatcherLifecycleCallbacks(t *testing.T) {
	tests := []struct {
		name   string
		stream RefreshStream
		event  dwn.SubscriptionLifecycleEvent
		want   []refreshCoordinatorCall
	}{
		{
			name:   "established",
			stream: RefreshStreamTopology,
			event:  dwn.SubscriptionLifecycleEvent{Kind: dwn.SubscriptionLifecycleEstablished},
			want:   []refreshCoordinatorCall{{method: "live", stream: RefreshStreamTopology, live: true}},
		},
		{
			name:   "established requires full refresh",
			stream: RefreshStreamDelivery,
			event: dwn.SubscriptionLifecycleEvent{
				Kind:             dwn.SubscriptionLifecycleEstablished,
				NeedsFullRefresh: true,
			},
			want: []refreshCoordinatorCall{{
				method: "live", stream: RefreshStreamDelivery, live: true, needsFullRefresh: true,
			}},
		},
		{
			name:   "progress gap",
			stream: RefreshStreamDelivery,
			event: dwn.SubscriptionLifecycleEvent{
				Kind: dwn.SubscriptionLifecycleProgressGap,
				Gap:  &dwn.ProgressGapInfo{Reason: "compacted"},
			},
			want: []refreshCoordinatorCall{{
				method: "live", stream: RefreshStreamDelivery, needsFullRefresh: true,
			}},
		},
		{
			name:   "retrying preserves pending invalidation",
			stream: RefreshStreamTopology,
			event: dwn.SubscriptionLifecycleEvent{
				Kind: dwn.SubscriptionLifecycleRetrying, Attempt: 2, Err: errors.New("offline"),
			},
			want: []refreshCoordinatorCall{{method: "live", stream: RefreshStreamTopology}},
		},
		{
			name:   "terminal reconciles once",
			stream: RefreshStreamTopology,
			event: dwn.SubscriptionLifecycleEvent{
				Kind: dwn.SubscriptionLifecycleTerminal, Err: errors.New("denied"),
			},
			want: []refreshCoordinatorCall{
				{method: "live", stream: RefreshStreamTopology},
				{method: "notify", reason: RefreshReasonTopology},
			},
		},
		{name: "unknown lifecycle", stream: RefreshStreamDelivery, event: dwn.SubscriptionLifecycleEvent{Kind: "future"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			coordinator := newRecordingRefreshCoordinator()
			w := NewSubscriptionWatcher(SubscriptionWatcherConfig{})
			w.SetRefreshCoordinator(coordinator)
			w.handleSubscriptionLifecycle(test.stream, test.event)
			requireRefreshCoordinatorCalls(t, coordinator, test.want)
		})
	}
}

func TestSubscriptionWatcherStopFencesLifecycleCallbacks(t *testing.T) {
	manager := &recordingSubscriptionManager{}
	coordinator := newRecordingRefreshCoordinator()
	w := NewSubscriptionWatcher(SubscriptionWatcherConfig{
		AnchorEndpoint:  "https://example.com",
		AnchorTenant:    "did:dht:anchor",
		NetworkRecordID: "network-record",
		SelfDID:         "did:dht:self",
		Signer:          &dwn.Signer{DID: "did:dht:self"},
	})
	w.newManager = func(_ string, _ *slog.Logger) subscriptionManager { return manager }
	w.SetRefreshCoordinator(coordinator)
	if err := w.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	coordinator.takeCalls()

	manager.closeHook = func() {
		manager.mu.Lock()
		calls := append([]recordedSubscription(nil), manager.calls...)
		manager.mu.Unlock()
		for _, call := range calls {
			call.lifecycle(dwn.SubscriptionLifecycleEvent{Kind: dwn.SubscriptionLifecycleEstablished})
		}
	}
	w.Stop()

	if manager.closeCall.Load() != 1 {
		t.Fatalf("CloseAll calls = %d, want 1", manager.closeCall.Load())
	}
	for _, stream := range []RefreshStream{RefreshStreamTopology, RefreshStreamDelivery} {
		health := coordinator.streamHealth(stream)
		if health.Covered || health.Live {
			t.Fatalf("%s stream remained available after Stop: %#v", stream, health)
		}
	}
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

func newTestFeedWatcher(manager subscriptionManager, coordinator subscriptionRefreshCoordinator, feedSync *feedSyncRecorder, grantIDs []string) *SubscriptionWatcher {
	w := NewSubscriptionWatcher(SubscriptionWatcherConfig{
		AnchorEndpoint:  "https://example.com",
		AnchorTenant:    "did:dht:anchor",
		NetworkRecordID: "network-record",
		SelfDID:         "did:jwk:self",
		Signer:          &dwn.Signer{DID: "did:jwk:delegate"},
		FeedMode:        true,
		FeedGrantIDs:    grantIDs,
	})
	w.feedSync = feedSync
	if manager != nil {
		w.newManager = func(_ string, _ *slog.Logger) subscriptionManager { return manager }
	}
	if coordinator != nil {
		w.SetRefreshCoordinator(coordinator)
	}
	return w
}

func TestSubscriptionWatcherFeedModeStartsSingleFeedSubscription(t *testing.T) {
	manager := &recordingSubscriptionManager{}
	coordinator := newRecordingRefreshCoordinator()
	feedSync := newFeedSyncRecorder(testFeedLinkKey, nil, nil)
	feedSync.adopt(&state.FeedSyncState{LinkKey: testFeedLinkKey, Cursor: testCursor("5")})
	w := newTestFeedWatcher(manager, coordinator, feedSync, []string{"grant-a", "grant-b"})

	if err := w.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer w.Stop()

	requireRefreshCoordinatorCalls(t, coordinator, []refreshCoordinatorCall{
		{method: "degraded"},
		{method: "live", stream: RefreshStreamFeed},
		{method: "covered", stream: RefreshStreamFeed, covered: true},
	})

	if len(manager.calls) != 0 {
		t.Fatalf("records subscriptions = %d, want none in feed mode", len(manager.calls))
	}
	if len(manager.messagesCalls) != 1 {
		t.Fatalf("messages subscriptions = %d, want 1", len(manager.messagesCalls))
	}
	call := manager.messagesCalls[0]
	if call.target != "did:dht:anchor" {
		t.Fatalf("target = %q, want anchor tenant", call.target)
	}
	wantFilters := []dwn.MessagesFilter{{Protocol: protocols.MeshProtocolURI}}
	if !reflect.DeepEqual(call.opts.Filters, wantFilters) {
		t.Fatalf("filters = %#v, want %#v", call.opts.Filters, wantFilters)
	}
	if !reflect.DeepEqual(call.opts.PermissionGrantIDs, []string{"grant-a", "grant-b"}) {
		t.Fatalf("grant IDs = %v, want [grant-a grant-b]", call.opts.PermissionGrantIDs)
	}
	if call.opts.Cursor == nil || call.opts.Cursor.Position != "5" {
		t.Fatalf("cursor = %+v, want resumed position 5", call.opts.Cursor)
	}
	if call.handler == nil || call.lifecycle == nil {
		t.Fatal("feed handlers were not installed")
	}
}

func TestSubscriptionWatcherFeedModeOwnerOmitsCursorAndGrants(t *testing.T) {
	manager := &recordingSubscriptionManager{}
	// A checkpoint recorded under a different link key must not resume.
	feedSync := newFeedSyncRecorder(testFeedLinkKey, nil, nil)
	feedSync.adopt(&state.FeedSyncState{LinkKey: "stale^link^key^x", Cursor: testCursor("5")})
	w := newTestFeedWatcher(manager, newRecordingRefreshCoordinator(), feedSync, nil)

	if err := w.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer w.Stop()

	call := manager.messagesCalls[0]
	if len(call.opts.PermissionGrantIDs) != 0 {
		t.Fatalf("grant IDs = %v, want none for owner", call.opts.PermissionGrantIDs)
	}
	if call.opts.Cursor != nil {
		t.Fatalf("cursor = %+v, want nil after link key mismatch", call.opts.Cursor)
	}
}

func TestSubscriptionWatcherFeedEventsInvalidateAndPersistCursor(t *testing.T) {
	saves := &feedSaveRecorder{}
	feedSync := newFeedSyncRecorder(testFeedLinkKey, saves.save, nil)
	feedSync.debounce = time.Hour // only EOSE persists synchronously here
	coordinator := newRecordingRefreshCoordinator()
	w := newTestFeedWatcher(nil, coordinator, feedSync, nil)

	if err := w.handleFeedMessage(&dwn.SubscriptionMessage{
		Type:   dwn.SubscriptionEventType,
		Cursor: testCursor("7"),
	}); err != nil {
		t.Fatalf("handleFeedMessage event: %v", err)
	}
	requireRefreshCoordinatorCalls(t, coordinator, []refreshCoordinatorCall{{
		method: "invalidate", stream: RefreshStreamFeed, reason: RefreshReasonFeed,
	}})
	if got := saves.takeSaves(); len(got) != 0 {
		t.Fatalf("event persisted synchronously: %+v", got)
	}
	if got := feedSync.resumeCursor(); got == nil || got.Position != "7" {
		t.Fatalf("recorded cursor = %+v, want position 7", got)
	}

	// EOSE is a barrier: cursor persists immediately, no invalidation.
	if err := w.handleFeedMessage(&dwn.SubscriptionMessage{
		Type:   dwn.SubscriptionEOSEType,
		Cursor: testCursor("9"),
	}); err != nil {
		t.Fatalf("handleFeedMessage eose: %v", err)
	}
	requireRefreshCoordinatorCalls(t, coordinator, nil)
	got := saves.takeSaves()
	if len(got) != 1 || got[0].Cursor == nil || got[0].Cursor.Position != "9" {
		t.Fatalf("eose saves = %+v, want one save at position 9", got)
	}
}

func TestSubscriptionWatcherFeedProgressGapClearsCursor(t *testing.T) {
	saves := &feedSaveRecorder{}
	feedSync := newFeedSyncRecorder(testFeedLinkKey, saves.save, nil)
	feedSync.flushCursor(testCursor("7"))
	saves.takeSaves()
	coordinator := newRecordingRefreshCoordinator()
	w := newTestFeedWatcher(nil, coordinator, feedSync, nil)

	w.handleFeedLifecycle(dwn.SubscriptionLifecycleEvent{
		Kind: dwn.SubscriptionLifecycleProgressGap,
		Gap:  &dwn.ProgressGapInfo{Reason: "epoch_mismatch"},
	})

	requireRefreshCoordinatorCalls(t, coordinator, []refreshCoordinatorCall{{
		method: "live", stream: RefreshStreamFeed, needsFullRefresh: true,
	}})
	got := saves.takeSaves()
	if len(got) != 1 || got[0].Cursor != nil {
		t.Fatalf("gap saves = %+v, want one save with a cleared cursor", got)
	}
	if feedSync.resumeCursor() != nil {
		t.Fatal("cursor survived a progress gap")
	}
}

func TestSubscriptionWatcherFeedTerminalAuthDegradesToPolling(t *testing.T) {
	coordinator := newRecordingRefreshCoordinator()
	w := newTestFeedWatcher(nil, coordinator, nil, nil)
	w.initializeStreamCoverage(map[RefreshStream]bool{RefreshStreamFeed: true})
	coordinator.takeCalls()

	authErr := fmt.Errorf("terminal subscription error: %s: revoked: %w",
		dwn.MessagesSubscribeDeliveryAuthorizationFailedCode, dwn.ErrSubscriptionAuthorizationRevoked)
	w.handleFeedLifecycle(dwn.SubscriptionLifecycleEvent{
		Kind: dwn.SubscriptionLifecycleTerminal,
		Err:  authErr,
	})

	requireRefreshCoordinatorCalls(t, coordinator, []refreshCoordinatorCall{
		{method: "live", stream: RefreshStreamFeed},
		{method: "covered", stream: RefreshStreamFeed},
		{method: "degraded", degradedReason: feedAuthDegradedReason},
		{method: "notify", reason: RefreshReasonFeed},
	})
	if health := coordinator.streamHealth(RefreshStreamFeed); health.Covered || health.Live {
		t.Fatalf("feed stream health = %+v, want uncovered", health)
	}
}

func TestSubscriptionWatcherFeedTerminalWithoutAuthSentinelKeepsCoverage(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{name: "generic transport error", err: errors.New("connection torn down")},
		{
			// A server-side delivery fault is not a grant problem: it must
			// not trip the auth-degraded reason (which prescribes a wallet
			// remedy inapplicable on owner nodes).
			name: "delivery failed terminal",
			err: fmt.Errorf("terminal subscription error: %s: %s",
				dwn.MessagesSubscribeDeliveryFailedCode, "delivery stopped"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			coordinator := newRecordingRefreshCoordinator()
			w := newTestFeedWatcher(nil, coordinator, nil, nil)
			w.initializeStreamCoverage(map[RefreshStream]bool{RefreshStreamFeed: true})
			coordinator.takeCalls()

			w.handleFeedLifecycle(dwn.SubscriptionLifecycleEvent{
				Kind: dwn.SubscriptionLifecycleTerminal,
				Err:  tc.err,
			})

			requireRefreshCoordinatorCalls(t, coordinator, []refreshCoordinatorCall{
				{method: "live", stream: RefreshStreamFeed},
				{method: "notify", reason: RefreshReasonFeed},
			})
			if health := coordinator.streamHealth(RefreshStreamFeed); !health.Covered {
				t.Fatalf("feed stream health = %+v, want covered", health)
			}
		})
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
	// A role-only node is not feed-eligible: records streams, no recorder.
	if eng.subWatcher.feedMode || eng.feedSync != nil {
		t.Fatalf("feedMode = %v, feedSync = %v; want records mode", eng.subWatcher.feedMode, eng.feedSync)
	}
}

func TestEngineOwnerRunsFeedModeAndAdoptsCheckpoint(t *testing.T) {
	cfg := Config{
		AnchorEndpoint:  "https://example.com",
		AnchorTenant:    "did:dht:owner",
		NetworkRecordID: "record123",
		SelfDID:         "did:dht:owner",
		Signer:          &dwn.Signer{DID: "did:dht:owner"},
	}
	linkKey, err := feedLinkKey(cfg)
	if err != nil {
		t.Fatalf("feedLinkKey: %v", err)
	}
	saves := &feedSaveRecorder{}
	cfg.FeedSyncLoad = func() (*state.FeedSyncState, error) {
		return &state.FeedSyncState{
			LinkKey:     linkKey,
			Cursor:      testCursor("11"),
			Fingerprint: "ff00",
		}, nil
	}
	cfg.FeedSyncSave = saves.save

	eng, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer eng.Stop()

	if !eng.subWatcher.feedMode {
		t.Fatal("owner engine should run in feed mode")
	}
	if eng.feedSync == nil || eng.subWatcher.feedSync != eng.feedSync {
		t.Fatal("feed sync recorder not shared between engine and watcher")
	}
	if got := eng.feedSync.resumeCursor(); got == nil || got.Position != "11" {
		t.Fatalf("resume cursor = %+v, want adopted position 11", got)
	}
	if got := eng.feedSync.storedFingerprint(); got != "ff00" {
		t.Fatalf("stored fingerprint = %q, want adopted ff00", got)
	}
}
