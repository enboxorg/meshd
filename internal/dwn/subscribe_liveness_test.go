package dwn

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
)

//
// --- Contract tests against a fake server ---
//

func TestSubscriptionHeartbeatPongKeepsConnectionAlive(t *testing.T) {
	const wantPongs = 3
	var connections atomic.Int32
	serverErrors := make(chan error, 8)
	serverDone := make(chan struct{})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if connections.Add(1) != 1 {
			serverErrors <- fmt.Errorf("unexpected reconnect: pongs must keep the connection alive")
			return
		}
		defer close(serverDone)
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			serverErrors <- fmt.Errorf("accept: %w", err)
			return
		}
		defer conn.CloseNow()

		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		request, err := readWSRequest(ctx, conn)
		if err != nil {
			serverErrors <- err
			return
		}
		if err := writeSubscribeReply(ctx, conn, request.ID, "sdk-message-cid"); err != nil {
			serverErrors <- err
			return
		}

		// Pong several ping generations, proving each pong clears its
		// deadline and the next tick starts a fresh generation.
		pingIDs := make(map[string]bool)
		for len(pingIDs) < wantPongs {
			pingID, err := expectPing(ctx, conn, livenessHeartbeatIDPrefix)
			if err != nil {
				serverErrors <- err
				return
			}
			if pingIDs[pingID] {
				serverErrors <- fmt.Errorf("ping id %q reused across generations", pingID)
				return
			}
			pingIDs[pingID] = true
			if err := writePong(ctx, conn, pingID); err != nil {
				serverErrors <- err
				return
			}
		}

		// The connection must still deliver events and receive acks.
		token := ProgressToken{StreamID: "stream", Epoch: "epoch", Position: "1"}
		event := &SubscriptionMessage{
			Type:   SubscriptionEventType,
			Cursor: &token,
			Event:  &RecordEvent{Message: json.RawMessage(`{"recordId":"peer-1"}`)},
		}
		if err := writeSubscriptionMessage(ctx, conn, request.Subscription.ID, event); err != nil {
			serverErrors <- err
			return
		}
		if err := expectAckSkippingPings(ctx, conn, request.Subscription.ID, token); err != nil {
			serverErrors <- err
			return
		}

		terminalToken := ProgressToken{StreamID: "stream", Epoch: "epoch", Position: "2"}
		terminal := &SubscriptionMessage{
			Type:   SubscriptionErrorType,
			Cursor: &terminalToken,
			Error:  &SubscriptionError{Code: "Closed", Detail: "test complete"},
		}
		if err := writeSubscriptionMessage(ctx, conn, request.Subscription.ID, terminal); err != nil {
			serverErrors <- err
			return
		}
		if err := expectAckSkippingPings(ctx, conn, request.Subscription.ID, terminalToken); err != nil {
			serverErrors <- err
		}
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	terminal := make(chan struct{}, 1)
	manager := NewSubscriptionManager(server.URL, slog.Default(),
		WithHeartbeat(50*time.Millisecond, 400*time.Millisecond),
	)
	sub, err := manager.SubscribeWithAuthAndLifecycle(
		ctx,
		"did:dht:target",
		newTestSigner(t),
		RecordsFilter{Protocol: "https://example.com/protocol"},
		MessageAuth{},
		func(*SubscriptionMessage) error { return nil },
		func(event SubscriptionLifecycleEvent) {
			if event.Kind == SubscriptionLifecycleTerminal {
				terminal <- struct{}{}
			}
		},
	)
	if err != nil {
		t.Fatalf("SubscribeWithAuthAndLifecycle: %v", err)
	}
	defer sub.Close()

	select {
	case <-terminal:
	case <-ctx.Done():
		t.Fatalf("waiting for terminal lifecycle: %v", ctx.Err())
	}
	select {
	case <-serverDone:
	case <-ctx.Done():
		t.Fatalf("waiting for server: %v", ctx.Err())
	}
	drainServerErrors(t, serverErrors)
	if got := connections.Load(); got != 1 {
		t.Fatalf("connections = %d, want 1 (pongs must prevent reconnects)", got)
	}
}

func TestSubscriptionMissedHeartbeatPongForceClosesAndResumesCursor(t *testing.T) {
	eventToken := ProgressToken{StreamID: "stream", Epoch: "epoch", Position: "1", MessageCID: "cid-1"}
	var connections atomic.Int32
	serverErrors := make(chan error, 8)
	serverDone := make(chan struct{})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			serverErrors <- fmt.Errorf("accept: %w", err)
			return
		}
		defer conn.CloseNow()

		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		request, err := readWSRequest(ctx, conn)
		if err != nil {
			serverErrors <- err
			return
		}
		switch connection := connections.Add(1); connection {
		case 1:
			if err := writeSubscribeReply(ctx, conn, request.ID, "conn-1"); err != nil {
				serverErrors <- err
				return
			}
			event := &SubscriptionMessage{
				Type:   SubscriptionEventType,
				Cursor: eventToken.clone(),
				Event:  &RecordEvent{Message: json.RawMessage(`{"recordId":"peer-1"}`)},
			}
			if err := writeSubscriptionMessage(ctx, conn, request.Subscription.ID, event); err != nil {
				serverErrors <- err
				return
			}
			if err := expectAckSkippingPings(ctx, conn, request.Subscription.ID, eventToken); err != nil {
				serverErrors <- err
				return
			}
			// Swallow pings without ponging: the client must declare the
			// connection dead and force-close it.
			for {
				if _, _, err := conn.Read(ctx); err != nil {
					return
				}
			}
		case 2:
			defer close(serverDone)
			// The resubscribe must resume from the last delivered cursor.
			if err := expectDescriptorCursor(request, eventToken); err != nil {
				serverErrors <- err
				return
			}
			if err := writeSubscribeReply(ctx, conn, request.ID, "conn-2"); err != nil {
				serverErrors <- err
				return
			}
			terminalToken := ProgressToken{StreamID: "stream", Epoch: "epoch", Position: "2"}
			terminal := &SubscriptionMessage{
				Type:   SubscriptionErrorType,
				Cursor: &terminalToken,
				Error:  &SubscriptionError{Code: "Closed", Detail: "test complete"},
			}
			if err := writeSubscriptionMessage(ctx, conn, request.Subscription.ID, terminal); err != nil {
				serverErrors <- err
				return
			}
			if err := expectAckSkippingPings(ctx, conn, request.Subscription.ID, terminalToken); err != nil {
				serverErrors <- err
			}
		default:
			serverErrors <- fmt.Errorf("unexpected connection %d", connection)
		}
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	lifecycle := make(chan SubscriptionLifecycleEvent, 16)
	manager := NewSubscriptionManager(server.URL, slog.Default(),
		WithHeartbeat(50*time.Millisecond, 150*time.Millisecond),
	)
	sub, err := manager.SubscribeWithAuthAndLifecycle(
		ctx,
		"did:dht:target",
		newTestSigner(t),
		RecordsFilter{Protocol: "https://example.com/protocol"},
		MessageAuth{},
		func(*SubscriptionMessage) error { return nil },
		func(event SubscriptionLifecycleEvent) { lifecycle <- event },
	)
	if err != nil {
		t.Fatalf("SubscribeWithAuthAndLifecycle: %v", err)
	}
	defer sub.Close()

	var established []SubscriptionLifecycleEvent
	var retryingSeen, terminalSeen bool
	for !terminalSeen {
		select {
		case event := <-lifecycle:
			switch event.Kind {
			case SubscriptionLifecycleEstablished:
				established = append(established, event)
			case SubscriptionLifecycleRetrying:
				retryingSeen = true
			case SubscriptionLifecycleTerminal:
				terminalSeen = true
			}
		case <-ctx.Done():
			t.Fatalf("waiting for terminal lifecycle: %v", ctx.Err())
		}
	}
	if !retryingSeen {
		t.Error("missed pong did not produce a retrying lifecycle event")
	}
	if len(established) != 2 {
		t.Fatalf("established events = %d, want 2 (heartbeat must force a reconnect)", len(established))
	}
	if established[1].NeedsFullRefresh {
		t.Error("cursor-resumed establishment after heartbeat close must not require full refresh")
	}
	select {
	case <-serverDone:
	case <-ctx.Done():
		t.Fatalf("waiting for server: %v", ctx.Err())
	}
	drainServerErrors(t, serverErrors)
	if got := connections.Load(); got != 2 {
		t.Fatalf("connections = %d, want 2", got)
	}
}

func TestSubscriptionCheckHealthProbePongIsHealthyWithoutReconnect(t *testing.T) {
	var connections atomic.Int32
	serverErrors := make(chan error, 8)
	serverDone := make(chan struct{})
	probed := make(chan struct{})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if connections.Add(1) != 1 {
			serverErrors <- fmt.Errorf("unexpected reconnect after healthy probe")
			return
		}
		defer close(serverDone)
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			serverErrors <- fmt.Errorf("accept: %w", err)
			return
		}
		defer conn.CloseNow()

		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		request, err := readWSRequest(ctx, conn)
		if err != nil {
			serverErrors <- err
			return
		}
		if err := writeSubscribeReply(ctx, conn, request.ID, "sdk-message-cid"); err != nil {
			serverErrors <- err
			return
		}

		pingID, err := expectPing(ctx, conn, livenessProbeIDPrefix)
		if err != nil {
			serverErrors <- err
			return
		}
		if err := writePong(ctx, conn, pingID); err != nil {
			serverErrors <- err
			return
		}
		close(probed)

		terminalToken := ProgressToken{StreamID: "stream", Epoch: "epoch", Position: "1"}
		terminal := &SubscriptionMessage{
			Type:   SubscriptionErrorType,
			Cursor: &terminalToken,
			Error:  &SubscriptionError{Code: "Closed", Detail: "test complete"},
		}
		if err := writeSubscriptionMessage(ctx, conn, request.Subscription.ID, terminal); err != nil {
			serverErrors <- err
			return
		}
		if err := expectAckSkippingPings(ctx, conn, request.Subscription.ID, terminalToken); err != nil {
			serverErrors <- err
		}
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	lifecycle := make(chan SubscriptionLifecycleEvent, 8)
	manager := NewSubscriptionManager(server.URL, slog.Default(),
		WithHeartbeat(-1, 0), // isolate the probe from heartbeat traffic
		WithHealthProbeTimeout(2*time.Second),
	)
	sub, err := manager.SubscribeWithAuthAndLifecycle(
		ctx,
		"did:dht:target",
		newTestSigner(t),
		RecordsFilter{Protocol: "https://example.com/protocol"},
		MessageAuth{},
		func(*SubscriptionMessage) error { return nil },
		func(event SubscriptionLifecycleEvent) { lifecycle <- event },
	)
	if err != nil {
		t.Fatalf("SubscribeWithAuthAndLifecycle: %v", err)
	}
	defer sub.Close()

	waitForLifecycleKind(t, ctx, lifecycle, SubscriptionLifecycleEstablished)
	if !sub.CheckHealth(ctx) {
		t.Fatal("CheckHealth = false, want healthy verdict from probe pong")
	}
	select {
	case <-probed:
	case <-ctx.Done():
		t.Fatalf("server never saw the probe: %v", ctx.Err())
	}

	waitForLifecycleKind(t, ctx, lifecycle, SubscriptionLifecycleTerminal)
	select {
	case <-serverDone:
	case <-ctx.Done():
		t.Fatalf("waiting for server: %v", ctx.Err())
	}
	drainServerErrors(t, serverErrors)
	if got := connections.Load(); got != 1 {
		t.Fatalf("connections = %d, want 1 (healthy probe must not reconnect)", got)
	}
}

func TestSubscriptionCheckHealthMissedProbeForceClosesAndResumesCursor(t *testing.T) {
	eventToken := ProgressToken{StreamID: "stream", Epoch: "epoch", Position: "1", MessageCID: "cid-1"}
	var connections atomic.Int32
	serverErrors := make(chan error, 8)
	serverDone := make(chan struct{})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			serverErrors <- fmt.Errorf("accept: %w", err)
			return
		}
		defer conn.CloseNow()

		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		request, err := readWSRequest(ctx, conn)
		if err != nil {
			serverErrors <- err
			return
		}
		switch connection := connections.Add(1); connection {
		case 1:
			if err := writeSubscribeReply(ctx, conn, request.ID, "conn-1"); err != nil {
				serverErrors <- err
				return
			}
			event := &SubscriptionMessage{
				Type:   SubscriptionEventType,
				Cursor: eventToken.clone(),
				Event:  &RecordEvent{Message: json.RawMessage(`{"recordId":"peer-1"}`)},
			}
			if err := writeSubscriptionMessage(ctx, conn, request.Subscription.ID, event); err != nil {
				serverErrors <- err
				return
			}
			// The probe ping may overtake the ack write; drop pings
			// unanswered — the probe must miss its pong.
			if err := expectAckDroppingPings(ctx, conn, request.Subscription.ID, eventToken); err != nil {
				serverErrors <- err
				return
			}
			// Swallow the probe ping: the client must force-close.
			for {
				if _, _, err := conn.Read(ctx); err != nil {
					return
				}
			}
		case 2:
			defer close(serverDone)
			if err := expectDescriptorCursor(request, eventToken); err != nil {
				serverErrors <- err
				return
			}
			if err := writeSubscribeReply(ctx, conn, request.ID, "conn-2"); err != nil {
				serverErrors <- err
				return
			}
			terminalToken := ProgressToken{StreamID: "stream", Epoch: "epoch", Position: "2"}
			terminal := &SubscriptionMessage{
				Type:   SubscriptionErrorType,
				Cursor: &terminalToken,
				Error:  &SubscriptionError{Code: "Closed", Detail: "test complete"},
			}
			if err := writeSubscriptionMessage(ctx, conn, request.Subscription.ID, terminal); err != nil {
				serverErrors <- err
				return
			}
			if err := expectAck(ctx, conn, request.Subscription.ID, terminalToken); err != nil {
				serverErrors <- err
			}
		default:
			serverErrors <- fmt.Errorf("unexpected connection %d", connection)
		}
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	events := make(chan SubscriptionMessage, 8)
	lifecycle := make(chan SubscriptionLifecycleEvent, 16)
	manager := NewSubscriptionManager(server.URL, slog.Default(),
		WithHeartbeat(-1, 0),
		WithHealthProbeTimeout(150*time.Millisecond),
	)
	sub, err := manager.SubscribeWithAuthAndLifecycle(
		ctx,
		"did:dht:target",
		newTestSigner(t),
		RecordsFilter{Protocol: "https://example.com/protocol"},
		MessageAuth{},
		func(message *SubscriptionMessage) error {
			events <- *message
			return nil
		},
		func(event SubscriptionLifecycleEvent) { lifecycle <- event },
	)
	if err != nil {
		t.Fatalf("SubscribeWithAuthAndLifecycle: %v", err)
	}
	defer sub.Close()

	// Probe only after the first event's cursor is remembered so the
	// resubscribe assertion is deterministic.
	select {
	case <-events:
	case <-ctx.Done():
		t.Fatalf("waiting for first event: %v", ctx.Err())
	}
	if sub.CheckHealth(ctx) {
		t.Fatal("CheckHealth = true, want unhealthy verdict for a missed probe pong")
	}

	waitForLifecycleKind(t, ctx, lifecycle, SubscriptionLifecycleTerminal)
	select {
	case <-serverDone:
	case <-ctx.Done():
		t.Fatalf("waiting for server: %v", ctx.Err())
	}
	drainServerErrors(t, serverErrors)
	if got := connections.Load(); got != 2 {
		t.Fatalf("connections = %d, want reconnect after missed probe", got)
	}
}

func TestSubscriptionCheckHealthFastForwardsReconnectBackoff(t *testing.T) {
	var connections atomic.Int32
	serverErrors := make(chan error, 8)
	serverDone := make(chan struct{})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			serverErrors <- fmt.Errorf("accept: %w", err)
			return
		}
		defer conn.CloseNow()

		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		request, err := readWSRequest(ctx, conn)
		if err != nil {
			serverErrors <- err
			return
		}
		switch connection := connections.Add(1); connection {
		case 1, 2:
			// Retryable failures grow the backoff to 2s before connection 3.
			if err := writeSubscriptionStatusReply(ctx, conn, request.ID, http.StatusInternalServerError, "flaky"); err != nil {
				serverErrors <- err
			}
		case 3:
			defer close(serverDone)
			if err := writeSubscribeReply(ctx, conn, request.ID, "conn-3"); err != nil {
				serverErrors <- err
				return
			}
			terminalToken := ProgressToken{StreamID: "stream", Epoch: "epoch", Position: "1"}
			terminal := &SubscriptionMessage{
				Type:   SubscriptionErrorType,
				Cursor: &terminalToken,
				Error:  &SubscriptionError{Code: "Closed", Detail: "test complete"},
			}
			if err := writeSubscriptionMessage(ctx, conn, request.Subscription.ID, terminal); err != nil {
				serverErrors <- err
				return
			}
			if err := expectAck(ctx, conn, request.Subscription.ID, terminalToken); err != nil {
				serverErrors <- err
			}
		default:
			serverErrors <- fmt.Errorf("unexpected connection %d", connection)
		}
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	lifecycle := make(chan SubscriptionLifecycleEvent, 16)
	manager := NewSubscriptionManager(server.URL, slog.Default())
	sub, err := manager.SubscribeWithAuthAndLifecycle(
		ctx,
		"did:dht:target",
		newTestSigner(t),
		RecordsFilter{Protocol: "https://example.com/protocol"},
		MessageAuth{},
		func(*SubscriptionMessage) error { return nil },
		func(event SubscriptionLifecycleEvent) { lifecycle <- event },
	)
	if err != nil {
		t.Fatalf("SubscribeWithAuthAndLifecycle: %v", err)
	}
	defer sub.Close()

	// Wait for the second retrying event: its scheduled wait is 2s.
	var secondRetry SubscriptionLifecycleEvent
	for retries := 0; retries < 2; {
		select {
		case event := <-lifecycle:
			if event.Kind == SubscriptionLifecycleRetrying {
				retries++
				secondRetry = event
			}
		case <-ctx.Done():
			t.Fatalf("waiting for second retry: %v", ctx.Err())
		}
	}
	if secondRetry.RetryIn < 2*time.Second {
		t.Fatalf("second retry backoff = %v, want >= 2s for a meaningful fast-forward", secondRetry.RetryIn)
	}

	// Fast-forward the 2s wait via the manager-level probe-all entry point.
	start := time.Now()
	manager.CheckHealth(ctx)
	waitForLifecycleKind(t, ctx, lifecycle, SubscriptionLifecycleEstablished)
	if elapsed := time.Since(start); elapsed >= secondRetry.RetryIn {
		t.Fatalf("reconnect took %v, want fast-forward well below the %v backoff", elapsed, secondRetry.RetryIn)
	}

	waitForLifecycleKind(t, ctx, lifecycle, SubscriptionLifecycleTerminal)
	select {
	case <-serverDone:
	case <-ctx.Done():
		t.Fatalf("waiting for server: %v", ctx.Err())
	}
	drainServerErrors(t, serverErrors)
	if got := connections.Load(); got != 3 {
		t.Fatalf("connections = %d, want 3", got)
	}
}

//
// --- Unit tests on the liveness generation discipline ---
//

func TestConnLivenessHeartbeatGenerationDiscipline(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	conn := newFakeLivenessConn()
	// Long deadline: expiry is driven explicitly for determinism.
	liveness := newConnLiveness(conn, slog.Default(), time.Minute)

	liveness.heartbeatTick(ctx)
	ping1 := conn.nextWrite(t)
	if ping1.Method != MethodPing || !strings.HasPrefix(ping1.ID, livenessHeartbeatIDPrefix) {
		t.Fatalf("heartbeat frame = %+v, want rpc.ping with %q id prefix", ping1, livenessHeartbeatIDPrefix)
	}

	// A tick while the pong is still awaited must not send another ping.
	liveness.heartbeatTick(ctx)
	conn.expectNoWrite(t)

	// A successful probe clears the pending heartbeat deadline and
	// supersedes ping1.
	probeResult := make(chan bool, 1)
	go func() { probeResult <- liveness.probe(ctx, time.Minute) }()
	probePing := conn.nextWrite(t)
	if probePing.Method != MethodPing || !strings.HasPrefix(probePing.ID, livenessProbeIDPrefix) {
		t.Fatalf("probe frame = %+v, want rpc.ping with %q id prefix", probePing, livenessProbeIDPrefix)
	}
	if !liveness.consumePong(probePing.ID, nil) {
		t.Fatal("probe pong not consumed")
	}
	if healthy := <-probeResult; !healthy {
		t.Fatal("probe = unhealthy, want healthy after pong")
	}

	// The late pong for the superseded ping mutates nothing.
	if liveness.consumePong(ping1.ID, nil) {
		t.Fatal("late pong for superseded ping was consumed")
	}

	// A new generation starts; the superseded pong and deadline stay inert.
	liveness.heartbeatTick(ctx)
	ping2 := conn.nextWrite(t)
	if ping2.ID == ping1.ID {
		t.Fatal("heartbeat reused a superseded ping id")
	}
	if liveness.consumePong(ping1.ID, nil) {
		t.Fatal("late pong for superseded ping was consumed after a new generation")
	}
	liveness.heartbeatDeadlineExpired(ping1.ID)
	if got := conn.closeCount.Load(); got != 0 {
		t.Fatalf("superseded deadline closed the connection %d times, want 0", got)
	}

	// Only the active generation's pong clears; only its deadline kills.
	if !liveness.consumePong(ping2.ID, nil) {
		t.Fatal("active heartbeat pong not consumed")
	}
	liveness.heartbeatTick(ctx)
	ping3 := conn.nextWrite(t)
	liveness.heartbeatDeadlineExpired(ping3.ID)
	if got := conn.closeCount.Load(); got != 1 {
		t.Fatalf("active deadline expiry closed the connection %d times, want 1", got)
	}
}

func TestConnLivenessProbeCoalescing(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	conn := newFakeLivenessConn()
	liveness := newConnLiveness(conn, slog.Default(), time.Minute)

	results := make(chan bool, 2)
	go func() { results <- liveness.probe(ctx, time.Minute) }()
	ping := conn.nextWrite(t)
	go func() { results <- liveness.probe(ctx, time.Minute) }()

	// Let the second prober coalesce onto the in-flight probe; a second
	// ping frame would betray a separate probe.
	time.Sleep(50 * time.Millisecond)
	conn.expectNoWrite(t)

	if !liveness.consumePong(ping.ID, nil) {
		t.Fatal("probe pong not consumed")
	}
	for range 2 {
		select {
		case healthy := <-results:
			if !healthy {
				t.Fatal("coalesced probe = unhealthy, want shared healthy verdict")
			}
		case <-time.After(2 * time.Second):
			t.Fatal("coalesced probe did not resolve")
		}
	}
	if got := conn.closeCount.Load(); got != 0 {
		t.Fatalf("healthy probe closed the connection %d times, want 0", got)
	}
}

func TestConnLivenessProbeErrorResponseAndShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	conn := newFakeLivenessConn()
	liveness := newConnLiveness(conn, slog.Default(), time.Minute)

	// An error response consumes the probe but is not proof of liveness.
	result := make(chan bool, 1)
	go func() { result <- liveness.probe(ctx, time.Minute) }()
	ping := conn.nextWrite(t)
	if !liveness.consumePong(ping.ID, &JsonRpcError{Code: -32601, Message: "method not found"}) {
		t.Fatal("probe error response not consumed")
	}
	if healthy := <-result; healthy {
		t.Fatal("probe = healthy, want unhealthy on error response")
	}

	// Connection teardown resolves an in-flight probe unhealthy.
	go func() { result <- liveness.probe(ctx, time.Minute) }()
	conn.nextWrite(t)
	liveness.shutdown()
	if healthy := <-result; healthy {
		t.Fatal("probe = healthy, want unhealthy after teardown")
	}
	// Probes after teardown are refused without touching the dead conn.
	if liveness.probe(ctx, time.Minute) {
		t.Fatal("probe on a torn-down connection reported healthy")
	}
	conn.expectNoWrite(t)
}

//
// --- Test helpers ---
//

type fakeLivenessConn struct {
	writes     chan JsonRpcRequest
	closeCount atomic.Int32
}

func newFakeLivenessConn() *fakeLivenessConn {
	return &fakeLivenessConn{writes: make(chan JsonRpcRequest, 16)}
}

func (c *fakeLivenessConn) Write(_ context.Context, _ websocket.MessageType, p []byte) error {
	var request JsonRpcRequest
	if err := json.Unmarshal(p, &request); err != nil {
		return err
	}
	c.writes <- request
	return nil
}

func (c *fakeLivenessConn) CloseNow() error {
	c.closeCount.Add(1)
	return nil
}

func (c *fakeLivenessConn) nextWrite(t *testing.T) JsonRpcRequest {
	t.Helper()
	select {
	case request := <-c.writes:
		return request
	case <-time.After(2 * time.Second):
		t.Fatal("expected a websocket write")
		return JsonRpcRequest{}
	}
}

func (c *fakeLivenessConn) expectNoWrite(t *testing.T) {
	t.Helper()
	select {
	case request := <-c.writes:
		t.Fatalf("unexpected websocket write: %+v", request)
	default:
	}
}

// expectPing reads one frame and asserts it is an rpc.ping whose id carries
// the given liveness prefix, returning the ping id.
func expectPing(ctx context.Context, conn *websocket.Conn, idPrefix string) (string, error) {
	request, err := readWSRequestAny(ctx, conn)
	if err != nil {
		return "", err
	}
	if request.Method != MethodPing {
		return "", fmt.Errorf("method = %q, want %q", request.Method, MethodPing)
	}
	if !strings.HasPrefix(request.ID, idPrefix) {
		return "", fmt.Errorf("ping id = %q, want prefix %q", request.ID, idPrefix)
	}
	if request.Params != nil {
		return "", fmt.Errorf("ping params = %+v, want none", request.Params)
	}
	return request.ID, nil
}

// writePong answers a ping with the server's success shape: a JSON-RPC
// response echoing the ping id with result {"ok":true}.
func writePong(ctx context.Context, conn *websocket.Conn, pingID string) error {
	return writeWSJSON(ctx, conn, map[string]any{
		"jsonrpc": "2.0",
		"id":      pingID,
		"result":  map[string]any{"ok": true},
	})
}

// expectAckSkippingPings reads frames until the ack arrives, answering any
// interleaved liveness pings so the connection stays verifiably alive.
func expectAckSkippingPings(ctx context.Context, conn *websocket.Conn, subscriptionID string, want ProgressToken) error {
	return expectAckTolerantOfPings(ctx, conn, subscriptionID, want, true)
}

// expectAckDroppingPings reads frames until the ack arrives, swallowing any
// interleaved liveness pings unanswered so their pong deadline can expire.
func expectAckDroppingPings(ctx context.Context, conn *websocket.Conn, subscriptionID string, want ProgressToken) error {
	return expectAckTolerantOfPings(ctx, conn, subscriptionID, want, false)
}

func expectAckTolerantOfPings(ctx context.Context, conn *websocket.Conn, subscriptionID string, want ProgressToken, pongPings bool) error {
	for {
		request, err := readWSRequestAny(ctx, conn)
		if err != nil {
			return err
		}
		if request.Method == MethodPing {
			if pongPings {
				if err := writePong(ctx, conn, request.ID); err != nil {
					return err
				}
			}
			continue
		}
		if request.Method != MethodAck {
			return fmt.Errorf("method = %q, want %q", request.Method, MethodAck)
		}
		if request.Subscription == nil || request.Subscription.ID != subscriptionID {
			return fmt.Errorf("ack subscription = %+v, want %q", request.Subscription, subscriptionID)
		}
		if request.Params == nil || request.Params.Cursor == nil || *request.Params.Cursor != want {
			return fmt.Errorf("ack cursor = %+v, want %+v", request.Params, want)
		}
		return nil
	}
}

func waitForLifecycleKind(t *testing.T, ctx context.Context, lifecycle <-chan SubscriptionLifecycleEvent, want SubscriptionLifecycleKind) {
	t.Helper()
	for {
		select {
		case event := <-lifecycle:
			if event.Kind == want {
				return
			}
		case <-ctx.Done():
			t.Fatalf("waiting for %q lifecycle: %v", want, ctx.Err())
		}
	}
}
