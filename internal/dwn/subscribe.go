package dwn

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"
)

// Default flow control parameters matching the DWN server defaults.
const (
	// defaultAckInterval is how many events to receive before sending an ack.
	// The server's maxInFlight is 32, so we ack well before hitting that.
	defaultAckInterval = 16
)

//
// --- Subscription event types ---
//

// SubscriptionMessage is a single event delivered by a subscription.
// Matches the server's SubscriptionMessage type.
type SubscriptionMessage struct {
	Type   string       `json:"type"`   // "event" or "eose"
	Cursor string       `json:"cursor"` // EventLog cursor for crash-safe reconnection
	Event  *RecordEvent `json:"event,omitempty"`
}

// RecordEvent contains the changed record and optional initial write.
type RecordEvent struct {
	Message      json.RawMessage `json:"message"`
	InitialWrite json.RawMessage `json:"initialWrite,omitempty"`
}

// EventHandler is called for each subscription event.
type EventHandler func(event *SubscriptionMessage)

//
// --- Subscription ---
//

// Subscription represents an active WebSocket subscription to a DWN.
//
// Wire protocol:
//   - Subscribe via rpc.subscribe.dwn.processMessage with subscription.id
//   - Events arrive as JSON-RPC responses with id = subscription.id
//   - Client sends rpc.ack with cursor for flow control (server maxInFlight=32)
//   - Close via rpc.subscribe.close
type Subscription struct {
	// SubscriptionID is the client-generated UUID for this subscription.
	// All events for this subscription arrive with this ID.
	SubscriptionID string

	target  string
	filter  RecordsFilter
	signer  *Signer
	auth    MessageAuth
	handler EventHandler
	cursor  string // last known cursor for reconnection
	logger  *slog.Logger

	mu     sync.Mutex
	conn   *websocket.Conn
	cancel context.CancelFunc
	done   chan struct{}
}

// SubscriptionManager manages multiple DWN WebSocket subscriptions
// with automatic reconnection and flow control.
type SubscriptionManager struct {
	mu       sync.Mutex
	subs     map[string]*Subscription
	logger   *slog.Logger
	endpoint string
}

// NewSubscriptionManager creates a new subscription manager for the given endpoint.
func NewSubscriptionManager(endpoint string, logger *slog.Logger) *SubscriptionManager {
	if logger == nil {
		logger = slog.Default()
	}
	return &SubscriptionManager{
		subs:     make(map[string]*Subscription),
		logger:   logger,
		endpoint: endpoint,
	}
}

// Subscribe starts a new subscription to the target DWN.
//
// The subscription automatically reconnects on failure, resuming from
// the last known cursor. Events are delivered to the handler function.
//
// RecordsWrite is NOT supported over WebSocket — use the HTTP client instead.
func (m *SubscriptionManager) Subscribe(
	ctx context.Context,
	target string,
	signer *Signer,
	filter RecordsFilter,
	handler EventHandler,
) (*Subscription, error) {
	return m.SubscribeWithAuth(ctx, target, signer, filter, MessageAuth{}, handler)
}

// SubscribeWithAuth starts a new subscription with explicit authorization
// options (protocol role, plain grant, or delegated grant), mirroring the
// Records read/query/delete builders.
func (m *SubscriptionManager) SubscribeWithAuth(
	ctx context.Context,
	target string,
	signer *Signer,
	filter RecordsFilter,
	auth MessageAuth,
	handler EventHandler,
) (*Subscription, error) {
	subCtx, cancel := context.WithCancel(ctx)
	subscriptionID := uuid.New().String()

	sub := &Subscription{
		SubscriptionID: subscriptionID,
		target:         target,
		filter:         filter,
		signer:         signer,
		auth:           auth,
		handler:        handler,
		logger: m.logger.With(
			slog.String("subscription_id", subscriptionID),
			slog.String("target", target),
		),
		cancel: cancel,
		done:   make(chan struct{}),
	}

	m.mu.Lock()
	m.subs[subscriptionID] = sub
	m.mu.Unlock()

	go sub.run(subCtx, m.endpoint)

	return sub, nil
}

// Close stops a subscription and sends rpc.subscribe.close to the server.
func (s *Subscription) Close() {
	s.cancel()
	<-s.done
}

// Cursor returns the last known EventLog cursor for crash-safe reconnection.
func (s *Subscription) Cursor() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cursor
}

// CloseAll stops all active subscriptions.
func (m *SubscriptionManager) CloseAll() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, sub := range m.subs {
		sub.cancel()
		<-sub.done
	}
	m.subs = make(map[string]*Subscription)
}

// run manages the subscription lifecycle with automatic reconnection.
func (s *Subscription) run(ctx context.Context, endpoint string) {
	defer close(s.done)

	backoff := 1 * time.Second
	maxBackoff := 30 * time.Second

	for {
		err := s.connect(ctx, endpoint)
		if ctx.Err() != nil {
			return
		}

		s.logger.WarnContext(ctx, "subscription disconnected, reconnecting",
			slog.Any("error", err),
			slog.Duration("backoff", backoff),
		)

		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}

		backoff = min(backoff*2, maxBackoff)
	}
}

// connect establishes a WebSocket connection and runs the subscription loop.
func (s *Subscription) connect(ctx context.Context, endpoint string) error {
	wsURL := httpToWS(endpoint)

	conn, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		return fmt.Errorf("dialing websocket: %w", err)
	}

	s.mu.Lock()
	s.conn = conn
	s.mu.Unlock()

	defer func() {
		// Try to send close-subscription before disconnecting.
		s.closeSubscription(conn)
		conn.CloseNow()
		s.mu.Lock()
		s.conn = nil
		s.mu.Unlock()
	}()

	// Step 1: Send the subscription request.
	if err := s.sendSubscribeRequest(ctx, conn); err != nil {
		return fmt.Errorf("sending subscribe request: %w", err)
	}

	// Step 2: Read the initial response confirming the subscription.
	if err := s.readSubscribeResponse(ctx, conn); err != nil {
		return fmt.Errorf("reading subscribe response: %w", err)
	}

	// Step 3: Read events and send acks.
	return s.eventLoop(ctx, conn)
}

// sendSubscribeRequest sends the rpc.subscribe.dwn.processMessage request.
func (s *Subscription) sendSubscribeRequest(ctx context.Context, conn *websocket.Conn) error {
	// Build the RecordsSubscribe DWN message.
	s.mu.Lock()
	cursor := s.cursor
	s.mu.Unlock()

	msg, err := buildSubscribeMessage(s.signer, s.filter, cursor, s.auth)
	if err != nil {
		return fmt.Errorf("building subscribe message: %w", err)
	}

	// Wrap in JSON-RPC subscription request.
	rpcReq := newJsonRpcSubscribeRequest(s.target, msg, s.SubscriptionID)

	data, err := json.Marshal(rpcReq)
	if err != nil {
		return fmt.Errorf("marshaling subscribe request: %w", err)
	}

	if err := conn.Write(ctx, websocket.MessageText, data); err != nil {
		return fmt.Errorf("writing subscribe request: %w", err)
	}

	return nil
}

// readSubscribeResponse reads and validates the initial subscription confirmation.
func (s *Subscription) readSubscribeResponse(ctx context.Context, conn *websocket.Conn) error {
	_, data, err := conn.Read(ctx)
	if err != nil {
		return fmt.Errorf("reading response: %w", err)
	}

	var rpcResp JsonRpcResponse
	if err := json.Unmarshal(data, &rpcResp); err != nil {
		return fmt.Errorf("parsing response: %w", err)
	}

	if rpcResp.Error != nil {
		return fmt.Errorf("subscription rejected: %w", rpcResp.Error)
	}

	if rpcResp.Result == nil || rpcResp.Result.Reply == nil {
		return fmt.Errorf("unexpected response: missing result.reply")
	}

	if rpcResp.Result.Reply.Status.Code != 200 {
		return fmt.Errorf("subscription failed: %d %s",
			rpcResp.Result.Reply.Status.Code,
			rpcResp.Result.Reply.Status.Detail)
	}

	s.logger.InfoContext(ctx, "subscription established")
	return nil
}

// eventLoop reads subscription events and sends acknowledgments.
//
// Flow control: the server enforces maxInFlight=32. We send an ack every
// defaultAckInterval events to stay well within the window.
func (s *Subscription) eventLoop(ctx context.Context, conn *websocket.Conn) error {
	unacked := 0
	var lastCursor string

	for {
		_, data, err := conn.Read(ctx)
		if err != nil {
			return fmt.Errorf("reading event: %w", err)
		}

		var rpcResp JsonRpcResponse
		if err := json.Unmarshal(data, &rpcResp); err != nil {
			s.logger.WarnContext(ctx, "failed to parse event", slog.Any("error", err))
			continue
		}

		// Only process messages addressed to our subscription.
		if rpcResp.ID != s.SubscriptionID {
			// Could be a response to an ack or other request — ignore.
			continue
		}

		if rpcResp.Error != nil {
			s.logger.WarnContext(ctx, "subscription error",
				slog.Int("code", rpcResp.Error.Code),
				slog.String("message", rpcResp.Error.Message),
			)
			continue
		}

		if rpcResp.Result == nil || rpcResp.Result.Reply == nil {
			continue
		}

		// Extract the subscription event from result.subscription (not result.reply).
		// The server sends events in result.subscription for subscription messages.
		subData := rpcResp.Result.Subscription
		if subData == nil {
			// Try parsing from the raw JSON for the subscription field.
			continue
		}

		// Parse the subscription event.
		// Events come as: {"jsonrpc":"2.0","id":"<sub-id>","result":{"subscription":{"type":"event","cursor":"...","event":{...}}}}
		// We need to handle the subscription field from result.
		// Let's re-parse with a more flexible structure.
		var eventResp subscriptionEventResponse
		if err := json.Unmarshal(data, &eventResp); err != nil {
			s.logger.WarnContext(ctx, "failed to parse subscription event", slog.Any("error", err))
			continue
		}

		if eventResp.Result.Subscription == nil {
			continue
		}

		event := eventResp.Result.Subscription

		// Update cursor.
		if event.Cursor != "" {
			lastCursor = event.Cursor
			s.mu.Lock()
			s.cursor = event.Cursor
			s.mu.Unlock()
		}

		// Deliver event to handler.
		s.handler(event)

		// Flow control: ack periodically.
		unacked++
		if unacked >= defaultAckInterval && lastCursor != "" {
			if err := s.sendAck(ctx, conn, lastCursor); err != nil {
				s.logger.WarnContext(ctx, "failed to send ack", slog.Any("error", err))
			}
			unacked = 0
		}
	}
}

// subscriptionEventResponse is the full JSON-RPC response for subscription events.
type subscriptionEventResponse struct {
	ID     string `json:"id"`
	Result struct {
		Subscription *SubscriptionMessage `json:"subscription,omitempty"`
	} `json:"result"`
}

// sendAck sends an rpc.ack message for flow control.
func (s *Subscription) sendAck(ctx context.Context, conn *websocket.Conn, cursor string) error {
	ack := newJsonRpcAck(s.SubscriptionID, cursor)

	data, err := json.Marshal(ack)
	if err != nil {
		return fmt.Errorf("marshaling ack: %w", err)
	}

	return conn.Write(ctx, websocket.MessageText, data)
}

// closeSubscription sends rpc.subscribe.close before disconnecting.
func (s *Subscription) closeSubscription(conn *websocket.Conn) {
	closeReq := newJsonRpcCloseSubscription(s.SubscriptionID)

	data, err := json.Marshal(closeReq)
	if err != nil {
		return
	}

	// Use a short timeout — we're disconnecting anyway.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_ = conn.Write(ctx, websocket.MessageText, data)
}

// buildSubscribeMessage creates a RecordsSubscribe DWN message.
//
// Like the other Records builders it supports protocol-role, plain-grant
// (permissionGrantId in descriptor + payload), and delegated-grant
// (authorDelegatedGrant + delegatedGrantId) authorization.
func buildSubscribeMessage(signer *Signer, filter RecordsFilter, cursor string, auth MessageAuth) (*Message, error) {
	desc := map[string]any{
		"interface":        "Records",
		"method":           "Subscribe",
		"messageTimestamp": Now(),
		"filter":           filterToMap(filter),
	}
	if cursor != "" {
		desc["cursor"] = cursor
	}

	return signGenericMessage(signer, desc, auth)
}

// httpToWS converts an HTTP(S) URL to a WS(S) URL.
func httpToWS(url string) string {
	if strings.HasPrefix(url, "https://") {
		return "wss://" + url[len("https://"):]
	}
	if strings.HasPrefix(url, "http://") {
		return "ws://" + url[len("http://"):]
	}
	return url
}
