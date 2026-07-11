package dwn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"
)

const (
	SubscriptionEventType = "event"
	SubscriptionEOSEType  = "eose"
	SubscriptionErrorType = "error"
)

//
// --- Subscription event types ---
//

// ProgressToken is a source-local EventLog cursor. Positions are decimal
// strings and are comparable only within the same stream and epoch.
type ProgressToken struct {
	StreamID   string `json:"streamId"`
	Epoch      string `json:"epoch"`
	Position   string `json:"position"`
	MessageCID string `json:"messageCid,omitempty"`
}

func (p *ProgressToken) clone() *ProgressToken {
	if p == nil {
		return nil
	}
	clone := *p
	return &clone
}

func (p *ProgressToken) valid() bool {
	if p == nil || p.StreamID == "" || p.Epoch == "" {
		return false
	}
	_, ok := normalizedDecimalPosition(p.Position)
	return ok
}

func shouldReplaceProgressToken(current, candidate *ProgressToken) bool {
	if !candidate.valid() {
		return false
	}
	if current == nil {
		return true
	}
	if candidate.StreamID != current.StreamID || candidate.Epoch != current.Epoch {
		return false
	}
	return decimalPositionGreater(candidate.Position, current.Position)
}

func decimalPositionGreater(candidate, existing string) bool {
	return compareDecimalPositions(candidate, existing) > 0
}

func compareDecimalPositions(candidate, existing string) int {
	candidate, candidateOK := normalizedDecimalPosition(candidate)
	existing, existingOK := normalizedDecimalPosition(existing)
	if !candidateOK {
		return -1
	}
	if !existingOK {
		return 1
	}
	if len(candidate) < len(existing) {
		return -1
	}
	if len(candidate) > len(existing) {
		return 1
	}
	if candidate < existing {
		return -1
	}
	if candidate > existing {
		return 1
	}
	return 0
}

func normalizedDecimalPosition(value string) (string, bool) {
	if value == "" {
		return "", false
	}
	for i := range len(value) {
		if value[i] < '0' || value[i] > '9' {
			return "", false
		}
	}
	value = strings.TrimLeft(value, "0")
	if value == "" {
		value = "0"
	}
	return value, true
}

// SubscriptionError is a terminal error delivered on an open subscription.
type SubscriptionError struct {
	Code   string `json:"code"`
	Detail string `json:"detail"`
}

// ProgressGapInfo describes why a stored cursor cannot be resumed.
type ProgressGapInfo struct {
	Code            string        `json:"code,omitempty"`
	Requested       ProgressToken `json:"requested"`
	OldestAvailable ProgressToken `json:"oldestAvailable"`
	LatestAvailable ProgressToken `json:"latestAvailable"`
	Reason          string        `json:"reason"`
}

type SubscriptionLifecycleKind string

const (
	SubscriptionLifecycleEstablished SubscriptionLifecycleKind = "established"
	SubscriptionLifecycleRetrying    SubscriptionLifecycleKind = "retrying"
	SubscriptionLifecycleProgressGap SubscriptionLifecycleKind = "progress_gap"
	SubscriptionLifecycleTerminal    SubscriptionLifecycleKind = "terminal"
)

// SubscriptionLifecycleEvent reports transport state separately from wire events.
type SubscriptionLifecycleEvent struct {
	Kind             SubscriptionLifecycleKind
	NeedsFullRefresh bool
	Attempt          int
	RetryIn          time.Duration
	Gap              *ProgressGapInfo
	Err              error
}

// SubscriptionLifecycleHandler receives serialized connection lifecycle events.
type SubscriptionLifecycleHandler func(event SubscriptionLifecycleEvent)

// SubscriptionMessage is a single event delivered by a subscription.
// Matches the server's SubscriptionMessage type.
type SubscriptionMessage struct {
	Type              string             `json:"type"` // "event", "eose", or "error"
	Cursor            *ProgressToken     `json:"cursor"`
	Event             *RecordEvent       `json:"event,omitempty"`
	Error             *SubscriptionError `json:"error,omitempty"`
	Seq               string             `json:"seq,omitempty"`
	MessageCID        string             `json:"messageCid,omitempty"`
	IsLatestBaseState *bool              `json:"isLatestBaseState,omitempty"`
	Protocol          string             `json:"protocol,omitempty"`
	EncodedData       string             `json:"encodedData,omitempty"`
}

// RecordEvent contains the changed record and optional initial write.
type RecordEvent struct {
	Message      json.RawMessage `json:"message"`
	InitialWrite json.RawMessage `json:"initialWrite,omitempty"`
}

// EventHandler is called for each subscription event.
type EventHandler func(event *SubscriptionMessage) error

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

	target           string
	filter           RecordsFilter
	signer           *Signer
	auth             MessageAuth
	handler          EventHandler
	lifecycleHandler SubscriptionLifecycleHandler
	cursor           *ProgressToken // last known cursor for reconnection
	logger           *slog.Logger

	mu     sync.Mutex
	conn   *websocket.Conn
	cancel context.CancelFunc
	done   chan struct{}
}

// SubscriptionManager manages multiple DWN WebSocket subscriptions
// with automatic reconnection and flow control.
type SubscriptionManager struct {
	mu        sync.Mutex
	subs      map[string]*Subscription
	logger    *slog.Logger
	endpoint  string
	closed    bool
	closeDone chan struct{}
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

func cloneSubscriptionFilter(filter RecordsFilter) RecordsFilter {
	filter.Author = cloneSubscriptionJSONValue(filter.Author)
	filter.Recipient = cloneSubscriptionJSONValue(filter.Recipient)
	if filter.Published != nil {
		published := *filter.Published
		filter.Published = &published
	}
	if filter.Tags != nil {
		filter.Tags = cloneSubscriptionJSONValue(filter.Tags).(map[string]any)
	}
	return filter
}

func cloneSubscriptionJSONValue(value any) any {
	switch typed := value.(type) {
	case []string:
		return append([]string(nil), typed...)
	case []any:
		clone := make([]any, len(typed))
		for i, item := range typed {
			clone[i] = cloneSubscriptionJSONValue(item)
		}
		return clone
	case map[string]any:
		clone := make(map[string]any, len(typed))
		for key, item := range typed {
			clone[key] = cloneSubscriptionJSONValue(item)
		}
		return clone
	case json.RawMessage:
		return append(json.RawMessage(nil), typed...)
	default:
		return value
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
	return m.SubscribeWithAuthAndLifecycle(ctx, target, signer, filter, auth, handler, nil)
}

// SubscribeWithAuthAndLifecycle starts a subscription and reports transport lifecycle state.
func (m *SubscriptionManager) SubscribeWithAuthAndLifecycle(
	ctx context.Context,
	target string,
	signer *Signer,
	filter RecordsFilter,
	auth MessageAuth,
	handler EventHandler,
	lifecycleHandler SubscriptionLifecycleHandler,
) (*Subscription, error) {
	if ctx == nil {
		return nil, fmt.Errorf("subscription context is required")
	}
	if target == "" {
		return nil, fmt.Errorf("subscription target is required")
	}
	if signer == nil {
		return nil, fmt.Errorf("subscription signer is required")
	}
	if handler == nil {
		return nil, fmt.Errorf("subscription event handler is required")
	}
	if err := auth.validate(); err != nil {
		return nil, fmt.Errorf("subscription auth: %w", err)
	}

	filter = cloneSubscriptionFilter(filter)
	auth.DelegatedGrant = append(json.RawMessage(nil), auth.DelegatedGrant...)

	subCtx, cancel := context.WithCancel(ctx)
	subscriptionID := uuid.New().String()

	sub := &Subscription{
		SubscriptionID:   subscriptionID,
		target:           target,
		filter:           filter,
		signer:           signer,
		auth:             auth,
		handler:          handler,
		lifecycleHandler: lifecycleHandler,
		logger: m.logger.With(
			slog.String("subscription_id", subscriptionID),
			slog.String("target", target),
		),
		cancel: cancel,
		done:   make(chan struct{}),
	}

	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		cancel()
		return nil, fmt.Errorf("subscription manager is closed")
	}
	if m.subs == nil {
		m.subs = make(map[string]*Subscription)
	}
	m.subs[subscriptionID] = sub
	m.mu.Unlock()

	go func() {
		sub.run(subCtx, m.endpoint)
		m.mu.Lock()
		if m.subs[subscriptionID] == sub {
			delete(m.subs, subscriptionID)
		}
		m.mu.Unlock()
	}()

	return sub, nil
}

// Close stops a subscription and sends rpc.subscribe.close to the server.
func (s *Subscription) Close() {
	// Callbacks run on the subscription goroutine to preserve event, cursor,
	// and acknowledgement ordering. They must return an error or cancel their
	// parent context instead of calling Close synchronously.
	s.cancel()
	<-s.done
}

// Cursor returns the last known EventLog cursor for crash-safe reconnection.
func (s *Subscription) Cursor() *ProgressToken {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cursor.clone()
}

func (s *Subscription) emitLifecycle(event SubscriptionLifecycleEvent) {
	if s.lifecycleHandler == nil {
		return
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			s.logger.Error("subscription lifecycle handler panicked", slog.Any("panic", recovered))
		}
	}()
	s.lifecycleHandler(event)
}

func (s *Subscription) clearCursor() {
	s.mu.Lock()
	s.cursor = nil
	s.mu.Unlock()
}

// CloseAll stops all active subscriptions.
func (m *SubscriptionManager) CloseAll() {
	m.mu.Lock()
	if m.closed {
		done := m.closeDone
		m.mu.Unlock()
		if done != nil {
			<-done
		}
		return
	}
	m.closed = true
	m.closeDone = make(chan struct{})
	done := m.closeDone
	subs := make([]*Subscription, 0, len(m.subs))
	for _, sub := range m.subs {
		subs = append(subs, sub)
	}
	m.subs = make(map[string]*Subscription)
	m.mu.Unlock()

	for _, sub := range subs {
		sub.cancel()
	}
	for _, sub := range subs {
		<-sub.done
	}
	close(done)
}

// run manages the subscription lifecycle with automatic reconnection.
func (s *Subscription) run(ctx context.Context, endpoint string) {
	defer close(s.done)

	backoff := time.Second
	const maxBackoff = 30 * time.Second
	attempt := 0

	for {
		established, err := s.connect(ctx, endpoint)
		if ctx.Err() != nil {
			return
		}

		if established {
			attempt = 0
			backoff = time.Second
		}

		var terminalErr *terminalSubscriptionError
		if errors.As(err, &terminalErr) {
			s.emitLifecycle(SubscriptionLifecycleEvent{
				Kind: SubscriptionLifecycleTerminal,
				Err:  terminalErr,
			})
			return
		}

		var gapErr *progressGapError
		if errors.As(err, &gapErr) {
			s.clearCursor()
			s.emitLifecycle(SubscriptionLifecycleEvent{
				Kind: SubscriptionLifecycleProgressGap,
				Gap:  gapErr.info,
				Err:  err,
			})
			backoff = time.Second
		}

		attempt++
		s.emitLifecycle(SubscriptionLifecycleEvent{
			Kind:    SubscriptionLifecycleRetrying,
			Attempt: attempt,
			RetryIn: backoff,
			Err:     err,
		})
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

// connect establishes a WebSocket connection and reports whether the handshake completed.
func (s *Subscription) connect(ctx context.Context, endpoint string) (bool, error) {
	wsURL := httpToWS(endpoint)

	conn, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		return false, fmt.Errorf("dialing websocket: %w", err)
	}

	s.mu.Lock()
	s.conn = conn
	s.mu.Unlock()

	defer func() {
		s.closeSubscription(conn)
		conn.CloseNow()
		s.mu.Lock()
		s.conn = nil
		s.mu.Unlock()
	}()

	requestID, resumeCursor, err := s.sendSubscribeRequest(ctx, conn)
	if err != nil {
		return false, fmt.Errorf("sending subscribe request: %w", err)
	}

	// Cursor replay can synchronously produce subscription frames before the
	// request-ID confirmation. The handshake demultiplexes both frame types.
	if err := s.readSubscribeResponse(ctx, conn, requestID, resumeCursor); err != nil {
		return false, fmt.Errorf("reading subscribe response: %w", err)
	}

	return true, s.eventLoop(ctx, conn)
}

// sendSubscribeRequest sends the rpc.subscribe.dwn.processMessage request.
func (s *Subscription) sendSubscribeRequest(ctx context.Context, conn *websocket.Conn) (string, *ProgressToken, error) {
	cursor := s.Cursor()

	msg, err := buildSubscribeMessage(s.signer, s.filter, cursor, s.auth)
	if err != nil {
		return "", nil, fmt.Errorf("building subscribe message: %w", err)
	}

	rpcReq := newJsonRpcSubscribeRequest(s.target, msg, s.SubscriptionID)
	data, err := json.Marshal(rpcReq)
	if err != nil {
		return "", nil, fmt.Errorf("marshaling subscribe request: %w", err)
	}

	if err := conn.Write(ctx, websocket.MessageText, data); err != nil {
		return "", nil, fmt.Errorf("writing subscribe request: %w", err)
	}

	return rpcReq.ID, cursor, nil
}

// progressGapError marks a cursor that production can no longer resume.
type progressGapError struct {
	info *ProgressGapInfo
}

func (e *progressGapError) Error() string {
	if e == nil || e.info == nil {
		return "subscription progress gap"
	}
	return fmt.Sprintf("subscription progress gap: %s", e.info.Reason)
}

// readSubscribeResponse demultiplexes replay events and the request reply.
// Production may deliver subscription-ID replay frames before the request-ID
// confirmation because it installs and drains the listener synchronously.
func (s *Subscription) readSubscribeResponse(ctx context.Context, conn *websocket.Conn, requestID string, resumeCursor *ProgressToken) error {
	for {
		_, data, err := conn.Read(ctx)
		if err != nil {
			return fmt.Errorf("reading response: %w", err)
		}

		var rpcResp JsonRpcResponse
		if err := json.Unmarshal(data, &rpcResp); err != nil {
			return fmt.Errorf("parsing response: %w", err)
		}

		if rpcResp.ID == s.SubscriptionID {
			if err := s.handleSubscriptionFrame(ctx, conn, data); err != nil {
				return err
			}
			continue
		}
		if rpcResp.ID != requestID {
			continue
		}
		if rpcResp.Error != nil {
			rejection := fmt.Errorf("subscription rejected: %w", rpcResp.Error)
			if permanentJSONRPCSubscriptionError(rpcResp.Error.Code) {
				return &terminalSubscriptionError{err: rejection}
			}
			return rejection
		}
		if rpcResp.Result == nil || rpcResp.Result.Reply == nil {
			return &terminalSubscriptionError{err: fmt.Errorf("unexpected response: missing result.reply")}
		}

		reply := rpcResp.Result.Reply
		if reply.Status.Code == http.StatusGone {
			gap := &ProgressGapInfo{}
			if len(reply.Error) > 0 {
				_ = json.Unmarshal(reply.Error, gap)
			}
			return &progressGapError{info: gap}
		}
		if reply.Status.Code != http.StatusOK {
			failure := fmt.Errorf("subscription failed: %d %s", reply.Status.Code, reply.Status.Detail)
			if permanentSubscriptionStatus(reply.Status.Code) {
				return &terminalSubscriptionError{err: failure}
			}
			return failure
		}
		if reply.Subscription == nil {
			return &terminalSubscriptionError{err: fmt.Errorf("unexpected response: missing reply.subscription")}
		}

		s.emitLifecycle(SubscriptionLifecycleEvent{
			Kind:             SubscriptionLifecycleEstablished,
			NeedsFullRefresh: resumeCursor == nil,
		})
		s.logger.InfoContext(ctx, "subscription established")
		return nil
	}
}

// eventLoop reads production subscription frames until the connection closes.
func (s *Subscription) eventLoop(ctx context.Context, conn *websocket.Conn) error {
	for {
		_, data, err := conn.Read(ctx)
		if err != nil {
			return fmt.Errorf("reading event: %w", err)
		}
		if err := s.handleSubscriptionFrame(ctx, conn, data); err != nil {
			return err
		}
	}
}

// subscriptionEventResponse is the production JSON-RPC event envelope.
type subscriptionEventResponse struct {
	ID     string `json:"id"`
	Result *struct {
		Subscription *SubscriptionMessage `json:"subscription,omitempty"`
	} `json:"result,omitempty"`
	Error *JsonRpcError `json:"error,omitempty"`
}

type terminalSubscriptionError struct {
	err error
}

func (e *terminalSubscriptionError) Error() string {
	return e.err.Error()
}

func (e *terminalSubscriptionError) Unwrap() error {
	return e.err
}

func permanentJSONRPCSubscriptionError(code int) bool {
	switch code {
	case -32700, -32600, -32601, JsonRpcInvalidParams:
		return true
	default:
		return false
	}
}

func permanentSubscriptionStatus(code int) bool {
	return code >= 400 && code < 500 &&
		code != http.StatusRequestTimeout &&
		code != http.StatusGone &&
		code != http.StatusTooManyRequests
}

func (s *Subscription) handleSubscriptionFrame(ctx context.Context, conn *websocket.Conn, data []byte) error {
	var response subscriptionEventResponse
	if err := json.Unmarshal(data, &response); err != nil {
		return fmt.Errorf("parsing subscription event: %w", err)
	}
	if response.ID != s.SubscriptionID {
		return nil
	}
	if response.Error != nil {
		return fmt.Errorf("subscription JSON-RPC error: %w", response.Error)
	}
	if response.Result == nil || response.Result.Subscription == nil {
		return fmt.Errorf("subscription frame missing result.subscription")
	}

	message := response.Result.Subscription
	if err := validateSubscriptionMessage(message); err != nil {
		return err
	}
	cursor := message.Cursor.clone()
	message.Cursor = cursor.clone()
	messageType := message.Type
	if err := s.validateCursorProgression(messageType, cursor); err != nil {
		return err
	}
	var terminalErr error
	if messageType == SubscriptionErrorType {
		terminalErr = fmt.Errorf("terminal subscription error: %s: %s", message.Error.Code, message.Error.Detail)
	}

	if s.handler != nil {
		if err := s.callEventHandler(message); err != nil {
			return fmt.Errorf("handling subscription %s: %w", messageType, err)
		}
	}

	s.rememberCursor(cursor)
	if err := s.sendAck(ctx, conn, cursor); err != nil {
		ackErr := fmt.Errorf("acknowledging subscription %s: %w", messageType, err)
		if terminalErr != nil {
			return &terminalSubscriptionError{err: fmt.Errorf("%w; %v", terminalErr, ackErr)}
		}
		return ackErr
	}
	if terminalErr != nil {
		return &terminalSubscriptionError{err: terminalErr}
	}
	return nil
}

func (s *Subscription) callEventHandler(message *SubscriptionMessage) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("subscription event handler panicked: %v", recovered)
		}
	}()
	return s.handler(message)
}

func validateSubscriptionMessage(message *SubscriptionMessage) error {
	if message == nil {
		return fmt.Errorf("nil subscription message")
	}
	if !message.Cursor.valid() {
		return fmt.Errorf("subscription %q has an invalid progress token", message.Type)
	}
	switch message.Type {
	case SubscriptionEventType:
		if message.Event == nil || len(message.Event.Message) == 0 {
			return fmt.Errorf("subscription event is missing event.message")
		}
	case SubscriptionEOSEType:
	case SubscriptionErrorType:
		if message.Error == nil {
			return fmt.Errorf("subscription error is missing error details")
		}
	default:
		return fmt.Errorf("unknown subscription message type %q", message.Type)
	}
	return nil
}

func (s *Subscription) rememberCursor(cursor *ProgressToken) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if shouldReplaceProgressToken(s.cursor, cursor) {
		s.cursor = cursor.clone()
	}
}

func (s *Subscription) validateCursorProgression(messageType string, candidate *ProgressToken) error {
	current := s.Cursor()
	if current == nil {
		return nil
	}
	if candidate.StreamID != current.StreamID {
		return subscriptionCursorGap(current, candidate, "stream_mismatch")
	}
	if candidate.Epoch != current.Epoch {
		return subscriptionCursorGap(current, candidate, "epoch_mismatch")
	}
	comparison := compareDecimalPositions(candidate.Position, current.Position)
	if comparison < 0 || (comparison == 0 && messageType != SubscriptionEOSEType) {
		return subscriptionCursorGap(current, candidate, "token_too_old")
	}
	return nil
}

func subscriptionCursorGap(current, candidate *ProgressToken, reason string) error {
	info := &ProgressGapInfo{Code: "ProgressGap", Reason: reason}
	if current != nil {
		info.Requested = *current.clone()
	}
	if candidate != nil {
		info.LatestAvailable = *candidate.clone()
	}
	return &progressGapError{info: info}
}

// sendAck sends an rpc.ack message for flow control.
func (s *Subscription) sendAck(ctx context.Context, conn *websocket.Conn, cursor *ProgressToken) error {
	if !cursor.valid() {
		return fmt.Errorf("invalid progress token")
	}
	ack := newJsonRpcAck(s.SubscriptionID, *cursor)

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
func buildSubscribeMessage(signer *Signer, filter RecordsFilter, cursor *ProgressToken, auth MessageAuth) (*Message, error) {
	desc := map[string]any{
		"interface":        "Records",
		"method":           "Subscribe",
		"messageTimestamp": Now(),
		"filter":           filterToMap(filter),
	}
	if cursor.valid() {
		desc["cursor"] = *cursor.clone()
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
