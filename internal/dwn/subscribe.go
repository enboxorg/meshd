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
)

// SubscriptionEvent is delivered to handlers when a matching record changes.
type SubscriptionEvent struct {
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
type EventHandler func(event *SubscriptionEvent)

// Subscription represents an active subscription to a DWN.
type Subscription struct {
	ID string

	endpoint string
	tenant   string
	filter   RecordsFilter
	signer   *Signer
	handler  EventHandler
	cursor   string
	logger   *slog.Logger

	cancel context.CancelFunc
	done   chan struct{}
}

// SubscriptionManager manages multiple DWN subscriptions with reconnection.
type SubscriptionManager struct {
	mu     sync.Mutex
	subs   map[string]*Subscription
	logger *slog.Logger
}

// NewSubscriptionManager creates a new subscription manager.
func NewSubscriptionManager(logger *slog.Logger) *SubscriptionManager {
	if logger == nil {
		logger = slog.Default()
	}
	return &SubscriptionManager{
		subs:   make(map[string]*Subscription),
		logger: logger,
	}
}

// Subscribe starts a new subscription to a DWN endpoint.
// The subscription automatically reconnects on failure.
func (m *SubscriptionManager) Subscribe(
	ctx context.Context,
	endpoint string,
	tenant string,
	signer *Signer,
	filter RecordsFilter,
	handler EventHandler,
) (*Subscription, error) {
	subCtx, cancel := context.WithCancel(ctx)

	key := subscriptionKey(endpoint, tenant, filter)

	sub := &Subscription{
		endpoint: endpoint,
		tenant:   tenant,
		filter:   filter,
		signer:   signer,
		handler:  handler,
		logger: m.logger.With(
			slog.String("endpoint", endpoint),
			slog.String("tenant", tenant),
		),
		cancel: cancel,
		done:   make(chan struct{}),
	}

	m.mu.Lock()
	m.subs[key] = sub
	m.mu.Unlock()

	go sub.run(subCtx)

	return sub, nil
}

// Close stops a subscription.
func (s *Subscription) Close() {
	s.cancel()
	<-s.done
}

// Cursor returns the last known EventLog cursor.
func (s *Subscription) Cursor() string {
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

func (s *Subscription) run(ctx context.Context) {
	defer close(s.done)

	backoff := 1 * time.Second
	maxBackoff := 30 * time.Second

	for {
		err := s.connect(ctx)
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

func (s *Subscription) connect(ctx context.Context) error {
	wsURL := httpToWS(s.endpoint)
	if s.tenant != "" {
		wsURL = wsURL + "/" + s.tenant
	}

	conn, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		return fmt.Errorf("dialing websocket: %w", err)
	}
	defer conn.CloseNow()

	msg, err := buildSubscribeMessage(s.signer, s.filter, s.cursor)
	if err != nil {
		return fmt.Errorf("building subscribe message: %w", err)
	}

	msgBytes, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshaling subscribe: %w", err)
	}

	if err := conn.Write(ctx, websocket.MessageText, msgBytes); err != nil {
		return fmt.Errorf("writing subscribe: %w", err)
	}

	for {
		_, data, err := conn.Read(ctx)
		if err != nil {
			return fmt.Errorf("reading: %w", err)
		}

		var event SubscriptionEvent
		if err := json.Unmarshal(data, &event); err != nil {
			s.logger.WarnContext(ctx, "unmarshaling event", slog.Any("error", err))
			continue
		}

		if event.Cursor != "" {
			s.cursor = event.Cursor
		}

		s.handler(&event)
	}
}

func buildSubscribeMessage(signer *Signer, filter RecordsFilter, cursor string) (*Message, error) {
	desc := map[string]any{
		"interface":        "Records",
		"method":           "Subscribe",
		"messageTimestamp": Now(),
		"filter":           filterToMap(filter),
	}

	return signGenericMessage(signer, desc, "")
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

func subscriptionKey(endpoint, tenant string, filter RecordsFilter) string {
	return fmt.Sprintf("%s|%s|%s|%s", endpoint, tenant, filter.Protocol, filter.ProtocolPath)
}
