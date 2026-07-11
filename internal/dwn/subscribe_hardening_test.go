package dwn

import (
	"context"
	"encoding/json"
	"errors"
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

func TestSubscriptionInvalidCursorProgressionTriggersFreshRepair(t *testing.T) {
	tests := []struct {
		name     string
		current  ProgressToken
		incoming ProgressToken
		reason   string
	}{
		{
			name:     "cross stream",
			current:  ProgressToken{StreamID: "stream-a", Epoch: "epoch", Position: "10"},
			incoming: ProgressToken{StreamID: "stream-b", Epoch: "epoch", Position: "11"},
			reason:   "stream_mismatch",
		},
		{
			name:     "lower token",
			current:  ProgressToken{StreamID: "stream", Epoch: "epoch", Position: "10"},
			incoming: ProgressToken{StreamID: "stream", Epoch: "epoch", Position: "9"},
			reason:   "token_too_old",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
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
					if err := expectDescriptorCursor(request, tc.current); err != nil {
						serverErrors <- err
						return
					}
					message := &SubscriptionMessage{
						Type:   SubscriptionEventType,
						Cursor: tc.incoming.clone(),
						Event:  &RecordEvent{Message: json.RawMessage(`{"recordId":"must-not-be-handled"}`)},
					}
					if err := writeSubscriptionMessage(ctx, conn, request.Subscription.ID, message); err != nil {
						serverErrors <- err
						return
					}

					// Cursor validation happens before the handler and acknowledgement.
					// The only client frame after rejection must be best-effort close.
					clientFrame, err := readWSRequestAny(ctx, conn)
					if err != nil {
						serverErrors <- fmt.Errorf("read frame after rejected token: %w", err)
						return
					}
					if clientFrame.Method != MethodCloseSubscribe {
						serverErrors <- fmt.Errorf("method after rejected token = %q, want %q (no ack)", clientFrame.Method, MethodCloseSubscribe)
					}
				case 2:
					defer close(serverDone)
					if _, ok := request.Params.Message.Descriptor["cursor"]; ok {
						serverErrors <- fmt.Errorf("fresh repair request still carried cursor")
						return
					}
					if err := writeSubscribeReply(ctx, conn, request.ID, "fresh-after-local-gap"); err != nil {
						serverErrors <- err
						return
					}
					terminalCursor := ProgressToken{StreamID: "fresh-stream", Epoch: "fresh-epoch", Position: "1"}
					terminal := &SubscriptionMessage{
						Type:   SubscriptionErrorType,
						Cursor: &terminalCursor,
						Error:  &SubscriptionError{Code: "Closed", Detail: "test complete"},
					}
					if err := writeSubscriptionMessage(ctx, conn, request.Subscription.ID, terminal); err != nil {
						serverErrors <- err
						return
					}
					if err := expectAck(ctx, conn, request.Subscription.ID, terminalCursor); err != nil {
						serverErrors <- err
					}
				default:
					serverErrors <- fmt.Errorf("unexpected connection %d", connection)
				}
			}))
			defer server.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			lifecycle := make(chan SubscriptionLifecycleEvent, 8)
			var handled atomic.Int32
			sub := &Subscription{
				SubscriptionID: "local-gap-subscription",
				target:         "did:dht:target",
				filter:         RecordsFilter{Protocol: "https://example.com/protocol"},
				signer:         newTestSigner(t),
				handler: func(*SubscriptionMessage) error {
					handled.Add(1)
					return nil
				},
				lifecycleHandler: func(event SubscriptionLifecycleEvent) { lifecycle <- event },
				cursor:           tc.current.clone(),
				logger:           slog.Default(),
				cancel:           cancel,
				done:             make(chan struct{}),
			}
			go sub.run(ctx, server.URL)
			defer sub.Close()

			var (
				gapSeen              bool
				freshEstablishedSeen bool
				terminalSeen         bool
			)
			for !terminalSeen {
				select {
				case event := <-lifecycle:
					switch event.Kind {
					case SubscriptionLifecycleProgressGap:
						gapSeen = true
						if event.Gap == nil || event.Gap.Reason != tc.reason {
							t.Fatalf("gap = %+v, want reason %q", event.Gap, tc.reason)
						}
						if sub.Cursor() != nil {
							t.Fatalf("cursor not cleared before repair: %+v", sub.Cursor())
						}
					case SubscriptionLifecycleEstablished:
						freshEstablishedSeen = event.NeedsFullRefresh
					case SubscriptionLifecycleTerminal:
						terminalSeen = true
					}
				case <-ctx.Done():
					t.Fatalf("waiting for repair lifecycle: %v", ctx.Err())
				}
			}

			if !gapSeen || !freshEstablishedSeen {
				t.Fatalf("gapSeen=%v freshEstablishedSeen=%v", gapSeen, freshEstablishedSeen)
			}
			if got := handled.Load(); got != 1 {
				t.Fatalf("handled messages = %d, want only the terminal message", got)
			}
			select {
			case <-serverDone:
			case <-ctx.Done():
				t.Fatalf("waiting for server: %v", ctx.Err())
			}
			drainServerErrors(t, serverErrors)
			if got := connections.Load(); got != 2 {
				t.Fatalf("connections = %d, want repair connection", got)
			}
		})
	}
}

func TestSubscriptionCursorProgressionAllowsOnlyExactEOSE(t *testing.T) {
	current := ProgressToken{StreamID: "stream", Epoch: "epoch", Position: "7"}
	sub := &Subscription{cursor: current.clone()}

	if err := sub.validateCursorProgression(SubscriptionEOSEType, current.clone()); err != nil {
		t.Fatalf("exact EOSE token rejected: %v", err)
	}

	err := sub.validateCursorProgression(SubscriptionEventType, current.clone())
	var gap *progressGapError
	if !errors.As(err, &gap) || gap.info == nil || gap.info.Reason != "token_too_old" {
		t.Fatalf("exact event token error = %v, want token_too_old gap", err)
	}

	epochMismatch := current
	epochMismatch.Epoch = "other-epoch"
	err = sub.validateCursorProgression(SubscriptionEOSEType, &epochMismatch)
	if !errors.As(err, &gap) || gap.info == nil || gap.info.Reason != "epoch_mismatch" {
		t.Fatalf("cross-epoch EOSE error = %v, want epoch_mismatch gap", err)
	}
}

func TestSubscriptionPermanentHandshakeStatusIsTerminal(t *testing.T) {
	for _, statusCode := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		t.Run(http.StatusText(statusCode), func(t *testing.T) {
			var connections atomic.Int32
			serverErrors := make(chan error, 2)
			serverDone := make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer close(serverDone)
				connections.Add(1)
				conn, err := websocket.Accept(w, r, nil)
				if err != nil {
					serverErrors <- err
					return
				}
				defer conn.CloseNow()
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				request, err := readWSRequest(ctx, conn)
				if err != nil {
					serverErrors <- err
					return
				}
				if err := writeSubscriptionStatusReply(ctx, conn, request.ID, statusCode, http.StatusText(statusCode)); err != nil {
					serverErrors <- err
				}
			}))
			defer server.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			lifecycle := make(chan SubscriptionLifecycleEvent, 4)
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

			select {
			case event := <-lifecycle:
				if event.Kind != SubscriptionLifecycleTerminal {
					t.Fatalf("lifecycle = %q, want terminal", event.Kind)
				}
				if event.Err == nil || !strings.Contains(event.Err.Error(), fmt.Sprintf("%d", statusCode)) {
					t.Fatalf("terminal error = %v, want status %d", event.Err, statusCode)
				}
			case <-ctx.Done():
				t.Fatalf("waiting for terminal lifecycle: %v", ctx.Err())
			}
			select {
			case <-sub.done:
			case <-ctx.Done():
				t.Fatalf("subscription did not terminate: %v", ctx.Err())
			}
			sub.Close()
			select {
			case <-serverDone:
			case <-ctx.Done():
				t.Fatalf("waiting for server: %v", ctx.Err())
			}
			drainServerErrors(t, serverErrors)
			if got := connections.Load(); got != 1 {
				t.Fatalf("connections = %d, want no reconnect", got)
			}
			select {
			case event := <-lifecycle:
				t.Fatalf("unexpected lifecycle after terminal: %+v", event)
			default:
			}
		})
	}
}

func TestSubscriptionRateLimitHandshakeRemainsRetryable(t *testing.T) {
	var connections atomic.Int32
	serverErrors := make(chan error, 4)
	serverDone := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			serverErrors <- err
			return
		}
		defer conn.CloseNow()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		request, err := readWSRequest(ctx, conn)
		if err != nil {
			serverErrors <- err
			return
		}
		switch connection := connections.Add(1); connection {
		case 1:
			if err := writeSubscriptionStatusReply(ctx, conn, request.ID, http.StatusTooManyRequests, "rate limited"); err != nil {
				serverErrors <- err
			}
		case 2:
			defer close(serverDone)
			if err := writeSubscriptionStatusReply(ctx, conn, request.ID, http.StatusUnauthorized, "expired"); err != nil {
				serverErrors <- err
			}
		default:
			serverErrors <- fmt.Errorf("unexpected connection %d", connection)
		}
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	lifecycle := make(chan SubscriptionLifecycleEvent, 4)
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

	var kinds []SubscriptionLifecycleKind
	for len(kinds) < 2 {
		select {
		case event := <-lifecycle:
			kinds = append(kinds, event.Kind)
		case <-ctx.Done():
			t.Fatalf("waiting for retry then terminal: %v; kinds=%v", ctx.Err(), kinds)
		}
	}
	if kinds[0] != SubscriptionLifecycleRetrying || kinds[1] != SubscriptionLifecycleTerminal {
		t.Fatalf("lifecycle = %v, want [retrying terminal]", kinds)
	}
	select {
	case <-serverDone:
	case <-ctx.Done():
		t.Fatalf("waiting for retry server: %v", ctx.Err())
	}
	drainServerErrors(t, serverErrors)
	if got := connections.Load(); got != 2 {
		t.Fatalf("connections = %d, want one retry", got)
	}
}

func TestSubscriptionManagerCloseAllIsTerminalAndConcurrentCallersWait(t *testing.T) {
	manager := NewSubscriptionManager("http://example.invalid", slog.Default())
	blockedCtx, blockedCancel := context.WithCancel(context.Background())
	blocked := &Subscription{cancel: blockedCancel, done: make(chan struct{})}
	manager.subs["blocked"] = blocked

	firstReturned := make(chan struct{})
	go func() {
		manager.CloseAll()
		close(firstReturned)
	}()

	select {
	case <-blockedCtx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("CloseAll did not cancel existing subscription")
	}

	secondStarted := make(chan struct{})
	secondReturned := make(chan struct{})
	go func() {
		close(secondStarted)
		manager.CloseAll()
		close(secondReturned)
	}()
	<-secondStarted

	select {
	case <-secondReturned:
		t.Fatal("concurrent CloseAll returned before active subscription stopped")
	case <-time.After(50 * time.Millisecond):
	}

	assertSubscribeRejectedAfterClose(t, manager)
	close(blocked.done)

	for name, returned := range map[string]<-chan struct{}{
		"first CloseAll":  firstReturned,
		"second CloseAll": secondReturned,
	} {
		select {
		case <-returned:
		case <-time.After(2 * time.Second):
			t.Fatalf("%s did not return after cleanup", name)
		}
	}

	assertSubscribeRejectedAfterClose(t, manager)
}

func TestSubscribeDefensivelyCopiesFilterAndAuth(t *testing.T) {
	published := true
	authors := []string{"did:example:alice", "did:example:bob"}
	recipients := []string{"did:example:carol", "did:example:dave"}
	rawTag := json.RawMessage(`{"operator":"eq","value":"original"}`)
	tagList := []any{"one", map[string]any{"nested": "original"}}
	tagRange := map[string]any{"gte": "a", "lt": "z"}
	tags := map[string]any{
		"raw":   rawTag,
		"list":  tagList,
		"range": tagRange,
	}
	delegatedGrant := json.RawMessage(`{"recordId":"grant-original","encodedData":"abc"}`)

	filter := RecordsFilter{
		Author:    authors,
		Recipient: recipients,
		Protocol:  "https://example.com/protocol",
		Published: &published,
		Tags:      tags,
	}
	auth := MessageAuth{DelegatedGrant: delegatedGrant}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	manager := NewSubscriptionManager("http://example.invalid", slog.Default())
	sub, err := manager.SubscribeWithAuthAndLifecycle(
		ctx,
		"did:dht:target",
		newTestSigner(t),
		filter,
		auth,
		func(*SubscriptionMessage) error { return nil },
		nil,
	)
	if err != nil {
		t.Fatalf("SubscribeWithAuthAndLifecycle: %v", err)
	}
	select {
	case <-sub.done:
	case <-time.After(2 * time.Second):
		t.Fatal("pre-canceled subscription did not stop")
	}
	defer sub.Close()

	authors[0] = "mutated-author"
	recipients[0] = "mutated-recipient"
	published = false
	rawTag[0] = 'X'
	tagList[0] = "mutated-list"
	tagList[1].(map[string]any)["nested"] = "mutated-nested"
	tagRange["gte"] = "mutated-range"
	tags["new"] = "mutated-root"
	delegatedGrant[0] = 'X'

	gotAuthors, ok := sub.filter.Author.([]string)
	if !ok || len(gotAuthors) != 2 || gotAuthors[0] != "did:example:alice" {
		t.Fatalf("stored authors = %#v, want original copy", sub.filter.Author)
	}
	gotRecipients, ok := sub.filter.Recipient.([]string)
	if !ok || len(gotRecipients) != 2 || gotRecipients[0] != "did:example:carol" {
		t.Fatalf("stored recipients = %#v, want original copy", sub.filter.Recipient)
	}
	if sub.filter.Published == nil || !*sub.filter.Published {
		t.Fatalf("stored published = %#v, want independent true", sub.filter.Published)
	}
	if _, ok := sub.filter.Tags["new"]; ok {
		t.Fatalf("stored tags observed caller map mutation: %#v", sub.filter.Tags)
	}
	if got := sub.filter.Tags["range"].(map[string]any)["gte"]; got != "a" {
		t.Fatalf("stored nested range = %#v, want a", got)
	}
	storedList := sub.filter.Tags["list"].([]any)
	if storedList[0] != "one" || storedList[1].(map[string]any)["nested"] != "original" {
		t.Fatalf("stored list = %#v, want original deep copy", storedList)
	}
	if got := string(sub.filter.Tags["raw"].(json.RawMessage)); got != `{"operator":"eq","value":"original"}` {
		t.Fatalf("stored raw tag = %q, want original", got)
	}
	if got := string(sub.auth.DelegatedGrant); got != `{"recordId":"grant-original","encodedData":"abc"}` {
		t.Fatalf("stored delegated grant = %q, want original", got)
	}
}

func writeSubscriptionStatusReply(ctx context.Context, conn *websocket.Conn, requestID string, code int, detail string) error {
	return writeWSJSON(ctx, conn, JsonRpcResponse{
		JSONRPC: "2.0",
		ID:      requestID,
		Result: &JsonRpcResult{Reply: &DwnReply{
			Status: Status{Code: code, Detail: detail},
		}},
	})
}

func assertSubscribeRejectedAfterClose(t *testing.T, manager *SubscriptionManager) {
	t.Helper()
	sub, err := manager.Subscribe(
		context.Background(),
		"did:dht:target",
		newTestSigner(t),
		RecordsFilter{Protocol: "https://example.com/protocol"},
		func(*SubscriptionMessage) error { return nil },
	)
	if err == nil || !strings.Contains(err.Error(), "manager is closed") {
		t.Fatalf("Subscribe after CloseAll = (%+v, %v), want closed error", sub, err)
	}
	if sub != nil {
		t.Fatalf("Subscribe after CloseAll returned subscription: %+v", sub)
	}
}
