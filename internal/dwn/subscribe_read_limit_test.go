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

func TestSubscriptionOversizedMessageReconnectsWithoutHandlingOrAck(t *testing.T) {
	var connections atomic.Int32
	serverErrors := make(chan error, 8)
	oversizedRejected := make(chan struct{})
	validAcked := make(chan struct{})
	serverFinished := make(chan struct{})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			serverErrors <- fmt.Errorf("accept: %w", err)
			return
		}
		defer conn.CloseNow()

		ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
		defer cancel()
		request, err := readWSRequest(ctx, conn)
		if err != nil {
			serverErrors <- err
			return
		}

		switch connection := connections.Add(1); connection {
		case 1:
			if err := writeSubscribeReply(ctx, conn, request.ID, "oversized-frame-subscription"); err != nil {
				serverErrors <- err
				return
			}
			token := ProgressToken{StreamID: "stream", Epoch: "epoch", Position: "1"}
			message := &SubscriptionMessage{
				Type:        SubscriptionEventType,
				Cursor:      &token,
				EncodedData: strings.Repeat("A", int(subscriptionMaxMessageBytes)),
				Event: &RecordEvent{
					Message: json.RawMessage("{\"recordId\":\"oversized-must-not-be-handled\"}"),
				},
			}
			if err := writeSubscriptionMessage(ctx, conn, request.Subscription.ID, message); err != nil {
				serverErrors <- err
				return
			}

			// The read limit closes the connection at the WebSocket layer. An
			// application rpc.ack must never be emitted for the rejected frame.
			_, _, err = conn.Read(ctx)
			if got := websocket.CloseStatus(err); got != websocket.StatusMessageTooBig {
				serverErrors <- fmt.Errorf("close status after oversized frame = %d (%v), want %d", got, err, websocket.StatusMessageTooBig)
				return
			}
			close(oversizedRejected)
		case 2:
			defer close(serverFinished)
			if _, ok := request.Params.Message.Descriptor["cursor"]; ok {
				serverErrors <- fmt.Errorf("reconnect after unhandled frame unexpectedly carried a cursor")
				return
			}
			if err := writeSubscribeReply(ctx, conn, request.ID, "valid-frame-subscription"); err != nil {
				serverErrors <- err
				return
			}

			validToken := ProgressToken{StreamID: "stream", Epoch: "epoch", Position: "1"}
			valid := &SubscriptionMessage{
				Type:   SubscriptionEventType,
				Cursor: &validToken,
				Event: &RecordEvent{
					Message: json.RawMessage("{\"recordId\":\"valid-after-reconnect\"}"),
				},
			}
			if err := writeSubscriptionMessage(ctx, conn, request.Subscription.ID, valid); err != nil {
				serverErrors <- err
				return
			}
			if err := expectAck(ctx, conn, request.Subscription.ID, validToken); err != nil {
				serverErrors <- err
				return
			}
			close(validAcked)

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

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	lifecycle := make(chan SubscriptionLifecycleEvent, 8)
	handled := make(chan SubscriptionMessage, 4)
	manager := NewSubscriptionManager(server.URL, slog.Default())
	sub, err := manager.SubscribeWithAuthAndLifecycle(
		ctx,
		"did:dht:target",
		newTestSigner(t),
		RecordsFilter{Protocol: "https://example.com/protocol"},
		MessageAuth{},
		func(message *SubscriptionMessage) error {
			copyMessage := *message
			if message.Event != nil {
				copyEvent := *message.Event
				copyEvent.Message = append(json.RawMessage(nil), message.Event.Message...)
				copyMessage.Event = &copyEvent
			}
			handled <- copyMessage
			return nil
		},
		func(event SubscriptionLifecycleEvent) {
			lifecycle <- event
		},
	)
	if err != nil {
		cancel()
		t.Fatalf("SubscribeWithAuthAndLifecycle: %v", err)
	}
	defer func() {
		cancel()
		sub.Close()
	}()

	var gotLifecycle []SubscriptionLifecycleKind
	for {
		select {
		case event := <-lifecycle:
			gotLifecycle = append(gotLifecycle, event.Kind)
			if event.Kind == SubscriptionLifecycleRetrying && !errors.Is(event.Err, websocket.ErrMessageTooBig) {
				t.Fatalf("retry error = %v, want websocket.ErrMessageTooBig", event.Err)
			}
			if event.Kind == SubscriptionLifecycleTerminal {
				goto terminal
			}
		case <-ctx.Done():
			t.Fatalf("waiting for reconnect lifecycle: %v; lifecycle=%v", ctx.Err(), gotLifecycle)
		}
	}

terminal:
	wantLifecycle := []SubscriptionLifecycleKind{
		SubscriptionLifecycleEstablished,
		SubscriptionLifecycleRetrying,
		SubscriptionLifecycleEstablished,
		SubscriptionLifecycleTerminal,
	}
	if fmt.Sprint(gotLifecycle) != fmt.Sprint(wantLifecycle) {
		t.Fatalf("lifecycle = %v, want %v", gotLifecycle, wantLifecycle)
	}

	select {
	case <-oversizedRejected:
	case <-ctx.Done():
		t.Fatalf("waiting for oversized rejection: %v", ctx.Err())
	}
	select {
	case <-validAcked:
	case <-ctx.Done():
		t.Fatalf("waiting for valid acknowledgement: %v", ctx.Err())
	}
	select {
	case <-serverFinished:
	case <-ctx.Done():
		t.Fatalf("waiting for server completion: %v", ctx.Err())
	}

	gotHandled := make([]SubscriptionMessage, 0, 2)
	for len(gotHandled) < 2 {
		select {
		case message := <-handled:
			gotHandled = append(gotHandled, message)
		case <-ctx.Done():
			t.Fatalf("waiting for handled messages: %v", ctx.Err())
		}
	}
	if len(handled) != 0 {
		t.Fatalf("unexpected extra handled message after oversized frame")
	}
	if gotHandled[0].Type != SubscriptionEventType ||
		gotHandled[0].Event == nil ||
		!strings.Contains(string(gotHandled[0].Event.Message), "valid-after-reconnect") {
		t.Fatalf("first handled message = %+v, want valid event from reconnect", gotHandled[0])
	}
	if gotHandled[1].Type != SubscriptionErrorType {
		t.Fatalf("second handled message type = %q, want terminal error", gotHandled[1].Type)
	}
	if got := connections.Load(); got != 2 {
		t.Fatalf("connections = %d, want one reconnect", got)
	}
	drainServerErrors(t, serverErrors)
}
