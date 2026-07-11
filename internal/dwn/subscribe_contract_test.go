package dwn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func TestSubscriptionProductionContractAndReplayHandshake(t *testing.T) {
	var connectionCount atomic.Int32
	serverErrors := make(chan error, 8)
	secondConnectionDone := make(chan struct{})

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
		connectionNumber := connectionCount.Add(1)
		switch connectionNumber {
		case 1:
			if _, ok := request.Params.Message.Descriptor["cursor"]; ok {
				serverErrors <- fmt.Errorf("fresh subscription unexpectedly carried cursor")
				return
			}
			token := ProgressToken{StreamID: "stream", Epoch: "epoch", Position: "1", MessageCID: "cid-1"}
			message := &SubscriptionMessage{
				Type:        SubscriptionEventType,
				Cursor:      &token,
				EncodedData: "Y2lwaGVyLTE",
				Event: &RecordEvent{
					Message:      json.RawMessage("{\"recordId\":\"peer-1\",\"descriptor\":{\"interface\":\"Records\",\"method\":\"Write\"}}"),
					InitialWrite: json.RawMessage("{\"recordId\":\"peer-1\"}"),
				},
			}
			if err := writeSubscriptionMessage(ctx, conn, request.Subscription.ID, message); err != nil {
				serverErrors <- err
				return
			}
			if err := expectAck(ctx, conn, request.Subscription.ID, token); err != nil {
				serverErrors <- err
				return
			}
			if err := writeSubscribeReply(ctx, conn, request.ID, "sdk-message-cid-1"); err != nil {
				serverErrors <- err
				return
			}
			conn.CloseNow()
		case 2:
			defer close(secondConnectionDone)
			if err := expectDescriptorCursor(request, ProgressToken{StreamID: "stream", Epoch: "epoch", Position: "1", MessageCID: "cid-1"}); err != nil {
				serverErrors <- err
				return
			}

			replayToken := ProgressToken{StreamID: "stream", Epoch: "epoch", Position: "2", MessageCID: "cid-2"}
			replay := &SubscriptionMessage{
				Type:        SubscriptionEventType,
				Cursor:      &replayToken,
				EncodedData: "Y2lwaGVyLTI",
				Event: &RecordEvent{
					Message: json.RawMessage("{\"recordId\":\"peer-2\",\"descriptor\":{\"interface\":\"Records\",\"method\":\"Write\"}}"),
				},
			}
			// Production can deliver replay and EOSE before the request-ID reply.
			if err := writeSubscriptionMessage(ctx, conn, request.Subscription.ID, replay); err != nil {
				serverErrors <- err
				return
			}
			if err := expectAck(ctx, conn, request.Subscription.ID, replayToken); err != nil {
				serverErrors <- err
				return
			}
			eose := &SubscriptionMessage{Type: SubscriptionEOSEType, Cursor: &replayToken}
			if err := writeSubscriptionMessage(ctx, conn, request.Subscription.ID, eose); err != nil {
				serverErrors <- err
				return
			}
			if err := expectAck(ctx, conn, request.Subscription.ID, replayToken); err != nil {
				serverErrors <- err
				return
			}
			if err := writeSubscribeReply(ctx, conn, request.ID, "sdk-message-cid-2"); err != nil {
				serverErrors <- err
				return
			}

			terminalToken := ProgressToken{StreamID: "stream", Epoch: "epoch", Position: "3", MessageCID: "cid-3"}
			terminal := &SubscriptionMessage{
				Type:   SubscriptionErrorType,
				Cursor: &terminalToken,
				Error:  &SubscriptionError{Code: "GrantRevoked", Detail: "grant is no longer active"},
			}
			if err := writeSubscriptionMessage(ctx, conn, request.Subscription.ID, terminal); err != nil {
				serverErrors <- err
				return
			}
			if err := expectAck(ctx, conn, request.Subscription.ID, terminalToken); err != nil {
				serverErrors <- err
				return
			}
		default:
			serverErrors <- fmt.Errorf("unexpected connection %d after terminal event", connectionNumber)
		}
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()

	messages := make(chan SubscriptionMessage, 8)
	lifecycle := make(chan SubscriptionLifecycleEvent, 8)
	manager := NewSubscriptionManager(server.URL, slog.Default())
	sub, err := manager.SubscribeWithAuthAndLifecycle(
		ctx,
		"did:dht:target",
		newTestSigner(t),
		RecordsFilter{Protocol: "https://example.com/protocol"},
		MessageAuth{},
		func(message *SubscriptionMessage) error {
			copyMessage := *message
			copyMessage.Cursor = message.Cursor.clone()
			messages <- copyMessage
			return nil
		},
		func(event SubscriptionLifecycleEvent) {
			lifecycle <- event
		},
	)
	if err != nil {
		t.Fatalf("SubscribeWithAuthAndLifecycle: %v", err)
	}
	defer sub.Close()

	gotMessages := make([]SubscriptionMessage, 0, 4)
	for len(gotMessages) < 4 {
		select {
		case message := <-messages:
			gotMessages = append(gotMessages, message)
		case <-ctx.Done():
			t.Fatalf("waiting for messages: %v; got %d", ctx.Err(), len(gotMessages))
		}
	}
	if gotMessages[0].Type != SubscriptionEventType || gotMessages[0].EncodedData != "Y2lwaGVyLTE" {
		t.Fatalf("first message = %+v, want live event with encodedData", gotMessages[0])
	}
	if gotMessages[1].Type != SubscriptionEventType || gotMessages[1].EncodedData != "Y2lwaGVyLTI" {
		t.Fatalf("second message = %+v, want replay event before reply", gotMessages[1])
	}
	if gotMessages[2].Type != SubscriptionEOSEType {
		t.Fatalf("third message type = %q, want eose", gotMessages[2].Type)
	}
	if gotMessages[3].Type != SubscriptionErrorType || gotMessages[3].Error == nil || gotMessages[3].Error.Code != "GrantRevoked" {
		t.Fatalf("fourth message = %+v, want terminal subscription error", gotMessages[3])
	}

	var established []SubscriptionLifecycleEvent
	var terminalSeen bool
	for !terminalSeen {
		select {
		case event := <-lifecycle:
			switch event.Kind {
			case SubscriptionLifecycleEstablished:
				established = append(established, event)
			case SubscriptionLifecycleTerminal:
				terminalSeen = true
			}
		case <-ctx.Done():
			t.Fatalf("waiting for terminal lifecycle: %v", ctx.Err())
		}
	}
	if len(established) != 2 {
		t.Fatalf("established events = %d, want 2", len(established))
	}
	if !established[0].NeedsFullRefresh {
		t.Error("fresh establishment must require full refresh")
	}
	if established[1].NeedsFullRefresh {
		t.Error("cursor-resumed establishment must not require full refresh")
	}

	select {
	case <-secondConnectionDone:
	case <-ctx.Done():
		t.Fatalf("waiting for server: %v", ctx.Err())
	}
	drainServerErrors(t, serverErrors)

	cursor := sub.Cursor()
	if cursor == nil || cursor.Position != "3" || cursor.MessageCID != "cid-3" {
		t.Fatalf("Cursor() = %+v, want terminal cursor", cursor)
	}
	cursor.Position = "999"
	if got := sub.Cursor(); got == nil || got.Position != "3" {
		t.Fatalf("Cursor defensive copy changed stored token: %+v", got)
	}
	if got := connectionCount.Load(); got != 2 {
		t.Fatalf("connections = %d, want exactly 2", got)
	}
}

func TestSubscriptionAcknowledgesBeyondServerWindow(t *testing.T) {
	const eventCount = 40
	serverErrors := make(chan error, 4)
	serverDone := make(chan struct{})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

		for i := 1; i <= eventCount; i++ {
			token := ProgressToken{
				StreamID:   "stream",
				Epoch:      "epoch",
				Position:   fmt.Sprintf("%d", i),
				MessageCID: fmt.Sprintf("cid-%d", i),
			}
			message := &SubscriptionMessage{
				Type:   SubscriptionEventType,
				Cursor: &token,
				Event: &RecordEvent{
					Message: json.RawMessage(fmt.Sprintf("{\"recordId\":\"peer-%d\",\"descriptor\":{\"interface\":\"Records\",\"method\":\"Write\"}}", i)),
				},
			}
			if err := writeSubscriptionMessage(ctx, conn, request.Subscription.ID, message); err != nil {
				serverErrors <- err
				return
			}
			if err := expectAck(ctx, conn, request.Subscription.ID, token); err != nil {
				serverErrors <- fmt.Errorf("event %d: %w", i, err)
				return
			}
		}

		terminalToken := ProgressToken{StreamID: "stream", Epoch: "epoch", Position: "41"}
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
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var handled atomic.Int32
	terminal := make(chan struct{}, 1)
	manager := NewSubscriptionManager(server.URL, slog.Default())
	sub, err := manager.SubscribeWithAuthAndLifecycle(
		ctx,
		"did:dht:target",
		newTestSigner(t),
		RecordsFilter{Protocol: "https://example.com/protocol"},
		MessageAuth{},
		func(*SubscriptionMessage) error {
			handled.Add(1)
			return nil
		},
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
	if got := handled.Load(); got != eventCount+1 {
		t.Fatalf("handled messages = %d, want %d", got, eventCount+1)
	}
}

func TestSubscriptionHandlerFailureDoesNotAdvanceCursor(t *testing.T) {
	wantErr := errors.New("cache update failed")
	sub := &Subscription{
		SubscriptionID: "sub-test",
		handler: func(*SubscriptionMessage) error {
			return wantErr
		},
		logger: slog.Default(),
	}
	token := ProgressToken{StreamID: "stream", Epoch: "epoch", Position: "1"}
	frame, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      sub.SubscriptionID,
		"result": map[string]any{
			"subscription": &SubscriptionMessage{
				Type:   SubscriptionEventType,
				Cursor: &token,
				Event:  &RecordEvent{Message: json.RawMessage("{\"recordId\":\"peer\"}")},
			},
		},
	})
	if err != nil {
		t.Fatalf("marshal frame: %v", err)
	}

	err = sub.handleSubscriptionFrame(context.Background(), nil, frame)
	if !errors.Is(err, wantErr) {
		t.Fatalf("handleSubscriptionFrame error = %v, want %v", err, wantErr)
	}
	if got := sub.Cursor(); got != nil {
		t.Fatalf("cursor advanced after handler failure: %+v", got)
	}
}

func TestProgressTokenOrderingAndDefensiveCopies(t *testing.T) {
	sub := &Subscription{}
	original := &ProgressToken{StreamID: "stream", Epoch: "epoch", Position: "9"}
	sub.rememberCursor(original)
	original.Position = "999"

	if got := sub.Cursor(); got == nil || got.Position != "9" {
		t.Fatalf("stored cursor = %+v, want independent position 9", got)
	}
	copyToken := sub.Cursor()
	copyToken.Position = "1000"
	if got := sub.Cursor(); got.Position != "9" {
		t.Fatalf("mutating Cursor result changed stored value: %+v", got)
	}

	sub.rememberCursor(&ProgressToken{StreamID: "stream", Epoch: "epoch", Position: "10"})
	if got := sub.Cursor(); got.Position != "10" {
		t.Fatalf("numeric cursor ordering failed: %+v", got)
	}
	sub.rememberCursor(&ProgressToken{StreamID: "stream", Epoch: "epoch", Position: "2"})
	if got := sub.Cursor(); got.Position != "10" {
		t.Fatalf("older cursor replaced current: %+v", got)
	}
	sub.rememberCursor(&ProgressToken{StreamID: "other", Epoch: "new", Position: "1"})
	if got := sub.Cursor(); got.StreamID != "stream" || got.Epoch != "epoch" || got.Position != "10" {
		t.Fatalf("incomparable cursor domain replaced current: %+v", got)
	}
	sub.rememberCursor(&ProgressToken{StreamID: "other", Epoch: "new", Position: "not-decimal"})
	if got := sub.Cursor(); got.Position != "10" {
		t.Fatalf("invalid cursor replaced current: %+v", got)
	}
}

func TestSubscribeValidatesArgumentsSynchronously(t *testing.T) {
	manager := NewSubscriptionManager("http://example.invalid", slog.Default())
	signer := newTestSigner(t)
	handler := func(*SubscriptionMessage) error { return nil }

	tests := []struct {
		name    string
		ctx     context.Context
		target  string
		signer  *Signer
		handler EventHandler
	}{
		{name: "nil context", target: "did:dht:target", signer: signer, handler: handler},
		{name: "empty target", ctx: context.Background(), signer: signer, handler: handler},
		{name: "nil signer", ctx: context.Background(), target: "did:dht:target", handler: handler},
		{name: "nil handler", ctx: context.Background(), target: "did:dht:target", signer: signer},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := manager.Subscribe(tc.ctx, tc.target, tc.signer, RecordsFilter{}, tc.handler); err == nil {
				t.Fatal("Subscribe error = nil")
			}
		})
	}
}

func readWSRequest(ctx context.Context, conn *websocket.Conn) (*JsonRpcRequest, error) {
	_, data, err := conn.Read(ctx)
	if err != nil {
		return nil, fmt.Errorf("read request: %w", err)
	}
	var request JsonRpcRequest
	if err := json.Unmarshal(data, &request); err != nil {
		return nil, fmt.Errorf("parse request: %w", err)
	}
	if request.Method != MethodSubscribe || request.Params == nil || request.Params.Message == nil || request.Subscription == nil {
		return nil, fmt.Errorf("invalid subscribe request: %+v", request)
	}
	return &request, nil
}

func writeSubscribeReply(ctx context.Context, conn *websocket.Conn, requestID, sdkSubscriptionID string) error {
	response := JsonRpcResponse{
		JSONRPC: "2.0",
		ID:      requestID,
		Result: &JsonRpcResult{
			Reply: &DwnReply{
				Status:       Status{Code: http.StatusOK, Detail: "OK"},
				Entries:      json.RawMessage(`[ {"recordId":"snapshot-only"} ]`),
				Cursor:       json.RawMessage(`{"messageCid":"pagination-only"}`),
				Subscription: &SubscriptionConfirm{ID: sdkSubscriptionID},
			},
		},
	}
	return writeWSJSON(ctx, conn, response)
}

func writeSubscriptionMessage(ctx context.Context, conn *websocket.Conn, subscriptionID string, message *SubscriptionMessage) error {
	return writeWSJSON(ctx, conn, map[string]any{
		"jsonrpc": "2.0",
		"id":      subscriptionID,
		"result": map[string]any{
			"subscription": message,
		},
	})
}

func writeWSJSON(ctx context.Context, conn *websocket.Conn, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("marshal websocket JSON: %w", err)
	}
	if err := conn.Write(ctx, websocket.MessageText, data); err != nil {
		return fmt.Errorf("write websocket JSON: %w", err)
	}
	return nil
}

func expectAck(ctx context.Context, conn *websocket.Conn, subscriptionID string, want ProgressToken) error {
	request, err := readWSRequestAny(ctx, conn)
	if err != nil {
		return err
	}
	if request.Method != MethodAck {
		return fmt.Errorf("method = %q, want %q", request.Method, MethodAck)
	}
	if request.ID != "" {
		return fmt.Errorf("ack id = %q, want notification", request.ID)
	}
	if request.Subscription == nil || request.Subscription.ID != subscriptionID {
		return fmt.Errorf("ack subscription = %+v, want %q", request.Subscription, subscriptionID)
	}
	if request.Params == nil || request.Params.Cursor == nil || *request.Params.Cursor != want {
		return fmt.Errorf("ack cursor = %+v, want %+v", request.Params, want)
	}
	return nil
}

func readWSRequestAny(ctx context.Context, conn *websocket.Conn) (*JsonRpcRequest, error) {
	_, data, err := conn.Read(ctx)
	if err != nil {
		return nil, fmt.Errorf("read websocket request: %w", err)
	}
	var request JsonRpcRequest
	if err := json.Unmarshal(data, &request); err != nil {
		return nil, fmt.Errorf("parse websocket request: %w", err)
	}
	return &request, nil
}

func expectDescriptorCursor(request *JsonRpcRequest, want ProgressToken) error {
	if request.Params == nil || request.Params.Message == nil {
		return fmt.Errorf("request missing DWN message")
	}
	raw, ok := request.Params.Message.Descriptor["cursor"]
	if !ok {
		return fmt.Errorf("resumed request missing descriptor cursor")
	}
	data, err := json.Marshal(raw)
	if err != nil {
		return fmt.Errorf("marshal descriptor cursor: %w", err)
	}
	var got ProgressToken
	if err := json.Unmarshal(data, &got); err != nil {
		return fmt.Errorf("parse descriptor cursor: %w", err)
	}
	if got != want {
		return fmt.Errorf("descriptor cursor = %+v, want %+v", got, want)
	}
	return nil
}

func drainServerErrors(t *testing.T, errors <-chan error) {
	t.Helper()
	for {
		select {
		case err := <-errors:
			t.Error(err)
		default:
			return
		}
	}
}
