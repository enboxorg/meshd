package dwn

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// writeMessagesSubscribeReply confirms a subscription and includes the
// MessagesSubscribe reply feed snapshot (head + fingerprint).
func writeMessagesSubscribeReply(ctx context.Context, conn *websocket.Conn, requestID, sdkSubscriptionID string, head *ProgressToken, fingerprint string) error {
	response := JsonRpcResponse{
		JSONRPC: "2.0",
		ID:      requestID,
		Result: &JsonRpcResult{
			Reply: &DwnReply{
				Status:       Status{Code: http.StatusOK, Detail: "OK"},
				Head:         head,
				Fingerprint:  fingerprint,
				Subscription: &SubscriptionConfirm{ID: sdkSubscriptionID},
			},
		},
	}
	return writeWSJSON(ctx, conn, response)
}

// verifyMessagesSubscribeRequest checks the signed MessagesSubscribe wire
// shape: descriptor fields plus the canonical permissionGrantIds mirrored in
// descriptor AND signature payload.
func verifyMessagesSubscribeRequest(request *JsonRpcRequest, wantFilters []map[string]any, wantGrantIDs []string, wantCursor *ProgressToken) error {
	desc := request.Params.Message.Descriptor
	if desc["interface"] != "Messages" || desc["method"] != "Subscribe" {
		return fmt.Errorf("descriptor interface/method = %v/%v, want Messages/Subscribe", desc["interface"], desc["method"])
	}

	filtersJSON, err := json.Marshal(desc["filters"])
	if err != nil {
		return fmt.Errorf("marshal filters: %w", err)
	}
	var gotFilters []map[string]any
	if err := json.Unmarshal(filtersJSON, &gotFilters); err != nil {
		return fmt.Errorf("parse filters: %w", err)
	}
	if gotFilters == nil {
		return fmt.Errorf("filters must always be present, got null")
	}
	if !reflect.DeepEqual(gotFilters, wantFilters) {
		return fmt.Errorf("filters = %v, want %v", gotFilters, wantFilters)
	}

	var gotDescriptorIDs []string
	if raw, ok := desc["permissionGrantIds"]; ok {
		idsJSON, err := json.Marshal(raw)
		if err != nil {
			return fmt.Errorf("marshal permissionGrantIds: %w", err)
		}
		if err := json.Unmarshal(idsJSON, &gotDescriptorIDs); err != nil {
			return fmt.Errorf("parse permissionGrantIds: %w", err)
		}
	}
	if !reflect.DeepEqual(gotDescriptorIDs, wantGrantIDs) {
		return fmt.Errorf("descriptor permissionGrantIds = %v, want %v", gotDescriptorIDs, wantGrantIDs)
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(request.Params.Message.Authorization.Signature.Payload)
	if err != nil {
		return fmt.Errorf("decode signature payload: %w", err)
	}
	var payload struct {
		DescriptorCid      string   `json:"descriptorCid"`
		PermissionGrantIDs []string `json:"permissionGrantIds"`
	}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return fmt.Errorf("parse signature payload: %w", err)
	}
	if !reflect.DeepEqual(payload.PermissionGrantIDs, wantGrantIDs) {
		return fmt.Errorf("payload permissionGrantIds = %v, want %v", payload.PermissionGrantIDs, wantGrantIDs)
	}
	if payload.DescriptorCid == "" {
		return fmt.Errorf("payload missing descriptorCid")
	}

	if wantCursor == nil {
		if _, ok := desc["cursor"]; ok {
			return fmt.Errorf("fresh subscription unexpectedly carried cursor")
		}
		return nil
	}
	return expectDescriptorCursor(request, *wantCursor)
}

func TestMessagesSubscribeHandshakeAndFeedSnapshot(t *testing.T) {
	serverErrors := make(chan error, 8)
	serverDone := make(chan struct{})

	resumeCursor := ProgressToken{StreamID: "stream", Epoch: "epoch", Position: "10", MessageCID: "cid-10"}
	head := ProgressToken{StreamID: "stream", Epoch: "epoch", Position: "12"}
	wantFilters := []map[string]any{
		{"protocol": "https://example.com/protocols/mesh"},
		{"interface": "Records", "method": "Write", "protocolPathPrefix": "network/node"},
	}
	wantGrantIDs := []string{"grant-a", "grant-b"}

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
		if err := verifyMessagesSubscribeRequest(request, wantFilters, wantGrantIDs, &resumeCursor); err != nil {
			serverErrors <- err
			return
		}
		if err := writeMessagesSubscribeReply(ctx, conn, request.ID, "messages-subscribe-cid", &head, "ab12"); err != nil {
			serverErrors <- err
			return
		}

		// One replayed event, then EOSE.
		eventToken := ProgressToken{StreamID: "stream", Epoch: "epoch", Position: "11", MessageCID: "cid-11"}
		event := &SubscriptionMessage{
			Type:        SubscriptionEventType,
			Cursor:      &eventToken,
			Seq:         "11",
			MessageCID:  "cid-11",
			Protocol:    "https://example.com/protocols/mesh",
			EncodedData: "ZGF0YQ",
			Event: &RecordEvent{
				Message: json.RawMessage(`{"descriptor":{"interface":"Records","method":"Write"}}`),
			},
		}
		if err := writeSubscriptionMessage(ctx, conn, request.Subscription.ID, event); err != nil {
			serverErrors <- err
			return
		}
		if err := expectAck(ctx, conn, request.Subscription.ID, eventToken); err != nil {
			serverErrors <- err
			return
		}
		eoseToken := ProgressToken{StreamID: "stream", Epoch: "epoch", Position: "12"}
		if err := writeSubscriptionMessage(ctx, conn, request.Subscription.ID, &SubscriptionMessage{Type: SubscriptionEOSEType, Cursor: &eoseToken}); err != nil {
			serverErrors <- err
			return
		}
		if err := expectAck(ctx, conn, request.Subscription.ID, eoseToken); err != nil {
			serverErrors <- err
			return
		}
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	messages := make(chan SubscriptionMessage, 4)
	lifecycle := make(chan SubscriptionLifecycleEvent, 4)
	manager := NewSubscriptionManager(server.URL, slog.Default())
	sub, err := manager.SubscribeMessagesWithLifecycle(
		ctx,
		"did:dht:tenant",
		newTestSigner(t),
		MessagesSubscribeOptions{
			Filters: []MessagesFilter{
				{Protocol: "https://example.com/protocols/mesh"},
				{Interface: "Records", Method: "Write", ProtocolPathPrefix: "network/node"},
			},
			// Unsorted with duplicates: the wire message must carry the
			// canonical list.
			PermissionGrantIDs: []string{"grant-b", "grant-a", "grant-b"},
			Cursor:             &resumeCursor,
		},
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
		t.Fatalf("SubscribeMessagesWithLifecycle: %v", err)
	}
	defer sub.Close()

	var established SubscriptionLifecycleEvent
	select {
	case established = <-lifecycle:
	case <-ctx.Done():
		t.Fatalf("waiting for established: %v", ctx.Err())
	}
	if established.Kind != SubscriptionLifecycleEstablished {
		t.Fatalf("first lifecycle = %+v, want established", established)
	}
	if established.NeedsFullRefresh {
		t.Error("cursor-seeded establishment must not require full refresh")
	}
	if established.Head == nil || *established.Head != head {
		t.Errorf("established head = %+v, want %+v", established.Head, head)
	}
	if established.Fingerprint != "ab12" {
		t.Errorf("established fingerprint = %q, want ab12", established.Fingerprint)
	}

	gotMessages := make([]SubscriptionMessage, 0, 2)
	for len(gotMessages) < 2 {
		select {
		case message := <-messages:
			gotMessages = append(gotMessages, message)
		case <-ctx.Done():
			t.Fatalf("waiting for messages: %v; got %d", ctx.Err(), len(gotMessages))
		}
	}
	if gotMessages[0].Type != SubscriptionEventType || gotMessages[0].Seq != "11" ||
		gotMessages[0].MessageCID != "cid-11" || gotMessages[0].EncodedData != "ZGF0YQ" {
		t.Errorf("first message = %+v, want replay event with feed metadata", gotMessages[0])
	}
	if gotMessages[1].Type != SubscriptionEOSEType {
		t.Errorf("second message = %+v, want eose", gotMessages[1])
	}

	select {
	case <-serverDone:
	case <-ctx.Done():
		t.Fatalf("waiting for server: %v", ctx.Err())
	}
	drainServerErrors(t, serverErrors)

	if cursor := sub.Cursor(); cursor == nil || cursor.Position != "12" {
		t.Errorf("Cursor() = %+v, want EOSE cursor", cursor)
	}
}

func TestMessagesSubscribeTerminalDeliveryErrorCodes(t *testing.T) {
	tests := []struct {
		code         string
		wantRevoked  bool
		wantTerminal bool
	}{
		{code: MessagesSubscribeDeliveryAuthorizationFailedCode, wantRevoked: true, wantTerminal: true},
		{code: MessagesSubscribeDeliveryFailedCode, wantRevoked: true, wantTerminal: true},
		{code: "SomeOtherTerminalCode", wantRevoked: false, wantTerminal: true},
	}

	for _, tc := range tests {
		t.Run(tc.code, func(t *testing.T) {
			serverErrors := make(chan error, 4)
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
				if err := writeMessagesSubscribeReply(ctx, conn, request.ID, "sub-cid", nil, ""); err != nil {
					serverErrors <- err
					return
				}
				token := ProgressToken{StreamID: "stream", Epoch: "epoch", Position: "1"}
				terminal := &SubscriptionMessage{
					Type:   SubscriptionErrorType,
					Cursor: &token,
					Error:  &SubscriptionError{Code: tc.code, Detail: "delivery stopped"},
				}
				if err := writeSubscriptionMessage(ctx, conn, request.Subscription.ID, terminal); err != nil {
					serverErrors <- err
					return
				}
				if err := expectAck(ctx, conn, request.Subscription.ID, token); err != nil {
					serverErrors <- err
				}
			}))
			defer server.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			lifecycle := make(chan SubscriptionLifecycleEvent, 4)
			manager := NewSubscriptionManager(server.URL, slog.Default())
			sub, err := manager.SubscribeMessagesWithLifecycle(
				ctx,
				"did:dht:tenant",
				newTestSigner(t),
				MessagesSubscribeOptions{},
				func(*SubscriptionMessage) error { return nil },
				func(event SubscriptionLifecycleEvent) { lifecycle <- event },
			)
			if err != nil {
				t.Fatalf("SubscribeMessagesWithLifecycle: %v", err)
			}
			defer sub.Close()

			var terminalEvent SubscriptionLifecycleEvent
			terminalSeen := false
			for !terminalSeen {
				select {
				case event := <-lifecycle:
					if event.Kind == SubscriptionLifecycleTerminal {
						terminalEvent = event
						terminalSeen = true
					}
				case <-ctx.Done():
					t.Fatalf("waiting for terminal lifecycle: %v", ctx.Err())
				}
			}
			if !tc.wantTerminal {
				t.Fatal("test table only models terminal cases")
			}
			if got := errors.Is(terminalEvent.Err, ErrSubscriptionAuthorizationRevoked); got != tc.wantRevoked {
				t.Errorf("errors.Is(err, ErrSubscriptionAuthorizationRevoked) = %v, want %v (err = %v)",
					got, tc.wantRevoked, terminalEvent.Err)
			}
			drainServerErrors(t, serverErrors)
		})
	}
}

func TestMessagesSubscribeValidatesOptions(t *testing.T) {
	manager := NewSubscriptionManager("http://127.0.0.1:0", slog.Default())
	ctx := context.Background()
	signer := newTestSigner(t)
	handler := func(*SubscriptionMessage) error { return nil }

	if _, err := manager.SubscribeMessages(ctx, "did:dht:tenant", signer, MessagesSubscribeOptions{
		PermissionGrantIDs: []string{},
	}, handler); !errors.Is(err, ErrPermissionGrantIDsEmpty) {
		t.Errorf("empty grant list error = %v, want ErrPermissionGrantIDsEmpty", err)
	}

	if _, err := manager.SubscribeMessages(ctx, "did:dht:tenant", signer, MessagesSubscribeOptions{
		Filters: []MessagesFilter{{}},
	}, handler); err == nil {
		t.Error("empty filter must be rejected at subscribe time")
	}

	if _, err := manager.SubscribeMessages(ctx, "did:dht:tenant", signer, MessagesSubscribeOptions{
		Cursor: &ProgressToken{StreamID: "s"},
	}, handler); err == nil {
		t.Error("invalid cursor must be rejected at subscribe time")
	}
}
