package dwn

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestSubscriptionRejectsMalformedAddressedFrameBeforeHandler(t *testing.T) {
	called := false
	sub := &Subscription{
		SubscriptionID: "sub-malformed",
		handler: func(*SubscriptionMessage) error {
			called = true
			return nil
		},
	}
	token := ProgressToken{StreamID: "stream", Epoch: "epoch", Position: "not-decimal"}
	frame := subscriptionTestFrame(t, sub.SubscriptionID, &SubscriptionMessage{
		Type:   SubscriptionEventType,
		Cursor: &token,
		Event:  &RecordEvent{Message: json.RawMessage("{\"recordId\":\"peer\"}")},
	})

	err := sub.handleSubscriptionFrame(context.Background(), nil, frame)
	if err == nil || !strings.Contains(err.Error(), "invalid progress token") {
		t.Fatalf("handleSubscriptionFrame error = %v, want invalid progress token", err)
	}
	if called {
		t.Fatal("handler was called for malformed frame")
	}
	if sub.Cursor() != nil {
		t.Fatalf("malformed frame advanced cursor: %+v", sub.Cursor())
	}
}

func TestSubscriptionHandlerPanicDoesNotAdvanceCursor(t *testing.T) {
	sub := &Subscription{
		SubscriptionID: "sub-panic",
		handler: func(*SubscriptionMessage) error {
			panic("boom")
		},
	}
	token := ProgressToken{StreamID: "stream", Epoch: "epoch", Position: "1"}
	frame := subscriptionTestFrame(t, sub.SubscriptionID, &SubscriptionMessage{
		Type:   SubscriptionEventType,
		Cursor: &token,
		Event:  &RecordEvent{Message: json.RawMessage("{\"recordId\":\"peer\"}")},
	})

	err := sub.handleSubscriptionFrame(context.Background(), nil, frame)
	if err == nil || !strings.Contains(err.Error(), "handler panicked") {
		t.Fatalf("handleSubscriptionFrame error = %v, want contained panic", err)
	}
	if sub.Cursor() != nil {
		t.Fatalf("handler panic advanced cursor: %+v", sub.Cursor())
	}
}

func subscriptionTestFrame(t *testing.T, subscriptionID string, message *SubscriptionMessage) []byte {
	t.Helper()
	frame, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      subscriptionID,
		"result": map[string]any{
			"subscription": message,
		},
	})
	if err != nil {
		t.Fatalf("marshal frame: %v", err)
	}
	return frame
}
