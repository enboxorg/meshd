package dwn

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func TestSubscriptionProgressGapClearsCursorBeforeFreshEstablishment(t *testing.T) {
	oldCursor := ProgressToken{StreamID: "old-stream", Epoch: "old-epoch", Position: "50", MessageCID: "old-cid"}
	oldest := ProgressToken{StreamID: "new-stream", Epoch: "new-epoch", Position: "10"}
	latest := ProgressToken{StreamID: "new-stream", Epoch: "new-epoch", Position: "20"}

	var connections atomic.Int32
	serverErrors := make(chan error, 4)
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
			if err := expectDescriptorCursor(request, oldCursor); err != nil {
				serverErrors <- err
				return
			}
			gapData, err := json.Marshal(ProgressGapInfo{
				Code:            "ProgressGap",
				Requested:       oldCursor,
				OldestAvailable: oldest,
				LatestAvailable: latest,
				Reason:          "epoch_mismatch",
			})
			if err != nil {
				serverErrors <- fmt.Errorf("marshal gap: %w", err)
				return
			}
			response := JsonRpcResponse{
				JSONRPC: "2.0",
				ID:      request.ID,
				Result: &JsonRpcResult{
					Reply: &DwnReply{
						Status: Status{Code: http.StatusGone, Detail: "Progress token gap"},
						Error:  gapData,
					},
				},
			}
			if err := writeWSJSON(ctx, conn, response); err != nil {
				serverErrors <- err
			}
		case 2:
			defer close(serverDone)
			if _, ok := request.Params.Message.Descriptor["cursor"]; ok {
				serverErrors <- fmt.Errorf("fresh request after gap still carried cursor")
				return
			}
			if err := writeSubscribeReply(ctx, conn, request.ID, "fresh-sdk-subscription"); err != nil {
				serverErrors <- err
				return
			}
			terminalCursor := ProgressToken{StreamID: "new-stream", Epoch: "new-epoch", Position: "21"}
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
	sub := &Subscription{
		SubscriptionID:   "gap-subscription",
		target:           "did:dht:target",
		filter:           RecordsFilter{Protocol: "https://example.com/protocol"},
		signer:           newTestSigner(t),
		handler:          func(*SubscriptionMessage) error { return nil },
		lifecycleHandler: func(event SubscriptionLifecycleEvent) { lifecycle <- event },
		cursor:           oldCursor.clone(),
		logger:           slog.Default(),
		cancel:           cancel,
		done:             make(chan struct{}),
	}
	go sub.run(ctx, server.URL)
	defer sub.Close()

	var sequence []SubscriptionLifecycleKind
	var gotGap *ProgressGapInfo
	terminalSeen := false
	for !terminalSeen {
		select {
		case event := <-lifecycle:
			sequence = append(sequence, event.Kind)
			switch event.Kind {
			case SubscriptionLifecycleProgressGap:
				gotGap = event.Gap
				if sub.Cursor() != nil {
					t.Fatalf("cursor was not cleared before ProgressGap lifecycle: %+v", sub.Cursor())
				}
			case SubscriptionLifecycleEstablished:
				if !event.NeedsFullRefresh {
					t.Error("fresh establishment after gap must require full refresh")
				}
			case SubscriptionLifecycleTerminal:
				terminalSeen = true
			}
		case <-ctx.Done():
			t.Fatalf("waiting for lifecycle: %v; sequence=%v", ctx.Err(), sequence)
		}
	}

	if gotGap == nil || gotGap.Reason != "epoch_mismatch" || gotGap.Requested != oldCursor || gotGap.OldestAvailable != oldest || gotGap.LatestAvailable != latest {
		t.Fatalf("gap = %+v, want production gap metadata", gotGap)
	}
	gapIndex, establishedIndex := -1, -1
	for i, kind := range sequence {
		if kind == SubscriptionLifecycleProgressGap && gapIndex < 0 {
			gapIndex = i
		}
		if kind == SubscriptionLifecycleEstablished && establishedIndex < 0 {
			establishedIndex = i
		}
	}
	if gapIndex < 0 || establishedIndex <= gapIndex {
		t.Fatalf("lifecycle sequence = %v, want gap before fresh established", sequence)
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
