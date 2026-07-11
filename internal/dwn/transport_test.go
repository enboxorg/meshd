package dwn

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewJsonRpcRequest(t *testing.T) {
	s := newTestSigner(t)

	msg, err := BuildRecordsQuery(s, RecordsFilter{
		Protocol:     "https://example.com/test",
		ProtocolPath: "root",
	}, "", nil, "")
	if err != nil {
		t.Fatalf("building message: %v", err)
	}

	req := newJsonRpcRequest("did:dht:target123", msg)

	t.Run("jsonrpc version", func(t *testing.T) {
		if req.JSONRPC != "2.0" {
			t.Errorf("jsonrpc = %q, want '2.0'", req.JSONRPC)
		}
	})

	t.Run("method", func(t *testing.T) {
		if req.Method != MethodProcessMessage {
			t.Errorf("method = %q, want %q", req.Method, MethodProcessMessage)
		}
	})

	t.Run("has UUID id", func(t *testing.T) {
		if req.ID == "" {
			t.Error("id should be a non-empty UUID")
		}
		// UUID format: 8-4-4-4-12
		parts := strings.Split(req.ID, "-")
		if len(parts) != 5 {
			t.Errorf("id = %q, not a valid UUID", req.ID)
		}
	})

	t.Run("params", func(t *testing.T) {
		if req.Params == nil {
			t.Fatal("params should not be nil")
		}
		if req.Params.Target != "did:dht:target123" {
			t.Errorf("target = %q", req.Params.Target)
		}
		if req.Params.Message == nil {
			t.Error("message should not be nil")
		}
	})

	t.Run("no subscription", func(t *testing.T) {
		if req.Subscription != nil {
			t.Error("regular request should not have subscription field")
		}
	})
}

func TestNewJsonRpcSubscribeRequest(t *testing.T) {
	s := newTestSigner(t)
	msg, _ := buildSubscribeMessage(s, RecordsFilter{
		Protocol:     "https://example.com/test",
		ProtocolPath: "root",
	}, nil, MessageAuth{})

	subID := "sub-test-123"
	req := newJsonRpcSubscribeRequest("did:dht:target", msg, subID)

	t.Run("method", func(t *testing.T) {
		if req.Method != MethodSubscribe {
			t.Errorf("method = %q, want %q", req.Method, MethodSubscribe)
		}
	})

	t.Run("subscription id", func(t *testing.T) {
		if req.Subscription == nil {
			t.Fatal("subscription should not be nil")
		}
		if req.Subscription.ID != subID {
			t.Errorf("subscription.id = %q, want %q", req.Subscription.ID, subID)
		}
	})

	t.Run("has request id", func(t *testing.T) {
		if req.ID == "" {
			t.Error("should have a request id distinct from subscription id")
		}
		if req.ID == subID {
			t.Error("request id should differ from subscription id")
		}
	})
}

func TestNewJsonRpcAck(t *testing.T) {
	cursor := ProgressToken{StreamID: "stream", Epoch: "epoch", Position: "123", MessageCID: "bafy-message"}
	ack := newJsonRpcAck("sub-456", cursor)

	t.Run("method", func(t *testing.T) {
		if ack.Method != MethodAck {
			t.Errorf("method = %q, want %q", ack.Method, MethodAck)
		}
	})

	t.Run("no id (notification)", func(t *testing.T) {
		if ack.ID != "" {
			t.Errorf("ack should be a notification (no id), got %q", ack.ID)
		}
	})

	t.Run("cursor in params", func(t *testing.T) {
		if ack.Params == nil {
			t.Fatal("params should not be nil")
		}
		if ack.Params.Cursor == nil || *ack.Params.Cursor != cursor {
			t.Errorf("params.cursor = %#v, want %#v", ack.Params.Cursor, cursor)
		}
	})

	t.Run("subscription id", func(t *testing.T) {
		if ack.Subscription == nil || ack.Subscription.ID != "sub-456" {
			t.Errorf("subscription.id = %v, want 'sub-456'", ack.Subscription)
		}
	})

	t.Run("json serialization matches server expectation", func(t *testing.T) {
		data, err := json.Marshal(ack)
		if err != nil {
			t.Fatalf("marshaling: %v", err)
		}

		var parsed map[string]any
		json.Unmarshal(data, &parsed)

		// Must have method, params.cursor, subscription.id
		if parsed["method"] != "rpc.ack" {
			t.Errorf("method = %v", parsed["method"])
		}

		params, ok := parsed["params"].(map[string]any)
		if !ok {
			t.Fatal("params missing or not an object")
		}
		cursorObject, ok := params["cursor"].(map[string]any)
		if !ok {
			t.Fatalf("params.cursor = %#v, want object", params["cursor"])
		}
		if cursorObject["streamId"] != "stream" || cursorObject["epoch"] != "epoch" || cursorObject["position"] != "123" || cursorObject["messageCid"] != "bafy-message" {
			t.Errorf("params.cursor = %#v, want production ProgressToken", cursorObject)
		}

		sub, ok := parsed["subscription"].(map[string]any)
		if !ok {
			t.Fatal("subscription missing")
		}
		if sub["id"] != "sub-456" {
			t.Errorf("subscription.id = %v", sub["id"])
		}

		// Should NOT have "id" field (notification).
		if _, hasID := parsed["id"]; hasID {
			// The JSON omitempty should handle this since ID is ""
			idVal := parsed["id"]
			if idVal != nil && idVal != "" {
				t.Errorf("ack should not have 'id' field, got %v", idVal)
			}
		}
	})
}

func TestNewJsonRpcCloseSubscription(t *testing.T) {
	close := newJsonRpcCloseSubscription("sub-789")

	if close.Method != MethodCloseSubscribe {
		t.Errorf("method = %q, want %q", close.Method, MethodCloseSubscribe)
	}
	if close.ID == "" {
		t.Error("close request should have an id")
	}
	if close.Subscription == nil || close.Subscription.ID != "sub-789" {
		t.Error("should have subscription.id = 'sub-789'")
	}
}

func TestHTTPTransportSend(t *testing.T) {
	s := newTestSigner(t)

	t.Run("dwn-request header contains JSON-RPC", func(t *testing.T) {
		var capturedHeader string
		var capturedBody []byte
		var capturedMethod string
		var capturedPath string

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedHeader = r.Header.Get("dwn-request")
			capturedBody, _ = io.ReadAll(r.Body)
			capturedMethod = r.Method
			capturedPath = r.URL.Path

			resp := JsonRpcResponse{
				JSONRPC: "2.0",
				ID:      "test",
				Result: &JsonRpcResult{
					Reply: &DwnReply{
						Status: Status{Code: 200, Detail: "OK"},
					},
				},
			}
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		transport := NewHTTPTransport(server.URL)
		msg, _ := BuildRecordsQuery(s, RecordsFilter{
			Protocol:     "https://example.com/test",
			ProtocolPath: "root",
		}, "", nil, "")

		_, err := transport.Send(context.Background(), "did:dht:target", msg, nil)
		if err != nil {
			t.Fatalf("Send: %v", err)
		}

		// Verify request went to POST /
		if capturedMethod != "POST" {
			t.Errorf("method = %q, want POST", capturedMethod)
		}
		if capturedPath != "/" {
			t.Errorf("path = %q, want '/'", capturedPath)
		}

		// Verify dwn-request header has JSON-RPC envelope
		if capturedHeader == "" {
			t.Fatal("dwn-request header is empty")
		}

		var rpcReq JsonRpcRequest
		if err := json.Unmarshal([]byte(capturedHeader), &rpcReq); err != nil {
			t.Fatalf("parsing dwn-request header: %v", err)
		}

		if rpcReq.JSONRPC != "2.0" {
			t.Errorf("jsonrpc = %q", rpcReq.JSONRPC)
		}
		if rpcReq.Method != MethodProcessMessage {
			t.Errorf("method = %q", rpcReq.Method)
		}
		if rpcReq.Params.Target != "did:dht:target" {
			t.Errorf("target = %q", rpcReq.Params.Target)
		}

		// Body should be empty for non-data requests
		if len(capturedBody) != 0 {
			t.Errorf("body should be empty for query, got %d bytes", len(capturedBody))
		}
	})

	t.Run("RecordsWrite sends binary data in body", func(t *testing.T) {
		var capturedHeader string
		var capturedBody []byte
		var capturedContentType string

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedHeader = r.Header.Get("dwn-request")
			capturedBody, _ = io.ReadAll(r.Body)
			capturedContentType = r.Header.Get("Content-Type")

			resp := JsonRpcResponse{
				JSONRPC: "2.0",
				ID:      "test",
				Result: &JsonRpcResult{
					Reply: &DwnReply{
						Status: Status{Code: 202, Detail: "Accepted"},
					},
				},
			}
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		transport := NewHTTPTransport(server.URL)

		// Build a message and send with large binary data
		writeResult, _ := BuildRecordsWrite(s, RecordsWriteOptions{
			Protocol:     "https://example.com/test",
			ProtocolPath: "root",
			DataFormat:   "application/octet-stream",
			Data:         make([]byte, 50000), // > 30KB threshold
		})
		msg := writeResult.Message

		largeData := make([]byte, 50000)
		for i := range largeData {
			largeData[i] = byte(i % 256)
		}

		_, err := transport.Send(context.Background(), "did:dht:target", msg, largeData)
		if err != nil {
			t.Fatalf("Send: %v", err)
		}

		// Header should still have JSON-RPC
		if capturedHeader == "" {
			t.Fatal("dwn-request header missing")
		}

		// Body should be the binary data
		if len(capturedBody) != 50000 {
			t.Errorf("body size = %d, want 50000", len(capturedBody))
		}

		// Content-Type should be octet-stream
		if capturedContentType != "application/octet-stream" {
			t.Errorf("content-type = %q, want application/octet-stream", capturedContentType)
		}
	})

	t.Run("RecordsRead response with dwn-response header", func(t *testing.T) {
		binaryData := []byte("this is the record data payload")

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Server sends JSON-RPC in dwn-response header, data in body.
			rpcResp := JsonRpcResponse{
				JSONRPC: "2.0",
				ID:      "test",
				Result: &JsonRpcResult{
					Reply: &DwnReply{
						Status: Status{Code: 200, Detail: "OK"},
						Entry:  json.RawMessage(`{"recordsWrite":{"descriptor":{"interface":"Records"}}}`),
					},
				},
			}
			respJSON, _ := json.Marshal(rpcResp)

			w.Header().Set("dwn-response", string(respJSON))
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Write(binaryData)
		}))
		defer server.Close()

		transport := NewHTTPTransport(server.URL)
		msg, _ := BuildRecordsRead(s, RecordsFilter{
			RecordID: "bafy123",
		}, "")

		result, err := transport.Send(context.Background(), "did:dht:target", msg, nil)
		if err != nil {
			t.Fatalf("Send: %v", err)
		}

		if result.Reply == nil {
			t.Fatal("reply should not be nil")
		}
		if result.Reply.Status.Code != 200 {
			t.Errorf("status = %d", result.Reply.Status.Code)
		}

		// Binary data should be in result.Data
		if string(result.Data) != string(binaryData) {
			t.Errorf("data = %q, want %q", result.Data, binaryData)
		}

		// Entry metadata should be present
		if result.Reply.Entry == nil {
			t.Error("entry should be present from dwn-response header")
		}
	})

	t.Run("JSON-RPC error response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			resp := JsonRpcResponse{
				JSONRPC: "2.0",
				ID:      "test",
				Error: &JsonRpcError{
					Code:    JsonRpcInvalidParams,
					Message: "missing required field",
				},
			}
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		transport := NewHTTPTransport(server.URL)
		msg, _ := BuildRecordsQuery(s, RecordsFilter{Protocol: "test"}, "", nil, "")

		_, err := transport.Send(context.Background(), "did:dht:target", msg, nil)
		if err == nil {
			t.Fatal("expected error for JSON-RPC error response")
		}

		var rpcErr *JsonRpcError
		if !errors.As(err, &rpcErr) {
			t.Fatalf("error = %T %v, want *JsonRpcError", err, err)
		}
	})

	t.Run("rate limit response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Retry-After", "5")
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(`{"error":"Rate limit exceeded"}`))
		}))
		defer server.Close()

		transport := NewHTTPTransport(server.URL)
		msg, _ := BuildRecordsQuery(s, RecordsFilter{Protocol: "test"}, "", nil, "")

		_, err := transport.Send(context.Background(), "did:dht:target", msg, nil)
		if err == nil {
			t.Fatal("expected error for rate limit")
		}
		if !errors.Is(err, ErrRateLimited) {
			t.Fatalf("errors.Is(%v, ErrRateLimited) = false", err)
		}
		var rateErr *RateLimitError
		if !errors.As(err, &rateErr) {
			t.Fatalf("error = %T %v, want *RateLimitError", err, err)
		}
		if rateErr.RetryAfter != 5*time.Second {
			t.Errorf("RetryAfter = %v, want 5s", rateErr.RetryAfter)
		}
	})
}

func TestHTTPTransportNoTenantInURL(t *testing.T) {
	var capturedURL string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedURL = r.URL.String()
		resp := JsonRpcResponse{
			JSONRPC: "2.0",
			ID:      "test",
			Result: &JsonRpcResult{
				Reply: &DwnReply{
					Status: Status{Code: 200, Detail: "OK"},
				},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	s := newTestSigner(t)
	transport := NewHTTPTransport(server.URL)
	msg, _ := BuildRecordsQuery(s, RecordsFilter{Protocol: "test"}, "", nil, "")

	_, err := transport.Send(context.Background(), "did:dht:somelong-tenant-did", msg, nil)
	if err != nil {
		t.Fatalf("Send: %v", err)
	}

	// The URL should be just "/" — tenant DID is in the JSON-RPC params, not the URL.
	if capturedURL != "/" {
		t.Errorf("URL = %q, want '/'. Tenant DID must NOT be in the URL path.", capturedURL)
	}
}

func TestJsonRpcErrorInterface(t *testing.T) {
	err := &JsonRpcError{
		Code:    JsonRpcInvalidParams,
		Message: "test error",
	}

	// Should satisfy error interface.
	var e error = err
	if e.Error() != "JSON-RPC error -32602: test error" {
		t.Errorf("Error() = %q", e.Error())
	}
}

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, time.July, 11, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name  string
		value string
		want  time.Duration
		ok    bool
	}{
		{name: "delay seconds", value: "5", want: 5 * time.Second, ok: true},
		{name: "trimmed delay seconds", value: " 5 ", want: 5 * time.Second, ok: true},
		{name: "zero", value: "0", want: 0, ok: true},
		{name: "HTTP date", value: now.Add(7 * time.Second).Format(http.TimeFormat), want: 7 * time.Second, ok: true},
		{name: "past HTTP date", value: now.Add(-time.Second).Format(http.TimeFormat), want: 0, ok: true},
		{name: "empty", value: "", ok: false},
		{name: "negative", value: "-1", ok: false},
		{name: "fraction", value: "1.5", ok: false},
		{name: "malformed", value: "later", ok: false},
		{name: "duration overflow", value: "9223372037", ok: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseRetryAfter(tc.value, now)
			if ok != tc.ok {
				t.Fatalf("parseRetryAfter(%q) ok = %v, want %v", tc.value, ok, tc.ok)
			}
			if tc.ok && got != tc.want {
				t.Errorf("parseRetryAfter(%q) = %v, want %v", tc.value, got, tc.want)
			}
		})
	}
}

func TestHTTPTransportRateLimitClassification(t *testing.T) {
	signer := newTestSigner(t)

	tests := []struct {
		name      string
		status    int
		header    string
		rpcErr    *JsonRpcError
		wantRetry time.Duration
		wantRate  bool
	}{
		{name: "JSON-RPC retry data", status: http.StatusOK, rpcErr: &JsonRpcError{Code: JsonRpcTooManyRequests, Message: "tenant limited", Data: json.RawMessage(`{"retryAfterSec":2}`)}, wantRetry: 2 * time.Second, wantRate: true},
		{name: "header overrides JSON-RPC data", status: http.StatusTooManyRequests, header: "5", rpcErr: &JsonRpcError{Code: JsonRpcTooManyRequests, Message: "tenant limited", Data: json.RawMessage(`{"retryAfterSec":2}`)}, wantRetry: 5 * time.Second, wantRate: true},
		{name: "JSON-RPC default delay", status: http.StatusOK, rpcErr: &JsonRpcError{Code: JsonRpcTooManyRequests, Message: "tenant limited"}, wantRetry: time.Second, wantRate: true},
		{name: "message text alone is not rate limit", status: http.StatusOK, rpcErr: &JsonRpcError{Code: JsonRpcInvalidParams, Message: "RateLimitExceeded: not actually a 429"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.header != "" {
					w.Header().Set("Retry-After", tc.header)
				}
				w.WriteHeader(tc.status)
				if err := json.NewEncoder(w).Encode(JsonRpcResponse{JSONRPC: "2.0", ID: "test", Error: tc.rpcErr}); err != nil {
					t.Errorf("encoding response: %v", err)
				}
			}))
			defer server.Close()

			transport := NewHTTPTransport(server.URL)
			msg, _ := BuildRecordsQuery(signer, RecordsFilter{Protocol: "test"}, "", nil, "")

			_, err := transport.Send(context.Background(), "did:dht:target", msg, nil)
			if err == nil {
				t.Fatal("expected transport error")
			}

			gotRate := errors.Is(err, ErrRateLimited)
			if gotRate != tc.wantRate {
				t.Fatalf("errors.Is(%v, ErrRateLimited) = %v, want %v", err, gotRate, tc.wantRate)
			}
			if !tc.wantRate {
				var rpcErr *JsonRpcError
				if !errors.As(err, &rpcErr) {
					t.Fatalf("error = %T %v, want *JsonRpcError", err, err)
				}
				return
			}

			var rateErr *RateLimitError
			if !errors.As(err, &rateErr) {
				t.Fatalf("error = %T %v, want *RateLimitError", err, err)
			}
			if rateErr.RetryAfter != tc.wantRetry {
				t.Errorf("RetryAfter = %v, want %v", rateErr.RetryAfter, tc.wantRetry)
			}
		})
	}
}

func TestHTTPTransportPreservesCanceledContext(t *testing.T) {
	signer := newTestSigner(t)
	msg, err := BuildRecordsQuery(signer, RecordsFilter{Protocol: "test"}, "", nil, "")
	if err != nil {
		t.Fatalf("BuildRecordsQuery: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	transport := NewHTTPTransport("http://127.0.0.1:1")
	_, err = transport.Send(ctx, "did:dht:target", msg, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Send error = %v, want context canceled", err)
	}
	if !errors.Is(err, ErrTransport) {
		t.Fatalf("Send error = %v, want ErrTransport", err)
	}
}
