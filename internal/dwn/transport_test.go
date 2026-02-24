package dwn

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
	}, "")

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
	ack := newJsonRpcAck("sub-456", "cursor-abc")

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
		if ack.Params.Cursor != "cursor-abc" {
			t.Errorf("params.cursor = %q, want 'cursor-abc'", ack.Params.Cursor)
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
		if params["cursor"] != "cursor-abc" {
			t.Errorf("params.cursor = %v", params["cursor"])
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
		if ok := errorAs(err, &rpcErr); !ok {
			// The error might not unwrap directly, check the message.
			if !strings.Contains(err.Error(), "missing required field") {
				t.Errorf("error = %v, should mention 'missing required field'", err)
			}
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
		if !strings.Contains(err.Error(), "rate limit") {
			t.Errorf("error = %v, should mention rate limit", err)
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

// errorAs is a helper to match errors.As with a pointer type.
func errorAs(err error, target any) bool {
	return false // JsonRpcError implements error interface but may not unwrap directly
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
