package dwn

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// mockDWNServer creates an httptest.Server that mimics the DWN wire protocol.
// It reads dwn-request header, returns JSON-RPC responses.
func mockDWNServer(t *testing.T, handler func(rpcReq *JsonRpcRequest) *JsonRpcResponse) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dwnReq := r.Header.Get("dwn-request")
		if dwnReq == "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "missing dwn-request header"})
			return
		}

		var rpcReq JsonRpcRequest
		if err := json.Unmarshal([]byte(dwnReq), &rpcReq); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid JSON-RPC"})
			return
		}

		resp := handler(&rpcReq)
		json.NewEncoder(w).Encode(resp)
	}))
}

func TestSimpleAgentDID(t *testing.T) {
	s := newTestSigner(t)
	agent := NewSimpleAgent("http://localhost:8080", s)

	if agent.DID() != s.DID {
		t.Errorf("DID() = %q, want %q", agent.DID(), s.DID)
	}
}

func TestSimpleAgentRecordsWrite(t *testing.T) {
	s := newTestSigner(t)

	server := mockDWNServer(t, func(rpcReq *JsonRpcRequest) *JsonRpcResponse {
		// Verify the request structure.
		if rpcReq.Method != MethodProcessMessage {
			t.Errorf("method = %q, want %q", rpcReq.Method, MethodProcessMessage)
		}
		if rpcReq.Params == nil || rpcReq.Params.Message == nil {
			t.Fatal("missing params.message")
		}
		if rpcReq.Params.Message.Descriptor["interface"] != "Records" {
			t.Errorf("interface = %v", rpcReq.Params.Message.Descriptor["interface"])
		}
		if rpcReq.Params.Message.Descriptor["method"] != "Write" {
			t.Errorf("method = %v", rpcReq.Params.Message.Descriptor["method"])
		}

		return &JsonRpcResponse{
			JSONRPC: "2.0",
			ID:      rpcReq.ID,
			Result: &JsonRpcResult{
				Reply: &DwnReply{
					Status: Status{Code: 202, Detail: "Accepted"},
				},
			},
		}
	})
	defer server.Close()

	agent := NewSimpleAgent(server.URL, s)

	resp, err := agent.SendDwnRequest(context.Background(), DwnRequest{
		Target:      s.DID,
		MessageType: InterfaceRecordsWrite,
		MessageParams: &WriteParams{
			Protocol:     "https://example.com/test",
			ProtocolPath: "root",
			DataFormat:   "application/json",
			Data:         []byte(`{"hello":"world"}`),
		},
	})
	if err != nil {
		t.Fatalf("SendDwnRequest: %v", err)
	}

	if resp.Status.Code != 202 {
		t.Errorf("status = %d, want 202", resp.Status.Code)
	}
}

func TestSimpleAgentRecordsQuery(t *testing.T) {
	s := newTestSigner(t)

	server := mockDWNServer(t, func(rpcReq *JsonRpcRequest) *JsonRpcResponse {
		entries := []json.RawMessage{
			json.RawMessage(`{"recordId":"rec1","descriptor":{"interface":"Records","method":"Write","protocol":"https://example.com/test","protocolPath":"root","dataFormat":"application/json","dataCid":"bafy123","dataSize":10,"dateCreated":"2025-01-01T00:00:00.000000Z","messageTimestamp":"2025-01-01T00:00:00.000000Z"}}`),
			json.RawMessage(`{"recordId":"rec2","descriptor":{"interface":"Records","method":"Write","protocol":"https://example.com/test","protocolPath":"root","dataFormat":"application/json","dataCid":"bafy456","dataSize":20,"dateCreated":"2025-01-02T00:00:00.000000Z","messageTimestamp":"2025-01-02T00:00:00.000000Z"}}`),
		}
		entriesJSON, _ := json.Marshal(entries)

		return &JsonRpcResponse{
			JSONRPC: "2.0",
			ID:      rpcReq.ID,
			Result: &JsonRpcResult{
				Reply: &DwnReply{
					Status:  Status{Code: 200, Detail: "OK"},
					Entries: entriesJSON,
				},
			},
		}
	})
	defer server.Close()

	agent := NewSimpleAgent(server.URL, s)

	resp, err := agent.SendDwnRequest(context.Background(), DwnRequest{
		Target:      s.DID,
		MessageType: InterfaceRecordsQuery,
		MessageParams: &QueryParams{
			Filter: RecordsFilter{
				Protocol:     "https://example.com/test",
				ProtocolPath: "root",
			},
		},
	})
	if err != nil {
		t.Fatalf("SendDwnRequest: %v", err)
	}

	if resp.Status.Code != 200 {
		t.Errorf("status = %d, want 200", resp.Status.Code)
	}

	entries, err := QueryEntries(resp.Reply)
	if err != nil {
		t.Fatalf("QueryEntries: %v", err)
	}

	if len(entries) != 2 {
		t.Errorf("entries = %d, want 2", len(entries))
	}
}

func TestSimpleAgentDefaultsTarget(t *testing.T) {
	s := newTestSigner(t)

	var capturedTarget string
	server := mockDWNServer(t, func(rpcReq *JsonRpcRequest) *JsonRpcResponse {
		capturedTarget = rpcReq.Params.Target
		return &JsonRpcResponse{
			JSONRPC: "2.0",
			ID:      rpcReq.ID,
			Result: &JsonRpcResult{
				Reply: &DwnReply{
					Status: Status{Code: 200, Detail: "OK"},
				},
			},
		}
	})
	defer server.Close()

	agent := NewSimpleAgent(server.URL, s)

	// Send with empty target — should default to agent's DID.
	_, err := agent.SendDwnRequest(context.Background(), DwnRequest{
		MessageType: InterfaceRecordsQuery,
		MessageParams: &QueryParams{
			Filter: RecordsFilter{Protocol: "test"},
		},
	})
	if err != nil {
		t.Fatalf("SendDwnRequest: %v", err)
	}

	if capturedTarget != s.DID {
		t.Errorf("target = %q, want agent DID %q", capturedTarget, s.DID)
	}
}

func TestSimpleAgentUnsupportedType(t *testing.T) {
	s := newTestSigner(t)
	agent := NewSimpleAgent("http://localhost:8080", s)

	_, err := agent.SendDwnRequest(context.Background(), DwnRequest{
		MessageType:   "UnknownInterface",
		MessageParams: "whatever",
	})
	if err == nil {
		t.Error("expected error for unsupported message type")
	}
}

func TestSimpleAgentWrongParams(t *testing.T) {
	s := newTestSigner(t)

	server := mockDWNServer(t, func(rpcReq *JsonRpcRequest) *JsonRpcResponse {
		return &JsonRpcResponse{
			JSONRPC: "2.0",
			ID:      rpcReq.ID,
			Result:  &JsonRpcResult{Reply: &DwnReply{Status: Status{Code: 200, Detail: "OK"}}},
		}
	})
	defer server.Close()

	agent := NewSimpleAgent(server.URL, s)

	// Pass wrong params type.
	tests := map[string]struct {
		msgType DwnInterface
		params  any
	}{
		"RecordsWrite with QueryParams": {
			msgType: InterfaceRecordsWrite,
			params:  &QueryParams{},
		},
		"RecordsRead with WriteParams": {
			msgType: InterfaceRecordsRead,
			params:  &WriteParams{},
		},
		"RecordsQuery with DeleteParams": {
			msgType: InterfaceRecordsQuery,
			params:  &DeleteParams{},
		},
		"RecordsDelete with ReadParams": {
			msgType: InterfaceRecordsDelete,
			params:  &ReadParams{},
		},
		"ProtocolsConfigure with string": {
			msgType: InterfaceProtocolsConfigure,
			params:  "wrong",
		},
		"ProtocolsQuery with int": {
			msgType: InterfaceProtocolsQuery,
			params:  42,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := agent.SendDwnRequest(context.Background(), DwnRequest{
				Target:        s.DID,
				MessageType:   tc.msgType,
				MessageParams: tc.params,
			})
			if err == nil {
				t.Error("expected error for wrong params type")
			}
			if err != nil && !containsSubstring(err.Error(), "requires") {
				t.Errorf("error should mention 'requires', got: %v", err)
			}
		})
	}
}

func containsSubstring(s, substr string) bool {
	return len(s) >= len(substr) && searchSubstring(s, substr)
}

func searchSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// Verify SimpleAgent implements Agent interface at compile time.
var _ Agent = (*SimpleAgent)(nil)

func TestSimpleAgentImplementsAgent(t *testing.T) {
	s := newTestSigner(t)
	var agent Agent = NewSimpleAgent("http://localhost:8080", s)

	// Should compile and be usable as Agent.
	if agent.DID() == "" {
		t.Error("DID should not be empty")
	}
	_ = fmt.Sprintf("agent DID: %s", agent.DID())
}
