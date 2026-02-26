// Package dwn provides a client for interacting with Decentralized Web Nodes.
//
// The transport layer implements the DWN server's JSON-RPC 2.0 wire protocol:
//   - All requests go to POST / (no tenant in URL)
//   - DWN message goes in the "dwn-request" HTTP header as JSON-RPC 2.0
//   - HTTP body is reserved for binary data (RecordsWrite payloads)
//   - RecordsRead responses with data use "dwn-response" header + binary body
//   - WebSocket subscriptions use rpc.subscribe.dwn.processMessage + rpc.ack
package dwn

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"
)

// Sentinel errors for the transport layer.
var (
	ErrTransport   = errors.New("transport error")
	ErrRateLimited = errors.New("rate limited")
)

//
// --- JSON-RPC 2.0 types ---
//

// JsonRpcRequest is a JSON-RPC 2.0 request per the DWN server wire protocol.
type JsonRpcRequest struct {
	JSONRPC      string              `json:"jsonrpc"`
	ID           string              `json:"id,omitempty"`
	Method       string              `json:"method"`
	Params       *JsonRpcParams      `json:"params,omitempty"`
	Subscription *JsonRpcSubscription `json:"subscription,omitempty"`
}

// JsonRpcParams carries the target DID and DWN message.
// For rpc.ack messages, only Cursor is set (Target and Message are omitted).
type JsonRpcParams struct {
	Target  string   `json:"target,omitempty"`
	Message *Message `json:"message,omitempty"`
	Cursor  string   `json:"cursor,omitempty"`
}

// JsonRpcSubscription identifies a subscription in WebSocket messages.
type JsonRpcSubscription struct {
	ID string `json:"id"`
}

// JsonRpcResponse is a JSON-RPC 2.0 response.
type JsonRpcResponse struct {
	JSONRPC string           `json:"jsonrpc"`
	ID      string           `json:"id,omitempty"`
	Result  *JsonRpcResult   `json:"result,omitempty"`
	Error   *JsonRpcError    `json:"error,omitempty"`
}

// JsonRpcResult wraps the DWN reply.
type JsonRpcResult struct {
	Reply        *DwnReply            `json:"reply,omitempty"`
	Subscription *SubscriptionConfirm `json:"subscription,omitempty"`
}

// SubscriptionConfirm is the subscription ID in the initial response.
type SubscriptionConfirm struct {
	ID string `json:"id"`
}

// DwnReply is the DWN-level response within the JSON-RPC result.
type DwnReply struct {
	Status  Status          `json:"status"`
	Entries json.RawMessage `json:"entries,omitempty"`
	Cursor  json.RawMessage `json:"cursor,omitempty"`
	Entry   json.RawMessage `json:"entry,omitempty"`
	Record  json.RawMessage `json:"record,omitempty"`

	// Subscription is populated in the initial subscribe response.
	Subscription *SubscriptionConfirm `json:"subscription,omitempty"`
}

// JsonRpcError is a JSON-RPC 2.0 error.
type JsonRpcError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

func (e *JsonRpcError) Error() string {
	return fmt.Sprintf("JSON-RPC error %d: %s", e.Code, e.Message)
}

// JSON-RPC error codes matching the DWN server.
const (
	JsonRpcInvalidParams = -32602
)

// JSON-RPC method names.
const (
	MethodProcessMessage = "dwn.processMessage"
	MethodSubscribe      = "rpc.subscribe.dwn.processMessage"
	MethodAck            = "rpc.ack"
	MethodCloseSubscribe = "rpc.subscribe.close"
)

//
// --- JSON-RPC factory functions ---
//

// newJsonRpcRequest creates a JSON-RPC 2.0 request for dwn.processMessage.
func newJsonRpcRequest(target string, msg *Message) *JsonRpcRequest {
	return &JsonRpcRequest{
		JSONRPC: "2.0",
		ID:      uuid.New().String(),
		Method:  MethodProcessMessage,
		Params: &JsonRpcParams{
			Target:  target,
			Message: msg,
		},
	}
}

// newJsonRpcSubscribeRequest creates a JSON-RPC 2.0 subscribe request.
func newJsonRpcSubscribeRequest(target string, msg *Message, subscriptionID string) *JsonRpcRequest {
	return &JsonRpcRequest{
		JSONRPC: "2.0",
		ID:      uuid.New().String(),
		Method:  MethodSubscribe,
		Params: &JsonRpcParams{
			Target:  target,
			Message: msg,
		},
		Subscription: &JsonRpcSubscription{
			ID: subscriptionID,
		},
	}
}

// newJsonRpcAck creates a JSON-RPC 2.0 ack notification (no id field).
// This is a notification — no response is expected from the server.
func newJsonRpcAck(subscriptionID string, cursor string) *JsonRpcRequest {
	return &JsonRpcRequest{
		JSONRPC: "2.0",
		Method:  MethodAck,
		Params: &JsonRpcParams{
			Cursor: cursor,
		},
		Subscription: &JsonRpcSubscription{
			ID: subscriptionID,
		},
	}
}

// newJsonRpcCloseSubscription creates a close-subscription request.
func newJsonRpcCloseSubscription(subscriptionID string) *JsonRpcRequest {
	return &JsonRpcRequest{
		JSONRPC: "2.0",
		ID:      uuid.New().String(),
		Method:  MethodCloseSubscribe,
		Params:  &JsonRpcParams{}, // empty params, per server expectation
		Subscription: &JsonRpcSubscription{
			ID: subscriptionID,
		},
	}
}

//
// --- HTTP Transport ---
//

// httpTransportOptions configures the HTTP transport.
type httpTransportOptions struct {
	httpClient *http.Client
}

// HTTPTransportOption configures an HTTPTransport.
type HTTPTransportOption func(*httpTransportOptions)

// WithTransportHTTPClient sets a custom HTTP client for the transport.
func WithTransportHTTPClient(c *http.Client) HTTPTransportOption {
	return func(o *httpTransportOptions) {
		o.httpClient = c
	}
}

// HTTPTransport implements the DWN HTTP wire protocol.
//
// Wire protocol:
//   - All requests go to POST <endpoint>/ (no tenant DID in URL)
//   - JSON-RPC 2.0 envelope goes in the "dwn-request" HTTP header
//   - HTTP body is used only for binary data (RecordsWrite data stream)
//   - For RecordsRead responses with data: JSON-RPC response is in
//     "dwn-response" header and binary data is the HTTP body
type HTTPTransport struct {
	endpoint   string
	httpClient *http.Client
}

// NewHTTPTransport creates a new HTTP transport for the given DWN endpoint.
func NewHTTPTransport(endpoint string, opts ...HTTPTransportOption) *HTTPTransport {
	options := &httpTransportOptions{
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
	for _, opt := range opts {
		opt(options)
	}

	return &HTTPTransport{
		endpoint:   endpoint,
		httpClient: options.httpClient,
	}
}

// SendResult holds the parsed response from a DWN HTTP request.
type SendResult struct {
	Reply *DwnReply
	// Data contains the binary response body for RecordsRead responses.
	// nil for non-data responses.
	Data []byte
}

// Send sends a DWN message via the HTTP wire protocol.
//
// For RecordsWrite: the message goes in dwn-request header, binary data in body.
// For all other messages: the message goes in dwn-request header, no body.
//
// Response parsing:
//   - If dwn-response header is present: parse JSON-RPC from header, data from body
//   - Otherwise: parse JSON-RPC from body
func (t *HTTPTransport) Send(ctx context.Context, target string, msg *Message, data []byte) (*SendResult, error) {
	rpcReq := newJsonRpcRequest(target, msg)

	rpcJSON, err := json.Marshal(rpcReq)
	if err != nil {
		return nil, fmt.Errorf("%w: marshaling JSON-RPC request: %v", ErrTransport, err)
	}

	var body io.Reader
	var contentType string

	if len(data) > 0 {
		body = bytes.NewReader(data)
		contentType = "application/octet-stream"
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", t.endpoint, body)
	if err != nil {
		return nil, fmt.Errorf("%w: creating HTTP request: %v", ErrTransport, err)
	}

	// The DWN message always goes in the dwn-request header.
	httpReq.Header.Set("dwn-request", string(rpcJSON))

	if contentType != "" {
		httpReq.Header.Set("Content-Type", contentType)
	}

	resp, err := t.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("%w: sending HTTP request: %v", ErrTransport, err)
	}
	defer resp.Body.Close()

	return t.parseResponse(resp)
}

// parseResponse handles both response formats:
//   - dwn-response header present: JSON-RPC in header, binary data in body
//   - dwn-response header absent: JSON-RPC in body
func (t *HTTPTransport) parseResponse(resp *http.Response) (*SendResult, error) {
	dwnResponseHeader := resp.Header.Get("dwn-response")

	if dwnResponseHeader != "" {
		// RecordsRead with data: JSON-RPC envelope in header, binary data in body.
		var rpcResp JsonRpcResponse
		if err := json.Unmarshal([]byte(dwnResponseHeader), &rpcResp); err != nil {
			return nil, fmt.Errorf("%w: parsing dwn-response header: %v", ErrTransport, err)
		}

		if rpcResp.Error != nil {
			return nil, rpcResp.Error
		}

		// Read the binary data from the body.
		data, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("%w: reading response data: %v", ErrTransport, err)
		}

		result := &SendResult{Data: data}
		if rpcResp.Result != nil {
			result.Reply = rpcResp.Result.Reply
		}
		return result, nil
	}

	// Standard response: JSON-RPC in body.
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("%w: reading response body: %v", ErrTransport, err)
	}

	// Handle non-JSON-RPC error responses (e.g., per-IP rate limit).
	if resp.StatusCode == http.StatusTooManyRequests {
		// Try to parse as JSON-RPC first.
		var rpcResp JsonRpcResponse
		if err := json.Unmarshal(respBody, &rpcResp); err == nil && rpcResp.Error != nil {
			return nil, fmt.Errorf("%w: %s", ErrRateLimited, rpcResp.Error.Message)
		}
		return nil, fmt.Errorf("%w: HTTP 429: %s", ErrRateLimited, string(respBody))
	}

	var rpcResp JsonRpcResponse
	if err := json.Unmarshal(respBody, &rpcResp); err != nil {
		return nil, fmt.Errorf("%w: parsing response body (HTTP %d): %s: %v",
			ErrTransport, resp.StatusCode, string(respBody), err)
	}

	if rpcResp.Error != nil {
		return nil, rpcResp.Error
	}

	result := &SendResult{}
	if rpcResp.Result != nil {
		result.Reply = rpcResp.Result.Reply
	}
	return result, nil
}
