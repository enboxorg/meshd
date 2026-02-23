package dwn

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// clientOptions holds configuration for the DWN client.
type clientOptions struct {
	httpClient *http.Client
}

// ClientOption configures a Client.
type ClientOption func(*clientOptions)

// WithHTTPClient sets a custom HTTP client.
func WithHTTPClient(c *http.Client) ClientOption {
	return func(o *clientOptions) {
		o.httpClient = c
	}
}

// Client is a high-level client for a DWN instance.
//
// It wraps the HTTP transport layer and provides typed methods for each
// DWN interface (RecordsWrite, RecordsRead, RecordsQuery, RecordsDelete,
// ProtocolsConfigure, ProtocolsQuery).
//
// The wire protocol uses:
//   - POST / for all requests (no tenant in URL)
//   - dwn-request header for JSON-RPC 2.0 envelope
//   - HTTP body for binary data (RecordsWrite payloads)
//   - dwn-response header for RecordsRead responses with data
type Client struct {
	transport *HTTPTransport
	signer    *Signer
}

// NewClient creates a DWN client for the given endpoint.
func NewClient(endpoint string, signer *Signer, opts ...ClientOption) *Client {
	options := &clientOptions{
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
	for _, opt := range opts {
		opt(options)
	}

	return &Client{
		transport: NewHTTPTransport(endpoint, WithTransportHTTPClient(options.httpClient)),
		signer:    signer,
	}
}

// RecordsWriteResult holds the response from a RecordsWrite.
type RecordsWriteResult struct {
	Reply    *DwnReply
	RecordID string
}

// RecordsWrite creates or updates a record on the target DWN.
//
// For data payloads:
//   - Data ≤ 30KB is inlined as base64url encodedData in the message
//   - Data > 30KB is sent as binary in the HTTP body
//
// The target parameter is the DID of the DWN owner.
func (c *Client) RecordsWrite(ctx context.Context, target string, opts RecordsWriteOptions) (*RecordsWriteResult, error) {
	msg, err := BuildRecordsWrite(c.signer, opts)
	if err != nil {
		return nil, fmt.Errorf("building RecordsWrite: %w", err)
	}

	// Determine if data should go in the body (large payloads)
	// or inline in the message (small payloads, already base64url encoded).
	var bodyData []byte
	if len(opts.Data) > maxInlineDataSize {
		// Large data: send as binary body, clear inline encoding.
		bodyData = opts.Data
		msg.EncodedData = ""
	}
	// Small data: already base64url encoded in msg.EncodedData by BuildRecordsWrite.

	result, err := c.transport.Send(ctx, target, msg, bodyData)
	if err != nil {
		return nil, err
	}

	return &RecordsWriteResult{
		Reply:    result.Reply,
		RecordID: msg.RecordID,
	}, nil
}

// maxInlineDataSize is the max data size that gets base64url-encoded inline.
// Matches DwnConstant.maxDataSizeAllowedToBeEncoded in the SDK.
const maxInlineDataSize = 30_000

// RecordsReadResult holds the response from a RecordsRead.
type RecordsReadResult struct {
	Reply *DwnReply
	// Data is the binary record data, if present.
	// This comes from the HTTP body when the server uses dwn-response header.
	Data []byte
}

// RecordsRead reads a single record from the target DWN.
func (c *Client) RecordsRead(ctx context.Context, target string, filter RecordsFilter, protocolRole string) (*RecordsReadResult, error) {
	msg, err := BuildRecordsRead(c.signer, filter, protocolRole)
	if err != nil {
		return nil, fmt.Errorf("building RecordsRead: %w", err)
	}

	result, err := c.transport.Send(ctx, target, msg, nil)
	if err != nil {
		return nil, err
	}

	return &RecordsReadResult{
		Reply: result.Reply,
		Data:  result.Data,
	}, nil
}

// RecordsQuery queries records on the target DWN.
func (c *Client) RecordsQuery(ctx context.Context, target string, filter RecordsFilter, dateSort string, pagination *Pagination, protocolRole string) (*DwnReply, error) {
	msg, err := BuildRecordsQuery(c.signer, filter, dateSort, pagination, protocolRole)
	if err != nil {
		return nil, fmt.Errorf("building RecordsQuery: %w", err)
	}

	result, err := c.transport.Send(ctx, target, msg, nil)
	if err != nil {
		return nil, err
	}

	return result.Reply, nil
}

// RecordsDelete deletes a record on the target DWN.
func (c *Client) RecordsDelete(ctx context.Context, target string, recordID string, prune bool, protocolRole string) (*DwnReply, error) {
	msg, err := BuildRecordsDelete(c.signer, recordID, prune, protocolRole)
	if err != nil {
		return nil, fmt.Errorf("building RecordsDelete: %w", err)
	}

	result, err := c.transport.Send(ctx, target, msg, nil)
	if err != nil {
		return nil, err
	}

	return result.Reply, nil
}

// ProtocolsConfigure installs a protocol definition on the target DWN.
func (c *Client) ProtocolsConfigure(ctx context.Context, target string, definition json.RawMessage) (*DwnReply, error) {
	msg, err := BuildProtocolsConfigure(c.signer, definition)
	if err != nil {
		return nil, fmt.Errorf("building ProtocolsConfigure: %w", err)
	}

	result, err := c.transport.Send(ctx, target, msg, nil)
	if err != nil {
		return nil, err
	}

	return result.Reply, nil
}

// ProtocolsQuery queries installed protocols on the target DWN.
func (c *Client) ProtocolsQuery(ctx context.Context, target string, protocolURI string) (*DwnReply, error) {
	msg, err := BuildProtocolsQuery(c.signer, protocolURI)
	if err != nil {
		return nil, fmt.Errorf("building ProtocolsQuery: %w", err)
	}

	result, err := c.transport.Send(ctx, target, msg, nil)
	if err != nil {
		return nil, err
	}

	return result.Reply, nil
}

// QueryEntries extracts RecordsWrite entries from a query reply.
func QueryEntries(reply *DwnReply) ([]json.RawMessage, error) {
	if reply == nil {
		return nil, fmt.Errorf("nil reply")
	}
	if reply.Status.Code != 200 {
		return nil, fmt.Errorf("query failed: %d %s", reply.Status.Code, reply.Status.Detail)
	}
	if reply.Entries == nil {
		return nil, nil
	}

	var entries []json.RawMessage
	if err := json.Unmarshal(reply.Entries, &entries); err != nil {
		return nil, fmt.Errorf("unmarshaling entries: %w", err)
	}
	return entries, nil
}

// ReadEntry extracts the entry from a read reply.
func ReadEntry(reply *DwnReply) (json.RawMessage, error) {
	if reply == nil {
		return nil, fmt.Errorf("nil reply")
	}
	if reply.Status.Code != 200 {
		return nil, fmt.Errorf("read failed: %d %s", reply.Status.Code, reply.Status.Detail)
	}
	return reply.Entry, nil
}

// ReadData is a convenience that extracts both the entry metadata and binary data
// from a RecordsRead result. Returns (entry, data, error).
func ReadData(result *RecordsReadResult) (json.RawMessage, io.Reader, error) {
	if result.Reply == nil {
		return nil, nil, fmt.Errorf("nil reply")
	}
	if result.Reply.Status.Code != 200 {
		return nil, nil, fmt.Errorf("read failed: %d %s",
			result.Reply.Status.Code, result.Reply.Status.Detail)
	}

	entry := result.Reply.Entry
	if entry == nil {
		entry = result.Reply.Record
	}

	var reader io.Reader
	if len(result.Data) > 0 {
		reader = io.NopCloser(newByteReader(result.Data))
	}

	return entry, reader, nil
}

// byteReader wraps []byte to satisfy io.Reader.
type byteReader struct {
	data []byte
	pos  int
}

func newByteReader(data []byte) *byteReader {
	return &byteReader{data: data}
}

func (r *byteReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}
