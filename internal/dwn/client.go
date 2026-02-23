// Package dwn provides an HTTP client for interacting with Decentralized Web Nodes.
//
// The client supports the core DWN interfaces needed for mesh coordination:
//   - RecordsWrite: create/update records
//   - RecordsRead: read a single record
//   - RecordsQuery: query records with filters
//   - RecordsDelete: delete records
//   - RecordsSubscribe: real-time subscriptions (see subscribe.go)
//   - ProtocolsConfigure: install protocols on a DWN
//   - ProtocolsQuery: check which protocols are installed
//
// All messages are signed with the caller's DID key before sending.
package dwn

import (
	"bytes"
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

// Client is an HTTP client for a DWN instance.
type Client struct {
	endpoint   string
	signer     *Signer
	httpClient *http.Client
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
		endpoint:   endpoint,
		signer:     signer,
		httpClient: options.httpClient,
	}
}

// send sends a DWN message to the endpoint and returns the response.
func (c *Client) send(ctx context.Context, tenant string, msg *Message) (*Response, error) {
	body, err := json.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("marshaling message: %w", err)
	}

	url := c.endpoint
	if tenant != "" {
		url = c.endpoint + "/" + tenant
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sending request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	var dwnResp Response
	if err := json.Unmarshal(respBody, &dwnResp); err != nil {
		return nil, fmt.Errorf("unmarshaling response (HTTP %d, body: %s): %w",
			resp.StatusCode, string(respBody), err)
	}

	return &dwnResp, nil
}

// RecordsWrite creates or updates a record on the target DWN.
// Returns the response and the record ID.
func (c *Client) RecordsWrite(ctx context.Context, tenant string, opts RecordsWriteOptions) (*Response, string, error) {
	msg, err := BuildRecordsWrite(c.signer, opts)
	if err != nil {
		return nil, "", fmt.Errorf("building RecordsWrite: %w", err)
	}

	resp, err := c.send(ctx, tenant, msg)
	if err != nil {
		return nil, "", err
	}

	return resp, msg.RecordID, nil
}

// RecordsRead reads a single record from the target DWN.
func (c *Client) RecordsRead(ctx context.Context, tenant string, filter RecordsFilter, protocolRole string) (*Response, error) {
	msg, err := BuildRecordsRead(c.signer, filter, protocolRole)
	if err != nil {
		return nil, fmt.Errorf("building RecordsRead: %w", err)
	}

	return c.send(ctx, tenant, msg)
}

// RecordsQuery queries records on the target DWN.
func (c *Client) RecordsQuery(ctx context.Context, tenant string, filter RecordsFilter, dateSort string, pagination *Pagination, protocolRole string) (*Response, error) {
	msg, err := BuildRecordsQuery(c.signer, filter, dateSort, pagination, protocolRole)
	if err != nil {
		return nil, fmt.Errorf("building RecordsQuery: %w", err)
	}

	return c.send(ctx, tenant, msg)
}

// RecordsDelete deletes a record on the target DWN.
func (c *Client) RecordsDelete(ctx context.Context, tenant string, recordID string, prune bool, protocolRole string) (*Response, error) {
	msg, err := BuildRecordsDelete(c.signer, recordID, prune, protocolRole)
	if err != nil {
		return nil, fmt.Errorf("building RecordsDelete: %w", err)
	}

	return c.send(ctx, tenant, msg)
}

// ProtocolsConfigure installs a protocol definition on the target DWN.
func (c *Client) ProtocolsConfigure(ctx context.Context, tenant string, definition json.RawMessage) (*Response, error) {
	msg, err := BuildProtocolsConfigure(c.signer, definition)
	if err != nil {
		return nil, fmt.Errorf("building ProtocolsConfigure: %w", err)
	}

	return c.send(ctx, tenant, msg)
}

// ProtocolsQuery queries installed protocols on the target DWN.
func (c *Client) ProtocolsQuery(ctx context.Context, tenant string, protocolURI string) (*Response, error) {
	msg, err := BuildProtocolsQuery(c.signer, protocolURI)
	if err != nil {
		return nil, fmt.Errorf("building ProtocolsQuery: %w", err)
	}

	return c.send(ctx, tenant, msg)
}
