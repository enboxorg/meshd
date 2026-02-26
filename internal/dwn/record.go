package dwn

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
)

// Record represents a DWN record with lazy data access.
//
// Records are returned by DwnAPI operations (Write, Query, Read).
// Data is accessed lazily — the first call to Data() may trigger a
// RecordsRead to fetch the data if it wasn't included in the response.
//
// Records hold a reference to the Agent for operations like Update,
// Delete, and lazy data fetching. This mirrors @enbox/api's Record class.
type Record struct {
	// Immutable fields (set on initial write, never change).
	ID           string `json:"recordId"`
	ContextID    string `json:"contextId,omitempty"`
	DateCreated  string `json:"dateCreated"`
	Protocol     string `json:"protocol"`
	ProtocolPath string `json:"protocolPath"`
	Schema       string `json:"schema,omitempty"`
	ParentID     string `json:"parentId,omitempty"`
	Recipient    string `json:"recipient,omitempty"`

	// Mutable fields (change with each update).
	DataFormat   string         `json:"dataFormat"`
	DataCID      string         `json:"dataCid"`
	DataSize     int            `json:"dataSize"`
	Published    bool           `json:"published,omitempty"`
	DatePublished string        `json:"datePublished,omitempty"`
	Tags         map[string]any `json:"tags,omitempty"`
	Timestamp    string         `json:"messageTimestamp"`
	Author       string         `json:"author,omitempty"`

	// RawEntry is the raw JSON entry from the server response.
	// Available after RecordFromRead or RecordFromEntry.
	// Useful for extracting encryption metadata.
	RawEntry json.RawMessage `json:"-"`

	// Internal state.
	agent       Agent
	target      string // DID of the DWN tenant
	encodedData string // base64url-encoded data (for small payloads)
	rawData     []byte // raw binary data (from RecordsRead response body)

	mu           sync.Mutex
	dataConsumed bool
}

// RecordFromWrite constructs a Record from a RecordsWrite response.
func RecordFromWrite(agent Agent, target string, msg *Message, encodedData string) *Record {
	desc := msg.Descriptor

	r := &Record{
		ID:           msg.RecordID,
		ContextID:    msg.ContextID,
		Protocol:     stringFromMap(desc, "protocol"),
		ProtocolPath: stringFromMap(desc, "protocolPath"),
		Schema:       stringFromMap(desc, "schema"),
		DataFormat:   stringFromMap(desc, "dataFormat"),
		DataCID:      stringFromMap(desc, "dataCid"),
		DataSize:     intFromMap(desc, "dataSize"),
		DateCreated:  stringFromMap(desc, "dateCreated"),
		Timestamp:    stringFromMap(desc, "messageTimestamp"),
		Recipient:    stringFromMap(desc, "recipient"),
		ParentID:     stringFromMap(desc, "parentId"),
		Published:    boolFromMap(desc, "published"),
		DatePublished: stringFromMap(desc, "datePublished"),
		agent:        agent,
		target:       target,
		encodedData:  encodedData,
	}

	if tags, ok := desc["tags"].(map[string]any); ok {
		r.Tags = tags
	}

	return r
}

// RecordFromEntry constructs a Record from a raw DWN entry (query result).
func RecordFromEntry(agent Agent, target string, entry json.RawMessage) (*Record, error) {
	// Query results wrap the message in different formats.
	// Try the flat message format first, then wrapped.
	var msg struct {
		RecordID  string         `json:"recordId"`
		ContextID string         `json:"contextId"`
		Descriptor map[string]any `json:"descriptor"`
		EncodedData string       `json:"encodedData"`
	}
	if err := json.Unmarshal(entry, &msg); err != nil {
		return nil, fmt.Errorf("parsing entry: %w", err)
	}

	r := &Record{
		ID:           msg.RecordID,
		ContextID:    msg.ContextID,
		Protocol:     stringFromMap(msg.Descriptor, "protocol"),
		ProtocolPath: stringFromMap(msg.Descriptor, "protocolPath"),
		Schema:       stringFromMap(msg.Descriptor, "schema"),
		DataFormat:   stringFromMap(msg.Descriptor, "dataFormat"),
		DataCID:      stringFromMap(msg.Descriptor, "dataCid"),
		DataSize:     intFromMap(msg.Descriptor, "dataSize"),
		DateCreated:  stringFromMap(msg.Descriptor, "dateCreated"),
		Timestamp:    stringFromMap(msg.Descriptor, "messageTimestamp"),
		Recipient:    stringFromMap(msg.Descriptor, "recipient"),
		ParentID:     stringFromMap(msg.Descriptor, "parentId"),
		Published:    boolFromMap(msg.Descriptor, "published"),
		DatePublished: stringFromMap(msg.Descriptor, "datePublished"),
		RawEntry:     entry,
		agent:        agent,
		target:       target,
		encodedData:  msg.EncodedData,
	}

	if tags, ok := msg.Descriptor["tags"].(map[string]any); ok {
		r.Tags = tags
	}

	return r, nil
}

// RecordFromRead constructs a Record from a RecordsRead response.
func RecordFromRead(agent Agent, target string, reply *DwnReply, data []byte) (*Record, error) {
	entry := reply.Entry
	if entry == nil {
		entry = reply.Record
	}
	if entry == nil {
		return nil, fmt.Errorf("no entry in read response")
	}

	// The read response entry has a recordsWrite wrapper.
	var wrapper struct {
		RecordsWrite struct {
			RecordID    string         `json:"recordId"`
			ContextID   string         `json:"contextId"`
			Descriptor  map[string]any `json:"descriptor"`
			EncodedData string         `json:"encodedData"`
		} `json:"recordsWrite"`
	}
	if err := json.Unmarshal(entry, &wrapper); err != nil {
		return nil, fmt.Errorf("parsing read entry: %w", err)
	}

	desc := wrapper.RecordsWrite.Descriptor
	r := &Record{
		ID:           wrapper.RecordsWrite.RecordID,
		ContextID:    wrapper.RecordsWrite.ContextID,
		Protocol:     stringFromMap(desc, "protocol"),
		ProtocolPath: stringFromMap(desc, "protocolPath"),
		Schema:       stringFromMap(desc, "schema"),
		DataFormat:   stringFromMap(desc, "dataFormat"),
		DataCID:      stringFromMap(desc, "dataCid"),
		DataSize:     intFromMap(desc, "dataSize"),
		DateCreated:  stringFromMap(desc, "dateCreated"),
		Timestamp:    stringFromMap(desc, "messageTimestamp"),
		Recipient:    stringFromMap(desc, "recipient"),
		ParentID:     stringFromMap(desc, "parentId"),
		Published:    boolFromMap(desc, "published"),
		DatePublished: stringFromMap(desc, "datePublished"),
		RawEntry:     entry,
		agent:        agent,
		target:       target,
		encodedData:  wrapper.RecordsWrite.EncodedData,
		rawData:      data,
	}

	if tags, ok := desc["tags"].(map[string]any); ok {
		r.Tags = tags
	}

	return r, nil
}

//
// --- Data access (lazy) ---
//

// RecordData provides lazy access to a record's data.
//
// Data resolution order:
//  1. If encodedData exists (small payloads, base64url in message) → decode it
//  2. If rawData exists (from RecordsRead HTTP body) → use it
//  3. Otherwise → re-fetch via Agent.SendDwnRequest(RecordsRead)
//
// Data is consumed on first access. Subsequent calls will re-fetch.
type RecordData struct {
	record *Record
}

// Data returns a lazy accessor for the record's data.
func (r *Record) Data() *RecordData {
	return &RecordData{record: r}
}

// Bytes returns the record data as a byte slice.
func (d *RecordData) Bytes(ctx context.Context) ([]byte, error) {
	reader, err := d.Reader(ctx)
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	return io.ReadAll(reader)
}

// JSON unmarshals the record data into the given value.
func (d *RecordData) JSON(ctx context.Context, v any) error {
	data, err := d.Bytes(ctx)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

// Text returns the record data as a UTF-8 string.
func (d *RecordData) Text(ctx context.Context) (string, error) {
	data, err := d.Bytes(ctx)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// Reader returns an io.ReadCloser for the record data.
//
// This is a one-shot operation — the underlying data source is consumed.
// Subsequent calls will trigger a re-fetch from the DWN.
func (d *RecordData) Reader(ctx context.Context) (io.ReadCloser, error) {
	r := d.record

	r.mu.Lock()
	defer r.mu.Unlock()

	// 1. Try inline encoded data.
	if r.encodedData != "" {
		data, err := base64.RawURLEncoding.DecodeString(r.encodedData)
		if err != nil {
			return nil, fmt.Errorf("decoding inline data: %w", err)
		}
		r.encodedData = ""
		r.dataConsumed = true
		return io.NopCloser(bytes.NewReader(data)), nil
	}

	// 2. Try raw binary data (from HTTP body).
	if len(r.rawData) > 0 {
		data := r.rawData
		r.rawData = nil
		r.dataConsumed = true
		return io.NopCloser(bytes.NewReader(data)), nil
	}

	// 3. Re-fetch from DWN.
	if r.agent == nil {
		return nil, fmt.Errorf("no agent available to fetch data")
	}

	resp, err := r.agent.SendDwnRequest(ctx, DwnRequest{
		Target:      r.target,
		MessageType: InterfaceRecordsRead,
		MessageParams: &ReadParams{
			Filter: RecordsFilter{
				RecordID: r.ID,
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("fetching record data: %w", err)
	}

	if resp.Status.Code != 200 {
		return nil, fmt.Errorf("fetching data: %d %s", resp.Status.Code, resp.Status.Detail)
	}

	if len(resp.Data) > 0 {
		r.dataConsumed = true
		return io.NopCloser(bytes.NewReader(resp.Data)), nil
	}

	return nil, fmt.Errorf("no data in response")
}

//
// --- Record operations ---
//

// Update updates the record with new data.
// Returns a new Record reflecting the updated state.
func (r *Record) Update(ctx context.Context, data []byte, opts ...RecordUpdateOption) (*Record, error) {
	if r.agent == nil {
		return nil, fmt.Errorf("no agent available for update")
	}

	updateOpts := &recordUpdateOptions{}
	for _, opt := range opts {
		opt(updateOpts)
	}

	dataFormat := r.DataFormat
	if updateOpts.dataFormat != "" {
		dataFormat = updateOpts.dataFormat
	}

	tags := r.Tags
	if updateOpts.tags != nil {
		tags = updateOpts.tags
	}

	// For updates, derive parentContextID from the record's existing contextID.
	// contextId for a child is "parentContextId/recordId", so strip the last segment.
	var parentContextID string
	if r.ContextID != "" && r.ContextID != r.ID {
		// This is a child record — extract parent context by removing last segment.
		if idx := strings.LastIndex(r.ContextID, "/"); idx >= 0 {
			parentContextID = r.ContextID[:idx]
		}
	}

	resp, err := r.agent.SendDwnRequest(ctx, DwnRequest{
		Target:      r.target,
		MessageType: InterfaceRecordsWrite,
		MessageParams: &WriteParams{
			Protocol:        r.Protocol,
			ProtocolPath:    r.ProtocolPath,
			Schema:          r.Schema,
			Recipient:       r.Recipient,
			ParentContextID: parentContextID,
			DataFormat:      dataFormat,
			Tags:            tags,
			Data:            data,
			RecordID:        r.ID,
			DateCreated:     r.DateCreated,
			ProtocolRole:    updateOpts.protocolRole,
		},
		ProtocolRole: updateOpts.protocolRole,
	})
	if err != nil {
		return nil, err
	}

	if resp.Status.Code >= 300 {
		return nil, fmt.Errorf("update failed: %d %s", resp.Status.Code, resp.Status.Detail)
	}

	// Build updated record from the built message if available (has accurate
	// dataCid, messageTimestamp, dataSize from the computed descriptor).
	var updated *Record
	if resp.BuiltMessage != nil {
		var encoded string
		if len(data) <= maxInlineDataSize {
			encoded = base64.RawURLEncoding.EncodeToString(data)
		}
		updated = RecordFromWrite(r.agent, r.target, resp.BuiltMessage, encoded)
		updated.Author = r.Author
		if len(data) > maxInlineDataSize {
			updated.rawData = data
		}
	} else {
		// Fallback: construct manually.
		updated = &Record{
			ID:            r.ID,
			ContextID:     r.ContextID,
			DateCreated:   r.DateCreated,
			Protocol:      r.Protocol,
			ProtocolPath:  r.ProtocolPath,
			Schema:        r.Schema,
			ParentID:      r.ParentID,
			Recipient:     r.Recipient,
			DataFormat:    r.DataFormat,
			DataCID:       r.DataCID,
			Published:     r.Published,
			DatePublished: r.DatePublished,
			Tags:          r.Tags,
			Timestamp:     r.Timestamp,
			Author:        r.Author,
			agent:         r.agent,
			target:        r.target,
			DataSize:      len(data),
		}
		if len(data) <= maxInlineDataSize {
			updated.encodedData = base64.RawURLEncoding.EncodeToString(data)
		} else {
			updated.rawData = data
		}
	}

	return updated, nil
}

// Delete deletes the record.
func (r *Record) Delete(ctx context.Context, prune bool) error {
	if r.agent == nil {
		return fmt.Errorf("no agent available for delete")
	}

	resp, err := r.agent.SendDwnRequest(ctx, DwnRequest{
		Target:      r.target,
		MessageType: InterfaceRecordsDelete,
		MessageParams: &DeleteParams{
			RecordID: r.ID,
			Prune:    prune,
		},
	})
	if err != nil {
		return err
	}

	if resp.Status.Code >= 300 {
		return fmt.Errorf("delete failed: %d %s", resp.Status.Code, resp.Status.Detail)
	}

	return nil
}

// RecordUpdateOption configures a Record.Update call.
type RecordUpdateOption func(*recordUpdateOptions)

type recordUpdateOptions struct {
	dataFormat   string
	tags         map[string]any
	protocolRole string
}

// WithDataFormat overrides the data format for the update.
func WithDataFormat(format string) RecordUpdateOption {
	return func(o *recordUpdateOptions) {
		o.dataFormat = format
	}
}

// WithTags sets tags for the update.
func WithTags(tags map[string]any) RecordUpdateOption {
	return func(o *recordUpdateOptions) {
		o.tags = tags
	}
}

// WithUpdateProtocolRole sets the protocol role for role-based authorization on updates.
func WithUpdateProtocolRole(role string) RecordUpdateOption {
	return func(o *recordUpdateOptions) {
		o.protocolRole = role
	}
}

//
// --- Helpers ---
//

func stringFromMap(m map[string]any, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func intFromMap(m map[string]any, key string) int {
	if v, ok := m[key]; ok {
		switch n := v.(type) {
		case int:
			return n
		case float64:
			return int(n)
		case json.Number:
			i, _ := n.Int64()
			return int(i)
		}
	}
	return 0
}

func boolFromMap(m map[string]any, key string) bool {
	if v, ok := m[key]; ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return false
}
