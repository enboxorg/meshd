package dwn

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"

	dwncrypto "github.com/enboxorg/dwn-mesh/internal/dwn/crypto"
)

// DwnAPI is the high-level consumer API for DWN operations.
//
// It wraps an Agent and provides convenience methods for common operations.
// The consumer interacts with Records, never touching DWN messages directly.
//
// This mirrors @enbox/api's DwnApi class.
type DwnAPI struct {
	agent Agent
}

// NewDwnAPI creates a new DWN API backed by the given agent.
func NewDwnAPI(agent Agent) *DwnAPI {
	return &DwnAPI{agent: agent}
}

// Agent returns the underlying Agent.
func (api *DwnAPI) Agent() Agent {
	return api.agent
}

//
// --- Records operations ---
//

// Write creates or updates a record.
//
// Returns the Record and the DWN status. For initial writes, the Record
// has a newly generated ID. For updates, set params.RecordID.
func (api *DwnAPI) Write(ctx context.Context, target string, params WriteParams) (*Record, *Status, error) {
	resp, err := api.agent.SendDwnRequest(ctx, DwnRequest{
		Target:      target,
		MessageType: InterfaceRecordsWrite,
		MessageParams: &params,
	})
	if err != nil {
		return nil, nil, err
	}

	status := resp.Status

	// Construct a Record from the response.
	// For writes, we build the record from the params since the response
	// doesn't echo back the full message.
	record := &Record{
		ID:           "", // will be set from the write response or params
		Protocol:     params.Protocol,
		ProtocolPath: params.ProtocolPath,
		Schema:       params.Schema,
		Recipient:    params.Recipient,
		DataFormat:   params.DataFormat,
		Tags:         params.Tags,
		agent:        api.agent,
		target:       target,
	}

	if params.RecordID != "" {
		record.ID = params.RecordID
	}

	// Store data for lazy access.
	if len(params.Data) > 0 {
		if len(params.Data) <= maxInlineDataSize {
			record.encodedData = encodeData(params.Data)
		} else {
			record.rawData = params.Data
		}
		record.DataSize = len(params.Data)
	}

	return record, &status, nil
}

// Read reads a single record by filter.
//
// Returns the Record with its data available via record.Data().
func (api *DwnAPI) Read(ctx context.Context, target string, filter RecordsFilter, protocolRole string) (*Record, *Status, error) {
	resp, err := api.agent.SendDwnRequest(ctx, DwnRequest{
		Target:       target,
		MessageType:  InterfaceRecordsRead,
		MessageParams: &ReadParams{Filter: filter},
		ProtocolRole: protocolRole,
	})
	if err != nil {
		return nil, nil, err
	}

	status := resp.Status
	if status.Code != 200 {
		return nil, &status, nil
	}

	record, err := RecordFromRead(api.agent, target, resp.Reply, resp.Data)
	if err != nil {
		return nil, &status, fmt.Errorf("parsing read response: %w", err)
	}

	return record, &status, nil
}

// Query queries records matching the filter.
//
// Returns a slice of Records. Data is not included in query results —
// call record.Data() on each to fetch data lazily.
func (api *DwnAPI) Query(ctx context.Context, target string, params QueryParams, protocolRole string) ([]*Record, *Status, error) {
	resp, err := api.agent.SendDwnRequest(ctx, DwnRequest{
		Target:       target,
		MessageType:  InterfaceRecordsQuery,
		MessageParams: &params,
		ProtocolRole: protocolRole,
	})
	if err != nil {
		return nil, nil, err
	}

	status := resp.Status
	if status.Code != 200 {
		return nil, &status, nil
	}

	entries, err := QueryEntries(resp.Reply)
	if err != nil {
		return nil, &status, fmt.Errorf("parsing query entries: %w", err)
	}

	records := make([]*Record, 0, len(entries))
	for _, entry := range entries {
		record, err := RecordFromEntry(api.agent, target, entry)
		if err != nil {
			continue // skip unparseable entries
		}
		records = append(records, record)
	}

	return records, &status, nil
}

// Delete deletes a record.
func (api *DwnAPI) Delete(ctx context.Context, target string, recordID string, prune bool, protocolRole string) (*Status, error) {
	resp, err := api.agent.SendDwnRequest(ctx, DwnRequest{
		Target:       target,
		MessageType:  InterfaceRecordsDelete,
		MessageParams: &DeleteParams{
			RecordID: recordID,
			Prune:    prune,
		},
		ProtocolRole: protocolRole,
	})
	if err != nil {
		return nil, err
	}

	return &resp.Status, nil
}

//
// --- Protocols operations ---
//

// ConfigureProtocol installs a protocol definition on the target DWN.
func (api *DwnAPI) ConfigureProtocol(ctx context.Context, target string, definition json.RawMessage) (*Status, error) {
	resp, err := api.agent.SendDwnRequest(ctx, DwnRequest{
		Target:      target,
		MessageType: InterfaceProtocolsConfigure,
		MessageParams: &ConfigureParams{
			Definition: definition,
		},
	})
	if err != nil {
		return nil, err
	}

	return &resp.Status, nil
}

// QueryProtocols queries installed protocols on the target DWN.
func (api *DwnAPI) QueryProtocols(ctx context.Context, target string, protocolURI string) (*DwnReply, error) {
	resp, err := api.agent.SendDwnRequest(ctx, DwnRequest{
		Target:      target,
		MessageType: InterfaceProtocolsQuery,
		MessageParams: &ProtocolsQueryParams{
			Filter: protocolURI,
		},
	})
	if err != nil {
		return nil, err
	}

	return resp.Reply, nil
}

//
// --- ProtocolAPI (scoped operations) ---
//

// ProtocolDefinition describes a DWN protocol definition.
type ProtocolDefinition struct {
	Protocol  string                    `json:"protocol"`
	Published bool                      `json:"published"`
	Types     map[string]ProtocolType   `json:"types"`
	Structure map[string]ProtocolRule   `json:"structure"`
}

// ProtocolType defines a type within a protocol.
type ProtocolType struct {
	Schema      string   `json:"schema,omitempty"`
	DataFormats []string `json:"dataFormats,omitempty"`
}

// ProtocolRule defines a structural rule in a protocol.
type ProtocolRule struct {
	// Nested structure paths (child types).
	Children map[string]ProtocolRule `json:"-"`
}

// ProtocolAPI provides protocol-scoped DWN operations.
//
// It auto-injects protocol, protocolPath, schema, and dataFormat
// into every operation based on the protocol definition.
// This mirrors @enbox/api's TypedWeb5 class.
type ProtocolAPI struct {
	api        *DwnAPI
	definition ProtocolDefinition
	raw        json.RawMessage // the raw definition for ConfigureProtocol
	validPaths map[string]bool
}

// Using creates a protocol-scoped API.
//
// The returned ProtocolAPI auto-injects protocol URI, path, schema,
// and data format into every DWN operation based on the protocol definition.
func (api *DwnAPI) Using(definition ProtocolDefinition, raw json.RawMessage) *ProtocolAPI {
	paths := make(map[string]bool)
	walkStructure(definition.Structure, "", paths)

	return &ProtocolAPI{
		api:        api,
		definition: definition,
		raw:        raw,
		validPaths: paths,
	}
}

// Configure installs the protocol on the target DWN.
func (p *ProtocolAPI) Configure(ctx context.Context, target string) (*Status, error) {
	return p.api.ConfigureProtocol(ctx, target, p.raw)
}

// Create creates a record at the given protocol path.
//
// The protocol URI, path, schema, and data format are injected automatically.
func (p *ProtocolAPI) Create(ctx context.Context, target string, path string, data []byte, opts ...WriteOption) (*Record, *Status, error) {
	typeName, err := p.resolveType(path)
	if err != nil {
		return nil, nil, err
	}

	params := WriteParams{
		Protocol:     p.definition.Protocol,
		ProtocolPath: path,
		Data:         data,
	}

	if t, ok := p.definition.Types[typeName]; ok {
		params.Schema = t.Schema
		if len(t.DataFormats) > 0 {
			params.DataFormat = t.DataFormats[0]
		}
	}

	if params.DataFormat == "" {
		params.DataFormat = "application/json"
	}

	for _, opt := range opts {
		opt(&params)
	}

	return p.api.Write(ctx, target, params)
}

// Query queries records at the given protocol path.
func (p *ProtocolAPI) Query(ctx context.Context, target string, path string, opts ...QueryOption) ([]*Record, *Status, error) {
	if !p.validPaths[path] {
		return nil, nil, fmt.Errorf("invalid protocol path: %q", path)
	}

	qp := QueryParams{
		Filter: RecordsFilter{
			Protocol:     p.definition.Protocol,
			ProtocolPath: path,
		},
	}

	for _, opt := range opts {
		opt(&qp)
	}

	return p.api.Query(ctx, target, qp, "")
}

// Read reads a single record at the given protocol path.
func (p *ProtocolAPI) Read(ctx context.Context, target string, filter RecordsFilter) (*Record, *Status, error) {
	filter.Protocol = p.definition.Protocol
	return p.api.Read(ctx, target, filter, "")
}

// Delete deletes a record by ID.
func (p *ProtocolAPI) Delete(ctx context.Context, target string, recordID string, prune bool) (*Status, error) {
	return p.api.Delete(ctx, target, recordID, prune, "")
}

// resolveType extracts the type name from a protocol path and validates it.
func (p *ProtocolAPI) resolveType(path string) (string, error) {
	if !p.validPaths[path] {
		return "", fmt.Errorf("invalid protocol path: %q", path)
	}

	// Type name is the last segment of the path.
	typeName := path
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			typeName = path[i+1:]
			break
		}
	}

	return typeName, nil
}

// walkStructure recursively walks a protocol structure to build valid paths.
func walkStructure(structure map[string]ProtocolRule, prefix string, paths map[string]bool) {
	for name, rule := range structure {
		path := name
		if prefix != "" {
			path = prefix + "/" + name
		}
		paths[path] = true

		if len(rule.Children) > 0 {
			walkStructure(rule.Children, path, paths)
		}
	}
}

//
// --- Functional options for protocol-scoped operations ---
//

// WriteOption configures a protocol-scoped Write operation.
type WriteOption func(*WriteParams)

// WithRecipient sets the recipient DID.
func WithRecipient(did string) WriteOption {
	return func(p *WriteParams) {
		p.Recipient = did
	}
}

// WithParentContext sets the parent context ID for child records.
// The parentId descriptor field is derived automatically from the last
// segment of the parentContextID.
func WithParentContext(parentContextID string) WriteOption {
	return func(p *WriteParams) {
		p.ParentContextID = parentContextID
	}
}

// WithWriteTags sets tags on the write.
func WithWriteTags(tags map[string]any) WriteOption {
	return func(p *WriteParams) {
		p.Tags = tags
	}
}

// WithEncryption enables encryption for the write operation.
// The data will be encrypted with A256GCM and the CEK wrapped
// per-recipient using ECDH-ES+A256KW.
func WithEncryption(recipients []dwncrypto.KeyEncryptionInput) WriteOption {
	return func(p *WriteParams) {
		p.EncryptionRecipients = recipients
	}
}

// QueryOption configures a protocol-scoped Query operation.
type QueryOption func(*QueryParams)

// WithDateSort sets the date sort order.
func WithDateSort(sort string) QueryOption {
	return func(p *QueryParams) {
		p.DateSort = sort
	}
}

// WithContextFilter filters by context ID.
func WithContextFilter(contextID string) QueryOption {
	return func(p *QueryParams) {
		p.Filter.ContextID = contextID
	}
}

// WithLimit sets the pagination limit.
func WithLimit(limit int) QueryOption {
	return func(p *QueryParams) {
		if p.Pagination == nil {
			p.Pagination = &Pagination{}
		}
		p.Pagination.Limit = limit
	}
}

// encodeData base64url-encodes data for inline storage.
func encodeData(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}
