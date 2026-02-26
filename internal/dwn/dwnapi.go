package dwn

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
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
//
// To invoke role-based authorization, set params.ProtocolRole to the
// Protocol Path of the role (e.g., "network/node").
func (api *DwnAPI) Write(ctx context.Context, target string, params WriteParams) (*Record, *Status, error) {
	resp, err := api.agent.SendDwnRequest(ctx, DwnRequest{
		Target:       target,
		MessageType:  InterfaceRecordsWrite,
		MessageParams: &params,
		ProtocolRole: params.ProtocolRole,
	})
	if err != nil {
		return nil, nil, err
	}

	status := resp.Status

	// Construct a Record from the built message which has the computed
	// recordId, contextId, timestamps, and full descriptor.
	var record *Record
	if resp.BuiltMessage != nil {
		var encoded string
		if len(params.Data) > 0 && len(params.Data) <= maxInlineDataSize {
			encoded = encodeData(params.Data)
		}
		record = RecordFromWrite(api.agent, target, resp.BuiltMessage, encoded)
		record.Author = api.agent.DID()
		// Store raw data for large payloads.
		if len(params.Data) > maxInlineDataSize {
			record.rawData = params.Data
		}
	} else {
		// Fallback: construct manually if built message is not available.
		record = &Record{
			ID:           params.RecordID,
			Protocol:     params.Protocol,
			ProtocolPath: params.ProtocolPath,
			Schema:       params.Schema,
			Recipient:    params.Recipient,
			DataFormat:   params.DataFormat,
			Tags:         params.Tags,
			agent:        api.agent,
			target:       target,
		}
		if len(params.Data) > 0 {
			if len(params.Data) <= maxInlineDataSize {
				record.encodedData = encodeData(params.Data)
			} else {
				record.rawData = params.Data
			}
			record.DataSize = len(params.Data)
		}
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

// encodeData base64url-encodes data for inline storage.
func encodeData(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}
