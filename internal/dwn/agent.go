package dwn

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	dwncrypto "github.com/enboxorg/dwn-mesh/internal/dwn/crypto"
)

//
// --- Agent interface (the signing boundary) ---
//

// Agent is the core abstraction for interacting with DWN.
//
// The consumer never touches JWS, CID computation, or key material directly.
// Instead, the Agent handles all signing, message construction, and transport.
// This mirrors @enbox/api's Web5Agent interface.
//
// There are two operations:
//   - Process: operates on a local DWN (the agent's own)
//   - Send: operates on a remote DWN (another party's)
type Agent interface {
	// DID returns the agent's decentralized identifier.
	DID() string

	// ProcessDwnRequest creates, signs, and processes a DWN message locally.
	// This is for operating on the agent's own DWN.
	ProcessDwnRequest(ctx context.Context, req DwnRequest) (*DwnResponse, error)

	// SendDwnRequest creates, signs, and sends a DWN message to a remote DWN.
	// This is for operating on another party's DWN.
	SendDwnRequest(ctx context.Context, req DwnRequest) (*DwnResponse, error)
}

// DwnInterface identifies the type of DWN message.
type DwnInterface string

const (
	InterfaceRecordsWrite      DwnInterface = "RecordsWrite"
	InterfaceRecordsRead       DwnInterface = "RecordsRead"
	InterfaceRecordsQuery      DwnInterface = "RecordsQuery"
	InterfaceRecordsDelete     DwnInterface = "RecordsDelete"
	InterfaceRecordsSubscribe  DwnInterface = "RecordsSubscribe"
	InterfaceProtocolsConfigure DwnInterface = "ProtocolsConfigure"
	InterfaceProtocolsQuery    DwnInterface = "ProtocolsQuery"
)

// DwnRequest describes what operation to perform.
// The Agent constructs and signs the actual DWN message from these parameters.
type DwnRequest struct {
	// Author is the DID that signs the message.
	// Defaults to the agent's own DID if empty.
	Author string

	// Target is the DID of the DWN tenant to operate on.
	Target string

	// MessageType identifies which DWN interface/method to use.
	MessageType DwnInterface

	// MessageParams holds the type-specific parameters.
	// The Agent creates and signs the DWN message from these.
	MessageParams any

	// DataStream provides record data for RecordsWrite.
	DataStream io.Reader

	// ProtocolRole for role-based authorization.
	ProtocolRole string

	// Store controls whether to persist the result locally.
	Store bool
}

// DwnResponse is the result of processing or sending a DWN request.
type DwnResponse struct {
	// Status is the DWN-level response status.
	Status Status

	// Message is the signed DWN message that was sent/processed.
	Message json.RawMessage

	// Reply is the full DWN reply.
	Reply *DwnReply

	// Data is binary record data (for RecordsRead responses).
	Data []byte
}

//
// --- RecordsWrite params ---
//

// WriteParams configures a RecordsWrite operation.
type WriteParams struct {
	Protocol     string
	ProtocolPath string
	Schema       string
	Recipient    string
	ParentID     string
	ContextID    string
	Tags         map[string]any
	DataFormat   string
	Published    *bool

	// Data is the record payload. For the DwnRequest, this should also
	// be set on DwnRequest.DataStream for large payloads.
	Data []byte

	// RecordID is set for updates (empty for initial writes).
	RecordID string

	// EncryptionRecipients enables encryption for this write.
	// When set, the data is encrypted with A256GCM and the CEK is
	// wrapped per-recipient using ECDH-ES+A256KW.
	EncryptionRecipients []dwncrypto.KeyEncryptionInput
}

// ReadParams configures a RecordsRead operation.
type ReadParams struct {
	Filter RecordsFilter
}

// QueryParams configures a RecordsQuery operation.
type QueryParams struct {
	Filter     RecordsFilter
	DateSort   string
	Pagination *Pagination
}

// DeleteParams configures a RecordsDelete operation.
type DeleteParams struct {
	RecordID string
	Prune    bool
}

// SubscribeParams configures a RecordsSubscribe operation.
type SubscribeParams struct {
	Filter RecordsFilter
	Cursor string
}

// ConfigureParams configures a ProtocolsConfigure operation.
type ConfigureParams struct {
	Definition json.RawMessage
}

// ProtocolsQueryParams configures a ProtocolsQuery operation.
type ProtocolsQueryParams struct {
	Filter string // protocol URI
}

//
// --- SimpleAgent implementation ---
//

// SimpleAgent is a basic Agent implementation that uses a single DID/key pair
// and an HTTP transport to a remote DWN server.
//
// This is the "batteries included" agent for simple use cases like dwn-mesh.
// For more complex scenarios (multi-identity, local DWN, sync), implement
// the Agent interface directly.
type SimpleAgent struct {
	did    string
	signer *Signer
	client *Client
}

// NewSimpleAgent creates an agent that signs with the given signer and
// sends all requests to the given DWN endpoint.
func NewSimpleAgent(endpoint string, signer *Signer) *SimpleAgent {
	return &SimpleAgent{
		did:    signer.DID,
		signer: signer,
		client: NewClient(endpoint, signer),
	}
}

// DID returns the agent's DID.
func (a *SimpleAgent) DID() string {
	return a.did
}

// ProcessDwnRequest for SimpleAgent sends to the remote DWN (no local DWN).
// In a full implementation this would process against a local DWN store.
func (a *SimpleAgent) ProcessDwnRequest(ctx context.Context, req DwnRequest) (*DwnResponse, error) {
	// SimpleAgent has no local DWN — delegate to SendDwnRequest.
	return a.SendDwnRequest(ctx, req)
}

// SendDwnRequest creates, signs, and sends a DWN message to the remote DWN.
func (a *SimpleAgent) SendDwnRequest(ctx context.Context, req DwnRequest) (*DwnResponse, error) {
	target := req.Target
	if target == "" {
		target = a.did
	}

	switch req.MessageType {
	case InterfaceRecordsWrite:
		return a.sendRecordsWrite(ctx, target, req)
	case InterfaceRecordsRead:
		return a.sendRecordsRead(ctx, target, req)
	case InterfaceRecordsQuery:
		return a.sendRecordsQuery(ctx, target, req)
	case InterfaceRecordsDelete:
		return a.sendRecordsDelete(ctx, target, req)
	case InterfaceProtocolsConfigure:
		return a.sendProtocolsConfigure(ctx, target, req)
	case InterfaceProtocolsQuery:
		return a.sendProtocolsQuery(ctx, target, req)
	default:
		return nil, fmt.Errorf("unsupported message type: %s", req.MessageType)
	}
}

func (a *SimpleAgent) sendRecordsWrite(ctx context.Context, target string, req DwnRequest) (*DwnResponse, error) {
	params, ok := req.MessageParams.(*WriteParams)
	if !ok {
		return nil, fmt.Errorf("RecordsWrite requires *WriteParams, got %T", req.MessageParams)
	}

	data := params.Data
	if data == nil && req.DataStream != nil {
		var err error
		data, err = io.ReadAll(req.DataStream)
		if err != nil {
			return nil, fmt.Errorf("reading data stream: %w", err)
		}
	}

	result, err := a.client.RecordsWrite(ctx, target, RecordsWriteOptions{
		Protocol:             params.Protocol,
		ProtocolPath:         params.ProtocolPath,
		Schema:               params.Schema,
		Recipient:            params.Recipient,
		ParentID:             params.ParentID,
		ContextID:            params.ContextID,
		Tags:                 params.Tags,
		DataFormat:           params.DataFormat,
		Published:            params.Published,
		Data:                 data,
		RecordID:             params.RecordID,
		ProtocolRole:         req.ProtocolRole,
		EncryptionRecipients: params.EncryptionRecipients,
	})
	if err != nil {
		return nil, err
	}

	return &DwnResponse{
		Status: result.Reply.Status,
		Reply:  result.Reply,
	}, nil
}

func (a *SimpleAgent) sendRecordsRead(ctx context.Context, target string, req DwnRequest) (*DwnResponse, error) {
	params, ok := req.MessageParams.(*ReadParams)
	if !ok {
		return nil, fmt.Errorf("RecordsRead requires *ReadParams, got %T", req.MessageParams)
	}

	result, err := a.client.RecordsRead(ctx, target, params.Filter, req.ProtocolRole)
	if err != nil {
		return nil, err
	}

	return &DwnResponse{
		Status: result.Reply.Status,
		Reply:  result.Reply,
		Data:   result.Data,
	}, nil
}

func (a *SimpleAgent) sendRecordsQuery(ctx context.Context, target string, req DwnRequest) (*DwnResponse, error) {
	params, ok := req.MessageParams.(*QueryParams)
	if !ok {
		return nil, fmt.Errorf("RecordsQuery requires *QueryParams, got %T", req.MessageParams)
	}

	reply, err := a.client.RecordsQuery(ctx, target, params.Filter, params.DateSort, params.Pagination, req.ProtocolRole)
	if err != nil {
		return nil, err
	}

	return &DwnResponse{
		Status: reply.Status,
		Reply:  reply,
	}, nil
}

func (a *SimpleAgent) sendRecordsDelete(ctx context.Context, target string, req DwnRequest) (*DwnResponse, error) {
	params, ok := req.MessageParams.(*DeleteParams)
	if !ok {
		return nil, fmt.Errorf("RecordsDelete requires *DeleteParams, got %T", req.MessageParams)
	}

	reply, err := a.client.RecordsDelete(ctx, target, params.RecordID, params.Prune, req.ProtocolRole)
	if err != nil {
		return nil, err
	}

	return &DwnResponse{
		Status: reply.Status,
		Reply:  reply,
	}, nil
}

func (a *SimpleAgent) sendProtocolsConfigure(ctx context.Context, target string, req DwnRequest) (*DwnResponse, error) {
	params, ok := req.MessageParams.(*ConfigureParams)
	if !ok {
		return nil, fmt.Errorf("ProtocolsConfigure requires *ConfigureParams, got %T", req.MessageParams)
	}

	reply, err := a.client.ProtocolsConfigure(ctx, target, params.Definition)
	if err != nil {
		return nil, err
	}

	return &DwnResponse{
		Status: reply.Status,
		Reply:  reply,
	}, nil
}

func (a *SimpleAgent) sendProtocolsQuery(ctx context.Context, target string, req DwnRequest) (*DwnResponse, error) {
	params, ok := req.MessageParams.(*ProtocolsQueryParams)
	if !ok {
		return nil, fmt.Errorf("ProtocolsQuery requires *ProtocolsQueryParams, got %T", req.MessageParams)
	}

	reply, err := a.client.ProtocolsQuery(ctx, target, params.Filter)
	if err != nil {
		return nil, err
	}

	return &DwnResponse{
		Status: reply.Status,
		Reply:  reply,
	}, nil
}
