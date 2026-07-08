package dwn

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	dwncrypto "github.com/enboxorg/meshd/internal/dwn/crypto"
)

// Sentinel errors.
var (
	ErrMissingProtocol = errors.New("protocol and protocolPath are required")
	ErrMissingData     = errors.New("data and dataFormat are required")

	// ErrGrantInvocationConflict is returned when both a permission grant ID
	// and a delegated grant are supplied for the same message. A message may
	// invoke a plain grant via permissionGrantId OR a delegated grant via
	// authorization.authorDelegatedGrant, never both.
	ErrGrantInvocationConflict = errors.New("permissionGrantId and delegatedGrant are mutually exclusive")
)

//
// --- Timestamps ---
//

// Timestamp returns an RFC 3339 timestamp with microsecond precision,
// as required by the DWN spec: "2024-01-15T10:30:00.000000Z"
func Timestamp(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.000000Z")
}

// Now returns the current time as a DWN-formatted timestamp.
func Now() string {
	return Timestamp(time.Now())
}

//
// --- Signer ---
//

// Signer holds the keys and DID URI needed to sign DWN messages.
type Signer struct {
	DID        string
	PrivateKey ed25519.PrivateKey
}

// KeyID returns the DID URL for the signing key.
func (s *Signer) KeyID() string {
	return s.DID + "#0"
}

//
// --- Response types ---
//

// Status is the DWN response status.
type Status struct {
	Code   int    `json:"code"`
	Detail string `json:"detail"`
}

// Response is the old response type, kept temporarily for backward compat.
// Prefer DwnReply from transport.go for new code.
//
// Deprecated: Use DwnReply instead.
type Response = DwnReply

//
// --- Filter and pagination ---
//

// RecordsFilter defines query/read/subscribe filter criteria.
// Only non-zero fields are included in the wire message.
type RecordsFilter struct {
	RecordID     string         `json:"recordId,omitempty"`
	Author       any            `json:"author,omitempty"` // string or []string
	Recipient    any            `json:"recipient,omitempty"`
	Protocol     string         `json:"protocol,omitempty"`
	ProtocolPath string         `json:"protocolPath,omitempty"`
	ContextID    string         `json:"contextId,omitempty"`
	Schema       string         `json:"schema,omitempty"`
	ParentID     string         `json:"parentId,omitempty"`
	DataFormat   string         `json:"dataFormat,omitempty"`
	Published    *bool          `json:"published,omitempty"`
	Tags         map[string]any `json:"tags,omitempty"`
}

// Pagination controls result pagination.
type Pagination struct {
	Limit  int             `json:"limit,omitempty"`
	Cursor json.RawMessage `json:"cursor,omitempty"`
}

//
// --- Authorization ---
//

// Authorization wraps the JWS signature for message authentication.
type Authorization struct {
	Signature *GeneralJWS `json:"signature"`

	// AuthorDelegatedGrant is the FULL delegated grant RecordsWrite message
	// exactly as received (including encodedData). It is kept as raw JSON so
	// the bytes are embedded verbatim — the server recomputes its CID and
	// compares it against delegatedGrantId in the signature payload, so the
	// grant must not be re-marshaled field by field.
	AuthorDelegatedGrant json.RawMessage `json:"authorDelegatedGrant,omitempty"`
}

// MessageAuth bundles the authorization options shared by the Records
// read/query/delete/subscribe builders.
//
// PermissionGrantID and DelegatedGrant are mutually exclusive: plain
// (non-delegated) grants are invoked via permissionGrantId, while grants
// issued with delegated:true MUST be invoked by embedding the full grant
// message as authorization.authorDelegatedGrant.
type MessageAuth struct {
	// ProtocolRole is the protocol path of a role to invoke for role-based
	// authorization (e.g. "network/node").
	ProtocolRole string

	// PermissionGrantID invokes a plain DWN permission grant. It is included
	// in both the descriptor and the signed payload.
	PermissionGrantID string

	// DelegatedGrant is the full delegated grant RecordsWrite message as
	// received (including encodedData). When set, the message is signed as an
	// author-delegate: the grant is embedded verbatim as
	// authorization.authorDelegatedGrant and its CID is included in the
	// signed payload as delegatedGrantId.
	DelegatedGrant json.RawMessage
}

// validate enforces mutual exclusion of the grant invocation modes.
func (a MessageAuth) validate() error {
	if a.PermissionGrantID != "" && len(a.DelegatedGrant) > 0 {
		return ErrGrantInvocationConflict
	}
	return nil
}

// genericSignaturePayload is the JWS payload for non-RecordsWrite messages.
type genericSignaturePayload struct {
	DescriptorCID     string `json:"descriptorCid"`
	PermissionGrantID string `json:"permissionGrantId,omitempty"`
	DelegatedGrantID  string `json:"delegatedGrantId,omitempty"`
	ProtocolRole      string `json:"protocolRole,omitempty"`
}

// recordsWriteSignaturePayload is the extended JWS payload for RecordsWrite.
// It includes recordId, contextId, and optional attestation/encryption CIDs.
type recordsWriteSignaturePayload struct {
	DescriptorCID     string `json:"descriptorCid"`
	RecordID          string `json:"recordId"`
	ContextID         string `json:"contextId,omitempty"`
	AttestationCID    string `json:"attestationCid,omitempty"`
	EncryptionCID     string `json:"encryptionCid,omitempty"`
	PermissionGrantID string `json:"permissionGrantId,omitempty"`
	DelegatedGrantID  string `json:"delegatedGrantId,omitempty"`
	ProtocolRole      string `json:"protocolRole,omitempty"`
}

//
// --- Message envelope ---
//

// Message is a complete DWN message.
type Message struct {
	RecordID      string                `json:"recordId,omitempty"`
	ContextID     string                `json:"contextId,omitempty"`
	Descriptor    map[string]any        `json:"descriptor"`
	Authorization *Authorization        `json:"authorization,omitempty"`
	Encryption    *dwncrypto.Encryption `json:"encryption,omitempty"`
	EncodedData   string                `json:"encodedData,omitempty"`
}

//
// --- Builder functions ---
//

// RecordsWriteOptions configures a RecordsWrite message.
type RecordsWriteOptions struct {
	Protocol     string
	ProtocolPath string
	Schema       string
	Recipient    string
	Tags         map[string]any
	Data         []byte
	DataFormat   string
	Published    *bool

	// PermissionGrantID invokes a plain (non-delegated) DWN permission grant.
	// It is included in both the descriptor and signed payload.
	// Mutually exclusive with DelegatedGrant.
	PermissionGrantID string

	// DelegatedGrant is the full delegated grant RecordsWrite message as
	// received (including encodedData). When set, the message is signed as an
	// author-delegate: the grant is embedded verbatim as
	// authorization.authorDelegatedGrant, its CID is included in the signed
	// payload as delegatedGrantId, and the grantor becomes the logical author
	// (used for the entry ID of initial writes).
	// Mutually exclusive with PermissionGrantID.
	DelegatedGrant json.RawMessage

	// For updates: set RecordID to the existing record's ID.
	// Leave empty for initial writes.
	RecordID string

	// DateCreated is the original dateCreated timestamp from the initial write.
	// This is REQUIRED for updates (when RecordID is set) because dateCreated
	// is an immutable property that MUST NOT change across updates.
	// Leave empty for initial writes (will be set to the current time).
	DateCreated string

	// ParentContextID is the contextId of the parent record for child records.
	// For root records (top level of a protocol structure), leave empty.
	// For child records, set to the parent's full contextId.
	//
	// The parentId descriptor field is derived from this (last segment).
	// The final contextId is computed as parentContextId + "/" + recordId.
	ParentContextID string

	// ProtocolRole for role-based authorization.
	ProtocolRole string

	// Squash indicates this is a squash (snapshot) write. When true,
	// the server atomically creates this new record and deletes all
	// sibling records at the same protocol path within the same parent
	// context that have an older messageTimestamp.
	// The protocol rule set at this record's protocolPath MUST have
	// $squash: true. Squash writes MUST be initial writes (new records).
	Squash bool

	// EncryptionRecipients enables encryption for this write.
	// When set, the plaintext Data is encrypted with AES-256-CTR (encryption-v1)
	// and the CEK is wrapped per-recipient. The descriptor's dataCid and
	// dataSize will reference the ciphertext, not the plaintext.
	EncryptionRecipients []dwncrypto.KeyEncryptionInput
}

// BuildRecordsWriteResult holds the result of building a RecordsWrite message.
type BuildRecordsWriteResult struct {
	// Message is the signed DWN message.
	Message *Message

	// WireData is the data bytes to send in the HTTP body as
	// application/octet-stream (ciphertext if encrypted, plaintext otherwise).
	// This is what dataCid/dataSize in the descriptor reference.
	WireData []byte
}

// BuildRecordsWrite constructs and signs a RecordsWrite message.
//
// When EncryptionRecipients is set, the plaintext data is encrypted using
// AES-256-CTR (encryption-v1). The descriptor's dataCid and dataSize will
// reference the ciphertext. The encryption property is set on the message and
// its CID is included in the authorization signature payload.
func BuildRecordsWrite(s *Signer, opts RecordsWriteOptions) (*BuildRecordsWriteResult, error) {
	if opts.Protocol == "" || opts.ProtocolPath == "" {
		return nil, ErrMissingProtocol
	}
	if opts.DataFormat == "" {
		return nil, ErrMissingData
	}
	if opts.PermissionGrantID != "" && len(opts.DelegatedGrant) > 0 {
		return nil, ErrGrantInvocationConflict
	}

	// When a delegated grant is invoked, the grantor (the grant's signer) is
	// the logical author of the message, not the local signer. The author
	// feeds into the entry ID (recordId) computation for initial writes.
	authorDID := s.DID
	var delegatedGrantID string
	if len(opts.DelegatedGrant) > 0 {
		var err error
		delegatedGrantID, err = ComputeDelegatedGrantID(opts.DelegatedGrant)
		if err != nil {
			return nil, err
		}
		authorDID, err = delegatedGrantAuthor(opts.DelegatedGrant)
		if err != nil {
			return nil, err
		}
	}

	now := Now()

	// If encryption is requested, encrypt the data first.
	// dataCid/dataSize in the descriptor must reference the ciphertext.
	var (
		wireData   = opts.Data // The data that goes on the wire (ciphertext or plaintext).
		encryption *dwncrypto.Encryption
	)

	if len(opts.EncryptionRecipients) > 0 {
		ct, enc, err := dwncrypto.EncryptData(opts.Data, opts.EncryptionRecipients)
		if err != nil {
			return nil, fmt.Errorf("encrypting data: %w", err)
		}
		wireData = ct
		encryption = enc
	}

	dataCID, err := ComputeDataCID(wireData)
	if err != nil {
		return nil, fmt.Errorf("computing data CID: %w", err)
	}
	dataSize := len(wireData)

	// Build descriptor as map — only include non-zero fields.
	// This matches the SDK's removeUndefinedProperties() behavior.
	//
	// For updates (RecordID set), dateCreated MUST be the original value
	// because it is immutable across record updates. For initial writes,
	// dateCreated is set to the current time.
	dateCreated := now
	if opts.DateCreated != "" {
		dateCreated = opts.DateCreated
	}

	desc := map[string]any{
		"interface":        "Records",
		"method":           "Write",
		"protocol":         opts.Protocol,
		"protocolPath":     opts.ProtocolPath,
		"dataCid":          dataCID,
		"dataSize":         dataSize,
		"dateCreated":      dateCreated,
		"messageTimestamp": now,
		"dataFormat":       opts.DataFormat,
	}
	if opts.Schema != "" {
		desc["schema"] = opts.Schema
	}
	if opts.Recipient != "" {
		desc["recipient"] = opts.Recipient
	}
	// Derive parentId from ParentContextID (last segment is the parent's recordId).
	if opts.ParentContextID != "" {
		segments := strings.Split(opts.ParentContextID, "/")
		parentID := segments[len(segments)-1]
		desc["parentId"] = parentID
	}
	if len(opts.Tags) > 0 {
		desc["tags"] = opts.Tags
	}
	if opts.Published != nil {
		desc["published"] = *opts.Published
		if *opts.Published {
			desc["datePublished"] = now
		}
	}
	if opts.Squash {
		desc["squash"] = true
	}
	if opts.PermissionGrantID != "" {
		desc["permissionGrantId"] = opts.PermissionGrantID
	}

	// Compute record ID.
	recordID := opts.RecordID
	isInitialWrite := recordID == ""

	if isInitialWrite {
		// Entry ID = CID({...descriptor, author: authorDID})
		entryIDInput := make(map[string]any, len(desc)+1)
		for k, v := range desc {
			entryIDInput[k] = v
		}
		entryIDInput["author"] = authorDID

		recordID, err = ComputeCID(entryIDInput)
		if err != nil {
			return nil, fmt.Errorf("computing record ID: %w", err)
		}
	}

	// Compute contextId per the DWN spec:
	// - Root records: contextId = recordId
	// - Child records: contextId = parentContextId + "/" + recordId
	var contextID string
	if opts.ParentContextID != "" {
		contextID = opts.ParentContextID + "/" + recordID
	} else {
		contextID = recordID
	}

	// Compute descriptor CID.
	descriptorCID, err := ComputeCID(desc)
	if err != nil {
		return nil, fmt.Errorf("computing descriptor CID: %w", err)
	}

	// RecordsWrite uses the extended signature payload.
	sigPayload := recordsWriteSignaturePayload{
		DescriptorCID:     descriptorCID,
		RecordID:          recordID,
		ContextID:         contextID,
		PermissionGrantID: opts.PermissionGrantID,
		DelegatedGrantID:  delegatedGrantID,
		ProtocolRole:      opts.ProtocolRole,
	}

	// If encryption is present, compute its CID for the signature payload.
	if encryption != nil {
		// Convert encryption to a map for CID computation (matching SDK behavior).
		encMap, err := structToMap(encryption)
		if err != nil {
			return nil, fmt.Errorf("converting encryption to map: %w", err)
		}
		encCID, err := ComputeCID(encMap)
		if err != nil {
			return nil, fmt.Errorf("computing encryption CID: %w", err)
		}
		sigPayload.EncryptionCID = encCID
	}

	jws, err := SignJWS(sigPayload, s.KeyID(), s.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("signing: %w", err)
	}

	authz := &Authorization{Signature: jws}
	if len(opts.DelegatedGrant) > 0 {
		authz.AuthorDelegatedGrant = opts.DelegatedGrant
	}

	msg := &Message{
		RecordID:      recordID,
		ContextID:     contextID,
		Descriptor:    desc,
		Encryption:    encryption,
		Authorization: authz,
	}

	// NOTE: encodedData is a read-side optimization — the server inlines small
	// data in query/subscribe responses. On the write side, data always goes in
	// the HTTP body as application/octet-stream regardless of size.

	return &BuildRecordsWriteResult{
		Message:  msg,
		WireData: wireData,
	}, nil
}

// structToMap converts a struct to map[string]any via JSON round-trip.
// Used to produce the canonical representation for CID computation.
func structToMap(v any) (map[string]any, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// BuildRecordsRead constructs and signs a RecordsRead message.
func BuildRecordsRead(s *Signer, filter RecordsFilter, protocolRole string, permissionGrantID ...string) (*Message, error) {
	return BuildRecordsReadWithAuth(s, filter, MessageAuth{
		ProtocolRole:      protocolRole,
		PermissionGrantID: optionalString(permissionGrantID),
	})
}

// BuildRecordsReadWithAuth constructs and signs a RecordsRead message with
// explicit authorization options (protocol role, plain grant, or delegated
// grant).
func BuildRecordsReadWithAuth(s *Signer, filter RecordsFilter, auth MessageAuth) (*Message, error) {
	desc := map[string]any{
		"interface":        "Records",
		"method":           "Read",
		"messageTimestamp": Now(),
		"filter":           filterToMap(filter),
	}

	return signGenericMessage(s, desc, auth)
}

// BuildRecordsQuery constructs and signs a RecordsQuery message.
func BuildRecordsQuery(s *Signer, filter RecordsFilter, dateSort string, pagination *Pagination, protocolRole string, permissionGrantID ...string) (*Message, error) {
	return BuildRecordsQueryWithAuth(s, filter, dateSort, pagination, MessageAuth{
		ProtocolRole:      protocolRole,
		PermissionGrantID: optionalString(permissionGrantID),
	})
}

// BuildRecordsQueryWithAuth constructs and signs a RecordsQuery message with
// explicit authorization options (protocol role, plain grant, or delegated
// grant).
func BuildRecordsQueryWithAuth(s *Signer, filter RecordsFilter, dateSort string, pagination *Pagination, auth MessageAuth) (*Message, error) {
	desc := map[string]any{
		"interface":        "Records",
		"method":           "Query",
		"messageTimestamp": Now(),
		"filter":           filterToMap(filter),
	}
	if dateSort != "" {
		desc["dateSort"] = dateSort
	}
	if pagination != nil {
		p := map[string]any{}
		if pagination.Limit > 0 {
			p["limit"] = pagination.Limit
		}
		if pagination.Cursor != nil {
			p["cursor"] = pagination.Cursor
		}
		desc["pagination"] = p
	}

	return signGenericMessage(s, desc, auth)
}

// BuildRecordsDelete constructs and signs a RecordsDelete message.
func BuildRecordsDelete(s *Signer, recordID string, prune bool, protocolRole string, permissionGrantID ...string) (*Message, error) {
	return BuildRecordsDeleteWithAuth(s, recordID, prune, MessageAuth{
		ProtocolRole:      protocolRole,
		PermissionGrantID: optionalString(permissionGrantID),
	})
}

// BuildRecordsDeleteWithAuth constructs and signs a RecordsDelete message with
// explicit authorization options (protocol role, plain grant, or delegated
// grant).
func BuildRecordsDeleteWithAuth(s *Signer, recordID string, prune bool, auth MessageAuth) (*Message, error) {
	desc := map[string]any{
		"interface":        "Records",
		"method":           "Delete",
		"messageTimestamp": Now(),
		"recordId":         recordID,
		"prune":            prune, // required field per SDK
	}

	return signGenericMessage(s, desc, auth)
}

// BuildProtocolsConfigure constructs and signs a ProtocolsConfigure message.
func BuildProtocolsConfigure(s *Signer, definition json.RawMessage) (*Message, error) {
	// Parse definition so it embeds properly in the descriptor map.
	var defMap map[string]any
	if err := json.Unmarshal(definition, &defMap); err != nil {
		return nil, fmt.Errorf("parsing protocol definition: %w", err)
	}

	desc := map[string]any{
		"interface":        "Protocols",
		"method":           "Configure",
		"messageTimestamp": Now(),
		"definition":       defMap,
	}

	return signGenericMessage(s, desc, MessageAuth{})
}

// BuildProtocolsQuery constructs and signs a ProtocolsQuery message.
func BuildProtocolsQuery(s *Signer, protocolURI string) (*Message, error) {
	desc := map[string]any{
		"interface":        "Protocols",
		"method":           "Query",
		"messageTimestamp": Now(),
	}
	if protocolURI != "" {
		desc["filter"] = map[string]any{"protocol": protocolURI}
	}

	return signGenericMessage(s, desc, MessageAuth{})
}

// signGenericMessage signs a non-RecordsWrite message with the generic
// signature payload (descriptorCid only, no recordId/contextId).
//
// A plain permission grant ID is included in both the descriptor and the
// signed payload (the server validates they match). A delegated grant is
// embedded verbatim as authorization.authorDelegatedGrant with its CID in the
// signed payload only — nothing is added to the descriptor.
func signGenericMessage(s *Signer, desc map[string]any, auth MessageAuth) (*Message, error) {
	if err := auth.validate(); err != nil {
		return nil, err
	}

	if auth.PermissionGrantID != "" {
		desc["permissionGrantId"] = auth.PermissionGrantID
	}

	var delegatedGrantID string
	if len(auth.DelegatedGrant) > 0 {
		var err error
		delegatedGrantID, err = ComputeDelegatedGrantID(auth.DelegatedGrant)
		if err != nil {
			return nil, err
		}
	}

	descriptorCID, err := ComputeCID(desc)
	if err != nil {
		return nil, fmt.Errorf("computing descriptor CID: %w", err)
	}

	sigPayload := genericSignaturePayload{
		DescriptorCID:     descriptorCID,
		PermissionGrantID: auth.PermissionGrantID,
		DelegatedGrantID:  delegatedGrantID,
		ProtocolRole:      auth.ProtocolRole,
	}

	jws, err := SignJWS(sigPayload, s.KeyID(), s.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("signing: %w", err)
	}

	authz := &Authorization{Signature: jws}
	if len(auth.DelegatedGrant) > 0 {
		authz.AuthorDelegatedGrant = auth.DelegatedGrant
	}

	return &Message{
		Descriptor:    desc,
		Authorization: authz,
	}, nil
}

func optionalString(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

// filterToMap converts a RecordsFilter to a map, omitting zero-value fields.
func filterToMap(f RecordsFilter) map[string]any {
	m := make(map[string]any)
	if f.RecordID != "" {
		m["recordId"] = f.RecordID
	}
	if f.Author != nil {
		m["author"] = f.Author
	}
	if f.Recipient != nil {
		m["recipient"] = f.Recipient
	}
	if f.Protocol != "" {
		m["protocol"] = f.Protocol
	}
	if f.ProtocolPath != "" {
		m["protocolPath"] = f.ProtocolPath
	}
	if f.ContextID != "" {
		m["contextId"] = f.ContextID
	}
	if f.Schema != "" {
		m["schema"] = f.Schema
	}
	if f.ParentID != "" {
		m["parentId"] = f.ParentID
	}
	if f.DataFormat != "" {
		m["dataFormat"] = f.DataFormat
	}
	if f.Published != nil {
		m["published"] = *f.Published
	}
	if len(f.Tags) > 0 {
		m["tags"] = f.Tags
	}
	return m
}

// QueryResult extracts entries from a query response.
//
// Deprecated: Use QueryEntries in client.go instead.
func QueryResult(resp *Response) ([]json.RawMessage, error) {
	return QueryEntries(resp)
}

// ReadResult extracts the entry from a read response.
//
// Deprecated: Use ReadEntry in client.go instead.
func ReadResult(resp *Response) (json.RawMessage, error) {
	return ReadEntry(resp)
}
