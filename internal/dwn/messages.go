package dwn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"unicode/utf16"

	gocid "github.com/ipfs/go-cid"
)

// Messages interface support: MessagesQuery, MessagesRead, MessagesSubscribe.
//
// These are the replication-log feed read surfaces of the enbox DWN. Unlike
// Records/Protocols operations, Messages operations invoke permission grants
// as a PLURAL, canonical `permissionGrantIds` list mirrored in the descriptor
// AND the signature payload, and never use protocol roles or delegated grants.

// Sentinel errors mirroring the dwn-sdk-js permission grant invocation rules.
var (
	// ErrPermissionGrantInvocationAmbiguous mirrors
	// MessagePermissionGrantCreateInvocationAmbiguous: a message may invoke
	// the singular permissionGrantId or the plural permissionGrantIds, never
	// both.
	ErrPermissionGrantInvocationAmbiguous = errors.New("permission grant invocation must use either permissionGrantId or permissionGrantIds, not both")

	// ErrPermissionGrantIDsEmpty mirrors MessagePermissionGrantIdsEmpty: an
	// explicitly supplied permissionGrantIds list must contain at least one
	// grant ID.
	ErrPermissionGrantIDsEmpty = errors.New("permissionGrantIds must contain at least one grant ID")

	// ErrPermissionGrantIDsNotCanonical mirrors
	// MessagePermissionGrantIdsNotCanonical: a received permissionGrantIds
	// list must already be sorted and deduplicated.
	ErrPermissionGrantIDsNotCanonical = errors.New("permissionGrantIds must be sorted and deduplicated")

	// ErrMessagesEntryNotFound is returned by MessagesRead when the target
	// DWN does not have a message with the requested CID.
	ErrMessagesEntryNotFound = errors.New("messages entry not found")
)

//
// --- Canonical permissionGrantIds ---
//

// compareStringsUTF16 compares two strings by UTF-16 code units, matching
// JavaScript's `<`/`>` string comparison (used by the SDK's
// lexicographicalCompare). For ASCII this equals bytewise order, but astral
// (surrogate-pair) characters sort BEFORE U+E000..U+FFFF, unlike UTF-8 byte
// order — the golden fixtures pin this down.
func compareStringsUTF16(a, b string) int {
	ua := utf16.Encode([]rune(a))
	ub := utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			if ua[i] < ub[i] {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(ua) < len(ub):
		return -1
	case len(ua) > len(ub):
		return 1
	default:
		return 0
	}
}

// sortStringsUTF16 sorts in place by UTF-16 code-unit order.
func sortStringsUTF16(values []string) {
	// Insertion sort keeps this dependency-free; grant ID lists are small.
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && compareStringsUTF16(values[j], values[j-1]) < 0; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}

// CanonicalPermissionGrantIDs normalizes a permission grant ID list to the
// canonical wire form: deduplicated and sorted by UTF-16 code-unit order
// (JavaScript string order). A nil list means "no grants invoked" and returns
// nil; an explicitly supplied empty list is an error, mirroring the SDK.
func CanonicalPermissionGrantIDs(ids []string) ([]string, error) {
	if ids == nil {
		return nil, nil
	}
	if len(ids) == 0 {
		return nil, ErrPermissionGrantIDsEmpty
	}
	seen := make(map[string]struct{}, len(ids))
	canonical := make([]string, 0, len(ids))
	for _, id := range ids {
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		canonical = append(canonical, id)
	}
	sortStringsUTF16(canonical)
	return canonical, nil
}

// ValidateCanonicalPermissionGrantIDs verifies a received permissionGrantIds
// list is already in canonical form (sorted, deduplicated, non-empty),
// mirroring the SDK's parse-time validation.
func ValidateCanonicalPermissionGrantIDs(ids []string) error {
	if ids == nil {
		return nil
	}
	canonical, err := CanonicalPermissionGrantIDs(ids)
	if err != nil {
		return err
	}
	if len(canonical) != len(ids) {
		return ErrPermissionGrantIDsNotCanonical
	}
	for i := range ids {
		if ids[i] != canonical[i] {
			return ErrPermissionGrantIDsNotCanonical
		}
	}
	return nil
}

// NormalizePermissionGrantInvocation applies the SDK's grant invocation
// rules: singular and plural forms are mutually exclusive, and a supplied
// plural list is canonicalized. It returns the normalized plural list (nil
// when the invocation is singular or absent).
func NormalizePermissionGrantInvocation(permissionGrantID string, permissionGrantIDs []string) ([]string, error) {
	if permissionGrantID != "" && permissionGrantIDs != nil {
		return nil, ErrPermissionGrantInvocationAmbiguous
	}
	if permissionGrantID != "" {
		return nil, nil
	}
	return CanonicalPermissionGrantIDs(permissionGrantIDs)
}

//
// --- MessagesFilter ---
//

// MessagesTimestampRange is the messageTimestamp range criterion of a
// MessagesFilter. At least one bound must be set.
type MessagesTimestampRange struct {
	From string `json:"from,omitempty"`
	To   string `json:"to,omitempty"`
}

// MessagesFilter selects messages from the replication-log feed.
//
// The wire schema is additionalProperties:false with minProperties:1 — only
// these fields may appear and at least one must be set. ProtocolPathPrefix
// and ContextIDPrefix are segment-aware prefixes: they match a candidate that
// equals the prefix or starts with the prefix followed by "/".
type MessagesFilter struct {
	Interface          string                  `json:"interface,omitempty"`
	Method             string                  `json:"method,omitempty"`
	Protocol           string                  `json:"protocol,omitempty"`
	ProtocolPathPrefix string                  `json:"protocolPathPrefix,omitempty"`
	ContextIDPrefix    string                  `json:"contextIdPrefix,omitempty"`
	MessageTimestamp   *MessagesTimestampRange `json:"messageTimestamp,omitempty"`
}

// messagesFilterToMap converts a filter to its wire map, omitting zero-value
// fields. Empty filters are rejected (schema minProperties: 1).
func messagesFilterToMap(f MessagesFilter) (map[string]any, error) {
	m := make(map[string]any)
	if f.Interface != "" {
		m["interface"] = f.Interface
	}
	if f.Method != "" {
		m["method"] = f.Method
	}
	if f.Protocol != "" {
		m["protocol"] = f.Protocol
	}
	if f.ProtocolPathPrefix != "" {
		m["protocolPathPrefix"] = f.ProtocolPathPrefix
	}
	if f.ContextIDPrefix != "" {
		m["contextIdPrefix"] = f.ContextIDPrefix
	}
	if f.MessageTimestamp != nil {
		r := make(map[string]any)
		if f.MessageTimestamp.From != "" {
			r["from"] = f.MessageTimestamp.From
		}
		if f.MessageTimestamp.To != "" {
			r["to"] = f.MessageTimestamp.To
		}
		if len(r) == 0 {
			return nil, fmt.Errorf("messages filter messageTimestamp range requires from or to")
		}
		m["messageTimestamp"] = r
	}
	if len(m) == 0 {
		return nil, fmt.Errorf("messages filter requires at least one field")
	}
	return m, nil
}

// messagesFiltersToWire converts a filter list to the descriptor's `filters`
// value. The field is ALWAYS present on the wire, as an empty array when no
// filters are given.
func messagesFiltersToWire(filters []MessagesFilter) ([]any, error) {
	wire := make([]any, 0, len(filters))
	for i, f := range filters {
		m, err := messagesFilterToMap(f)
		if err != nil {
			return nil, fmt.Errorf("filter %d: %w", i, err)
		}
		wire = append(wire, m)
	}
	return wire, nil
}

// progressTokenToMap converts a ProgressToken to its wire map for embedding
// inside a signed descriptor.
func progressTokenToMap(t *ProgressToken) map[string]any {
	m := map[string]any{
		"streamId": t.StreamID,
		"epoch":    t.Epoch,
		"position": t.Position,
	}
	if t.MessageCID != "" {
		m["messageCid"] = t.MessageCID
	}
	return m
}

//
// --- Messages message builders ---
//

// messagesSignaturePayload is the JWS payload for Messages interface
// operations: {descriptorCid, permissionGrantIds}. The SAME canonical grant
// ID list appears in the descriptor and in this payload.
type messagesSignaturePayload struct {
	DescriptorCID      string   `json:"descriptorCid"`
	PermissionGrantIDs []string `json:"permissionGrantIds,omitempty"`
}

// signMessagesMessage adds the canonical grant IDs to the descriptor, signs
// the Messages-specific payload, and assembles the message. Messages
// operations never use protocol roles or authorDelegatedGrant.
func signMessagesMessage(s *Signer, desc map[string]any, canonicalGrantIDs []string) (*Message, error) {
	if len(canonicalGrantIDs) > 0 {
		desc["permissionGrantIds"] = canonicalGrantIDs
	}

	descriptorCID, err := ComputeCID(desc)
	if err != nil {
		return nil, fmt.Errorf("computing descriptor CID: %w", err)
	}

	sigPayload := messagesSignaturePayload{
		DescriptorCID:      descriptorCID,
		PermissionGrantIDs: canonicalGrantIDs,
	}

	jws, err := SignJWS(sigPayload, s.KeyID(), s.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("signing: %w", err)
	}

	return &Message{
		Descriptor:    desc,
		Authorization: &Authorization{Signature: jws},
	}, nil
}

// MessagesQueryOptions configures a MessagesQuery message.
type MessagesQueryOptions struct {
	// Filters selects the feed scope; an empty list queries the whole feed.
	// The filters field is always present on the wire.
	Filters []MessagesFilter

	// PermissionGrantIDs invokes a grant set. The list is canonicalized
	// (deduplicated, sorted) before signing; nil means owner-authored.
	PermissionGrantIDs []string

	// Cursor resumes the feed after this progress token.
	Cursor *ProgressToken

	// Limit bounds the page size when > 0.
	Limit int

	// CidsOnly requests entries without the full message (seq/messageCid
	// metadata only) — used for fingerprint convergence probes.
	CidsOnly bool

	// MessageTimestamp overrides the descriptor timestamp. Leave empty for
	// the current time; used for deterministic fixtures.
	MessageTimestamp string
}

// BuildMessagesQuery constructs and signs a MessagesQuery message.
func BuildMessagesQuery(s *Signer, opts MessagesQueryOptions) (*Message, error) {
	canonicalIDs, err := CanonicalPermissionGrantIDs(opts.PermissionGrantIDs)
	if err != nil {
		return nil, err
	}
	filters, err := messagesFiltersToWire(opts.Filters)
	if err != nil {
		return nil, err
	}

	timestamp := opts.MessageTimestamp
	if timestamp == "" {
		timestamp = Now()
	}

	desc := map[string]any{
		"interface":        "Messages",
		"method":           "Query",
		"messageTimestamp": timestamp,
		"filters":          filters,
	}
	if opts.Cursor != nil {
		if !opts.Cursor.valid() {
			return nil, fmt.Errorf("invalid progress token cursor")
		}
		desc["cursor"] = progressTokenToMap(opts.Cursor)
	}
	if opts.Limit > 0 {
		desc["limit"] = opts.Limit
	}
	if opts.CidsOnly {
		desc["cidsOnly"] = true
	}

	return signMessagesMessage(s, desc, canonicalIDs)
}

// MessagesReadOptions configures a MessagesRead message.
type MessagesReadOptions struct {
	// MessageCID is the CID of the message to read.
	MessageCID string

	// PermissionGrantIDs invokes a grant set; nil means owner-authored.
	PermissionGrantIDs []string

	// MessageTimestamp overrides the descriptor timestamp (see
	// MessagesQueryOptions.MessageTimestamp).
	MessageTimestamp string
}

// BuildMessagesRead constructs and signs a MessagesRead message.
func BuildMessagesRead(s *Signer, opts MessagesReadOptions) (*Message, error) {
	if _, err := gocid.Decode(opts.MessageCID); err != nil {
		return nil, fmt.Errorf("%q is not a valid CID: %w", opts.MessageCID, err)
	}
	canonicalIDs, err := CanonicalPermissionGrantIDs(opts.PermissionGrantIDs)
	if err != nil {
		return nil, err
	}

	timestamp := opts.MessageTimestamp
	if timestamp == "" {
		timestamp = Now()
	}

	desc := map[string]any{
		"interface":        "Messages",
		"method":           "Read",
		"messageTimestamp": timestamp,
		"messageCid":       opts.MessageCID,
	}

	return signMessagesMessage(s, desc, canonicalIDs)
}

// MessagesSubscribeOptions configures a MessagesSubscribe message.
type MessagesSubscribeOptions struct {
	// Filters selects the feed scope; an empty list subscribes to the whole
	// feed. The filters field is always present on the wire.
	Filters []MessagesFilter

	// PermissionGrantIDs invokes a grant set; nil means owner-authored.
	PermissionGrantIDs []string

	// Cursor resumes from this progress token: stored events after it are
	// replayed, then an EOSE marker, then live events.
	Cursor *ProgressToken

	// MessageTimestamp overrides the descriptor timestamp (see
	// MessagesQueryOptions.MessageTimestamp).
	MessageTimestamp string
}

// BuildMessagesSubscribe constructs and signs a MessagesSubscribe message.
func BuildMessagesSubscribe(s *Signer, opts MessagesSubscribeOptions) (*Message, error) {
	canonicalIDs, err := CanonicalPermissionGrantIDs(opts.PermissionGrantIDs)
	if err != nil {
		return nil, err
	}
	filters, err := messagesFiltersToWire(opts.Filters)
	if err != nil {
		return nil, err
	}

	timestamp := opts.MessageTimestamp
	if timestamp == "" {
		timestamp = Now()
	}

	desc := map[string]any{
		"interface":        "Messages",
		"method":           "Subscribe",
		"messageTimestamp": timestamp,
		"filters":          filters,
	}
	if opts.Cursor != nil {
		if !opts.Cursor.valid() {
			return nil, fmt.Errorf("invalid progress token cursor")
		}
		desc["cursor"] = progressTokenToMap(opts.Cursor)
	}

	return signMessagesMessage(s, desc, canonicalIDs)
}

//
// --- Client methods ---
//

// ProgressGapError reports a 410 Gone reply: the supplied progress token can
// no longer be resumed against the remote replication log.
type ProgressGapError struct {
	Info *ProgressGapInfo
}

func (e *ProgressGapError) Error() string {
	if e == nil || e.Info == nil {
		return "progress gap"
	}
	return fmt.Sprintf("progress gap: %s", e.Info.Reason)
}

// parseProgressGapReply extracts the structured gap metadata from a 410 reply.
func parseProgressGapReply(reply *DwnReply) *ProgressGapError {
	gap := &ProgressGapInfo{}
	if len(reply.Error) > 0 {
		_ = json.Unmarshal(reply.Error, gap)
	}
	return &ProgressGapError{Info: gap}
}

// MessagesQueryEntry is one entry of a MessagesQuery reply. Message is empty
// when the query was cidsOnly.
type MessagesQueryEntry struct {
	Seq               string          `json:"seq"`
	MessageCID        string          `json:"messageCid"`
	IsLatestBaseState bool            `json:"isLatestBaseState"`
	Protocol          string          `json:"protocol,omitempty"`
	Message           json.RawMessage `json:"message,omitempty"`
	EncodedData       string          `json:"encodedData,omitempty"`
}

// MessagesQueryResult is the parsed reply of a MessagesQuery.
type MessagesQueryResult struct {
	Entries []MessagesQueryEntry

	// Cursor is the high-water progress token for the next page.
	Cursor *ProgressToken

	// Drained reports whether the scan reached the log head.
	Drained bool

	// Fingerprint is the server's set fingerprint over the queried scope
	// (64 lowercase hex chars). Present only for the empty filter set or a
	// pure protocol-only filter set over non-core protocols.
	Fingerprint string
}

// MessagesQuery pages the target tenant's replication-log feed.
//
// A 410 reply returns a *ProgressGapError carrying the structured gap
// metadata so callers can reset their checkpoint and re-baseline.
func (c *Client) MessagesQuery(ctx context.Context, target string, opts MessagesQueryOptions) (*MessagesQueryResult, error) {
	msg, err := BuildMessagesQuery(c.signer, opts)
	if err != nil {
		return nil, fmt.Errorf("building MessagesQuery: %w", err)
	}

	result, err := c.transport.Send(ctx, target, msg, nil)
	if err != nil {
		return nil, err
	}
	reply := result.Reply
	if reply == nil {
		return nil, fmt.Errorf("messages query: missing reply")
	}
	switch reply.Status.Code {
	case http.StatusOK:
	case http.StatusGone:
		return nil, parseProgressGapReply(reply)
	case http.StatusTooManyRequests:
		return nil, queryRateLimitError(reply.Status)
	default:
		return nil, fmt.Errorf("messages query failed: %d %s", reply.Status.Code, reply.Status.Detail)
	}

	queryResult := &MessagesQueryResult{
		Drained:     reply.Drained,
		Fingerprint: reply.Fingerprint,
	}
	if len(reply.Entries) > 0 {
		if err := json.Unmarshal(reply.Entries, &queryResult.Entries); err != nil {
			return nil, fmt.Errorf("unmarshaling messages query entries: %w", err)
		}
	}
	if len(reply.Cursor) > 0 {
		cursor := &ProgressToken{}
		if err := json.Unmarshal(reply.Cursor, cursor); err != nil {
			return nil, fmt.Errorf("unmarshaling messages query cursor: %w", err)
		}
		queryResult.Cursor = cursor
	}
	return queryResult, nil
}

// MessagesReadResult is the parsed reply of a MessagesRead.
type MessagesReadResult struct {
	// MessageCID is the CID of the returned message.
	MessageCID string

	// Message is the stored message, verbatim.
	Message json.RawMessage

	// Data is the record data when the server returned any (RecordsWrite
	// messages with data). It rides the dwn-response header/body transport
	// split exactly like RecordsRead.
	Data []byte
}

// MessagesRead fetches a single message (and its data, if any) by CID from
// the target tenant's DWN. A 404 reply returns an error wrapping
// ErrMessagesEntryNotFound.
func (c *Client) MessagesRead(ctx context.Context, target string, messageCid string, permissionGrantIDs []string) (*MessagesReadResult, error) {
	msg, err := BuildMessagesRead(c.signer, MessagesReadOptions{
		MessageCID:         messageCid,
		PermissionGrantIDs: permissionGrantIDs,
	})
	if err != nil {
		return nil, fmt.Errorf("building MessagesRead: %w", err)
	}

	result, err := c.transport.Send(ctx, target, msg, nil)
	if err != nil {
		return nil, err
	}
	reply := result.Reply
	if reply == nil {
		return nil, fmt.Errorf("messages read: missing reply")
	}
	switch reply.Status.Code {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, fmt.Errorf("messages read %s: %w", messageCid, ErrMessagesEntryNotFound)
	case http.StatusTooManyRequests:
		return nil, queryRateLimitError(reply.Status)
	default:
		return nil, fmt.Errorf("messages read failed: %d %s", reply.Status.Code, reply.Status.Detail)
	}

	var entry struct {
		MessageCID string          `json:"messageCid"`
		Message    json.RawMessage `json:"message"`
	}
	if len(reply.Entry) == 0 {
		return nil, fmt.Errorf("messages read: missing entry")
	}
	if err := json.Unmarshal(reply.Entry, &entry); err != nil {
		return nil, fmt.Errorf("unmarshaling messages read entry: %w", err)
	}

	return &MessagesReadResult{
		MessageCID: entry.MessageCID,
		Message:    entry.Message,
		Data:       result.Data,
	}, nil
}
