package dwn

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const (
	DwnScopeInterfaceRecords   = "Records"
	DwnScopeInterfaceProtocols = "Protocols"
	DwnScopeInterfaceMessages  = "Messages"

	DwnScopeMethodRead      = "Read"
	DwnScopeMethodWrite     = "Write"
	DwnScopeMethodDelete    = "Delete"
	DwnScopeMethodConfigure = "Configure"
	DwnScopeMethodQuery     = "Query"
)

type PermissionScope struct {
	Interface    string `json:"interface"`
	Method       string `json:"method"`
	Protocol     string `json:"protocol,omitempty"`
	ProtocolPath string `json:"protocolPath,omitempty"`
	ContextID    string `json:"contextId,omitempty"`
}

type PermissionGrant struct {
	ID          string
	Grantor     string
	Grantee     string
	DateGranted string
	DateExpires string
	Delegated   bool
	Scope       PermissionScope
}

type PermissionGrantMatch struct {
	Grantor      string
	Grantee      string
	MessageType  DwnInterface
	Protocol     string
	ProtocolPath string
	ContextID    string
	Now          time.Time

	// AllowDelegated permits grants issued with delegated:true to match
	// FindPermissionGrantID. Delegated grants must normally be invoked by
	// embedding the full grant message (see FindDelegatedGrant), not as plain
	// permissionGrantId grants, so FindPermissionGrantID skips them by
	// default. This exists only as a compatibility escape hatch for legacy
	// call sites. It has no effect on FindDelegatedGrant.
	AllowDelegated bool
}

func ParsePermissionGrant(raw json.RawMessage) (*PermissionGrant, error) {
	var msg struct {
		RecordID    string `json:"recordId"`
		EncodedData string `json:"encodedData"`
		Descriptor  struct {
			Recipient   string `json:"recipient"`
			DateCreated string `json:"dateCreated"`
		} `json:"descriptor"`
		Authorization struct {
			Signature *GeneralJWS `json:"signature"`
		} `json:"authorization"`
	}
	if err := json.Unmarshal(raw, &msg); err != nil {
		return nil, fmt.Errorf("parse permission grant message: %w", err)
	}
	if msg.RecordID == "" {
		return nil, fmt.Errorf("permission grant missing recordId")
	}
	if msg.EncodedData == "" {
		return nil, fmt.Errorf("permission grant %s missing encodedData", msg.RecordID)
	}
	if msg.Descriptor.Recipient == "" {
		return nil, fmt.Errorf("permission grant %s missing descriptor.recipient", msg.RecordID)
	}
	grantor, err := signerDIDFromJWS(msg.Authorization.Signature)
	if err != nil {
		return nil, fmt.Errorf("permission grant %s: %w", msg.RecordID, err)
	}
	data, err := base64.RawURLEncoding.DecodeString(msg.EncodedData)
	if err != nil {
		return nil, fmt.Errorf("decode permission grant %s data: %w", msg.RecordID, err)
	}
	var grantData struct {
		DateExpires string          `json:"dateExpires"`
		Delegated   bool            `json:"delegated,omitempty"`
		Scope       PermissionScope `json:"scope"`
	}
	if err := json.Unmarshal(data, &grantData); err != nil {
		return nil, fmt.Errorf("parse permission grant %s data: %w", msg.RecordID, err)
	}
	if grantData.DateExpires == "" {
		return nil, fmt.Errorf("permission grant %s missing dateExpires", msg.RecordID)
	}
	if grantData.Scope.Interface == "" || grantData.Scope.Method == "" {
		return nil, fmt.Errorf("permission grant %s missing scope interface or method", msg.RecordID)
	}
	return &PermissionGrant{
		ID:          msg.RecordID,
		Grantor:     grantor,
		Grantee:     msg.Descriptor.Recipient,
		DateGranted: msg.Descriptor.DateCreated,
		DateExpires: grantData.DateExpires,
		Delegated:   grantData.Delegated,
		Scope:       grantData.Scope,
	}, nil
}

// FindPermissionGrantID returns the ID of a plain (non-delegated) permission
// grant matching the given criteria, or "" when none matches. Grants issued
// with delegated:true are skipped unless match.AllowDelegated is set — they
// must be invoked as delegated grants (see FindDelegatedGrant).
func FindPermissionGrantID(rawGrants []json.RawMessage, match PermissionGrantMatch) (string, error) {
	var fallback string
	for _, raw := range rawGrants {
		grant, err := ParsePermissionGrant(raw)
		if err != nil {
			continue
		}
		if grant.Delegated && !match.AllowDelegated {
			continue
		}
		if !permissionGrantMatches(grant, match) {
			continue
		}
		if grant.Scope.Interface+grant.Scope.Method == string(match.MessageType) {
			return grant.ID, nil
		}
		if fallback == "" {
			fallback = grant.ID
		}
	}
	return fallback, nil
}

// FindDelegatedGrant returns the raw message and parsed form of a delegated
// grant (delegated:true) matching the given criteria, using the same matching
// semantics as FindPermissionGrantID: grantor/grantee/expiry checks, a
// Records/Read scope satisfying both RecordsRead and RecordsQuery, and an
// exact interface+method scope preferred over a broader match. The raw
// message is returned exactly as supplied so it can be embedded verbatim as
// authorization.authorDelegatedGrant.
//
// Returns (nil, nil, nil) when no delegated grant matches.
func FindDelegatedGrant(rawGrants []json.RawMessage, match PermissionGrantMatch) (json.RawMessage, *PermissionGrant, error) {
	var (
		fallbackRaw   json.RawMessage
		fallbackGrant *PermissionGrant
	)
	for _, raw := range rawGrants {
		grant, err := ParsePermissionGrant(raw)
		if err != nil {
			continue
		}
		if !grant.Delegated {
			continue
		}
		if !permissionGrantMatches(grant, match) {
			continue
		}
		if grant.Scope.Interface+grant.Scope.Method == string(match.MessageType) {
			return raw, grant, nil
		}
		if fallbackRaw == nil {
			fallbackRaw = raw
			fallbackGrant = grant
		}
	}
	return fallbackRaw, fallbackGrant, nil
}

func permissionGrantMatches(grant *PermissionGrant, match PermissionGrantMatch) bool {
	if grant == nil {
		return false
	}
	if match.Grantor != "" && grant.Grantor != match.Grantor {
		return false
	}
	if match.Grantee != "" && grant.Grantee != match.Grantee {
		return false
	}
	if !permissionGrantActive(grant, match.Now) {
		return false
	}
	if !scopeInterfaceMethodMatches(grant.Scope, match.MessageType) {
		return false
	}
	return scopeTargetMatches(grant.Scope, match.Protocol, match.ProtocolPath, match.ContextID)
}

func permissionGrantActive(grant *PermissionGrant, now time.Time) bool {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	expiresAt, err := time.Parse(time.RFC3339, grant.DateExpires)
	if err != nil {
		return false
	}
	return now.Before(expiresAt)
}

func scopeInterfaceMethodMatches(scope PermissionScope, messageType DwnInterface) bool {
	switch messageType {
	case InterfaceRecordsRead, InterfaceRecordsQuery:
		return scope.Interface == DwnScopeInterfaceRecords && scope.Method == DwnScopeMethodRead
	case InterfaceRecordsWrite:
		return scope.Interface == DwnScopeInterfaceRecords && scope.Method == DwnScopeMethodWrite
	case InterfaceRecordsDelete:
		return scope.Interface == DwnScopeInterfaceRecords && scope.Method == DwnScopeMethodDelete
	case InterfaceProtocolsQuery:
		return scope.Interface == DwnScopeInterfaceProtocols && scope.Method == DwnScopeMethodQuery
	case InterfaceProtocolsConfigure:
		return scope.Interface == DwnScopeInterfaceProtocols && scope.Method == DwnScopeMethodConfigure
	default:
		return false
	}
}

func scopeTargetMatches(scope PermissionScope, protocol, protocolPath, contextID string) bool {
	if scope.Protocol != "" && scope.Protocol != protocol {
		return false
	}
	if scope.ProtocolPath != "" && scope.ProtocolPath != protocolPath {
		return false
	}
	if scope.ContextID != "" && scope.ContextID != contextID {
		return false
	}
	return true
}

func signerDIDFromJWS(jws *GeneralJWS) (string, error) {
	if jws == nil || len(jws.Signatures) == 0 {
		return "", fmt.Errorf("permission grant missing authorization signature")
	}
	headerData, err := base64.RawURLEncoding.DecodeString(jws.Signatures[0].Protected)
	if err != nil {
		return "", fmt.Errorf("decode permission grant protected header: %w", err)
	}
	var header struct {
		KID string `json:"kid"`
	}
	if err := json.Unmarshal(headerData, &header); err != nil {
		return "", fmt.Errorf("parse permission grant protected header: %w", err)
	}
	if header.KID == "" {
		return "", fmt.Errorf("permission grant protected header missing kid")
	}
	if i := strings.LastIndex(header.KID, "#"); i > 0 {
		return header.KID[:i], nil
	}
	return header.KID, nil
}

//
// --- Feed-grant selection (Messages replication-log scopes) ---
//

// FeedGrantCoverageError reports that no active grant covers part of a
// requested feed scope. Protocol is empty when the full-tenant scope lacked
// an unscoped Messages/Read grant, otherwise it names the uncovered
// protocol.
type FeedGrantCoverageError struct {
	Protocol string
}

func (e *FeedGrantCoverageError) Error() string {
	if e.Protocol == "" {
		return "no active unscoped Messages/Read permission grant covers the full feed scope"
	}
	return fmt.Sprintf("no active protocol-root Messages/Read permission grant covers protocol %s", e.Protocol)
}

// SelectFeedGrants returns the permission grants a delegate must invoke for
// a Messages feed operation over the given scope, porting the enbox agent's
// resolveMessagesScopes rules:
//
//   - Only active Messages/Read grants participate: grantor and grantee
//     match, and dateGranted <= now < dateExpires (compared as DWN timestamp
//     strings, like the agent).
//   - Full scope requires at least one UNSCOPED grant; the invoked set is
//     every active unscoped grant.
//   - Protocol-set scope requires EVERY protocol to be covered by a
//     protocol-root grant (scope.protocol == p with no protocolPath or
//     contextId) or an unscoped grant; the invoked set is every active grant
//     participating in that root set.
//   - Exact protocolPath/contextId grants never authorize feed scopes; they
//     cover a strict subset of the messages in those scopes.
//
// The returned grants are sorted by ID (UTF-16 code-unit order). Missing
// coverage returns a *FeedGrantCoverageError naming the uncovered protocol.
// Revoked grants must be excluded by the caller before selection.
func SelectFeedGrants(grants []*PermissionGrant, grantor, grantee string, now time.Time, scope SyncScope) ([]*PermissionGrant, error) {
	if now.IsZero() {
		now = time.Now()
	}
	nowTimestamp := Timestamp(now)

	active := make([]*PermissionGrant, 0, len(grants))
	for _, grant := range grants {
		if isActiveMessagesFeedGrant(grant, grantor, grantee, nowTimestamp) {
			active = append(active, grant)
		}
	}

	var selected []*PermissionGrant
	switch scope.Kind {
	case SyncScopeKindFull:
		for _, grant := range active {
			if grantScopeIsUnscoped(grant.Scope) {
				selected = append(selected, grant)
			}
		}
		if len(selected) == 0 {
			return nil, &FeedGrantCoverageError{}
		}
	case SyncScopeKindProtocolSet:
		protocols, err := NormalizeSyncProtocols(scope.Protocols)
		if err != nil {
			return nil, err
		}
		for _, protocol := range protocols {
			if !anyGrantMatchesProtocolRoot(active, protocol) {
				return nil, &FeedGrantCoverageError{Protocol: protocol}
			}
		}
		for _, grant := range active {
			if grantParticipatesInProtocolSet(grant, protocols) {
				selected = append(selected, grant)
			}
		}
	default:
		return nil, fmt.Errorf("unknown sync scope kind %q", scope.Kind)
	}

	for i := 1; i < len(selected); i++ {
		for j := i; j > 0 && compareStringsUTF16(selected[j].ID, selected[j-1].ID) < 0; j-- {
			selected[j], selected[j-1] = selected[j-1], selected[j]
		}
	}
	return selected, nil
}

// FeedGrantIDs extracts the canonical invoked ID list from a feed-grant
// selection, ready for permissionGrantIds invocation.
func FeedGrantIDs(grants []*PermissionGrant) []string {
	if len(grants) == 0 {
		return nil
	}
	ids := make([]string, len(grants))
	for i, grant := range grants {
		ids[i] = grant.ID
	}
	sortStringsUTF16(ids)
	return ids
}

// isActiveMessagesFeedGrant mirrors the agent's isActiveMessagesGrant:
// grantor/grantee match, active window dateGranted <= now < dateExpires by
// timestamp-string comparison, and a Messages/Read scope.
func isActiveMessagesFeedGrant(grant *PermissionGrant, grantor, grantee, now string) bool {
	if grant == nil {
		return false
	}
	if grant.Grantor != grantor || grant.Grantee != grantee {
		return false
	}
	if grant.DateGranted > now || grant.DateExpires <= now {
		return false
	}
	return grant.Scope.Interface == DwnScopeInterfaceMessages && grant.Scope.Method == DwnScopeMethodRead
}

// grantScopeIsUnscoped reports whether the scope covers the full tenant feed.
func grantScopeIsUnscoped(scope PermissionScope) bool {
	return scope.Protocol == "" && scope.ProtocolPath == "" && scope.ContextID == ""
}

// grantMatchesProtocolRoot reports whether a grant authorizes the root feed
// of a protocol: unscoped, or scoped to exactly that protocol with no
// protocolPath or contextId narrowing.
func grantMatchesProtocolRoot(grant *PermissionGrant, protocol string) bool {
	if grantScopeIsUnscoped(grant.Scope) {
		return true
	}
	return grant.Scope.Protocol == protocol &&
		grant.Scope.ProtocolPath == "" &&
		grant.Scope.ContextID == ""
}

func anyGrantMatchesProtocolRoot(grants []*PermissionGrant, protocol string) bool {
	for _, grant := range grants {
		if grantMatchesProtocolRoot(grant, protocol) {
			return true
		}
	}
	return false
}

func grantParticipatesInProtocolSet(grant *PermissionGrant, protocols []string) bool {
	for _, protocol := range protocols {
		if grantMatchesProtocolRoot(grant, protocol) {
			return true
		}
	}
	return false
}
