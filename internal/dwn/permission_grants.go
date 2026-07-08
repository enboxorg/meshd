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
