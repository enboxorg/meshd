package dwn

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

// Replication-link identity: canonical sync scopes, projection IDs,
// authorization epochs, and link keys. These port the enbox agent's
// types/sync.ts and sync-link-key.ts hash algorithms: base64url (no padding)
// SHA-256 over canonical JSON — JSON.stringify with keys in ALPHABETICAL
// order and no extra whitespace. Key order is part of the hash input, so the
// canonical structs below declare fields in alphabetical JSON-key order.

// Version strings of the link-identity hash algorithms.
const (
	// SyncProjectionRootVersion identifies the projection-ID algorithm used
	// by durable message-feed full/protocol sync scopes.
	SyncProjectionRootVersion = "replication-log-feed-v1"

	// SyncAuthorizationEpochVersion identifies the authorization-epoch
	// algorithm used by delegated Messages.Read sync links.
	SyncAuthorizationEpochVersion = "messages-read-grants-v1"
)

// LinkKeySeparator joins the components of compound replication link
// identifiers.
const LinkKeySeparator = "^"

// SyncScope kinds.
const (
	SyncScopeKindFull        = "full"
	SyncScopeKindProtocolSet = "protocolSet"
)

// ErrSyncScopeEmptyProtocols is returned when a protocol-set scope has no
// protocol URIs.
var ErrSyncScopeEmptyProtocols = errors.New("protocol-set scope requires at least one protocol URI")

// SyncScope describes the primary CID set a replication link syncs: the full
// tenant feed or a set of protocol roots. Narrow protocolPath/contextId sync
// is not representable; a delegate must have grant coverage for every full
// protocol in the protocol set.
type SyncScope struct {
	Kind      string
	Protocols []string
}

// FullSyncScope returns the full-tenant scope.
func FullSyncScope() SyncScope {
	return SyncScope{Kind: SyncScopeKindFull}
}

// ProtocolSetSyncScope returns a protocol-set scope with the protocol list
// normalized to canonical scope-union order.
func ProtocolSetSyncScope(protocols []string) (SyncScope, error) {
	normalized, err := NormalizeSyncProtocols(protocols)
	if err != nil {
		return SyncScope{}, err
	}
	return SyncScope{Kind: SyncScopeKindProtocolSet, Protocols: normalized}, nil
}

// NormalizeSyncProtocols normalizes a protocol list into canonical
// scope-union order: deduplicated and sorted by UTF-16 code-unit order
// (JavaScript string order). An empty result is an error.
func NormalizeSyncProtocols(protocols []string) ([]string, error) {
	seen := make(map[string]struct{}, len(protocols))
	unique := make([]string, 0, len(protocols))
	for _, p := range protocols {
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		unique = append(unique, p)
	}
	if len(unique) == 0 {
		return nil, ErrSyncScopeEmptyProtocols
	}
	sortStringsUTF16(unique)
	return unique, nil
}

// canonicalize validates the scope and returns it in canonical form.
func (s SyncScope) canonicalize() (canonicalSyncScope, error) {
	switch s.Kind {
	case SyncScopeKindFull:
		return canonicalSyncScope{Kind: SyncScopeKindFull}, nil
	case SyncScopeKindProtocolSet:
		normalized, err := NormalizeSyncProtocols(s.Protocols)
		if err != nil {
			return canonicalSyncScope{}, err
		}
		return canonicalSyncScope{Kind: SyncScopeKindProtocolSet, Protocols: normalized}, nil
	default:
		return canonicalSyncScope{}, fmt.Errorf("unknown sync scope kind %q", s.Kind)
	}
}

// Canonical JSON shapes. Field declaration order IS the serialized key order
// and must stay alphabetical — reordering silently changes every persisted
// projection ID and authorization epoch.
type canonicalSyncScope struct {
	Kind      string   `json:"kind"`
	Protocols []string `json:"protocols,omitempty"`
}

type canonicalProjectionIDInput struct {
	Scope     canonicalSyncScope `json:"scope"`
	TenantDID string             `json:"tenantDid"`
	Version   string             `json:"version"`
}

type canonicalEpochGrant struct {
	DateExpires string `json:"dateExpires"`
	DateGranted string `json:"dateGranted,omitempty"`
	ID          string `json:"id"`
}

type canonicalOwnerEpochInput struct {
	Kind    string `json:"kind"`
	Version string `json:"version"`
}

type canonicalDelegateEpochInput struct {
	DelegateDID string                `json:"delegateDid"`
	Grants      []canonicalEpochGrant `json:"grants"`
	Kind        string                `json:"kind"`
	Version     string                `json:"version"`
}

// hashCanonicalObject computes base64url-no-padding(SHA-256(canonical JSON)).
// JSON.stringify does not HTML-escape, so the encoder must not either.
func hashCanonicalObject(value any) (string, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(value); err != nil {
		return "", fmt.Errorf("encoding canonical object: %w", err)
	}
	canonical := bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
	sum := sha256.Sum256(canonical)
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// ComputeProjectionID computes the deterministic projection ID of a sync
// scope for a tenant. It intentionally excludes endpoint, grant IDs, and
// authorization epoch.
func ComputeProjectionID(tenantDID string, scope SyncScope) (string, error) {
	canonicalScope, err := scope.canonicalize()
	if err != nil {
		return "", err
	}
	return hashCanonicalObject(canonicalProjectionIDInput{
		Scope:     canonicalScope,
		TenantDID: tenantDID,
		Version:   SyncProjectionRootVersion,
	})
}

// SyncAuthorizationGrant is the grant metadata that participates in
// delegated authorization-epoch hashing. DateGranted may be empty, in which
// case it is omitted from the canonical form (the SDK's undefined).
type SyncAuthorizationGrant struct {
	ID          string
	DateGranted string
	DateExpires string
}

// SyncAuthorizationGrantsFromPermissionGrants maps parsed permission grants
// to authorization-epoch inputs.
func SyncAuthorizationGrantsFromPermissionGrants(grants []*PermissionGrant) []SyncAuthorizationGrant {
	out := make([]SyncAuthorizationGrant, 0, len(grants))
	for _, grant := range grants {
		out = append(out, SyncAuthorizationGrant{
			ID:          grant.ID,
			DateGranted: grant.DateGranted,
			DateExpires: grant.DateExpires,
		})
	}
	return out
}

// ComputeOwnerAuthorizationEpoch computes the stable authorization epoch of
// an owner link (owner links do not invoke grants).
func ComputeOwnerAuthorizationEpoch() string {
	epoch, err := hashCanonicalObject(canonicalOwnerEpochInput{
		Kind:    "owner",
		Version: SyncAuthorizationEpochVersion,
	})
	if err != nil {
		// Static input; marshaling cannot fail.
		panic(err)
	}
	return epoch
}

// ComputeDelegateAuthorizationEpoch computes the authorization epoch of a
// delegate link from the delegate DID plus the active grant set. A changed
// grant set creates a new link key even when the projection ID is unchanged.
func ComputeDelegateAuthorizationEpoch(delegateDID string, grants []SyncAuthorizationGrant) (string, error) {
	if len(grants) == 0 {
		return "", errors.New("delegate authorization requires at least one grant")
	}
	sorted := make([]SyncAuthorizationGrant, len(grants))
	copy(sorted, grants)
	for i := 1; i < len(sorted); i++ {
		for j := i; j > 0 && compareStringsUTF16(sorted[j].ID, sorted[j-1].ID) < 0; j-- {
			sorted[j], sorted[j-1] = sorted[j-1], sorted[j]
		}
	}
	canonicalGrants := make([]canonicalEpochGrant, len(sorted))
	for i, grant := range sorted {
		canonicalGrants[i] = canonicalEpochGrant{
			DateExpires: grant.DateExpires,
			DateGranted: grant.DateGranted,
			ID:          grant.ID,
		}
	}
	return hashCanonicalObject(canonicalDelegateEpochInput{
		DelegateDID: delegateDID,
		Grants:      canonicalGrants,
		Kind:        "delegate",
		Version:     SyncAuthorizationEpochVersion,
	})
}

// BuildLinkKey builds the runtime identifier of a replication link:
// (tenantDid, remoteEndpoint, projectionId, authorizationEpoch) joined with
// "^".
func BuildLinkKey(tenantDID, remoteEndpoint, projectionID, authorizationEpoch string) string {
	return tenantDID + LinkKeySeparator + remoteEndpoint + LinkKeySeparator + projectionID + LinkKeySeparator + authorizationEpoch
}
