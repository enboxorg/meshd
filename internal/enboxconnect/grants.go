package enboxconnect

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
)

// permissionsProtocolURI is the DWN permissions protocol URI
// (dwn-sdk-js src/core/constants.ts PERMISSIONS_PROTOCOL_URI).
const permissionsProtocolURI = "https://identity.foundation/dwn/permissions"

// parsedGrant is the subset of a permission grant RecordsWrite message that
// grant validation needs (dwn-sdk-js src/protocols/permission-grant.ts).
type parsedGrant struct {
	// ID is the grant's record ID.
	ID string
	// Grantee is descriptor.recipient.
	Grantee string
	// Scope is the grant scope from the decoded encodedData, kept generic
	// for field-by-field subset comparison.
	Scope map[string]any
	// Delegated is the delegated flag from the decoded encodedData.
	Delegated bool
}

// parseGrant validates the structural fields PermissionGrant.parse requires
// (encodedData, an authorization signer, descriptor.recipient, and scope +
// dateExpires inside the decoded data) and extracts what validation needs.
func parseGrant(raw json.RawMessage) (*parsedGrant, error) {
	var msg struct {
		RecordID   string `json:"recordId"`
		Descriptor struct {
			Recipient string `json:"recipient"`
		} `json:"descriptor"`
		EncodedData   string `json:"encodedData"`
		Authorization struct {
			Signature struct {
				Signatures []struct {
					Protected string `json:"protected"`
				} `json:"signatures"`
			} `json:"signature"`
		} `json:"authorization"`
	}
	if err := json.Unmarshal(raw, &msg); err != nil {
		return nil, fmt.Errorf("parsing grant message: %w", err)
	}
	if msg.EncodedData == "" {
		return nil, fmt.Errorf("permission grant message is missing encodedData")
	}
	if err := checkGrantSigner(msg.Authorization.Signature.Signatures); err != nil {
		return nil, err
	}
	if msg.Descriptor.Recipient == "" {
		return nil, fmt.Errorf("permission grant message is missing descriptor.recipient (grantee)")
	}

	dataJSON, err := base64.RawURLEncoding.DecodeString(msg.EncodedData)
	if err != nil {
		return nil, fmt.Errorf("decoding grant encodedData: %w", err)
	}
	var data struct {
		DateExpires string         `json:"dateExpires"`
		Delegated   bool           `json:"delegated"`
		Scope       map[string]any `json:"scope"`
	}
	if err := json.Unmarshal(dataJSON, &data); err != nil {
		return nil, fmt.Errorf("parsing grant data: %w", err)
	}
	if data.Scope == nil {
		return nil, fmt.Errorf("permission grant data is missing required property `scope`")
	}
	if data.DateExpires == "" {
		return nil, fmt.Errorf("permission grant data is missing required property `dateExpires`")
	}

	return &parsedGrant{
		ID:        msg.RecordID,
		Grantee:   msg.Descriptor.Recipient,
		Scope:     data.Scope,
		Delegated: data.Delegated,
	}, nil
}

// checkGrantSigner mirrors Message.getSigner presence validation: the grant
// must carry an authorization signature whose protected header names a kid.
func checkGrantSigner(signatures []struct {
	Protected string `json:"protected"`
}) error {
	if len(signatures) == 0 {
		return fmt.Errorf("permission grant message is missing authorization (unable to extract grantor)")
	}
	protectedJSON, err := base64.RawURLEncoding.DecodeString(signatures[0].Protected)
	if err != nil {
		return fmt.Errorf("decoding grant signature protected header: %w", err)
	}
	var protected struct {
		KID string `json:"kid"`
	}
	if err := json.Unmarshal(protectedJSON, &protected); err != nil {
		return fmt.Errorf("parsing grant signature protected header: %w", err)
	}
	if protected.KID == "" {
		return fmt.Errorf("permission grant message is missing authorization (unable to extract grantor)")
	}
	return nil
}

// validateGrants validates that the wallet granted exactly what was
// requested, mirroring validateConnectResultGrants in
// packages/auth/src/connect/validate-grants.ts: every grant's grantee must
// be the delegate DID; each grant that is not a recognized session
// revocation grant must have a scope that is a subset of a requested scope.
func validateGrants(
	grants []json.RawMessage,
	delegateDID string,
	requested []ConnectPermissionRequest,
	revocations []SessionRevocation,
) error {
	revokedGrantIDs := make(map[string]string, len(revocations))
	for _, revocation := range revocations {
		revokedGrantIDs[revocation.RevocationGrantID] = revocation.GrantID
	}

	requestedScopes, err := requestedScopeMaps(requested)
	if err != nil {
		return err
	}

	for _, grantMessage := range grants {
		grant, err := parseGrant(grantMessage)
		if err != nil {
			return err
		}

		if grant.Grantee != delegateDID {
			return fmt.Errorf(
				"wallet returned a grant for %q, but the delegate DID is %q; revoke the approved session in your wallet",
				grant.Grantee, delegateDID)
		}

		if isSessionRevocationGrant(grant, revokedGrantIDs) {
			continue
		}

		if !isRequestedScope(grant.Scope, requestedScopes) {
			return fmt.Errorf(
				"wallet returned a grant outside the requested permission scope; revoke the approved session in your wallet")
		}
	}
	return nil
}

// isSessionRevocationGrant reports whether the grant is one of the
// session-revocation delegations named by the response's sessionRevocations
// mapping: its scope must be Records/Write on the DWN permissions protocol
// with contextId equal to the grant it revokes.
func isSessionRevocationGrant(grant *parsedGrant, revokedGrantIDs map[string]string) bool {
	revokedGrantID, found := revokedGrantIDs[grant.ID]
	if !found {
		return false
	}

	return grant.Scope["interface"] == "Records" &&
		grant.Scope["method"] == "Write" &&
		grant.Scope["protocol"] == permissionsProtocolURI &&
		grant.Scope["contextId"] == revokedGrantID
}

// isRequestedScope reports whether the granted scope is a subset of any
// requested scope.
func isRequestedScope(grantScope map[string]any, requestedScopes []map[string]any) bool {
	for _, requestedScope := range requestedScopes {
		if isScopeSubset(grantScope, requestedScope) {
			return true
		}
	}
	return false
}

// isScopeSubset reports whether grantScope is a subset of requestedScope:
// interface and method must match, and every field present on the requested
// scope must be present and JSON-equal on the granted scope. The granted
// scope may carry additional (narrowing) fields.
func isScopeSubset(grantScope, requestedScope map[string]any) bool {
	if !reflect.DeepEqual(grantScope["interface"], requestedScope["interface"]) ||
		!reflect.DeepEqual(grantScope["method"], requestedScope["method"]) {
		return false
	}

	for key, requestedValue := range requestedScope {
		grantedValue, present := grantScope[key]
		if !present || !reflect.DeepEqual(grantedValue, requestedValue) {
			return false
		}
	}
	return true
}

// requestedScopeMaps flattens the requested permission scopes into generic
// maps for field-by-field comparison against granted scopes.
func requestedScopeMaps(requested []ConnectPermissionRequest) ([]map[string]any, error) {
	var out []map[string]any
	for _, permissionRequest := range requested {
		for _, scope := range permissionRequest.PermissionScopes {
			scopeJSON, err := json.Marshal(scope)
			if err != nil {
				return nil, fmt.Errorf("marshaling requested scope: %w", err)
			}
			var m map[string]any
			if err := json.Unmarshal(scopeJSON, &m); err != nil {
				return nil, fmt.Errorf("normalizing requested scope: %w", err)
			}
			out = append(out, m)
		}
	}
	return out, nil
}
