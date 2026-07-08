package enboxconnect

import "encoding/json"

// Wire types for the Enbox connect protocol. JSON field names mirror the
// TypeScript source of truth (packages/agent/src/enbox-connect-protocol.ts)
// exactly.

// PermissionScope is a DWN permission scope
// (dwn-sdk-js src/types/permission-types.ts PermissionScope).
type PermissionScope struct {
	Interface    string `json:"interface"`
	Method       string `json:"method"`
	Protocol     string `json:"protocol,omitempty"`
	ContextID    string `json:"contextId,omitempty"`
	ProtocolPath string `json:"protocolPath,omitempty"`
}

// ConnectPermissionRequest carries a protocol definition together with the
// permission scopes requested for that protocol
// (enbox-connect-protocol.ts ConnectPermissionRequest).
type ConnectPermissionRequest struct {
	ProtocolDefinition json.RawMessage   `json:"protocolDefinition"`
	PermissionScopes   []PermissionScope `json:"permissionScopes"`
}

// ConnectClientMetadata is optional, self-reported client/environment
// display metadata (enbox-connect-protocol.ts ConnectClientMetadata).
type ConnectClientMetadata struct {
	Origin    string   `json:"origin,omitempty"`
	UserAgent string   `json:"userAgent,omitempty"`
	Platform  string   `json:"platform,omitempty"`
	Language  string   `json:"language,omitempty"`
	Languages []string `json:"languages,omitempty"`
	Timezone  string   `json:"timezone,omitempty"`
}

// EnboxConnectRequest is the signed JWT payload the app pushes (encrypted)
// to the connect relay (enbox-connect-protocol.ts EnboxConnectRequest).
type EnboxConnectRequest struct {
	ClientDID                  string                     `json:"clientDid"`
	AppName                    string                     `json:"appName"`
	AppIcon                    string                     `json:"appIcon,omitempty"`
	ClientMetadata             *ConnectClientMetadata     `json:"clientMetadata,omitempty"`
	RequestedSessionTTLSeconds int                        `json:"requestedSessionTtlSeconds,omitempty"`
	DelegateDID                string                     `json:"delegateDid,omitempty"`
	PermissionRequests         []ConnectPermissionRequest `json:"permissionRequests"`
	Nonce                      string                     `json:"nonce"`
	State                      string                     `json:"state"`
	CallbackURL                string                     `json:"callbackUrl"`
	ResponseMode               string                     `json:"responseMode"`
	SupportedDIDMethods        []string                   `json:"supportedDidMethods"`
}

// SessionRevocation maps a session grant to the delegated grant that
// authorizes the delegate to revoke it
// (enbox-connect-protocol.ts EnboxConnectResponse.sessionRevocations).
type SessionRevocation struct {
	GrantID           string `json:"grantId"`
	RevocationGrantID string `json:"revocationGrantId"`
}

// EnboxConnectResponse is the signed JWT payload the wallet returns through
// the relay (enbox-connect-protocol.ts EnboxConnectResponse).
type EnboxConnectResponse struct {
	ProviderDID         string              `json:"providerDid"`
	DelegateDID         string              `json:"delegateDid"`
	Audience            string              `json:"aud"`
	IssuedAt            int64               `json:"iat"`
	ExpiresAt           int64               `json:"exp"`
	Nonce               string              `json:"nonce,omitempty"`
	DelegateGrants      []json.RawMessage   `json:"delegateGrants"`
	DelegatePortableDID json.RawMessage     `json:"delegatePortableDid,omitempty"`
	SessionRevocations  []SessionRevocation `json:"sessionRevocations,omitempty"`
}

// connectPushedResponse is the relay's answer to a pushed authorization
// request (enbox-connect-protocol.ts ConnectPushedResponse).
type connectPushedResponse struct {
	RequestURI string `json:"request_uri"`
	ExpiresIn  int    `json:"expires_in"`
}
