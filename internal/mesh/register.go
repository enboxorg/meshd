package mesh

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/enboxorg/meshd/internal/control"
	"github.com/enboxorg/meshd/internal/dwn"
	dwncrypto "github.com/enboxorg/meshd/internal/dwn/crypto"
	"github.com/enboxorg/meshd/protocols"
)

// writeEncryptionParams carries the inputs needed to build the encryption-v1
// keyEncryption inputs for a single encrypted write.
type writeEncryptionParams struct {
	anchorEndpoint  string
	anchorDID       string
	signer          *dwn.Signer
	encMgr          *dwncrypto.EncryptionKeyManager
	protocolPath    string
	parentContextID string

	// protocolDef optionally overrides the installed protocol definition. When
	// empty it is resolved automatically (rebuilt locally for the owner, fetched
	// from the anchor DWN for a node writer).
	protocolDef json.RawMessage

	// epochSource optionally overrides the role-audience epoch source. When nil a
	// DWN-backed source querying the anchor DWN is used.
	epochSource dwncrypto.AudienceEpochSource
}

// buildEncryptionRecipients produces the keyEncryption inputs for an encrypted
// write: the CEK is wrapped to the owner's published $keyAgreement key at
// protocolPath, plus one roleAudience entry per reading role. It fails closed
// when a reading role has no published audienceEpoch.
func buildEncryptionRecipients(ctx context.Context, p writeEncryptionParams) ([]dwncrypto.KeyEncryptionInput, error) {
	def, err := resolveInstalledDefinition(ctx, p)
	if err != nil {
		return nil, fmt.Errorf("resolving installed protocol definition: %w", err)
	}

	src := p.epochSource
	if src == nil {
		src = control.NewDWNAudienceEpochSource(ctx, dwn.NewClient(p.anchorEndpoint, p.signer), p.anchorDID, nil)
	}

	return dwncrypto.BuildWriteEncryption(def, p.protocolPath, p.parentContextID, src)
}

// resolveInstalledDefinition returns the installed mesh protocol definition
// (with the owner's published $keyAgreement keys).
//
//   - An explicit override wins.
//   - The network owner rebuilds it locally: its encryption root is the anchor
//     DID's #enc key, so InjectEncryptionDirectives reproduces the published
//     keys deterministically.
//   - A node writer (which does not hold the owner's root) fetches it from the
//     anchor DWN via ProtocolsQuery.
func resolveInstalledDefinition(ctx context.Context, p writeEncryptionParams) (json.RawMessage, error) {
	if len(p.protocolDef) > 0 {
		return p.protocolDef, nil
	}
	if p.encMgr != nil && p.anchorDID != "" && strings.HasPrefix(p.encMgr.RootKeyID, p.anchorDID+"#") {
		return dwncrypto.InjectEncryptionDirectives(protocols.MeshProtocolJSON, p.encMgr.RootPrivateKey, p.encMgr.RootKeyID)
	}
	return fetchInstalledProtocolDefinition(ctx, dwn.NewClient(p.anchorEndpoint, p.signer), p.anchorDID, protocols.MeshProtocolURI)
}

// fetchInstalledProtocolDefinition queries the target DWN for the installed
// definition of protocolURI. A ProtocolsConfigure message carries the
// definition in descriptor.definition.
func fetchInstalledProtocolDefinition(ctx context.Context, client *dwn.Client, target, protocolURI string) (json.RawMessage, error) {
	reply, err := client.ProtocolsQuery(ctx, target, protocolURI)
	if err != nil {
		return nil, fmt.Errorf("querying installed protocol: %w", err)
	}
	entries, err := dwn.QueryEntries(reply)
	if err != nil {
		return nil, fmt.Errorf("parsing protocol query: %w", err)
	}
	for _, entry := range entries {
		if def := extractProtocolDefinition(entry); def != nil {
			return def, nil
		}
	}
	return nil, fmt.Errorf("installed protocol definition for %q not found on %s", protocolURI, target)
}

// extractProtocolDefinition pulls descriptor.definition out of a
// ProtocolsConfigure query entry (flat or wrapped form).
func extractProtocolDefinition(entry json.RawMessage) json.RawMessage {
	type configure struct {
		Descriptor struct {
			Definition json.RawMessage `json:"definition"`
		} `json:"descriptor"`
	}
	var probe struct {
		configure
		ProtocolsConfigure configure `json:"protocolsConfigure"`
		Message            configure `json:"message"`
	}
	if err := json.Unmarshal(entry, &probe); err != nil {
		return nil
	}
	switch {
	case len(probe.Descriptor.Definition) > 0:
		return probe.Descriptor.Definition
	case len(probe.ProtocolsConfigure.Descriptor.Definition) > 0:
		return probe.ProtocolsConfigure.Descriptor.Definition
	case len(probe.Message.Descriptor.Definition) > 0:
		return probe.Message.Descriptor.Definition
	}
	return nil
}

const (
	schemaMember       = "https://enbox.id/schemas/wireguard-mesh/member"
	schemaNodeRequest  = "https://enbox.id/schemas/wireguard-mesh/node-request"
	schemaNodeApproval = "https://enbox.id/schemas/wireguard-mesh/node-approval"
	schemaNode         = "https://enbox.id/schemas/wireguard-mesh/node"
	schemaNodeInfo     = "https://enbox.id/schemas/wireguard-mesh/node-info"
	schemaEndpoint     = "https://enbox.id/schemas/wireguard-mesh/endpoint"
	schemaACLPolicy    = "https://enbox.id/schemas/wireguard-mesh/acl-policy"
	schemaPreAuthKey   = "https://enbox.id/schemas/wireguard-mesh/pre-auth-key"
)

// MemberRegistration holds the result of creating a member record.
type MemberRegistration struct {
	MemberRecordID string
	DateCreated    string
}

// CreateMemberParams configures member creation.
type CreateMemberParams struct {
	AnchorEndpoint       string
	AnchorDID            string
	NetworkRecordID      string
	MemberDID            string
	Signer               *dwn.Signer
	EncryptionKeyManager *dwncrypto.EncryptionKeyManager
	Label                string
	PermissionGrantID    string

	// ProtocolDefinition is the installed mesh protocol definition (with injected
	// $keyAgreement keys). Empty resolves it automatically (owner rebuilds it,
	// node fetches it from the anchor DWN).
	ProtocolDefinition json.RawMessage

	// AudienceEpochSource resolves role-audience epochs for roleAudience
	// keyEncryption entries. Nil uses a DWN-backed source on the anchor DWN.
	AudienceEpochSource dwncrypto.AudienceEpochSource
}

// CreateMember creates a member record on the anchor DWN.
// The member record assigns the network/member role to the specified DID
// via the recipient field. Only the network owner (anchor) can create members.
func CreateMember(ctx context.Context, params CreateMemberParams) (*MemberRegistration, error) {
	memberData := map[string]any{
		"addedAt": time.Now().UTC().Format(time.RFC3339),
	}
	if params.Label != "" {
		memberData["label"] = params.Label
	}
	memberDataBytes, err := json.Marshal(memberData)
	if err != nil {
		return nil, fmt.Errorf("marshaling member data: %w", err)
	}

	// Encrypt to the owner's published key + each reading role's audience key.
	var recipients []dwncrypto.KeyEncryptionInput
	if params.EncryptionKeyManager != nil {
		recipients, err = buildEncryptionRecipients(ctx, writeEncryptionParams{
			anchorEndpoint:  params.AnchorEndpoint,
			anchorDID:       params.AnchorDID,
			signer:          params.Signer,
			encMgr:          params.EncryptionKeyManager,
			protocolPath:    "network/member",
			parentContextID: params.NetworkRecordID,
			protocolDef:     params.ProtocolDefinition,
			epochSource:     params.AudienceEpochSource,
		})
		if err != nil {
			return nil, fmt.Errorf("deriving member encryption: %w", err)
		}
	}

	agent := dwn.NewSimpleAgent(params.AnchorEndpoint, params.Signer)
	api := dwn.NewDwnAPI(agent)

	record, status, err := api.Write(ctx, params.AnchorDID, dwn.WriteParams{
		Protocol:             protocols.MeshProtocolURI,
		ProtocolPath:         "network/member",
		Schema:               schemaMember,
		DataFormat:           "application/json",
		Recipient:            params.MemberDID,
		ParentContextID:      params.NetworkRecordID,
		Data:                 memberDataBytes,
		EncryptionRecipients: recipients,
		PermissionGrantID:    params.PermissionGrantID,
	})
	if err != nil {
		return nil, fmt.Errorf("writing member record: %w", err)
	}
	if status.Code >= 300 {
		return nil, fmt.Errorf("member write failed: %d %s", status.Code, status.Detail)
	}

	dateCreated := ""
	if record.DateCreated != "" {
		dateCreated = record.DateCreated
	}

	return &MemberRegistration{
		MemberRecordID: record.ID,
		DateCreated:    dateCreated,
	}, nil
}

// NodeRegistration holds the result of registering a node on DWN.
type NodeRegistration struct {
	NodeRecordID string

	// DateCreated is the dateCreated timestamp from the initial write.
	// Store this and pass it back for subsequent updates so the immutable
	// dateCreated field is preserved.
	DateCreated string
}

// RegisterNodeParams configures node registration.
type RegisterNodeParams struct {
	// AnchorEndpoint is the DWN server URL.
	AnchorEndpoint string

	// AnchorDID is the DID of the anchor DWN owner (network creator).
	AnchorDID string

	// NetworkRecordID is the root network record ID (used as contextId).
	NetworkRecordID string

	// MemberRecordID is the parent member record ID. If empty, the node
	// is created as a top-level owner-provisioned device (network/node).
	// If set, the node is created under the member (network/member/node).
	MemberRecordID string

	// NodeDID is the device's DID URI (did:jwk). Set as recipient to
	// assign the node role and enable recipient-based authorization.
	NodeDID string

	// Signer signs DWN messages. Must be the network owner's signer.
	Signer *dwn.Signer

	// EncryptionKeyManager derives encryption keys for protocol paths.
	EncryptionKeyManager *dwncrypto.EncryptionKeyManager

	// MeshIP is this node's allocated mesh IP.
	MeshIP string

	// Label is a human-readable label for this node.
	Label string

	// OwnerDID is the wallet/member DID that owns this node. It is optional
	// and defaults to NodeDID for local-only devices.
	OwnerDID string

	// DelegateDID is the local delegate/session DID that has wallet grants to
	// operate this node. It is optional and omitted for local-only devices.
	DelegateDID string

	// ExpiresAt is the optional owner-controlled membership expiry. Empty means
	// the node membership does not expire automatically.
	ExpiresAt string

	// ExistingNodeRecordID is set when updating an existing node record.
	// Leave empty for initial registration.
	ExistingNodeRecordID string

	// ExistingDateCreated is the dateCreated timestamp from the initial write.
	// Required when ExistingNodeRecordID is set (updates), because
	// dateCreated is immutable across record updates.
	ExistingDateCreated string

	// Squash indicates this is a squash (snapshot) write.
	Squash bool

	// PermissionGrantID invokes a wallet/member grant when the signer is a
	// local node DID acting for the network owner.
	PermissionGrantID string

	// ProtocolDefinition is the installed mesh protocol definition (with injected
	// $keyAgreement keys). Empty resolves it automatically (owner rebuilds it,
	// node fetches it from the anchor DWN).
	ProtocolDefinition json.RawMessage

	// AudienceEpochSource resolves role-audience epochs for roleAudience
	// keyEncryption entries. Nil uses a DWN-backed source on the anchor DWN.
	AudienceEpochSource dwncrypto.AudienceEpochSource
}

// RegisterNode writes or updates the node record (encrypted) on the anchor DWN.
//
// The node record contains owner-controlled membership data: mesh IP, label,
// allowed IPs, and addedAt. Operational data (hostname, OS, capabilities) is
// written separately via WriteNodeInfo.
//
// The recipient field is set to the node's DID, which assigns the role
// (network/node or network/member/node) for authorization. The node can then
// write its own nodeInfo and endpoint records as the recipient.
func RegisterNode(ctx context.Context, params RegisterNodeParams) (*NodeRegistration, error) {
	if params.EncryptionKeyManager == nil {
		return nil, fmt.Errorf("EncryptionKeyManager is required for encrypted writes")
	}

	nodeData := map[string]any{
		"meshIP":  params.MeshIP,
		"addedAt": time.Now().UTC().Format(time.RFC3339),
	}
	if params.Label != "" {
		nodeData["label"] = params.Label
	}
	if params.OwnerDID != "" && params.OwnerDID != params.NodeDID {
		nodeData["ownerDID"] = params.OwnerDID
		nodeData["memberDID"] = params.OwnerDID
	}
	if params.DelegateDID != "" && params.DelegateDID != params.NodeDID {
		nodeData["delegateDID"] = params.DelegateDID
	}
	if params.ExpiresAt != "" {
		nodeData["expiresAt"] = params.ExpiresAt
	}
	nodeDataBytes, err := json.Marshal(nodeData)
	if err != nil {
		return nil, fmt.Errorf("marshaling node data: %w", err)
	}

	// Determine the protocol path and parent context based on whether
	// this is a member-associated node or an owner-provisioned node.
	var protocolPath string
	var parentContextID string
	var encryptionPath string

	if params.MemberRecordID != "" {
		// Member-associated node: network/member/node
		protocolPath = "network/member/node"
		parentContextID = params.NetworkRecordID + "/" + params.MemberRecordID
		encryptionPath = "network/member/node"
	} else {
		// Owner-provisioned node: network/node
		protocolPath = "network/node"
		parentContextID = params.NetworkRecordID
		encryptionPath = "network/node"
	}

	// Encrypt to the owner's published key + each reading role's audience key.
	recipients, err := buildEncryptionRecipients(ctx, writeEncryptionParams{
		anchorEndpoint:  params.AnchorEndpoint,
		anchorDID:       params.AnchorDID,
		signer:          params.Signer,
		encMgr:          params.EncryptionKeyManager,
		protocolPath:    encryptionPath,
		parentContextID: parentContextID,
		protocolDef:     params.ProtocolDefinition,
		epochSource:     params.AudienceEpochSource,
	})
	if err != nil {
		return nil, fmt.Errorf("deriving node encryption: %w", err)
	}

	agent := dwn.NewSimpleAgent(params.AnchorEndpoint, params.Signer)
	api := dwn.NewDwnAPI(agent)

	writeParams := dwn.WriteParams{
		Protocol:             protocols.MeshProtocolURI,
		ProtocolPath:         protocolPath,
		Schema:               schemaNode,
		DataFormat:           "application/json",
		Recipient:            params.NodeDID,
		ParentContextID:      parentContextID,
		Data:                 nodeDataBytes,
		EncryptionRecipients: recipients,
		Squash:               params.Squash,
		PermissionGrantID:    params.PermissionGrantID,
	}

	// If updating, set the existing record ID and preserve dateCreated.
	if params.ExistingNodeRecordID != "" {
		writeParams.RecordID = params.ExistingNodeRecordID
		writeParams.DateCreated = params.ExistingDateCreated
	}

	record, status, err := api.Write(ctx, params.AnchorDID, writeParams)
	if err != nil {
		return nil, fmt.Errorf("writing node record: %w", err)
	}
	if status.Code >= 300 {
		return nil, fmt.Errorf("node write failed: %d %s", status.Code, status.Detail)
	}

	dateCreated := ""
	if record.DateCreated != "" {
		dateCreated = record.DateCreated
	}

	return &NodeRegistration{
		NodeRecordID: record.ID,
		DateCreated:  dateCreated,
	}, nil
}

// WriteNodeInfoParams configures a nodeInfo write.
type WriteNodeInfoParams struct {
	AnchorEndpoint       string
	AnchorDID            string
	NetworkRecordID      string
	MemberRecordID       string // empty for owner-provisioned nodes
	NodeRecordID         string
	Signer               *dwn.Signer
	EncryptionKeyManager *dwncrypto.EncryptionKeyManager
	Hostname             string
	PermissionGrantID    string

	// ProtocolDefinition is the installed mesh protocol definition (with injected
	// $keyAgreement keys). Empty resolves it automatically (owner rebuilds it,
	// node fetches it from the anchor DWN).
	ProtocolDefinition json.RawMessage

	// AudienceEpochSource resolves role-audience epochs for roleAudience
	// keyEncryption entries. Nil uses a DWN-backed source on the anchor DWN.
	AudienceEpochSource dwncrypto.AudienceEpochSource
}

// WriteNodeInfo writes or updates the node's operational info record (encrypted).
//
// The nodeInfo record is a child of the node record and contains device-managed
// operational data: hostname, OS, and capabilities. It is written by the device
// itself using recipient-of-node authorization.
func WriteNodeInfo(ctx context.Context, params WriteNodeInfoParams) error {
	if params.EncryptionKeyManager == nil {
		return fmt.Errorf("EncryptionKeyManager is required for encrypted writes")
	}

	hostname := params.Hostname
	if hostname == "" {
		hostname, _ = os.Hostname()
	}

	infoData := map[string]any{
		"hostname": hostname,
		"os":       runtime.GOOS,
	}
	infoDataBytes, err := json.Marshal(infoData)
	if err != nil {
		return fmt.Errorf("marshaling nodeInfo data: %w", err)
	}

	// Determine protocol path and parent context.
	var protocolPath string
	var nodeContextID string
	var encryptionPath string

	if params.MemberRecordID != "" {
		protocolPath = "network/member/node/nodeInfo"
		nodeContextID = params.NetworkRecordID + "/" + params.MemberRecordID + "/" + params.NodeRecordID
		encryptionPath = "network/member/node/nodeInfo"
	} else {
		protocolPath = "network/node/nodeInfo"
		nodeContextID = params.NetworkRecordID + "/" + params.NodeRecordID
		encryptionPath = "network/node/nodeInfo"
	}

	// Encrypt to the owner's published key + each reading role's audience key.
	recipients, err := buildEncryptionRecipients(ctx, writeEncryptionParams{
		anchorEndpoint:  params.AnchorEndpoint,
		anchorDID:       params.AnchorDID,
		signer:          params.Signer,
		encMgr:          params.EncryptionKeyManager,
		protocolPath:    encryptionPath,
		parentContextID: nodeContextID,
		protocolDef:     params.ProtocolDefinition,
		epochSource:     params.AudienceEpochSource,
	})
	if err != nil {
		return fmt.Errorf("deriving nodeInfo encryption: %w", err)
	}

	agent := dwn.NewSimpleAgent(params.AnchorEndpoint, params.Signer)
	api := dwn.NewDwnAPI(agent)

	_, status, err := api.Write(ctx, params.AnchorDID, dwn.WriteParams{
		Protocol:             protocols.MeshProtocolURI,
		ProtocolPath:         protocolPath,
		Schema:               schemaNodeInfo,
		DataFormat:           "application/json",
		Recipient:            params.AnchorDID,
		ParentContextID:      nodeContextID,
		Data:                 infoDataBytes,
		EncryptionRecipients: recipients,
		Squash:               true,
		PermissionGrantID:    params.PermissionGrantID,
	})
	if err != nil {
		return fmt.Errorf("writing nodeInfo: %w", err)
	}
	if status.Code >= 300 {
		return fmt.Errorf("nodeInfo write failed: %d %s", status.Code, status.Detail)
	}

	return nil
}

// WriteEndpoint writes or updates the node's endpoint record (encrypted).
//
// The endpoint record is a child of the node record and contains the
// node's network-reachable endpoints (public IPs, local IPs, NAT type).
func WriteEndpoint(ctx context.Context, params WriteEndpointParams) error {
	if params.EncryptionKeyManager == nil {
		return fmt.Errorf("EncryptionKeyManager is required for encrypted writes")
	}

	epMap := map[string]any{
		"publicEndpoints": params.PublicEndpoints,
		"localEndpoints":  params.LocalEndpoints,
		"natType":         params.NATType,
		"updatedAt":       time.Now().UTC().Format(time.RFC3339),
	}
	if params.DiscoKey != "" {
		epMap["discoKey"] = params.DiscoKey
	}
	endpointData, err := json.Marshal(epMap)
	if err != nil {
		return fmt.Errorf("marshaling endpoint: %w", err)
	}

	// Determine protocol path and parent context.
	var protocolPath string
	var nodeContextID string
	var encryptionPath string

	if params.MemberRecordID != "" {
		protocolPath = "network/member/node/endpoint"
		nodeContextID = params.NetworkRecordID + "/" + params.MemberRecordID + "/" + params.NodeRecordID
		encryptionPath = "network/member/node/endpoint"
	} else {
		protocolPath = "network/node/endpoint"
		nodeContextID = params.NetworkRecordID + "/" + params.NodeRecordID
		encryptionPath = "network/node/endpoint"
	}

	// Encrypt to the owner's published key + each reading role's audience key.
	recipients, err := buildEncryptionRecipients(ctx, writeEncryptionParams{
		anchorEndpoint:  params.AnchorEndpoint,
		anchorDID:       params.AnchorDID,
		signer:          params.Signer,
		encMgr:          params.EncryptionKeyManager,
		protocolPath:    encryptionPath,
		parentContextID: nodeContextID,
		protocolDef:     params.ProtocolDefinition,
		epochSource:     params.AudienceEpochSource,
	})
	if err != nil {
		return fmt.Errorf("deriving endpoint encryption: %w", err)
	}

	agent := dwn.NewSimpleAgent(params.AnchorEndpoint, params.Signer)
	api := dwn.NewDwnAPI(agent)

	_, status, err := api.Write(ctx, params.AnchorDID, dwn.WriteParams{
		Protocol:             protocols.MeshProtocolURI,
		ProtocolPath:         protocolPath,
		Schema:               schemaEndpoint,
		DataFormat:           "application/json",
		Recipient:            params.AnchorDID,
		ParentContextID:      nodeContextID,
		Data:                 endpointData,
		EncryptionRecipients: recipients,
		Squash:               true,
		PermissionGrantID:    params.PermissionGrantID,
	})
	if err != nil {
		return fmt.Errorf("writing endpoint: %w", err)
	}
	if status.Code >= 300 {
		return fmt.Errorf("endpoint write failed: %d %s", status.Code, status.Detail)
	}

	return nil
}

// WriteEndpointParams configures an endpoint write.
type WriteEndpointParams struct {
	AnchorEndpoint       string
	AnchorDID            string
	NetworkRecordID      string
	MemberRecordID       string // empty for owner-provisioned nodes
	NodeRecordID         string
	Signer               *dwn.Signer
	EncryptionKeyManager *dwncrypto.EncryptionKeyManager
	PublicEndpoints      []control.PublicEndpoint
	LocalEndpoints       []string
	NATType              string
	PermissionGrantID    string

	// DiscoKey is this node's current disco public key (base64).
	DiscoKey string

	// ProtocolDefinition is the installed mesh protocol definition (with injected
	// $keyAgreement keys). Empty resolves it automatically (owner rebuilds it,
	// node fetches it from the anchor DWN).
	ProtocolDefinition json.RawMessage

	// AudienceEpochSource resolves role-audience epochs for roleAudience
	// keyEncryption entries. Nil uses a DWN-backed source on the anchor DWN.
	AudienceEpochSource dwncrypto.AudienceEpochSource
}

// WriteACLPolicyParams configures an ACL policy write.
type WriteACLPolicyParams struct {
	AnchorEndpoint       string
	AnchorDID            string
	NetworkRecordID      string
	Signer               *dwn.Signer
	EncryptionKeyManager *dwncrypto.EncryptionKeyManager
	PermissionGrantID    string

	// PolicyData is the JSON-encoded ACL policy payload.
	PolicyData []byte

	// ProtocolDefinition is the installed mesh protocol definition (with injected
	// $keyAgreement keys). Empty resolves it automatically (owner rebuilds it,
	// node fetches it from the anchor DWN).
	ProtocolDefinition json.RawMessage

	// AudienceEpochSource resolves role-audience epochs for roleAudience
	// keyEncryption entries. Nil uses a DWN-backed source on the anchor DWN.
	AudienceEpochSource dwncrypto.AudienceEpochSource
}

// WriteACLPolicy writes a squashed ACL policy snapshot (encrypted) on the anchor
// DWN. Only the network author (anchor) can create/update the ACL policy.
func WriteACLPolicy(ctx context.Context, params WriteACLPolicyParams) error {
	if params.EncryptionKeyManager == nil {
		return fmt.Errorf("EncryptionKeyManager is required for encrypted writes")
	}

	// Encrypt to the owner's published key + each reading role's audience key.
	recipients, err := buildEncryptionRecipients(ctx, writeEncryptionParams{
		anchorEndpoint:  params.AnchorEndpoint,
		anchorDID:       params.AnchorDID,
		signer:          params.Signer,
		encMgr:          params.EncryptionKeyManager,
		protocolPath:    "network/aclPolicy",
		parentContextID: params.NetworkRecordID,
		protocolDef:     params.ProtocolDefinition,
		epochSource:     params.AudienceEpochSource,
	})
	if err != nil {
		return fmt.Errorf("deriving ACL policy encryption: %w", err)
	}

	agent := dwn.NewSimpleAgent(params.AnchorEndpoint, params.Signer)
	api := dwn.NewDwnAPI(agent)

	_, status, err := api.Write(ctx, params.AnchorDID, dwn.WriteParams{
		Protocol:             protocols.MeshProtocolURI,
		ProtocolPath:         "network/aclPolicy",
		Schema:               schemaACLPolicy,
		DataFormat:           "application/json",
		ParentContextID:      params.NetworkRecordID,
		Data:                 params.PolicyData,
		EncryptionRecipients: recipients,
		Squash:               true,
		PermissionGrantID:    params.PermissionGrantID,
	})
	if err != nil {
		return fmt.Errorf("writing ACL policy: %w", err)
	}
	if status.Code >= 300 {
		return fmt.Errorf("ACL policy write failed: %d %s", status.Code, status.Detail)
	}

	return nil
}

// DiscoverLocalEndpoints discovers local network endpoints for this node.
// It enumerates non-loopback network interfaces and returns ip:port strings
// for all unicast addresses on those interfaces.
//
// Public endpoint discovery (STUN) is handled by meshnet's magicsock layer
// when the real engine is running. This function only discovers LAN-reachable
// endpoints for the initial DWN record, enabling direct connections between
// peers on the same local network.
func DiscoverLocalEndpoints(listenPort uint16) []string {
	if listenPort == 0 {
		listenPort = 41641 // Default WireGuard port.
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}

	var endpoints []string
	for _, iface := range ifaces {
		// Skip loopback, down, and point-to-point interfaces.
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if iface.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipNet.IP

			// Skip loopback and link-local addresses.
			if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
				continue
			}

			// Parse as netip.Addr for consistent formatting.
			parsed, ok := netip.AddrFromSlice(ip)
			if !ok {
				continue
			}
			parsed = parsed.Unmap() // normalize IPv4-in-IPv6

			ap := netip.AddrPortFrom(parsed, listenPort)
			endpoints = append(endpoints, ap.String())
		}
	}

	return endpoints
}
