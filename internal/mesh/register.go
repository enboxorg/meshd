package mesh

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"time"

	"github.com/enboxorg/meshd/internal/dwn"
	dwncrypto "github.com/enboxorg/meshd/internal/dwn/crypto"
)

const (
	protocolMesh = "https://enbox.org/protocols/wireguard-mesh"

	schemaNode      = "https://enbox.org/schemas/wireguard-mesh/node"
	schemaEndpoint  = "https://enbox.org/schemas/wireguard-mesh/endpoint"
	schemaACLPolicy = "https://enbox.org/schemas/wireguard-mesh/acl-policy"
)

// NodeRegistration holds the result of registering a node on DWN.
type NodeRegistration struct {
	NodeRecordID string
	MeshIP       string

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

	// SelfDID is this node's DID URI (did:jwk).
	SelfDID string

	// Signer signs DWN messages.
	Signer *dwn.Signer

	// EncryptionKeyManager derives encryption keys for protocol paths.
	EncryptionKeyManager *dwncrypto.EncryptionKeyManager

	// DiscoKey is this node's disco public key (base64). The disco key
	// enables DERP relay and direct connection upgrades between peers.
	// Optional: if empty, the disco key is omitted from the node record.
	DiscoKey string

	// MeshIP is this node's allocated mesh IP.
	MeshIP string

	// Hostname is the machine hostname. Auto-detected if empty.
	Hostname string

	// Label is a human-readable label for this node.
	Label string

	// ExistingNodeRecordID is set when updating an existing node record.
	// Leave empty for initial registration.
	ExistingNodeRecordID string

	// ExistingDateCreated is the dateCreated timestamp from the initial write.
	// Required when ExistingNodeRecordID is set (updates), because
	// dateCreated is immutable across record updates.
	ExistingDateCreated string

	// ProtocolRole is the role to invoke for authorization (e.g., "network/node").
	// Required when writing to another party's DWN as a non-owner.
	ProtocolRole string

	// UseContextEncryption enables Protocol Context encryption instead of
	// Protocol Path encryption. Non-anchor nodes MUST set this to true so
	// the anchor can decrypt their records using the shared context key.
	// When true, the EncryptionKeyManager must have the context key stored
	// (via StoreContextKey) for the NetworkRecordID.
	UseContextEncryption bool

	// Squash indicates this is a squash (snapshot) write. When true,
	// the server atomically creates this new record and deletes all
	// older sibling node records at the same protocol path within
	// the same parent context. Use this when re-registering to replace
	// a previous node record.
	Squash bool
}

// RegisterNode writes or updates the node record (encrypted) on the anchor DWN.
//
// The node record is a merged record containing the node's mesh IP, hostname,
// OS, and capabilities. The WireGuard public key is NOT stored — peers derive
// it from the node's did:jwk identity. The recipient field is set to the node's
// DID, which assigns the network/node role for authorization.
func RegisterNode(ctx context.Context, params RegisterNodeParams) (*NodeRegistration, error) {
	if params.EncryptionKeyManager == nil {
		return nil, fmt.Errorf("EncryptionKeyManager is required for encrypted writes")
	}

	hostname := params.Hostname
	if hostname == "" {
		hostname, _ = os.Hostname()
	}

	nodeData := map[string]any{
		"meshIP":   params.MeshIP,
		"hostname": hostname,
		"os":       runtime.GOOS,
		"addedAt":  time.Now().UTC().Format(time.RFC3339),
	}
	if params.Label != "" {
		nodeData["label"] = params.Label
	}
	nodeDataBytes, err := json.Marshal(nodeData)
	if err != nil {
		return nil, fmt.Errorf("marshaling node data: %w", err)
	}

	// Derive encryption recipients.
	// Non-anchor nodes use Protocol Context scheme (shared context key) so the
	// anchor can decrypt. The anchor uses Protocol Path scheme (derived from
	// its own root key).
	var recipients []dwncrypto.KeyEncryptionInput
	if params.UseContextEncryption {
		recipients, err = params.EncryptionKeyManager.DeriveContextWriteEncryption(params.NetworkRecordID)
		if err != nil {
			return nil, fmt.Errorf("deriving node context encryption: %w", err)
		}
	} else {
		recipients, err = params.EncryptionKeyManager.DeriveWriteEncryption("network/node")
		if err != nil {
			return nil, fmt.Errorf("deriving node encryption: %w", err)
		}
	}

	agent := dwn.NewSimpleAgent(params.AnchorEndpoint, params.Signer)
	api := dwn.NewDwnAPI(agent)

	writeParams := dwn.WriteParams{
		Protocol:             protocolMesh,
		ProtocolPath:         "network/node",
		Schema:               schemaNode,
		DataFormat:           "application/json",
		Recipient:            params.SelfDID,
		ParentContextID:     params.NetworkRecordID,
		Data:                 nodeDataBytes,
		ProtocolRole:         params.ProtocolRole,
		EncryptionRecipients: recipients,
		Squash:               params.Squash,
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

	// Extract dateCreated from the record — callers need this for future updates.
	dateCreated := ""
	if record.DateCreated != "" {
		dateCreated = record.DateCreated
	}

	return &NodeRegistration{
		NodeRecordID: record.ID,
		MeshIP:       params.MeshIP,
		DateCreated:  dateCreated,
	}, nil
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

	// Derive encryption recipients.
	var recipients []dwncrypto.KeyEncryptionInput
	if params.UseContextEncryption {
		recipients, err = params.EncryptionKeyManager.DeriveContextWriteEncryption(params.NetworkRecordID)
		if err != nil {
			return fmt.Errorf("deriving endpoint context encryption: %w", err)
		}
	} else {
		recipients, err = params.EncryptionKeyManager.DeriveWriteEncryption("network/node/endpoint")
		if err != nil {
			return fmt.Errorf("deriving endpoint encryption: %w", err)
		}
	}

	agent := dwn.NewSimpleAgent(params.AnchorEndpoint, params.Signer)
	api := dwn.NewDwnAPI(agent)

	// The endpoint's parent is the node record, whose contextId is networkRecordID/nodeRecordID.
	nodeContextID := params.NetworkRecordID + "/" + params.NodeRecordID
	_, status, err := api.Write(ctx, params.AnchorDID, dwn.WriteParams{
		Protocol:             protocolMesh,
		ProtocolPath:         "network/node/endpoint",
		Schema:               schemaEndpoint,
		DataFormat:           "application/json",
		Recipient:            params.AnchorDID,
		ParentContextID:     nodeContextID,
		Data:                 endpointData,
		ProtocolRole:         params.ProtocolRole,
		EncryptionRecipients: recipients,
		Squash:               params.Squash,
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
	NodeRecordID         string
	Signer               *dwn.Signer
	EncryptionKeyManager *dwncrypto.EncryptionKeyManager
	PublicEndpoints      []PublicEndpoint
	LocalEndpoints       []string
	NATType              string
	ProtocolRole         string

	// DiscoKey is this node's current disco public key (base64).
	// Included in the endpoint record so peers can discover the disco key
	// alongside the network endpoints for DERP relay and hole punching.
	DiscoKey string

	// UseContextEncryption enables Protocol Context encryption instead of
	// Protocol Path encryption. See RegisterNodeParams.UseContextEncryption.
	UseContextEncryption bool

	// Squash indicates this is a squash (snapshot) write. See
	// RegisterNodeParams.Squash.
	Squash bool
}

// PublicEndpoint describes a publicly reachable endpoint.
type PublicEndpoint struct {
	Address  string `json:"address"`
	Port     int    `json:"port"`
	Priority int    `json:"priority,omitempty"`
	Source   string `json:"source,omitempty"`
}

// WriteACLPolicyParams configures an ACL policy write.
type WriteACLPolicyParams struct {
	AnchorEndpoint       string
	AnchorDID            string
	NetworkRecordID      string
	Signer               *dwn.Signer
	EncryptionKeyManager *dwncrypto.EncryptionKeyManager

	// PolicyData is the JSON-encoded ACL policy payload.
	PolicyData []byte
}

// WriteACLPolicy writes or updates the ACL policy record (encrypted) on the
// anchor DWN. Only the network author (anchor) can create/update the ACL policy.
// The protocol enforces $recordLimit: max 1 — newer writes replace older ones.
func WriteACLPolicy(ctx context.Context, params WriteACLPolicyParams) error {
	if params.EncryptionKeyManager == nil {
		return fmt.Errorf("EncryptionKeyManager is required for encrypted writes")
	}

	// The anchor always uses Protocol Path encryption for records it owns.
	recipients, err := params.EncryptionKeyManager.DeriveWriteEncryption("network/aclPolicy")
	if err != nil {
		return fmt.Errorf("deriving ACL policy encryption: %w", err)
	}

	agent := dwn.NewSimpleAgent(params.AnchorEndpoint, params.Signer)
	api := dwn.NewDwnAPI(agent)

	_, status, err := api.Write(ctx, params.AnchorDID, dwn.WriteParams{
		Protocol:             protocolMesh,
		ProtocolPath:         "network/aclPolicy",
		Schema:               schemaACLPolicy,
		DataFormat:           "application/json",
		ParentContextID:      params.NetworkRecordID,
		Data:                 params.PolicyData,
		EncryptionRecipients: recipients,
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
