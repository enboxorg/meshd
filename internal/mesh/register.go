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

	schemaNodeInfo = "https://enbox.org/schemas/wireguard-mesh/node-info"
	schemaEndpoint = "https://enbox.org/schemas/wireguard-mesh/endpoint"
	schemaMember   = "https://enbox.org/schemas/wireguard-mesh/member"
)

// NodeRegistration holds the result of registering a node on DWN.
type NodeRegistration struct {
	NodeInfoRecordID string
	MeshIP           string
	WireGuardPubKey  string

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

	// SelfDID is this node's DID URI.
	SelfDID string

	// Signer signs DWN messages.
	Signer *dwn.Signer

	// EncryptionKeyManager derives encryption keys for protocol paths.
	EncryptionKeyManager *dwncrypto.EncryptionKeyManager

	// WireGuardPubKey is this node's WireGuard public key (base64).
	WireGuardPubKey string

	// MeshIP is this node's allocated mesh IP.
	MeshIP string

	// Hostname is the machine hostname. Auto-detected if empty.
	Hostname string

	// ExistingNodeInfoRecordID is set when updating an existing nodeInfo.
	// Leave empty for initial registration.
	ExistingNodeInfoRecordID string

	// ExistingDateCreated is the dateCreated timestamp from the initial write.
	// Required when ExistingNodeInfoRecordID is set (updates), because
	// dateCreated is immutable across record updates.
	ExistingDateCreated string

	// ProtocolRole is the role to invoke for authorization (e.g., "network/member").
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
	// older sibling nodeInfo records at the same protocol path within
	// the same parent context. Use this when re-registering to replace
	// a previous nodeInfo record. Requires $squash: true on the
	// nodeInfo protocol rule set.
	Squash bool
}

// RegisterNode writes or updates the node's nodeInfo record (encrypted) on
// the anchor DWN.
//
// It creates a nodeInfo record under the network context with the node's
// WireGuard public key, mesh IP, hostname, and OS. The record is encrypted
// using the protocol path derivation scheme at "network/nodeInfo".
func RegisterNode(ctx context.Context, params RegisterNodeParams) (*NodeRegistration, error) {
	if params.EncryptionKeyManager == nil {
		return nil, fmt.Errorf("EncryptionKeyManager is required for encrypted writes")
	}

	hostname := params.Hostname
	if hostname == "" {
		hostname, _ = os.Hostname()
	}

	nodeInfoData, err := json.Marshal(map[string]any{
		"wireguardPublicKey": params.WireGuardPubKey,
		"meshIP":             params.MeshIP,
		"hostname":           hostname,
		"os":                 runtime.GOOS,
	})
	if err != nil {
		return nil, fmt.Errorf("marshaling nodeInfo: %w", err)
	}

	// Derive encryption recipients.
	// Non-anchor nodes use Protocol Context scheme (shared context key) so the
	// anchor can decrypt. The anchor uses Protocol Path scheme (derived from
	// its own root key).
	var recipients []dwncrypto.KeyEncryptionInput
	if params.UseContextEncryption {
		recipients, err = params.EncryptionKeyManager.DeriveContextWriteEncryption(params.NetworkRecordID)
		if err != nil {
			return nil, fmt.Errorf("deriving nodeInfo context encryption: %w", err)
		}
	} else {
		recipients, err = params.EncryptionKeyManager.DeriveWriteEncryption("network/nodeInfo")
		if err != nil {
			return nil, fmt.Errorf("deriving nodeInfo encryption: %w", err)
		}
	}

	agent := dwn.NewSimpleAgent(params.AnchorEndpoint, params.Signer)
	api := dwn.NewDwnAPI(agent)

	writeParams := dwn.WriteParams{
		Protocol:             protocolMesh,
		ProtocolPath:         "network/nodeInfo",
		Schema:               schemaNodeInfo,
		DataFormat:           "application/json",
		Recipient:            params.AnchorDID,
		ParentContextID:     params.NetworkRecordID,
		Data:                 nodeInfoData,
		Tags: map[string]any{
			"did":      params.SelfDID,
			"hostname": hostname,
			"os":       runtime.GOOS,
		},
		ProtocolRole:         params.ProtocolRole,
		EncryptionRecipients: recipients,
		Squash:               params.Squash,
	}

	// If updating, set the existing record ID and preserve dateCreated.
	if params.ExistingNodeInfoRecordID != "" {
		writeParams.RecordID = params.ExistingNodeInfoRecordID
		writeParams.DateCreated = params.ExistingDateCreated
	}

	record, status, err := api.Write(ctx, params.AnchorDID, writeParams)
	if err != nil {
		return nil, fmt.Errorf("writing nodeInfo: %w", err)
	}
	if status.Code >= 300 {
		return nil, fmt.Errorf("nodeInfo write failed: %d %s", status.Code, status.Detail)
	}

	// Extract dateCreated from the record — callers need this for future updates.
	dateCreated := ""
	if record.DateCreated != "" {
		dateCreated = record.DateCreated
	}

	return &NodeRegistration{
		NodeInfoRecordID: record.ID,
		MeshIP:           params.MeshIP,
		WireGuardPubKey:  params.WireGuardPubKey,
		DateCreated:      dateCreated,
	}, nil
}

// WriteEndpoint writes or updates the node's endpoint record (encrypted).
//
// The endpoint record is a child of the nodeInfo record and contains the
// node's network-reachable endpoints (public IPs, local IPs, NAT type).
func WriteEndpoint(ctx context.Context, params WriteEndpointParams) error {
	if params.EncryptionKeyManager == nil {
		return fmt.Errorf("EncryptionKeyManager is required for encrypted writes")
	}

	endpointData, err := json.Marshal(map[string]any{
		"publicEndpoints": params.PublicEndpoints,
		"localEndpoints":  params.LocalEndpoints,
		"natType":         params.NATType,
		"updatedAt":       time.Now().UTC().Format(time.RFC3339),
	})
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
		recipients, err = params.EncryptionKeyManager.DeriveWriteEncryption("network/nodeInfo/endpoint")
		if err != nil {
			return fmt.Errorf("deriving endpoint encryption: %w", err)
		}
	}

	agent := dwn.NewSimpleAgent(params.AnchorEndpoint, params.Signer)
	api := dwn.NewDwnAPI(agent)

	// The endpoint's parent is nodeInfo, whose contextId is networkRecordID/nodeInfoRecordID.
	nodeInfoContextID := params.NetworkRecordID + "/" + params.NodeInfoRecordID
	_, status, err := api.Write(ctx, params.AnchorDID, dwn.WriteParams{
		Protocol:             protocolMesh,
		ProtocolPath:         "network/nodeInfo/endpoint",
		Schema:               schemaEndpoint,
		DataFormat:           "application/json",
		Recipient:            params.AnchorDID,
		ParentContextID:     nodeInfoContextID,
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
	NodeInfoRecordID     string
	Signer               *dwn.Signer
	EncryptionKeyManager *dwncrypto.EncryptionKeyManager
	PublicEndpoints      []PublicEndpoint
	LocalEndpoints       []string
	NATType              string
	ProtocolRole         string

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

// CreateMember creates an encrypted member record on the anchor DWN.
func CreateMember(ctx context.Context, params CreateMemberParams) error {
	if params.EncryptionKeyManager == nil {
		return fmt.Errorf("EncryptionKeyManager is required for encrypted writes")
	}

	memberData, err := json.Marshal(map[string]any{
		"joinedAt": time.Now().UTC().Format(time.RFC3339),
		"label":    params.Label,
	})
	if err != nil {
		return fmt.Errorf("marshaling member: %w", err)
	}

	var recipients []dwncrypto.KeyEncryptionInput
	if params.UseContextEncryption {
		recipients, err = params.EncryptionKeyManager.DeriveContextWriteEncryption(params.NetworkRecordID)
		if err != nil {
			return fmt.Errorf("deriving member context encryption: %w", err)
		}
	} else {
		recipients, err = params.EncryptionKeyManager.DeriveWriteEncryption("network/member")
		if err != nil {
			return fmt.Errorf("deriving member encryption: %w", err)
		}
	}

	agent := dwn.NewSimpleAgent(params.AnchorEndpoint, params.Signer)
	api := dwn.NewDwnAPI(agent)

	_, status, err := api.Write(ctx, params.AnchorDID, dwn.WriteParams{
		Protocol:             protocolMesh,
		ProtocolPath:         "network/member",
		Schema:               schemaMember,
		DataFormat:           "application/json",
		Recipient:            params.MemberDID,
		ParentContextID:     params.NetworkRecordID,
		Data:                 memberData,
		Tags:                 map[string]any{"status": "active"},
		EncryptionRecipients: recipients,
	})
	if err != nil {
		return fmt.Errorf("writing member: %w", err)
	}
	if status.Code >= 300 {
		return fmt.Errorf("member write failed: %d %s", status.Code, status.Detail)
	}

	return nil
}

// CreateMemberParams configures a member record creation.
type CreateMemberParams struct {
	AnchorEndpoint       string
	AnchorDID            string
	NetworkRecordID      string
	MemberDID            string
	Label                string
	Signer               *dwn.Signer
	EncryptionKeyManager *dwncrypto.EncryptionKeyManager

	// UseContextEncryption enables Protocol Context encryption instead of
	// Protocol Path encryption. See RegisterNodeParams.UseContextEncryption.
	UseContextEncryption bool
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
