package mesh

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/enboxorg/meshd/internal/control"
	"github.com/enboxorg/meshd/internal/dwn"
	dwncrypto "github.com/enboxorg/meshd/internal/dwn/crypto"
	"github.com/enboxorg/meshd/protocols"
)

// DelegateSessionParams describes an enbox-connect wallet session acting on
// the owner's DWN tenant: the delegate signs every message and invokes the
// owner-issued delegated grants.
type DelegateSessionParams struct {
	// Endpoint is the owner's DWN endpoint.
	Endpoint string
	// OwnerDID is the wallet owner (grantor, DWN tenant).
	OwnerDID string
	// DelegateSigner signs DWN messages as the delegate (grantee).
	DelegateSigner *dwn.Signer
	// DelegateX25519Priv is the delegate's root X25519 private key (the
	// conversion of its Ed25519 key), used to unwrap grant-key envelopes.
	DelegateX25519Priv []byte
	// Grants are the raw delegated grant messages from the connect session.
	Grants []json.RawMessage
	// Logger defaults to slog.Default().
	Logger *slog.Logger
}

// DelegateSession is an initialized wallet-delegate control-plane session:
// resolved grants, delivered grant keys, the installed protocol definition,
// and a sealed audience source rooted in the delegate's seal coverage.
type DelegateSession struct {
	Endpoint           string
	OwnerDID           string
	DelegateDID        string
	Signer             *dwn.Signer
	ProtocolDefinition json.RawMessage
	GrantKeys          *control.GrantKeySet
	AudienceSource     *control.SealedAudienceSource

	// ReadGrant/WriteGrant/DeleteGrant are the session's delegated grants
	// for mesh-protocol Records operations (nil when not granted).
	ReadGrant   json.RawMessage
	WriteGrant  json.RawMessage
	DeleteGrant json.RawMessage

	logger *slog.Logger
}

// NewDelegateSession resolves the session's delegated grants, fetches the
// installed mesh protocol definition from the owner tenant, unwraps the
// delivered grant keys, and builds the sealed audience source.
func NewDelegateSession(ctx context.Context, params DelegateSessionParams) (*DelegateSession, error) {
	if params.DelegateSigner == nil {
		return nil, fmt.Errorf("delegate signer is required")
	}
	logger := params.Logger
	if logger == nil {
		logger = slog.Default()
	}
	now := time.Now().UTC()

	s := &DelegateSession{
		Endpoint:    params.Endpoint,
		OwnerDID:    params.OwnerDID,
		DelegateDID: params.DelegateSigner.DID,
		Signer:      params.DelegateSigner,
		logger:      logger,
	}

	for _, op := range []struct {
		messageType dwn.DwnInterface
		dst         *json.RawMessage
	}{
		{dwn.InterfaceRecordsRead, &s.ReadGrant},
		{dwn.InterfaceRecordsWrite, &s.WriteGrant},
		{dwn.InterfaceRecordsDelete, &s.DeleteGrant},
	} {
		grant, _, err := dwn.FindDelegatedGrant(params.Grants, dwn.PermissionGrantMatch{
			Grantor:     params.OwnerDID,
			Grantee:     params.DelegateSigner.DID,
			MessageType: op.messageType,
			Protocol:    protocols.MeshProtocolURI,
			Now:         now,
		})
		if err != nil {
			return nil, fmt.Errorf("resolving %s grant: %w", op.messageType, err)
		}
		*op.dst = grant
	}
	if len(s.ReadGrant) == 0 || len(s.WriteGrant) == 0 {
		return nil, fmt.Errorf("wallet session is missing delegated read/write grants for %s", protocols.MeshProtocolURI)
	}

	client := dwn.NewClient(params.Endpoint, params.DelegateSigner)

	def, err := FetchInstalledProtocolDefinition(ctx, client, params.OwnerDID, protocols.MeshProtocolURI)
	if err != nil {
		return nil, fmt.Errorf("fetching installed mesh protocol from owner tenant: %w", err)
	}
	s.ProtocolDefinition = def

	grantKeys, err := control.FetchGrantKeys(ctx, client, params.OwnerDID, params.DelegateSigner.DID, protocols.MeshProtocolURI, params.DelegateX25519Priv, logger)
	if err != nil {
		return nil, fmt.Errorf("fetching grant keys: %w", err)
	}
	if grantKeys.Empty() {
		return nil, fmt.Errorf("no grant keys delivered to delegate %s — the wallet must issue wrapped grant keys for encrypted protocols", params.DelegateSigner.DID)
	}
	s.GrantKeys = grantKeys

	s.AudienceSource = control.NewSealedAudienceSource(control.SealedAudienceSourceConfig{
		Client:             client,
		Tenant:             params.OwnerDID,
		ProtocolDefinition: def,
		QueryAuth:          dwn.MessageAuth{DelegatedGrant: s.ReadGrant},
		WriteAuth:          dwn.MessageAuth{DelegatedGrant: s.WriteGrant},
		SealKeys:           grantKeys,
		Logger:             logger,
	})

	return s, nil
}

// ReadAuth returns the message auth for delegated read/query operations.
func (s *DelegateSession) ReadAuth() dwn.MessageAuth {
	return dwn.MessageAuth{DelegatedGrant: s.ReadGrant}
}

// WriteAuth returns the message auth for delegated write operations.
func (s *DelegateSession) WriteAuth() dwn.MessageAuth {
	return dwn.MessageAuth{DelegatedGrant: s.WriteGrant}
}

// DelegateNetworkResult describes the network a delegate session created or
// joined, mirroring the fields persisted in the local network state.
type DelegateNetworkResult struct {
	NetworkRecordID string
	NetworkName     string
	MeshCIDR        string
	MeshIP          string
	NodeRecordID    string
	NodeDateCreated string
}

// CreateNetworkParams configures delegate-direct network creation.
type CreateNetworkParams struct {
	Session     *DelegateSession
	NetworkName string
	MeshCIDR    string
	// NodeDID is this device's mesh identity, registered as the first node.
	NodeDID  string
	Label    string
	Hostname string
}

// CreateNetworkAsDelegate creates a wallet-owned mesh network directly from
// the CLI: the delegate writes the network record on the owner's tenant,
// eagerly provisions the sealed role-audience keys for the network's reading
// roles (so encrypted node writes never fail closed), and registers this
// device as the first node.
func CreateNetworkAsDelegate(ctx context.Context, params CreateNetworkParams) (*DelegateNetworkResult, error) {
	s := params.Session
	if s == nil {
		return nil, fmt.Errorf("delegate session is required")
	}
	name := params.NetworkName
	if name == "" {
		return nil, fmt.Errorf("network name is required")
	}
	cidr := params.MeshCIDR
	if cidr == "" {
		cidr = "10.200.0.0/16"
	}

	networkData, err := json.Marshal(map[string]any{
		"name":           name,
		"meshCIDR":       cidr,
		"anchorEndpoint": s.Endpoint,
	})
	if err != nil {
		return nil, fmt.Errorf("marshaling network record: %w", err)
	}

	agent := dwn.NewSimpleAgent(s.Endpoint, s.Signer)
	api := dwn.NewDwnAPI(agent)

	// The network record is public (anyone can read) — no encryption.
	record, status, err := api.Write(ctx, s.OwnerDID, dwn.WriteParams{
		Protocol:       protocols.MeshProtocolURI,
		ProtocolPath:   "network",
		Schema:         "https://enbox.id/schemas/wireguard-mesh/network",
		DataFormat:     "application/json",
		Data:           networkData,
		DelegatedGrant: s.WriteGrant,
	})
	if err != nil {
		return nil, fmt.Errorf("creating network record: %w", err)
	}
	if status.Code >= 300 {
		return nil, fmt.Errorf("network record write failed: %d %s", status.Code, status.Detail)
	}
	networkID := record.ID

	// Eagerly provision sealed audience keys for both reading roles so any
	// writer (including future role-holder nodes) finds them in place.
	for _, rolePath := range []string{"network/member", "network/node"} {
		if _, _, err := s.AudienceSource.Current(ctx, protocols.MeshProtocolURI, rolePath, networkID); err != nil {
			return nil, fmt.Errorf("provisioning %s audience key: %w", rolePath, err)
		}
	}

	result, err := registerDelegateNode(ctx, s, networkID, cidr, params.NodeDID, params.Label, params.Hostname)
	if err != nil {
		return nil, err
	}
	result.NetworkName = name
	return result, nil
}

// JoinNetworkParams configures a delegate-direct network join.
type JoinNetworkParams struct {
	Session *DelegateSession
	// NetworkRecordID selects the network to join. Empty joins the owner's
	// only network (errors when the owner has several).
	NetworkRecordID string
	NodeDID         string
	Label           string
	Hostname        string
}

// JoinNetworkAsDelegate registers this device as a node in an existing
// wallet-owned network. The delegate's write grant authorizes the node
// record directly — no dashboard approval round-trip.
func JoinNetworkAsDelegate(ctx context.Context, params JoinNetworkParams) (*DelegateNetworkResult, error) {
	s := params.Session
	if s == nil {
		return nil, fmt.Errorf("delegate session is required")
	}

	client := dwn.NewClient(s.Endpoint, s.Signer)
	reply, err := client.RecordsQueryWithAuth(ctx, s.OwnerDID, dwn.RecordsFilter{
		Protocol:     protocols.MeshProtocolURI,
		ProtocolPath: "network",
	}, "createdAscending", nil, s.ReadAuth())
	if err != nil {
		return nil, fmt.Errorf("querying networks: %w", err)
	}
	entries, err := dwn.QueryEntries(reply)
	if err != nil {
		return nil, fmt.Errorf("parsing network query: %w", err)
	}

	type networkInfo struct {
		id, name, cidr string
	}
	var networks []networkInfo
	for _, entry := range entries {
		rec, err := dwn.RecordFromEntry(nil, s.OwnerDID, entry)
		if err != nil {
			continue
		}
		var data struct {
			Name     string `json:"name"`
			MeshCIDR string `json:"meshCIDR"`
		}
		if raw, err := rec.Data().Bytes(ctx); err == nil {
			_ = json.Unmarshal(raw, &data)
		}
		networks = append(networks, networkInfo{id: rec.ID, name: data.Name, cidr: data.MeshCIDR})
	}
	if len(networks) == 0 {
		return nil, fmt.Errorf("owner %s has no mesh networks", s.OwnerDID)
	}

	var selected *networkInfo
	if params.NetworkRecordID != "" {
		for i := range networks {
			if networks[i].id == params.NetworkRecordID {
				selected = &networks[i]
				break
			}
		}
		if selected == nil {
			return nil, fmt.Errorf("network %s not found on owner tenant", params.NetworkRecordID)
		}
	} else if len(networks) == 1 {
		selected = &networks[0]
	} else {
		names := make([]string, len(networks))
		for i, n := range networks {
			names[i] = fmt.Sprintf("%s (%s)", n.name, n.id)
		}
		return nil, fmt.Errorf("owner has %d networks — pass --network to choose one of: %v", len(networks), names)
	}
	cidr := selected.cidr
	if cidr == "" {
		cidr = "10.200.0.0/16"
	}

	result, err := registerDelegateNode(ctx, s, selected.id, cidr, params.NodeDID, params.Label, params.Hostname)
	if err != nil {
		return nil, err
	}
	result.NetworkName = selected.name
	return result, nil
}

// registerDelegateNode writes (or refreshes) this device's node record at
// network/node with the delegate's grants, then writes its nodeInfo.
func registerDelegateNode(ctx context.Context, s *DelegateSession, networkID, cidr, nodeDID, label, hostname string) (*DelegateNetworkResult, error) {
	if nodeDID == "" {
		return nil, fmt.Errorf("node DID is required")
	}
	meshAddr, err := AllocateMeshIP(cidr, nodeDID)
	if err != nil {
		return nil, fmt.Errorf("allocating mesh IP: %w", err)
	}
	meshIP := meshAddr.String()

	reg, err := RegisterNode(ctx, RegisterNodeParams{
		AnchorEndpoint:     s.Endpoint,
		AnchorDID:          s.OwnerDID,
		NetworkRecordID:    networkID,
		NodeDID:            nodeDID,
		Signer:             s.Signer,
		MeshIP:             meshIP,
		Label:              label,
		OwnerDID:           s.OwnerDID,
		DelegateDID:        s.DelegateDID,
		DelegatedGrant:     s.WriteGrant,
		ProtocolDefinition: s.ProtocolDefinition,
		AudienceSource:     s.AudienceSource,
	})
	if err != nil {
		return nil, fmt.Errorf("registering node: %w", err)
	}

	if hostname == "" {
		hostname, _ = os.Hostname()
	}
	if err := WriteNodeInfo(ctx, WriteNodeInfoParams{
		AnchorEndpoint:     s.Endpoint,
		AnchorDID:          s.OwnerDID,
		NetworkRecordID:    networkID,
		NodeRecordID:       reg.NodeRecordID,
		Signer:             s.Signer,
		Hostname:           hostname,
		DelegatedGrant:     s.WriteGrant,
		ProtocolDefinition: s.ProtocolDefinition,
		AudienceSource:     s.AudienceSource,
	}); err != nil {
		return nil, fmt.Errorf("writing nodeInfo: %w", err)
	}

	return &DelegateNetworkResult{
		NetworkRecordID: networkID,
		MeshCIDR:        cidr,
		MeshIP:          meshIP,
		NodeRecordID:    reg.NodeRecordID,
		NodeDateCreated: reg.DateCreated,
	}, nil
}

// The audience source needs the crypto interface; keep the import used even
// when RegisterNode threads it as an interface value.
var _ dwncrypto.AudienceSource = (*control.SealedAudienceSource)(nil)
