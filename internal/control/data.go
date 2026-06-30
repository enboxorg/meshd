package control

// NetworkConfig is the parsed network record data.
type NetworkConfig struct {
	Name           string   `json:"name"`
	MeshCIDR       string   `json:"meshCIDR"`
	DNSServers     []string `json:"dnsServers,omitempty"`
	MagicDNSSuffix string   `json:"magicDNSSuffix,omitempty"`
}

// MemberRecord is the parsed member record data.
// A member represents a person/entity that has been invited to the network.
// Their DID comes from the recipient descriptor field.
type MemberRecord struct {
	DID      string `json:"-"` // did:jwk from the recipient descriptor field
	Label    string `json:"label,omitempty"`
	AddedAt  string `json:"addedAt"`
	RecordID string `json:"-"`
}

// NodeRecord is the parsed node record data (owner-controlled membership fields).
// The WireGuard public key is NOT stored here — it is derived from
// the DID (did:jwk → X25519 birational map) at conversion time.
type NodeRecord struct {
	DID         string   `json:"-"` // did:jwk from the recipient descriptor field
	MeshIP      string   `json:"meshIP"`
	AllowedIPs  []string `json:"allowedIPs,omitempty"`
	AddedAt     string   `json:"addedAt"`
	ExpiresAt   string   `json:"expiresAt,omitempty"`
	Label       string   `json:"label,omitempty"`
	MemberDID   string   `json:"memberDID,omitempty"`
	OwnerDID    string   `json:"ownerDID,omitempty"`
	DelegateDID string   `json:"delegateDID,omitempty"`
	SourceDWN   string   `json:"sourceDWN,omitempty"` // for cross-DWN member devices

	// Fields populated from child records (not from this record's data).
	Info      *NodeInfoData  `json:"-"`
	Endpoints []EndpointData `json:"-"`
	RecordID  string         `json:"-"`

	// MemberRecordID is the parent member record ID, if this node is
	// under a member (network/member/node path). Empty for owner-provisioned
	// top-level nodes (network/node path).
	MemberRecordID string `json:"-"`
}

// NormalizeOwnerDID keeps the newer ownerDID field and the older memberDID
// field interchangeable while records transition.
func (n *NodeRecord) NormalizeOwnerDID() {
	if n == nil {
		return
	}
	if n.OwnerDID == "" {
		n.OwnerDID = n.MemberDID
	}
	if n.MemberDID == "" {
		n.MemberDID = n.OwnerDID
	}
}

func (n *NodeRecord) EffectiveOwnerDID() string {
	if n == nil {
		return ""
	}
	if n.OwnerDID != "" {
		return n.OwnerDID
	}
	return n.MemberDID
}

// NodeInfoData is the parsed nodeInfo record data (device-controlled).
// This contains operational information that the device itself manages.
type NodeInfoData struct {
	Hostname     string   `json:"hostname,omitempty"`
	OS           string   `json:"os,omitempty"`
	Capabilities []string `json:"capabilities,omitempty"`
}

// EndpointData is the parsed endpoint record data.
type EndpointData struct {
	PublicEndpoints []PublicEndpoint `json:"publicEndpoints,omitempty"`
	LocalEndpoints  []string         `json:"localEndpoints,omitempty"`
	PreferredDERP   int              `json:"preferredDERP,omitempty"`
	DiscoKey        string           `json:"discoKey,omitempty"`
	NATType         string           `json:"natType,omitempty"`
	UpdatedAt       string           `json:"updatedAt"`
}

// PublicEndpoint is a discovered public ip:port.
type PublicEndpoint struct {
	Address  string `json:"address"`
	Port     int    `json:"port"`
	Priority int    `json:"priority,omitempty"`
	Source   string `json:"source,omitempty"`
}

// RelayData is the parsed relay record data.
type RelayData struct {
	URL      string `json:"url"`
	Region   string `json:"region"`
	STUNPort int    `json:"stunPort,omitempty"`
}

// ACLPolicyData is the parsed ACL policy record data.
type ACLPolicyData struct {
	Version       int                 `json:"version"`
	DefaultAction string              `json:"defaultAction,omitempty"`
	Groups        map[string][]string `json:"groups,omitempty"`
	Rules         []ACLRule           `json:"rules"`
}

// ACLRule is a single ACL rule.
type ACLRule struct {
	Action   string   `json:"action"`
	Src      []string `json:"src"`
	Dst      []string `json:"dst"`
	Proto    string   `json:"proto,omitempty"`
	SrcPorts []string `json:"srcPorts,omitempty"`
	DstPorts []string `json:"dstPorts,omitempty"`
}
