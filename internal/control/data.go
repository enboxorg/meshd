package control

// NetworkConfig is the parsed network record data.
type NetworkConfig struct {
	Name           string   `json:"name"`
	MeshCIDR       string   `json:"meshCIDR"`
	DefaultRelays  []string `json:"defaultRelays,omitempty"`
	DNSServers     []string `json:"dnsServers,omitempty"`
	MagicDNSSuffix string   `json:"magicDNSSuffix,omitempty"`
	ListenPort     int      `json:"listenPort,omitempty"`
}

// NodeRecord is the parsed node record data (merged member + nodeInfo).
// The WireGuard public key is NOT stored here — it is derived from
// the DID (did:jwk → X25519 birational map) at conversion time.
type NodeRecord struct {
	DID          string         `json:"-"`                     // did:jwk from the recipient descriptor field
	MeshIP       string         `json:"meshIP"`
	Hostname     string         `json:"hostname,omitempty"`
	OS           string         `json:"os,omitempty"`
	Capabilities []string       `json:"capabilities,omitempty"`
	AllowedIPs   []string       `json:"allowedIPs,omitempty"`
	AddedAt      string         `json:"addedAt"`
	Label        string         `json:"label,omitempty"`
	Endpoints    []EndpointData `json:"-"`
	RecordID     string         `json:"-"`
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
	RecordID string `json:"-"`
}

// ACLPolicyData is the parsed ACL policy record data.
type ACLPolicyData struct {
	Rules []ACLRule `json:"rules"`
}

// ACLRule is a single ACL rule.
type ACLRule struct {
	Action string   `json:"action"`
	Src    []string `json:"src"`
	Dst    []string `json:"dst"`
	Proto  string   `json:"proto,omitempty"`
	Ports  string   `json:"ports,omitempty"`
}
