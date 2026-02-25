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

// MemberInfo is the parsed member record data with metadata.
type MemberInfo struct {
	DID      string `json:"-"`
	JoinedAt string `json:"joinedAt"`
	Label    string `json:"label,omitempty"`
	Status   string `json:"-"`
	RecordID string `json:"-"`
}

// NodeInfoData is the parsed nodeInfo record data.
type NodeInfoData struct {
	DID                string         `json:"-"`
	WireGuardPublicKey string         `json:"wireguardPublicKey"`
	MeshIP             string         `json:"meshIP"`
	Hostname           string         `json:"hostname,omitempty"`
	OS                 string         `json:"os,omitempty"`
	DiscoKey           string         `json:"discoKey,omitempty"`
	Capabilities       []string       `json:"capabilities,omitempty"`
	AllowedIPs         []string       `json:"allowedIPs,omitempty"`
	Endpoints          []EndpointData `json:"-"`
	RecordID           string         `json:"-"`
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
