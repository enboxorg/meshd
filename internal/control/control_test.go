package control

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/netip"
	"testing"
	"time"

	dwncrypto "github.com/enboxorg/meshd/internal/dwn/crypto"
	"github.com/enboxorg/meshd/pkg/dids/didjwk"
)

// testDIDJWK creates a real did:jwk URI for testing.
// Returns the URI and the expected base64-encoded WireGuard public key.
func testDIDJWK(t *testing.T) (string, string) {
	t.Helper()
	id, err := didjwk.Create()
	if err != nil {
		t.Fatalf("creating did:jwk: %v", err)
	}
	wgKey := base64.StdEncoding.EncodeToString(id.X25519PublicKey)
	return id.URI, wgKey
}

func TestBuildStaticMapResponse(t *testing.T) {
	self := &Node{
		ID:     1,
		Name:   "laptop",
		DID:    "did:jwk:test-self",
		Key:    "AAAA==",
		MeshIP: netip.MustParseAddr("10.200.0.2"),
		AllowedIPs: []netip.Prefix{
			netip.MustParsePrefix("10.200.0.2/32"),
		},
		Endpoints: []string{"1.2.3.4:41641"},
		OS:        "linux",
	}

	peer := &Node{
		ID:     2,
		Name:   "server",
		DID:    "did:jwk:test-peer",
		Key:    "BBBB==",
		MeshIP: netip.MustParseAddr("10.200.0.3"),
		AllowedIPs: []netip.Prefix{
			netip.MustParsePrefix("10.200.0.3/32"),
		},
		Endpoints:     []string{"5.6.7.8:41641"},
		PreferredDERP: 1,
		OS:            "linux",
	}

	resp := BuildStaticMapResponse(self, []*Node{peer}, nil)

	t.Run("self node", func(t *testing.T) {
		if resp.Node == nil {
			t.Fatal("missing self node")
		}
		if resp.Node.Name != "laptop" {
			t.Errorf("name = %q", resp.Node.Name)
		}
	})

	t.Run("peers", func(t *testing.T) {
		if len(resp.Peers) != 1 {
			t.Fatalf("want 1 peer, got %d", len(resp.Peers))
		}
		if resp.Peers[0].Name != "server" {
			t.Errorf("peer name = %q", resp.Peers[0].Name)
		}
	})

	t.Run("DERP map present", func(t *testing.T) {
		if resp.DERPMap == nil {
			t.Fatal("missing DERP map")
		}
	})

	t.Run("default allow-all filter", func(t *testing.T) {
		if len(resp.PacketFilter) != 1 {
			t.Fatalf("want 1 filter rule, got %d", len(resp.PacketFilter))
		}
		if resp.PacketFilter[0].SrcIPs[0] != "*" {
			t.Error("default filter should allow all")
		}
	})

	t.Run("DNS config", func(t *testing.T) {
		if resp.DNSConfig == nil {
			t.Fatal("missing DNS config")
		}
		if resp.DNSConfig.MagicDNSSuffix != "mesh.local" {
			t.Errorf("magic DNS suffix = %q", resp.DNSConfig.MagicDNSSuffix)
		}
	})
}

func TestNodeRecordToNode(t *testing.T) {
	now := time.Now().UTC()
	recentUpdate := now.Add(-2 * time.Minute).Format(time.RFC3339)

	didURI, wantKey := testDIDJWK(t)

	rec := &NodeRecord{
		MeshIP:     "10.200.0.5",
		AllowedIPs: []string{"192.168.1.0/24"},
		AddedAt:    "2026-01-01T00:00:00Z",
		Info: &NodeInfoData{
			Hostname:     "myhost",
			OS:           "linux",
			Capabilities: []string{"relay"},
		},
		Endpoints: []EndpointData{
			{
				PublicEndpoints: []PublicEndpoint{
					{Address: "1.2.3.4", Port: 41641},
				},
				LocalEndpoints: []string{"192.168.1.5:41641"},
				PreferredDERP:  2,
				UpdatedAt:      recentUpdate,
			},
		},
	}

	node := nodeRecordToNodeWithThreshold(42, didURI, rec, DefaultPeerStaleThreshold, now)

	tests := map[string]struct {
		got  any
		want any
	}{
		"ID":            {got: node.ID, want: int64(42)},
		"DID":           {got: node.DID, want: didURI},
		"Key":           {got: node.Key, want: wantKey},
		"MeshIP":        {got: node.MeshIP, want: netip.MustParseAddr("10.200.0.5")},
		"Name":          {got: node.Name, want: "myhost"},
		"PreferredDERP": {got: node.PreferredDERP, want: 2},
		"Online":        {got: node.Online, want: true},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if tc.got != tc.want {
				t.Errorf("got %v, want %v", tc.got, tc.want)
			}
		})
	}

	t.Run("LastSeen", func(t *testing.T) {
		if node.LastSeen.IsZero() {
			t.Fatal("expected non-zero LastSeen")
		}
	})

	t.Run("AllowedIPs", func(t *testing.T) {
		// mesh IP /32 + additional subnet
		if len(node.AllowedIPs) != 2 {
			t.Fatalf("want 2 AllowedIPs, got %d", len(node.AllowedIPs))
		}
		if node.AllowedIPs[1].String() != "192.168.1.0/24" {
			t.Errorf("AllowedIPs[1] = %q", node.AllowedIPs[1])
		}
	})

	t.Run("Endpoints", func(t *testing.T) {
		if len(node.Endpoints) != 2 {
			t.Fatalf("want 2 endpoints, got %d", len(node.Endpoints))
		}
		if node.Endpoints[0] != "1.2.3.4:41641" {
			t.Errorf("[0] = %q", node.Endpoints[0])
		}
		if node.Endpoints[1] != "192.168.1.5:41641" {
			t.Errorf("[1] = %q", node.Endpoints[1])
		}
	})

	t.Run("non-jwk DID yields empty key", func(t *testing.T) {
		// nodeRecordToNode should not panic on a non-jwk DID.
		rec2 := &NodeRecord{MeshIP: "10.200.0.6", Info: &NodeInfoData{Hostname: "other"}}
		node2 := nodeRecordToNodeWithThreshold(99, "did:web:example.com", rec2, DefaultPeerStaleThreshold, now)
		if node2.Key != "" {
			t.Errorf("expected empty Key for non-jwk DID, got %q", node2.Key)
		}
	})
}

func TestNodeOnlineStatus(t *testing.T) {
	now := time.Date(2026, 2, 25, 12, 0, 0, 0, time.UTC)
	threshold := 5 * time.Minute

	didURI, _ := testDIDJWK(t)

	tests := []struct {
		name       string
		endpoints  []EndpointData
		wantOnline bool
		wantSeen   bool // whether LastSeen should be non-zero
	}{
		{
			name:       "no endpoints — offline",
			endpoints:  nil,
			wantOnline: false,
			wantSeen:   false,
		},
		{
			name: "no updatedAt — offline",
			endpoints: []EndpointData{
				{LocalEndpoints: []string{"192.168.1.5:41641"}},
			},
			wantOnline: false,
			wantSeen:   false,
		},
		{
			name: "recent update — online",
			endpoints: []EndpointData{
				{
					LocalEndpoints: []string{"192.168.1.5:41641"},
					UpdatedAt:      now.Add(-2 * time.Minute).Format(time.RFC3339),
				},
			},
			wantOnline: true,
			wantSeen:   true,
		},
		{
			name: "exactly at threshold — online",
			endpoints: []EndpointData{
				{
					LocalEndpoints: []string{"192.168.1.5:41641"},
					UpdatedAt:      now.Add(-threshold).Format(time.RFC3339),
				},
			},
			wantOnline: true,
			wantSeen:   true,
		},
		{
			name: "just past threshold — offline",
			endpoints: []EndpointData{
				{
					LocalEndpoints: []string{"192.168.1.5:41641"},
					UpdatedAt:      now.Add(-threshold - time.Second).Format(time.RFC3339),
				},
			},
			wantOnline: false,
			wantSeen:   true,
		},
		{
			name: "stale update — offline",
			endpoints: []EndpointData{
				{
					LocalEndpoints: []string{"192.168.1.5:41641"},
					UpdatedAt:      now.Add(-30 * time.Minute).Format(time.RFC3339),
				},
			},
			wantOnline: false,
			wantSeen:   true,
		},
		{
			name: "multiple endpoints uses most recent",
			endpoints: []EndpointData{
				{
					LocalEndpoints: []string{"192.168.1.5:41641"},
					UpdatedAt:      now.Add(-30 * time.Minute).Format(time.RFC3339),
				},
				{
					LocalEndpoints: []string{"10.0.0.1:41641"},
					UpdatedAt:      now.Add(-1 * time.Minute).Format(time.RFC3339),
				},
			},
			wantOnline: true,
			wantSeen:   true,
		},
		{
			name: "malformed updatedAt — offline",
			endpoints: []EndpointData{
				{
					LocalEndpoints: []string{"192.168.1.5:41641"},
					UpdatedAt:      "not-a-timestamp",
				},
			},
			wantOnline: false,
			wantSeen:   false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := &NodeRecord{
				MeshIP:    "10.200.0.5",
				Info:      &NodeInfoData{Hostname: "peer"},
				Endpoints: tc.endpoints,
			}

			node := nodeRecordToNodeWithThreshold(1, didURI, rec, threshold, now)

			if node.Online != tc.wantOnline {
				t.Errorf("Online = %v, want %v", node.Online, tc.wantOnline)
			}
			if tc.wantSeen && node.LastSeen.IsZero() {
				t.Error("expected non-zero LastSeen")
			}
			if !tc.wantSeen && !node.LastSeen.IsZero() {
				t.Errorf("expected zero LastSeen, got %v", node.LastSeen)
			}
		})
	}
}

func TestDefaultPeerStaleThreshold(t *testing.T) {
	// Verify the constant is reasonable (between 1 minute and 1 hour).
	if DefaultPeerStaleThreshold < time.Minute {
		t.Errorf("threshold %v is too short", DefaultPeerStaleThreshold)
	}
	if DefaultPeerStaleThreshold > time.Hour {
		t.Errorf("threshold %v is too long", DefaultPeerStaleThreshold)
	}
}

func TestDefaultDERPRegions(t *testing.T) {
	regions := defaultDERPRegions()

	t.Run("has bootstrap regions", func(t *testing.T) {
		if len(regions) == 0 {
			t.Fatal("no default DERP regions")
		}
		if len(regions) < 2 {
			t.Errorf("want at least 2 regions, got %d", len(regions))
		}
	})

	t.Run("each region has nodes", func(t *testing.T) {
		for id, r := range regions {
			if len(r.Nodes) == 0 {
				t.Errorf("region %d has no nodes", id)
			}
			for _, n := range r.Nodes {
				if n.HostName == "" {
					t.Errorf("region %d node %q has no hostname", id, n.Name)
				}
				if n.DERPPort == 0 {
					t.Errorf("region %d node %q has no DERP port", id, n.Name)
				}
				if n.STUNPort == 0 {
					t.Errorf("region %d node %q has no STUN port", id, n.Name)
				}
			}
		}
	})
}

func TestBuildDERPMapFallback(t *testing.T) {
	// A client with no relays should fall back to default DERP regions.
	c := &DWNClient{
		relays: nil,
	}
	dm := c.buildDERPMap()
	if len(dm.Regions) == 0 {
		t.Fatal("expected default DERP regions when no relays configured")
	}

	// A client with custom relays should NOT use defaults.
	c.relays = []*RelayData{
		{URL: "relay.example.com", Region: "custom", STUNPort: 3478},
	}
	dm = c.buildDERPMap()
	if len(dm.Regions) != 1 {
		t.Fatalf("want 1 custom region, got %d", len(dm.Regions))
	}
	if dm.Regions[1].Nodes[0].HostName != "relay.example.com" {
		t.Errorf("hostname = %q", dm.Regions[1].Nodes[0].HostName)
	}
}

func TestDefaultFilterRules(t *testing.T) {
	rules := defaultFilterRules()
	if len(rules) != 1 {
		t.Fatalf("want 1 rule, got %d", len(rules))
	}
	if rules[0].SrcIPs[0] != "*" {
		t.Error("should allow all sources")
	}
	if rules[0].DstPorts[0].IP != "*" {
		t.Error("should allow all destinations")
	}
	if rules[0].DstPorts[0].Ports.First != 0 || rules[0].DstPorts[0].Ports.Last != 65535 {
		t.Error("should allow all ports")
	}
}

func TestExtractEntryMetadata(t *testing.T) {
	t.Run("wrapped format with recipient", func(t *testing.T) {
		entry := json.RawMessage(`{
			"recordsWrite": {
				"recordId": "bafyreiabc123",
				"descriptor": {
					"interface": "Records",
					"method": "Write",
					"protocol": "https://enbox.org/protocols/wireguard-mesh",
					"protocolPath": "network/node",
					"recipient": "did:jwk:node456"
				},
				"encodedData": "dGVzdA"
			}
		}`)

		meta := extractEntryMetadata(entry)

		if meta.RecordID != "bafyreiabc123" {
			t.Errorf("RecordID = %q, want %q", meta.RecordID, "bafyreiabc123")
		}
		if meta.Recipient != "did:jwk:node456" {
			t.Errorf("Recipient = %q, want %q", meta.Recipient, "did:jwk:node456")
		}
	})

	t.Run("flat format", func(t *testing.T) {
		entry := json.RawMessage(`{
			"recordId": "bafyreiflat",
			"descriptor": {
				"recipient": "did:jwk:node789"
			}
		}`)

		meta := extractEntryMetadata(entry)

		if meta.RecordID != "bafyreiflat" {
			t.Errorf("RecordID = %q, want %q", meta.RecordID, "bafyreiflat")
		}
		if meta.Recipient != "did:jwk:node789" {
			t.Errorf("Recipient = %q, want %q", meta.Recipient, "did:jwk:node789")
		}
	})

	t.Run("empty entry", func(t *testing.T) {
		meta := extractEntryMetadata(json.RawMessage(`{}`))
		if meta.RecordID != "" || meta.Recipient != "" {
			t.Errorf("expected empty metadata, got %+v", meta)
		}
	})

	t.Run("nil entry", func(t *testing.T) {
		meta := extractEntryMetadata(nil)
		if meta.RecordID != "" || meta.Recipient != "" {
			t.Errorf("expected empty metadata, got %+v", meta)
		}
	})
}

func TestDetectDerivationScheme(t *testing.T) {
	tests := map[string]struct {
		enc  *dwncrypto.Encryption
		want string
	}{
		"nil encryption": {
			enc:  nil,
			want: "",
		},
		"protocolPath scheme": {
			enc: &dwncrypto.Encryption{
				Recipients: []dwncrypto.Recipient{
					{Header: dwncrypto.RecipientHeader{DerivationScheme: "protocolPath"}},
				},
			},
			want: "protocolPath",
		},
		"protocolContext scheme": {
			enc: &dwncrypto.Encryption{
				Recipients: []dwncrypto.Recipient{
					{Header: dwncrypto.RecipientHeader{DerivationScheme: "protocolContext"}},
				},
			},
			want: "protocolContext",
		},
		"no scheme defaults to protocolPath": {
			enc: &dwncrypto.Encryption{
				Recipients: []dwncrypto.Recipient{
					{Header: dwncrypto.RecipientHeader{}},
				},
			},
			want: "protocolPath",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := detectDerivationScheme(tc.enc)
			if got != tc.want {
				t.Errorf("detectDerivationScheme = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestParseEntryData(t *testing.T) {
	t.Run("direct JSON", func(t *testing.T) {
		var net NetworkConfig
		err := parseEntryData([]byte(`{"name":"test","meshCIDR":"10.200.0.0/16"}`), &net, nil)
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		if net.Name != "test" {
			t.Errorf("name = %q", net.Name)
		}
	})

	t.Run("wrapped encodedData", func(t *testing.T) {
		wrapped := `{"recordsWrite":{"encodedData":"eyJuYW1lIjoid3JhcHBlZCIsIm1lc2hDSURSIjoiMTAuMjAwLjAuMC8xNiJ9"}}`
		var net NetworkConfig
		err := parseEntryData([]byte(wrapped), &net, nil)
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		if net.Name != "wrapped" {
			t.Errorf("name = %q", net.Name)
		}
	})

	t.Run("nil entry", func(t *testing.T) {
		var net NetworkConfig
		err := parseEntryData(nil, &net, nil)
		if !errors.Is(err, ErrNoEntry) {
			t.Errorf("got %v, want %v", err, ErrNoEntry)
		}
	})

	t.Run("flat encodedData", func(t *testing.T) {
		flat := `{"encodedData":"eyJuYW1lIjoiZmxhdCIsIm1lc2hDSURSIjoiMTAuMjAwLjAuMC8xNiJ9"}`
		var net NetworkConfig
		err := parseEntryData([]byte(flat), &net, nil)
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		if net.Name != "flat" {
			t.Errorf("name = %q", net.Name)
		}
	})

	t.Run("wrapped encrypted data", func(t *testing.T) {
		// Test that encrypted data is decrypted when a decryptor is provided.
		rootPriv, _, err := dwncrypto.GenerateX25519KeyPair()
		if err != nil {
			t.Fatalf("generating key: %v", err)
		}

		mgr := &dwncrypto.EncryptionKeyManager{
			RootPrivateKey: rootPriv,
			RootKeyID:      "did:test#enc",
			ProtocolURI:    "https://example.com/proto",
		}

		recipients, err := mgr.DeriveWriteEncryption("network/node")
		if err != nil {
			t.Fatalf("deriving encryption: %v", err)
		}

		plaintext := []byte(`{"name":"encrypted","meshCIDR":"10.200.0.0/16"}`)
		ciphertext, enc, err := dwncrypto.EncryptData(plaintext, recipients)
		if err != nil {
			t.Fatalf("encrypting: %v", err)
		}

		// Build a wrapped entry with encryption.
		encodedData := base64.RawURLEncoding.EncodeToString(ciphertext)
		encJSON, _ := json.Marshal(enc)

		entry := []byte(`{"recordsWrite":{"encodedData":"` + encodedData + `","encryption":` + string(encJSON) + `}}`)

		// Decrypt using the key manager.
		decryptor := func(ct []byte, e *dwncrypto.Encryption) ([]byte, error) {
			privKey, err := mgr.DeriveDecryptionKey("network/node")
			if err != nil {
				return nil, err
			}
			return dwncrypto.DecryptData(ct, e, privKey, mgr.RootKeyID)
		}

		var net NetworkConfig
		err = parseEntryData(entry, &net, decryptor)
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		if net.Name != "encrypted" {
			t.Errorf("name = %q, want %q", net.Name, "encrypted")
		}
	})
}

// =============================================================================
// ACL policy tests
// =============================================================================

func TestParsePortRange(t *testing.T) {
	tests := []struct {
		input string
		want  PortRange
		ok    bool
	}{
		{"22", PortRange{22, 22}, true},
		{"0", PortRange{0, 0}, true},
		{"65535", PortRange{65535, 65535}, true},
		{"80-443", PortRange{80, 443}, true},
		{"8000-9000", PortRange{8000, 9000}, true},
		{"0-65535", PortRange{0, 65535}, true},
		{"443-80", PortRange{}, false},     // first > last
		{"65536", PortRange{}, false},      // overflow
		{"", PortRange{}, false},           // empty
		{"abc", PortRange{}, false},        // non-numeric
		{"80-", PortRange{}, false},        // missing last
		{"-80", PortRange{}, false},        // missing first
		{"80-abc", PortRange{}, false},     // non-numeric last
		{"100000", PortRange{}, false},     // too large
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got, ok := parsePortRange(tc.input)
			if ok != tc.ok {
				t.Fatalf("parsePortRange(%q) ok = %v, want %v", tc.input, ok, tc.ok)
			}
			if got != tc.want {
				t.Fatalf("parsePortRange(%q) = %+v, want %+v", tc.input, got, tc.want)
			}
		})
	}
}

func TestParsePortRanges(t *testing.T) {
	result := parsePortRanges([]string{"22", "80-443", "invalid", "8000-9000"})
	if len(result) != 3 {
		t.Fatalf("want 3 valid ranges, got %d", len(result))
	}
	if result[0] != (PortRange{22, 22}) {
		t.Errorf("[0] = %+v", result[0])
	}
	if result[1] != (PortRange{80, 443}) {
		t.Errorf("[1] = %+v", result[1])
	}
	if result[2] != (PortRange{8000, 9000}) {
		t.Errorf("[2] = %+v", result[2])
	}
}

func TestBuildFilterRules_WithACLPolicy(t *testing.T) {
	did1, _ := testDIDJWK(t)
	did2, _ := testDIDJWK(t)

	c := &DWNClient{
		nodes: map[string]*NodeRecord{
			did1: {DID: did1, MeshIP: "10.200.0.2"},
			did2: {DID: did2, MeshIP: "10.200.0.3"},
		},
		acl: &ACLPolicyData{
			Version:       1,
			DefaultAction: "drop",
			Rules: []ACLRule{
				{
					Action:   "accept",
					Src:      []string{"*"},
					Dst:      []string{"*"},
					DstPorts: []string{"53"},
				},
				{
					Action:   "accept",
					Src:      []string{did1},
					Dst:      []string{did2},
					DstPorts: []string{"22", "443", "8000-9000"},
				},
			},
		},
	}

	rules := c.buildFilterRules()

	if len(rules) != 2 {
		t.Fatalf("want 2 rules, got %d", len(rules))
	}

	// Rule 0: * -> * port 53.
	if rules[0].SrcIPs[0] != "*" {
		t.Errorf("rule[0].SrcIPs = %v", rules[0].SrcIPs)
	}
	if rules[0].DstPorts[0].IP != "*" {
		t.Errorf("rule[0].DstPorts[0].IP = %q", rules[0].DstPorts[0].IP)
	}
	if rules[0].DstPorts[0].Ports != (PortRange{53, 53}) {
		t.Errorf("rule[0].DstPorts[0].Ports = %+v", rules[0].DstPorts[0].Ports)
	}

	// Rule 1: did1 -> did2, 3 port ranges.
	if len(rules[1].SrcIPs) != 1 || rules[1].SrcIPs[0] != "10.200.0.2" {
		t.Errorf("rule[1].SrcIPs = %v", rules[1].SrcIPs)
	}
	// 1 dst IP × 3 port ranges = 3 DstPorts entries.
	if len(rules[1].DstPorts) != 3 {
		t.Fatalf("rule[1] want 3 DstPorts, got %d", len(rules[1].DstPorts))
	}
	for _, dp := range rules[1].DstPorts {
		if dp.IP != "10.200.0.3" {
			t.Errorf("DstPorts IP = %q, want 10.200.0.3", dp.IP)
		}
	}
	if rules[1].DstPorts[0].Ports != (PortRange{22, 22}) {
		t.Errorf("port[0] = %+v", rules[1].DstPorts[0].Ports)
	}
	if rules[1].DstPorts[1].Ports != (PortRange{443, 443}) {
		t.Errorf("port[1] = %+v", rules[1].DstPorts[1].Ports)
	}
	if rules[1].DstPorts[2].Ports != (PortRange{8000, 9000}) {
		t.Errorf("port[2] = %+v", rules[1].DstPorts[2].Ports)
	}
}

func TestBuildFilterRules_Groups(t *testing.T) {
	did1, _ := testDIDJWK(t)
	did2, _ := testDIDJWK(t)
	did3, _ := testDIDJWK(t)

	c := &DWNClient{
		nodes: map[string]*NodeRecord{
			did1: {DID: did1, MeshIP: "10.200.0.2"},
			did2: {DID: did2, MeshIP: "10.200.0.3"},
			did3: {DID: did3, MeshIP: "10.200.0.4"},
		},
		acl: &ACLPolicyData{
			Version:       1,
			DefaultAction: "drop",
			Groups: map[string][]string{
				"devs":    {did1, did2},
				"servers": {did3},
			},
			Rules: []ACLRule{
				{
					Action:   "accept",
					Src:      []string{"group:devs"},
					Dst:      []string{"group:servers"},
					DstPorts: []string{"22"},
				},
			},
		},
	}

	rules := c.buildFilterRules()

	if len(rules) != 1 {
		t.Fatalf("want 1 rule, got %d", len(rules))
	}

	// Source should be the 2 dev IPs.
	if len(rules[0].SrcIPs) != 2 {
		t.Fatalf("want 2 SrcIPs, got %d: %v", len(rules[0].SrcIPs), rules[0].SrcIPs)
	}

	// Destination should be the 1 server IP × 1 port.
	if len(rules[0].DstPorts) != 1 {
		t.Fatalf("want 1 DstPorts, got %d", len(rules[0].DstPorts))
	}
	if rules[0].DstPorts[0].IP != "10.200.0.4" {
		t.Errorf("DstPorts[0].IP = %q", rules[0].DstPorts[0].IP)
	}
	if rules[0].DstPorts[0].Ports != (PortRange{22, 22}) {
		t.Errorf("DstPorts[0].Ports = %+v", rules[0].DstPorts[0].Ports)
	}
}

func TestBuildFilterRules_NilACL(t *testing.T) {
	c := &DWNClient{
		nodes: map[string]*NodeRecord{},
		acl:   nil,
	}
	rules := c.buildFilterRules()
	if len(rules) != 1 || rules[0].SrcIPs[0] != "*" {
		t.Fatalf("nil ACL should produce allow-all, got %+v", rules)
	}
}

func TestBuildFilterRules_DefaultActionAccept(t *testing.T) {
	c := &DWNClient{
		nodes: map[string]*NodeRecord{},
		acl: &ACLPolicyData{
			Version:       1,
			DefaultAction: "accept",
			Rules: []ACLRule{
				// A drop rule only — no accept rules will be produced.
				{Action: "drop", Src: []string{"*"}, Dst: []string{"*"}},
			},
		},
	}
	rules := c.buildFilterRules()
	// No accept rules → defaultAction=accept → allow-all fallback.
	if len(rules) != 1 || rules[0].SrcIPs[0] != "*" {
		t.Fatalf("defaultAction=accept with no accept rules should produce allow-all, got %+v", rules)
	}
}

func TestBuildFilterRules_NoPorts(t *testing.T) {
	did1, _ := testDIDJWK(t)

	c := &DWNClient{
		nodes: map[string]*NodeRecord{
			did1: {DID: did1, MeshIP: "10.200.0.2"},
		},
		acl: &ACLPolicyData{
			Version: 1,
			Rules: []ACLRule{
				{
					Action: "accept",
					Src:    []string{"*"},
					Dst:    []string{did1},
					// No DstPorts → all ports.
				},
			},
		},
	}

	rules := c.buildFilterRules()
	if len(rules) != 1 {
		t.Fatalf("want 1 rule, got %d", len(rules))
	}
	if rules[0].DstPorts[0].Ports != (PortRange{0, 65535}) {
		t.Errorf("no dstPorts should mean all ports, got %+v", rules[0].DstPorts[0].Ports)
	}
}

func TestBuildFilterRules_DirectIP(t *testing.T) {
	c := &DWNClient{
		nodes: map[string]*NodeRecord{},
		acl: &ACLPolicyData{
			Version: 1,
			Rules: []ACLRule{
				{
					Action: "accept",
					Src:    []string{"10.200.0.0/16"},
					Dst:    []string{"10.200.0.5"},
					DstPorts: []string{"80"},
				},
			},
		},
	}

	rules := c.buildFilterRules()
	if len(rules) != 1 {
		t.Fatalf("want 1 rule, got %d", len(rules))
	}
	if rules[0].SrcIPs[0] != "10.200.0.0/16" {
		t.Errorf("SrcIPs[0] = %q", rules[0].SrcIPs[0])
	}
	if rules[0].DstPorts[0].IP != "10.200.0.5" {
		t.Errorf("DstPorts[0].IP = %q", rules[0].DstPorts[0].IP)
	}
}

func TestBuildFilterRules_UnresolvableDID(t *testing.T) {
	c := &DWNClient{
		nodes: map[string]*NodeRecord{},
		acl: &ACLPolicyData{
			Version: 1,
			Rules: []ACLRule{
				{
					Action: "accept",
					Src:    []string{"did:jwk:unknown"},
					Dst:    []string{"*"},
				},
			},
		},
	}

	rules := c.buildFilterRules()
	// The DID can't be resolved to an IP, so the rule should produce no SrcIPs
	// and be skipped entirely.
	if len(rules) != 0 {
		t.Fatalf("unresolvable DID should produce 0 rules, got %d", len(rules))
	}
}

func TestResolveMatchers(t *testing.T) {
	did1, _ := testDIDJWK(t)
	did2, _ := testDIDJWK(t)

	c := &DWNClient{
		acl: &ACLPolicyData{
			Groups: map[string][]string{
				"servers": {did1, did2},
			},
		},
	}

	didToIP := map[string]string{
		did1: "10.200.0.2",
		did2: "10.200.0.3",
	}

	t.Run("wildcard", func(t *testing.T) {
		result := c.resolveMatchers([]string{"*"}, didToIP)
		if len(result) != 1 || result[0] != "*" {
			t.Errorf("wildcard: got %v", result)
		}
	})

	t.Run("DID", func(t *testing.T) {
		result := c.resolveMatchers([]string{did1}, didToIP)
		if len(result) != 1 || result[0] != "10.200.0.2" {
			t.Errorf("DID: got %v", result)
		}
	})

	t.Run("group", func(t *testing.T) {
		result := c.resolveMatchers([]string{"group:servers"}, didToIP)
		if len(result) != 2 {
			t.Fatalf("group: want 2 IPs, got %d", len(result))
		}
	})

	t.Run("unknown group", func(t *testing.T) {
		result := c.resolveMatchers([]string{"group:unknown"}, didToIP)
		if len(result) != 0 {
			t.Errorf("unknown group: got %v", result)
		}
	})

	t.Run("direct IP", func(t *testing.T) {
		result := c.resolveMatchers([]string{"10.200.0.5"}, didToIP)
		if len(result) != 1 || result[0] != "10.200.0.5" {
			t.Errorf("direct IP: got %v", result)
		}
	})

	t.Run("CIDR", func(t *testing.T) {
		result := c.resolveMatchers([]string{"10.200.0.0/16"}, didToIP)
		if len(result) != 1 || result[0] != "10.200.0.0/16" {
			t.Errorf("CIDR: got %v", result)
		}
	})

	t.Run("mixed", func(t *testing.T) {
		result := c.resolveMatchers([]string{did1, "10.200.0.5", "group:servers"}, didToIP)
		// did1 → 1 IP, direct → 1 IP, group:servers → 2 IPs = 4 total
		if len(result) != 4 {
			t.Errorf("mixed: want 4, got %d: %v", len(result), result)
		}
	})

	t.Run("wildcard short-circuits", func(t *testing.T) {
		result := c.resolveMatchers([]string{did1, "*", "10.200.0.5"}, didToIP)
		if len(result) != 1 || result[0] != "*" {
			t.Errorf("wildcard should short-circuit: got %v", result)
		}
	})
}

func TestACLPolicyAccessor(t *testing.T) {
	c := &DWNClient{}
	if c.ACLPolicy() != nil {
		t.Fatal("expected nil ACL before loading")
	}

	policy := &ACLPolicyData{Version: 1, Rules: []ACLRule{{Action: "accept", Src: []string{"*"}, Dst: []string{"*"}}}}
	c.acl = policy
	if got := c.ACLPolicy(); got != policy {
		t.Fatal("expected ACL policy to be set")
	}
}

func TestACLPolicyDataSerialization(t *testing.T) {
	policy := ACLPolicyData{
		Version:       1,
		DefaultAction: "drop",
		Groups: map[string][]string{
			"devs": {"did:jwk:abc", "did:jwk:def"},
		},
		Rules: []ACLRule{
			{
				Action:   "accept",
				Src:      []string{"group:devs"},
				Dst:      []string{"*"},
				DstPorts: []string{"22", "80-443"},
			},
		},
	}

	data, err := json.Marshal(policy)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded ACLPolicyData
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.Version != 1 {
		t.Errorf("version = %d", decoded.Version)
	}
	if decoded.DefaultAction != "drop" {
		t.Errorf("defaultAction = %q", decoded.DefaultAction)
	}
	if len(decoded.Groups) != 1 {
		t.Fatalf("groups = %d", len(decoded.Groups))
	}
	if len(decoded.Groups["devs"]) != 2 {
		t.Errorf("groups[devs] = %v", decoded.Groups["devs"])
	}
	if len(decoded.Rules) != 1 {
		t.Fatalf("rules = %d", len(decoded.Rules))
	}
	if len(decoded.Rules[0].DstPorts) != 2 {
		t.Errorf("dstPorts = %v", decoded.Rules[0].DstPorts)
	}
}

func TestProtoToIPProto(t *testing.T) {
	tests := []struct {
		proto string
		want  []int
	}{
		{"tcp", []int{6}},
		{"udp", []int{17}},
		{"icmp", []int{1, 58}},
		{"*", nil},
		{"", nil},
	}
	for _, tt := range tests {
		t.Run(tt.proto, func(t *testing.T) {
			got := protoToIPProto(tt.proto)
			if len(got) != len(tt.want) {
				t.Fatalf("protoToIPProto(%q) = %v, want %v", tt.proto, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("protoToIPProto(%q)[%d] = %d, want %d", tt.proto, i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestBuildFilterRules_Proto(t *testing.T) {
	did1, _ := testDIDJWK(t)
	did2, _ := testDIDJWK(t)

	c := &DWNClient{
		nodes: map[string]*NodeRecord{
			did1: {DID: did1, MeshIP: "10.200.0.2"},
			did2: {DID: did2, MeshIP: "10.200.0.3"},
		},
		acl: &ACLPolicyData{
			Version:       1,
			DefaultAction: "drop",
			Rules: []ACLRule{
				{
					Action:   "accept",
					Src:      []string{"*"},
					Dst:      []string{"*"},
					Proto:    "tcp",
					DstPorts: []string{"22", "443"},
				},
				{
					Action: "accept",
					Src:    []string{did1},
					Dst:    []string{did2},
					Proto:  "udp",
				},
				{
					Action: "accept",
					Src:    []string{"*"},
					Dst:    []string{"*"},
					Proto:  "icmp",
				},
				{
					// No proto → all protocols (nil IPProto).
					Action:   "accept",
					Src:      []string{did1},
					Dst:      []string{did2},
					DstPorts: []string{"80"},
				},
			},
		},
	}

	rules := c.buildFilterRules()
	if len(rules) != 4 {
		t.Fatalf("want 4 rules, got %d", len(rules))
	}

	// Rule 0: TCP only (proto 6).
	if len(rules[0].IPProto) != 1 || rules[0].IPProto[0] != 6 {
		t.Errorf("rule[0].IPProto = %v, want [6]", rules[0].IPProto)
	}

	// Rule 1: UDP only (proto 17).
	if len(rules[1].IPProto) != 1 || rules[1].IPProto[0] != 17 {
		t.Errorf("rule[1].IPProto = %v, want [17]", rules[1].IPProto)
	}

	// Rule 2: ICMP (protos 1, 58).
	if len(rules[2].IPProto) != 2 || rules[2].IPProto[0] != 1 || rules[2].IPProto[1] != 58 {
		t.Errorf("rule[2].IPProto = %v, want [1 58]", rules[2].IPProto)
	}

	// Rule 3: No proto → nil (all protocols).
	if rules[3].IPProto != nil {
		t.Errorf("rule[3].IPProto = %v, want nil", rules[3].IPProto)
	}
}
