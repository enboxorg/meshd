package control

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/netip"
	"testing"

	dwncrypto "github.com/enboxorg/dwn-mesh/internal/dwn/crypto"
)

func TestBuildStaticMapResponse(t *testing.T) {
	self := &Node{
		ID:     1,
		Name:   "laptop",
		DID:    "did:dht:self123",
		Key:    "AAAA==",
		MeshIP: netip.MustParseAddr("10.200.0.1"),
		AllowedIPs: []netip.Prefix{
			netip.MustParsePrefix("10.200.0.1/32"),
		},
		Endpoints: []string{"1.2.3.4:41641"},
		OS:        "linux",
	}

	peer := &Node{
		ID:     2,
		Name:   "server",
		DID:    "did:dht:peer456",
		Key:    "BBBB==",
		MeshIP: netip.MustParseAddr("10.200.0.2"),
		AllowedIPs: []netip.Prefix{
			netip.MustParsePrefix("10.200.0.2/32"),
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

func TestNodeInfoToNode(t *testing.T) {
	info := &NodeInfoData{
		WireGuardPublicKey: "testkey==",
		MeshIP:             "10.200.0.5",
		Hostname:           "myhost",
		OS:                 "linux",
		Capabilities:       []string{"relay"},
		AllowedIPs:         []string{"192.168.1.0/24"},
		Endpoints: []EndpointData{
			{
				PublicEndpoints: []PublicEndpoint{
					{Address: "1.2.3.4", Port: 41641},
				},
				LocalEndpoints: []string{"192.168.1.5:41641"},
				PreferredDERP:  2,
			},
		},
	}

	node := nodeInfoToNode(42, "did:dht:test", info)

	tests := map[string]struct {
		got  any
		want any
	}{
		"ID":            {got: node.ID, want: int64(42)},
		"DID":           {got: node.DID, want: "did:dht:test"},
		"Key":           {got: node.Key, want: "testkey=="},
		"MeshIP":        {got: node.MeshIP, want: netip.MustParseAddr("10.200.0.5")},
		"Name":          {got: node.Name, want: "myhost"},
		"PreferredDERP": {got: node.PreferredDERP, want: 2},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if tc.got != tc.want {
				t.Errorf("got %v, want %v", tc.got, tc.want)
			}
		})
	}

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

		recipients, err := mgr.DeriveWriteEncryption("network/member")
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
			privKey, err := mgr.DeriveDecryptionKey("network/member")
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
