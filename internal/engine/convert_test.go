package engine

import (
	"encoding/base64"
	"net/netip"
	"testing"

	"github.com/enboxorg/meshd/internal/control"
	"github.com/enboxorg/meshnet/types/key"
)

// testWireGuardKey returns a valid base64-encoded 32-byte key for testing.
func testWireGuardKey() string {
	// Generate a real key pair so we have a valid 32-byte public key.
	priv := key.NewNode()
	pub := priv.Public()
	raw := pub.Raw32()
	// Encode as standard base64.
	return rawToBase64(raw[:])
}

func rawToBase64(b []byte) string {
	const base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	result := make([]byte, 0, (len(b)+2)/3*4)
	for i := 0; i < len(b); i += 3 {
		var val uint32
		remaining := len(b) - i
		switch {
		case remaining >= 3:
			val = uint32(b[i])<<16 | uint32(b[i+1])<<8 | uint32(b[i+2])
			result = append(result, base64Chars[val>>18], base64Chars[(val>>12)&0x3F], base64Chars[(val>>6)&0x3F], base64Chars[val&0x3F])
		case remaining == 2:
			val = uint32(b[i])<<16 | uint32(b[i+1])<<8
			result = append(result, base64Chars[val>>18], base64Chars[(val>>12)&0x3F], base64Chars[(val>>6)&0x3F], '=')
		case remaining == 1:
			val = uint32(b[i]) << 16
			result = append(result, base64Chars[val>>18], base64Chars[(val>>12)&0x3F], '=', '=')
		}
	}
	return string(result)
}

func TestConvertFullMapResponse(t *testing.T) {
	wgKey := testWireGuardKey()
	peerKey := testWireGuardKey()

	resp := &control.MapResponse{
		Node: &control.Node{
			ID:            1,
			Name:          "laptop",
			DID:           "did:dht:self123",
			Key:           wgKey,
			MeshIP:        netip.MustParseAddr("10.200.0.2"),
			AllowedIPs:    []netip.Prefix{netip.MustParsePrefix("10.200.0.2/32")},
			Endpoints:     []string{"1.2.3.4:41641"},
			PreferredDERP: 1,
			Online:        true,
			OS:            "linux",
		},
		Peers: []*control.Node{
			{
				ID:            2,
				Name:          "server",
				DID:           "did:dht:peer456",
				Key:           peerKey,
				MeshIP:        netip.MustParseAddr("10.200.0.2"),
				AllowedIPs:    []netip.Prefix{netip.MustParsePrefix("10.200.0.2/32")},
				Endpoints:     []string{"5.6.7.8:41641"},
				PreferredDERP: 2,
				Online:        true,
				OS:            "linux",
			},
		},
		DERPMap: &control.DERPMap{
			Regions: map[int]*control.DERPRegion{
				1: {
					RegionID:   1,
					RegionCode: "us-east",
					RegionName: "US East",
					Nodes: []control.DERPNode{
						{
							Name:     "relay-1",
							RegionID: 1,
							HostName: "derp1.example.com",
							DERPPort: 443,
							STUNPort: 3478,
						},
					},
				},
			},
		},
		PacketFilter: []control.FilterRule{
			{
				SrcIPs: []string{"*"},
				DstPorts: []control.NetPortRange{
					{IP: "*", Ports: control.PortRange{First: 0, Last: 65535}},
				},
			},
		},
		DNSConfig: &control.DNSConfig{
			Resolvers:      []string{"1.1.1.1"},
			Domains:        []string{"example.com"},
			MagicDNSSuffix: "mesh.local",
		},
	}

	conv := NewConverter("test-mesh")
	nm, err := conv.Convert(resp)
	if err != nil {
		t.Fatalf("Convert: %v", err)
	}

	tests := map[string]struct {
		check func(t *testing.T)
	}{
		"self node valid": {
			check: func(t *testing.T) {
				if !nm.SelfNode.Valid() {
					t.Fatal("SelfNode not valid")
				}
			},
		},
		"self node name": {
			check: func(t *testing.T) {
				if got := nm.SelfNode.Name(); got != "laptop.mesh.local." {
					t.Errorf("name = %q, want %q", got, "laptop.mesh.local.")
				}
			},
		},
		"self node address": {
			check: func(t *testing.T) {
				addrs := nm.SelfNode.Addresses()
				if addrs.Len() != 1 {
					t.Fatalf("want 1 address, got %d", addrs.Len())
				}
				if got := addrs.At(0); got != netip.MustParsePrefix("10.200.0.2/32") {
					t.Errorf("address = %v", got)
				}
			},
		},
		"self node key non-zero": {
			check: func(t *testing.T) {
				if nm.SelfNode.Key().IsZero() {
					t.Error("SelfNode key is zero")
				}
			},
		},
		"self node online": {
			check: func(t *testing.T) {
				online := nm.SelfNode.Online()
				if !online.Valid() {
					t.Fatal("SelfNode Online not set")
				}
				if !online.Get() {
					t.Error("SelfNode should be online")
				}
			},
		},
		"self node HomeDERP": {
			check: func(t *testing.T) {
				if got := nm.SelfNode.HomeDERP(); got != 1 {
					t.Errorf("HomeDERP = %d, want 1", got)
				}
			},
		},
		"self node endpoints": {
			check: func(t *testing.T) {
				eps := nm.SelfNode.Endpoints()
				if eps.Len() != 1 {
					t.Fatalf("want 1 endpoint, got %d", eps.Len())
				}
				want := netip.MustParseAddrPort("1.2.3.4:41641")
				if got := eps.At(0); got != want {
					t.Errorf("endpoint = %v, want %v", got, want)
				}
			},
		},
		"peer count": {
			check: func(t *testing.T) {
				if len(nm.Peers) != 1 {
					t.Fatalf("want 1 peer, got %d", len(nm.Peers))
				}
			},
		},
		"peer name": {
			check: func(t *testing.T) {
				if got := nm.Peers[0].Name(); got != "server.mesh.local." {
					t.Errorf("peer name = %q", got)
				}
			},
		},
		"peer key non-zero": {
			check: func(t *testing.T) {
				if nm.Peers[0].Key().IsZero() {
					t.Error("peer key is zero")
				}
			},
		},
		"peer sorted by ID": {
			check: func(t *testing.T) {
				if nm.Peers[0].ID() != 2 {
					t.Errorf("peer ID = %d, want 2", nm.Peers[0].ID())
				}
			},
		},
		"DERP map present": {
			check: func(t *testing.T) {
				if nm.DERPMap == nil {
					t.Fatal("DERPMap is nil")
				}
				if len(nm.DERPMap.Regions) != 1 {
					t.Fatalf("want 1 DERP region, got %d", len(nm.DERPMap.Regions))
				}
				r := nm.DERPMap.Regions[1]
				if r.RegionCode != "us-east" {
					t.Errorf("region code = %q", r.RegionCode)
				}
				if len(r.Nodes) != 1 {
					t.Fatalf("want 1 DERP node, got %d", len(r.Nodes))
				}
				if r.Nodes[0].HostName != "derp1.example.com" {
					t.Errorf("DERP hostname = %q", r.Nodes[0].HostName)
				}
			},
		},
		"DERP omits default regions": {
			check: func(t *testing.T) {
				if !nm.DERPMap.OmitDefaultRegions {
					t.Error("should omit default DERP regions")
				}
			},
		},
		"DNS config": {
			check: func(t *testing.T) {
				if !nm.DNS.Proxied {
					t.Error("MagicDNS should be enabled")
				}
				if len(nm.DNS.Resolvers) != 1 {
					t.Fatalf("want 1 resolver, got %d", len(nm.DNS.Resolvers))
				}
				if nm.DNS.Resolvers[0].Addr != "1.1.1.1" {
					t.Errorf("resolver = %q", nm.DNS.Resolvers[0].Addr)
				}
			},
		},
		"packet filter rules": {
			check: func(t *testing.T) {
				if nm.PacketFilterRules.IsNil() {
					t.Fatal("packet filter rules not set")
				}
				if nm.PacketFilterRules.Len() != 1 {
					t.Fatalf("want 1 rule, got %d", nm.PacketFilterRules.Len())
				}
			},
		},
		"domain": {
			check: func(t *testing.T) {
				if nm.Domain != "test-mesh" {
					t.Errorf("domain = %q", nm.Domain)
				}
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			tc.check(t)
		})
	}
}

func TestConvertNilMapResponse(t *testing.T) {
	conv := NewConverter("test")
	_, err := conv.Convert(nil)
	if err == nil {
		t.Fatal("expected error for nil MapResponse")
	}
}

func TestConvertMinimalMapResponse(t *testing.T) {
	// A MapResponse with no node, no peers, no DERP — should not error.
	resp := &control.MapResponse{
		PacketFilter: []control.FilterRule{
			{
				SrcIPs: []string{"*"},
				DstPorts: []control.NetPortRange{
					{IP: "*", Ports: control.PortRange{First: 0, Last: 65535}},
				},
			},
		},
	}

	conv := NewConverter("minimal")
	nm, err := conv.Convert(resp)
	if err != nil {
		t.Fatalf("Convert: %v", err)
	}

	if nm.SelfNode.Valid() {
		t.Error("SelfNode should not be valid for empty response")
	}
	if len(nm.Peers) != 0 {
		t.Errorf("want 0 peers, got %d", len(nm.Peers))
	}
}

func TestParseWireGuardKey(t *testing.T) {
	tests := map[string]struct {
		input   string
		wantErr bool
	}{
		"valid base64 key": {
			input:   testWireGuardKey(),
			wantErr: false,
		},
		"invalid base64": {
			input:   "not-valid-base64!!!",
			wantErr: true,
		},
		"wrong length": {
			input:   "AQID", // 3 bytes
			wantErr: true,
		},
		"empty": {
			input:   "",
			wantErr: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			k, err := parseWireGuardKey(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Error("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if k.IsZero() {
				t.Error("parsed key is zero")
			}
		})
	}
}

func TestFQDN(t *testing.T) {
	conv := NewConverter("test", WithConverterLogger(nil))
	// WithConverterLogger(nil) — converter should handle nil gracefully or use default

	tests := map[string]struct {
		hostname string
		want     string
	}{
		"normal":    {hostname: "laptop", want: "laptop.mesh.local."},
		"empty":     {hostname: "", want: ""},
		"with-dash": {hostname: "my-server", want: "my-server.mesh.local."},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := conv.fqdn(tc.hostname)
			if got != tc.want {
				t.Errorf("fqdn(%q) = %q, want %q", tc.hostname, got, tc.want)
			}
		})
	}
}

func TestConvertPeersSortedByID(t *testing.T) {
	key1 := testWireGuardKey()
	key2 := testWireGuardKey()
	key3 := testWireGuardKey()

	resp := &control.MapResponse{
		Peers: []*control.Node{
			{ID: 5, Name: "e", Key: key1, MeshIP: netip.MustParseAddr("10.200.0.5")},
			{ID: 2, Name: "b", Key: key2, MeshIP: netip.MustParseAddr("10.200.0.2")},
			{ID: 8, Name: "h", Key: key3, MeshIP: netip.MustParseAddr("10.200.0.8")},
		},
	}

	conv := NewConverter("test")
	nm, err := conv.Convert(resp)
	if err != nil {
		t.Fatalf("Convert: %v", err)
	}

	if len(nm.Peers) != 3 {
		t.Fatalf("want 3 peers, got %d", len(nm.Peers))
	}

	// Should be sorted by ID: 2, 5, 8.
	ids := make([]int64, len(nm.Peers))
	for i, p := range nm.Peers {
		ids[i] = int64(p.ID())
	}
	if ids[0] != 2 || ids[1] != 5 || ids[2] != 8 {
		t.Errorf("peers not sorted by ID: %v", ids)
	}
}

func TestConvertNodeDefaultAllowedIPs(t *testing.T) {
	// When AllowedIPs is empty, should default to the node's MeshIP.
	wgKey := testWireGuardKey()
	resp := &control.MapResponse{
		Node: &control.Node{
			ID:     1,
			Name:   "test",
			Key:    wgKey,
			MeshIP: netip.MustParseAddr("10.200.0.2"),
			// AllowedIPs is nil.
		},
	}

	conv := NewConverter("test")
	nm, err := conv.Convert(resp)
	if err != nil {
		t.Fatalf("Convert: %v", err)
	}

	allowed := nm.SelfNode.AllowedIPs()
	if allowed.Len() != 1 {
		t.Fatalf("want 1 AllowedIP, got %d", allowed.Len())
	}
	if got := allowed.At(0); got != netip.MustParsePrefix("10.200.0.2/32") {
		t.Errorf("AllowedIP = %v, want 10.200.0.2/32", got)
	}
}

func TestConvertInvalidPeerKeySkipped(t *testing.T) {
	// A peer with an invalid key should be skipped, not cause an error.
	goodKey := testWireGuardKey()

	resp := &control.MapResponse{
		Peers: []*control.Node{
			{ID: 1, Name: "good", Key: goodKey, MeshIP: netip.MustParseAddr("10.200.0.2")},
			{ID: 2, Name: "bad", Key: "not-a-key", MeshIP: netip.MustParseAddr("10.200.0.3")},
			{ID: 3, Name: "also-good", Key: goodKey, MeshIP: netip.MustParseAddr("10.200.0.4")},
		},
	}

	conv := NewConverter("test")
	nm, err := conv.Convert(resp)
	if err != nil {
		t.Fatalf("Convert: %v", err)
	}

	// Bad peer should be skipped.
	if len(nm.Peers) != 2 {
		t.Fatalf("want 2 peers (bad key skipped), got %d", len(nm.Peers))
	}
}

// testDiscoKey returns a valid base64-encoded 32-byte disco key for testing.
func testDiscoKey() (string, key.DiscoPublic) {
	priv := key.NewDisco()
	pub := priv.Public()
	raw := pub.Raw32()
	return base64.StdEncoding.EncodeToString(raw[:]), pub
}

func TestConvertNodeWithDiscoKey(t *testing.T) {
	wgKey := testWireGuardKey()
	discoB64, wantDisco := testDiscoKey()

	resp := &control.MapResponse{
		Node: &control.Node{
			ID:       1,
			Name:     "laptop",
			Key:      wgKey,
			DiscoKey: discoB64,
			MeshIP:   netip.MustParseAddr("10.200.0.1"),
			Online:   true,
		},
	}

	conv := NewConverter("test")
	nm, err := conv.Convert(resp)
	if err != nil {
		t.Fatalf("Convert: %v", err)
	}

	if !nm.SelfNode.Valid() {
		t.Fatal("SelfNode not valid")
	}
	gotDisco := nm.SelfNode.DiscoKey()
	if gotDisco.IsZero() {
		t.Fatal("SelfNode disco key is zero")
	}
	if gotDisco != wantDisco {
		t.Errorf("disco key = %v, want %v", gotDisco, wantDisco)
	}
}

func TestConvertPeerWithDiscoKey(t *testing.T) {
	selfKey := testWireGuardKey()
	peerKey := testWireGuardKey()
	discoB64, wantDisco := testDiscoKey()

	resp := &control.MapResponse{
		Node: &control.Node{
			ID:     1,
			Name:   "self",
			Key:    selfKey,
			MeshIP: netip.MustParseAddr("10.200.0.1"),
		},
		Peers: []*control.Node{
			{
				ID:       2,
				Name:     "peer",
				Key:      peerKey,
				DiscoKey: discoB64,
				MeshIP:   netip.MustParseAddr("10.200.0.2"),
				Online:   true,
			},
		},
	}

	conv := NewConverter("test")
	nm, err := conv.Convert(resp)
	if err != nil {
		t.Fatalf("Convert: %v", err)
	}

	if len(nm.Peers) != 1 {
		t.Fatalf("want 1 peer, got %d", len(nm.Peers))
	}
	gotDisco := nm.Peers[0].DiscoKey()
	if gotDisco.IsZero() {
		t.Fatal("peer disco key is zero")
	}
	if gotDisco != wantDisco {
		t.Errorf("disco key = %v, want %v", gotDisco, wantDisco)
	}
}

func TestConvertNodeWithoutDiscoKey(t *testing.T) {
	wgKey := testWireGuardKey()

	resp := &control.MapResponse{
		Node: &control.Node{
			ID:     1,
			Name:   "laptop",
			Key:    wgKey,
			MeshIP: netip.MustParseAddr("10.200.0.1"),
		},
	}

	conv := NewConverter("test")
	nm, err := conv.Convert(resp)
	if err != nil {
		t.Fatalf("Convert: %v", err)
	}

	// No disco key set — should be zero, not an error.
	if !nm.SelfNode.DiscoKey().IsZero() {
		t.Error("expected zero disco key when none provided")
	}
}

func TestConvertNodeWithInvalidDiscoKey(t *testing.T) {
	wgKey := testWireGuardKey()

	resp := &control.MapResponse{
		Node: &control.Node{
			ID:       1,
			Name:     "laptop",
			Key:      wgKey,
			DiscoKey: "not-valid-base64!!!",
			MeshIP:   netip.MustParseAddr("10.200.0.1"),
		},
	}

	conv := NewConverter("test")
	nm, err := conv.Convert(resp)
	if err != nil {
		t.Fatalf("Convert: %v (should not fail, invalid disco key is non-fatal)", err)
	}

	// Invalid disco key should be silently skipped (logged as debug).
	if !nm.SelfNode.DiscoKey().IsZero() {
		t.Error("expected zero disco key for invalid input")
	}
}

func TestParseDiscoKey(t *testing.T) {
	tests := map[string]struct {
		input   string
		wantErr bool
	}{
		"valid base64 key": {
			input: func() string {
				b64, _ := testDiscoKey()
				return b64
			}(),
			wantErr: false,
		},
		"invalid base64": {
			input:   "not-valid-base64!!!",
			wantErr: true,
		},
		"wrong length": {
			input:   "AQID", // 3 bytes
			wantErr: true,
		},
		"empty": {
			input:   "",
			wantErr: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			k, err := parseDiscoKey(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Error("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if k.IsZero() {
				t.Error("parsed key is zero")
			}
		})
	}
}
