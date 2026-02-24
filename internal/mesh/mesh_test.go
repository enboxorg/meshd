package mesh

import (
	"encoding/base64"
	"net/netip"
	"testing"
)

// =============================================================================
// WireGuard key tests
// =============================================================================

func TestGenerateWireGuardKeyPair(t *testing.T) {
	kp, err := GenerateWireGuardKeyPair()
	if err != nil {
		t.Fatalf("GenerateWireGuardKeyPair: %v", err)
	}

	// Verify key sizes.
	if len(kp.PrivateKey) != WireGuardKeySize {
		t.Fatalf("private key size = %d, want %d", len(kp.PrivateKey), WireGuardKeySize)
	}
	if len(kp.PublicKey) != WireGuardKeySize {
		t.Fatalf("public key size = %d, want %d", len(kp.PublicKey), WireGuardKeySize)
	}

	// Verify clamping.
	if kp.PrivateKey[0]&7 != 0 {
		t.Fatal("private key bits 0-2 not cleared")
	}
	if kp.PrivateKey[31]&128 != 0 {
		t.Fatal("private key bit 255 not cleared")
	}
	if kp.PrivateKey[31]&64 == 0 {
		t.Fatal("private key bit 254 not set")
	}

	// Public key should not be all zeros.
	allZero := true
	for _, b := range kp.PublicKey {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Fatal("public key is all zeros")
	}
}

func TestWireGuardKeyPairFromPrivate(t *testing.T) {
	original, err := GenerateWireGuardKeyPair()
	if err != nil {
		t.Fatalf("generating: %v", err)
	}

	restored, err := WireGuardKeyPairFromPrivate(original.PrivateKey[:])
	if err != nil {
		t.Fatalf("WireGuardKeyPairFromPrivate: %v", err)
	}

	if original.PublicKey != restored.PublicKey {
		t.Fatal("public keys don't match")
	}
}

func TestWireGuardKeyPairBase64(t *testing.T) {
	kp, err := GenerateWireGuardKeyPair()
	if err != nil {
		t.Fatalf("generating: %v", err)
	}

	pubB64 := kp.PublicKeyBase64()
	raw, err := base64.StdEncoding.DecodeString(pubB64)
	if err != nil {
		t.Fatalf("decoding public key base64: %v", err)
	}
	if len(raw) != WireGuardKeySize {
		t.Fatalf("decoded size = %d, want %d", len(raw), WireGuardKeySize)
	}

	privB64 := kp.PrivateKeyBase64()
	raw, err = base64.StdEncoding.DecodeString(privB64)
	if err != nil {
		t.Fatalf("decoding private key base64: %v", err)
	}
	if len(raw) != WireGuardKeySize {
		t.Fatalf("decoded size = %d, want %d", len(raw), WireGuardKeySize)
	}
}

func TestGenerateWireGuardKeyPair_Unique(t *testing.T) {
	kp1, _ := GenerateWireGuardKeyPair()
	kp2, _ := GenerateWireGuardKeyPair()

	if kp1.PublicKey == kp2.PublicKey {
		t.Fatal("two generated key pairs should differ")
	}
}

// =============================================================================
// IP allocation tests
// =============================================================================

func TestAllocateMeshIP(t *testing.T) {
	tests := map[string]struct {
		cidr string
		did  string
	}{
		"default CIDR": {
			cidr: "10.200.0.0/16",
			did:  "did:dht:test123",
		},
		"small CIDR": {
			cidr: "10.200.1.0/24",
			did:  "did:dht:test456",
		},
		"different DID": {
			cidr: "10.200.0.0/16",
			did:  "did:dht:other789",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			ip, err := AllocateMeshIP(tc.cidr, tc.did)
			if err != nil {
				t.Fatalf("AllocateMeshIP: %v", err)
			}

			if !ip.Is4() {
				t.Fatalf("expected IPv4, got %s", ip)
			}

			// Verify IP is within the CIDR.
			prefix, _ := netip.ParsePrefix(tc.cidr)
			if !prefix.Contains(ip) {
				t.Fatalf("allocated IP %s not in CIDR %s", ip, tc.cidr)
			}

			// Verify not the network address.
			base := prefix.Addr().As4()
			allocated := ip.As4()
			if base == allocated {
				t.Fatalf("allocated IP is the network address")
			}
		})
	}
}

func TestAllocateMeshIP_Deterministic(t *testing.T) {
	ip1, err := AllocateMeshIP("10.200.0.0/16", "did:dht:same-did")
	if err != nil {
		t.Fatalf("first allocation: %v", err)
	}

	ip2, err := AllocateMeshIP("10.200.0.0/16", "did:dht:same-did")
	if err != nil {
		t.Fatalf("second allocation: %v", err)
	}

	if ip1 != ip2 {
		t.Fatalf("same DID should produce same IP: got %s and %s", ip1, ip2)
	}
}

func TestAllocateMeshIP_DifferentDIDs(t *testing.T) {
	ip1, _ := AllocateMeshIP("10.200.0.0/16", "did:dht:alice")
	ip2, _ := AllocateMeshIP("10.200.0.0/16", "did:dht:bob")

	if ip1 == ip2 {
		t.Fatalf("different DIDs should (usually) produce different IPs: both got %s", ip1)
	}
}

func TestAllocateMeshIP_NotBroadcast(t *testing.T) {
	// Test with /24 where broadcast would be .255
	for i := 0; i < 100; i++ {
		did := "did:dht:" + string(rune('A'+i))
		ip, err := AllocateMeshIP("10.200.1.0/24", did)
		if err != nil {
			t.Fatalf("allocation for %s: %v", did, err)
		}

		octets := ip.As4()
		if octets[3] == 0 {
			t.Fatalf("allocated network address for %s: %s", did, ip)
		}
		if octets[3] == 255 {
			t.Fatalf("allocated broadcast address for %s: %s", did, ip)
		}
	}
}

func TestAllocateMeshIP_InvalidCIDR(t *testing.T) {
	_, err := AllocateMeshIP("invalid", "did:dht:test")
	if err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
}

func TestAllocateMeshIP_TooSmallCIDR(t *testing.T) {
	_, err := AllocateMeshIP("10.200.0.0/31", "did:dht:test")
	if err == nil {
		t.Fatal("expected error for /31 CIDR")
	}
}
