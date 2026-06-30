package mesh

import (
	"encoding/base64"
	"net/netip"
	"strings"
	"testing"

	"github.com/enboxorg/meshd/internal/did"
	"github.com/enboxorg/meshd/internal/dwn"
	"github.com/enboxorg/meshd/internal/invite"
	"github.com/enboxorg/meshd/pkg/dids/didjwk"
)

// =============================================================================
// WireGuard key tests
// =============================================================================

func TestWireGuardKeyFromIdentity(t *testing.T) {
	id, err := didjwk.Create()
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	kp, err := WireGuardKeyFromIdentity(id.X25519PrivateKey)
	if err != nil {
		t.Fatalf("WireGuardKeyFromIdentity: %v", err)
	}

	// Verify key sizes.
	if len(kp.PrivateKey) != WireGuardKeySize {
		t.Fatalf("private key size = %d, want %d", len(kp.PrivateKey), WireGuardKeySize)
	}
	if len(kp.PublicKey) != WireGuardKeySize {
		t.Fatalf("public key size = %d, want %d", len(kp.PublicKey), WireGuardKeySize)
	}

	// X25519 keys from identity are already clamped.
	if kp.PrivateKey[0]&7 != 0 {
		t.Fatal("private key bits 0-2 not cleared")
	}
	if kp.PrivateKey[31]&128 != 0 {
		t.Fatal("private key bit 255 not cleared")
	}
	if kp.PrivateKey[31]&64 == 0 {
		t.Fatal("private key bit 254 not set")
	}

	// Public key should match the identity's X25519 public key.
	if string(kp.PublicKey[:]) != string(id.X25519PublicKey) {
		t.Fatal("public key does not match identity's X25519 public key")
	}
}

func TestWireGuardKeyFromIdentity_InvalidLength(t *testing.T) {
	_, err := WireGuardKeyFromIdentity([]byte("too short"))
	if err == nil {
		t.Fatal("expected error for invalid key length")
	}
}

func TestWireGuardPubKeyFromDID(t *testing.T) {
	id, err := didjwk.Create()
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	kp, err := WireGuardKeyFromIdentity(id.X25519PrivateKey)
	if err != nil {
		t.Fatalf("WireGuardKeyFromIdentity: %v", err)
	}

	// Peer derives public key from the DID URI only.
	peerDerived, err := WireGuardPubKeyFromDID(id.URI)
	if err != nil {
		t.Fatalf("WireGuardPubKeyFromDID: %v", err)
	}

	// Should match the key pair's public key.
	if peerDerived != kp.PublicKeyBase64() {
		t.Fatalf("peer-derived pubkey %q != identity pubkey %q", peerDerived, kp.PublicKeyBase64())
	}
}

func TestWireGuardKeyPairBase64(t *testing.T) {
	id, err := didjwk.Create()
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	kp, err := WireGuardKeyFromIdentity(id.X25519PrivateKey)
	if err != nil {
		t.Fatalf("WireGuardKeyFromIdentity: %v", err)
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

func TestWireGuardKeyFromIdentity_Deterministic(t *testing.T) {
	id, err := didjwk.Create()
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	kp1, _ := WireGuardKeyFromIdentity(id.X25519PrivateKey)
	kp2, _ := WireGuardKeyFromIdentity(id.X25519PrivateKey)

	if kp1.PublicKey != kp2.PublicKey {
		t.Fatal("same identity should produce same WG key pair")
	}
}

func TestNodeJoinProofRoundTrip(t *testing.T) {
	node, err := did.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	signer := &dwn.Signer{DID: node.URI, PrivateKey: node.SigningKey}

	proof := SignNodeJoinProof(signer, "network-record", node.URI, "did:dht:member", "preauth-record")
	if proof == "" {
		t.Fatal("proof is empty")
	}
	if !VerifyNodeJoinProof(node.URI, proof, "network-record", "did:dht:member", "preauth-record") {
		t.Fatal("proof did not verify")
	}
	if VerifyNodeJoinProof(node.URI, proof, "other-network", "did:dht:member", "preauth-record") {
		t.Fatal("proof verified for a different network")
	}
}

func TestPreAuthNodeRequestDataSignsProofs(t *testing.T) {
	node, err := did.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	signer := &dwn.Signer{DID: node.URI, PrivateKey: node.SigningKey}
	payload := invite.New(
		"https://dwn.example",
		"did:jwk:anchor",
		"network-record",
		"test-net",
		"preauth-record",
		"preauth-secret",
		"",
	)

	got, err := preAuthNodeRequestData(WritePreAuthNodeRequestParams{
		Invite:      payload,
		NodeDID:     node.URI,
		MemberDID:   "did:jwk:wallet",
		RequestedBy: node.URI,
		Signer:      signer,
		Label:       "laptop",
	})
	if err != nil {
		t.Fatalf("preAuthNodeRequestData: %v", err)
	}
	if got.NodeDID != node.URI {
		t.Fatalf("node DID = %q, want %q", got.NodeDID, node.URI)
	}
	if got.MemberDID != "did:jwk:wallet" {
		t.Fatalf("member DID = %q", got.MemberDID)
	}
	if got.OwnerDID != "did:jwk:wallet" {
		t.Fatalf("owner DID = %q", got.OwnerDID)
	}
	if !VerifyNodeJoinProof(got.NodeDID, got.NodeProof, payload.NetworkID, got.MemberDID, payload.TokenID) {
		t.Fatal("node proof did not verify")
	}
	if !invite.VerifyProof(payload.Secret, payload.NetworkID, got.NodeDID, got.PreAuthProof) {
		t.Fatal("preauth proof did not verify")
	}
	if got.RequestedAt == "" {
		t.Fatal("requestedAt is empty")
	}
}

func TestWireGuardKeyFromIdentity_DifferentIdentities(t *testing.T) {
	id1, _ := didjwk.Create()
	id2, _ := didjwk.Create()

	kp1, _ := WireGuardKeyFromIdentity(id1.X25519PrivateKey)
	kp2, _ := WireGuardKeyFromIdentity(id2.X25519PrivateKey)

	if kp1.PublicKey == kp2.PublicKey {
		t.Fatal("different identities should produce different WG keys")
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

// =============================================================================
// Endpoint discovery tests
// =============================================================================

func TestDiscoverLocalEndpoints_ReturnsIPPort(t *testing.T) {
	endpoints := DiscoverLocalEndpoints(51820)

	// On any machine with a network interface we should get at least one
	// endpoint, but in minimal CI containers we might get zero.
	// Just verify format correctness for whatever we get.
	for _, ep := range endpoints {
		ap, err := netip.ParseAddrPort(ep)
		if err != nil {
			t.Errorf("endpoint %q is not a valid ip:port: %v", ep, err)
			continue
		}
		if ap.Port() != 51820 {
			t.Errorf("endpoint %q has port %d, want 51820", ep, ap.Port())
		}
		// Must not be loopback or link-local.
		addr := ap.Addr()
		if addr.IsLoopback() {
			t.Errorf("endpoint %q is loopback", ep)
		}
		if addr.IsLinkLocalUnicast() {
			t.Errorf("endpoint %q is link-local", ep)
		}
	}
}

func TestDiscoverLocalEndpoints_DefaultPort(t *testing.T) {
	endpoints := DiscoverLocalEndpoints(0) // 0 should default to 41641.

	for _, ep := range endpoints {
		ap, err := netip.ParseAddrPort(ep)
		if err != nil {
			t.Errorf("endpoint %q is not valid: %v", ep, err)
			continue
		}
		if ap.Port() != 41641 {
			t.Errorf("endpoint %q has port %d, want default 41641", ep, ap.Port())
		}
	}
}

func TestDiscoverLocalEndpoints_NoLoopback(t *testing.T) {
	endpoints := DiscoverLocalEndpoints(51820)

	for _, ep := range endpoints {
		if strings.HasPrefix(ep, "127.") || strings.HasPrefix(ep, "[::1]") {
			t.Errorf("loopback address discovered: %s", ep)
		}
	}
}

func TestDiscoverLocalEndpoints_NoDuplicates(t *testing.T) {
	endpoints := DiscoverLocalEndpoints(51820)

	seen := make(map[string]bool, len(endpoints))
	for _, ep := range endpoints {
		if seen[ep] {
			t.Errorf("duplicate endpoint: %s", ep)
		}
		seen[ep] = true
	}
}
