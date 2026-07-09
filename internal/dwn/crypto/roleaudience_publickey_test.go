package crypto

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// TestRolePathPublicKeyJWKMatchesInjectedKeyAgreement is the load-bearing guard
// for issue #187: the PUBLIC role-path key a node emits in its join request must
// be byte-identical to the `$keyAgreement.publicKeyJwk` that
// InjectEncryptionDirectives publishes at the same path. If the two diverge, an
// owner wraps the `$encryption/delivery` record to the wrong key and the node
// silently fails to decrypt — the exact failure mode #187 exists to remove.
func TestRolePathPublicKeyJWKMatchesInjectedKeyAgreement(t *testing.T) {
	root, _, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair: %v", err)
	}
	const protocol = "https://example.com/p"
	// Mirrors the wireguard-mesh hierarchy for the node-held role paths.
	definition := json.RawMessage(`{
		"protocol": "https://example.com/p",
		"structure": { "network": { "member": { "node": {} }, "node": {} } }
	}`)

	out, err := InjectEncryptionDirectives(definition, root)
	if err != nil {
		t.Fatalf("InjectEncryptionDirectives: %v", err)
	}
	var def map[string]any
	if err := json.Unmarshal(out, &def); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	for _, rolePath := range []string{"network/node", "network/member/node"} {
		injected := injectedKeyAgreementX(t, def, rolePath)

		jwk, err := RolePathPublicKeyJWK(root, protocol, rolePath)
		if err != nil {
			t.Fatalf("RolePathPublicKeyJWK(%s): %v", rolePath, err)
		}
		if jwk.KTY != "OKP" || jwk.CRV != "X25519" {
			t.Fatalf("%s: jwk kty/crv = %s/%s, want OKP/X25519", rolePath, jwk.KTY, jwk.CRV)
		}
		if jwk.KID != "" {
			t.Fatalf("%s: jwk must omit kid to match the injected wire shape, got %q", rolePath, jwk.KID)
		}
		if jwk.X != injected {
			t.Fatalf("%s: RolePathPublicKeyJWK x = %s, want injected %s", rolePath, jwk.X, injected)
		}
		raw, err := base64.RawURLEncoding.DecodeString(jwk.X)
		if err != nil || len(raw) != 32 {
			t.Fatalf("%s: x is not a 32-byte base64url key (len=%d err=%v)", rolePath, len(raw), err)
		}
	}
}

// TestRolePathPublicKeyJWKIsContextIndependent proves a node can precompute the
// network/member/node key before any approval assigns a member layer: the public
// key depends only on protocol + rolePath, never on a record/context id.
func TestRolePathPublicKeyJWKIsContextIndependent(t *testing.T) {
	root, _, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair: %v", err)
	}
	const protocol = "https://example.com/p"
	a, err := RolePathPublicKeyJWK(root, protocol, "network/member/node")
	if err != nil {
		t.Fatalf("RolePathPublicKeyJWK a: %v", err)
	}
	b, err := RolePathPublicKeyJWK(root, protocol, "network/member/node")
	if err != nil {
		t.Fatalf("RolePathPublicKeyJWK b: %v", err)
	}
	if a.X != b.X {
		t.Fatalf("role-path key is not deterministic: %s vs %s", a.X, b.X)
	}
	// A different rolePath yields a different key (no accidental collision).
	other, err := RolePathPublicKeyJWK(root, protocol, "network/node")
	if err != nil {
		t.Fatalf("RolePathPublicKeyJWK other: %v", err)
	}
	if other.X == a.X {
		t.Fatalf("network/node and network/member/node derived the same key: %s", a.X)
	}
}

// injectedKeyAgreementX walks an injected definition to the
// $keyAgreement.publicKeyJwk.x at a slash-delimited role path.
func injectedKeyAgreementX(t *testing.T, def map[string]any, rolePath string) string {
	t.Helper()
	node, ok := def["structure"].(map[string]any)
	if !ok {
		t.Fatalf("definition missing structure")
	}
	segs := strings.Split(rolePath, "/")
	for i, seg := range segs {
		child, ok := node[seg].(map[string]any)
		if !ok {
			t.Fatalf("path %s: missing segment %q", rolePath, seg)
		}
		if i == len(segs)-1 {
			ka, ok := child["$keyAgreement"].(map[string]any)
			if !ok {
				t.Fatalf("path %s: missing $keyAgreement", rolePath)
			}
			pub, ok := ka["publicKeyJwk"].(map[string]any)
			if !ok {
				t.Fatalf("path %s: $keyAgreement missing publicKeyJwk", rolePath)
			}
			x, _ := pub["x"].(string)
			return x
		}
		node = child
	}
	return ""
}
