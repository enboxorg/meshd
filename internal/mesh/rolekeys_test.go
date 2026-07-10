package mesh

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/enboxorg/meshd/internal/dwn"
	dwncrypto "github.com/enboxorg/meshd/internal/dwn/crypto"
	"github.com/enboxorg/meshd/internal/invite"
	"github.com/enboxorg/meshd/protocols"
)

// A did:jwk node publishes no DWN endpoint, so the owner cannot resolve its
// role-path keys by DID. The node must therefore emit the public half of every
// role-path key it needs delivered to it: the READING role a member-invited node
// authorizes as (network/member — the audience its peer records are encrypted to,
// issue #192) plus the roles it may HOLD (network/node, network/member/node).
func TestNodeRoleKeysEmitsReadingAndHeldPaths(t *testing.T) {
	root, _, err := dwncrypto.GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair: %v", err)
	}

	keys, err := nodeRoleKeys(root)
	if err != nil {
		t.Fatalf("nodeRoleKeys: %v", err)
	}

	want := map[string]bool{"network/member": true, "network/node": true, "network/member/node": true}
	if len(keys) != len(want) {
		t.Fatalf("nodeRoleKeys returned %d paths (%v), want exactly %v", len(keys), keysOf(keys), keysOf(mapKeys(want)))
	}
	if _, ok := keys["network/member"]; !ok {
		t.Fatal("nodeRoleKeys must emit network/member: it is the reading-role audience the node decrypts its peers with (#192)")
	}
	for path := range want {
		jwk, ok := keys[path]
		if !ok {
			t.Fatalf("nodeRoleKeys missing required path %q", path)
		}
		if jwk.KTY != "OKP" || jwk.CRV != "X25519" {
			t.Fatalf("%s: kty/crv = %s/%s, want OKP/X25519", path, jwk.KTY, jwk.CRV)
		}
		if jwk.KID != "" {
			t.Fatalf("%s: kid must be empty to match the injected wire shape, got %q", path, jwk.KID)
		}
		raw, err := base64.RawURLEncoding.DecodeString(jwk.X)
		if err != nil || len(raw) != 32 {
			t.Fatalf("%s: x is not a 32-byte base64url key (len=%d err=%v)", path, len(raw), err)
		}
	}
}

// Nodes without an encryption key (or callers that opt out) must omit roleKeys
// entirely so the request stays wire-compatible with older readers.
func TestNodeRoleKeysEmptyKeyOmitsField(t *testing.T) {
	for _, key := range [][]byte{nil, {}} {
		keys, err := nodeRoleKeys(key)
		if err != nil {
			t.Fatalf("nodeRoleKeys(%v): %v", key, err)
		}
		if keys != nil {
			t.Fatalf("nodeRoleKeys(%v) = %v, want nil", key, keys)
		}
	}
}

// The public key a node emits per role path must be byte-identical to the
// $keyAgreement.publicKeyJwk the same node injects into the REAL mesh protocol
// definition — otherwise the owner wraps the delivery to the wrong key and the
// node silently fails to decrypt (issue #187).
func TestNodeRoleKeysMatchInjectedMeshProtocol(t *testing.T) {
	root, _, err := dwncrypto.GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair: %v", err)
	}

	injected, err := dwncrypto.InjectEncryptionDirectives(protocols.MeshProtocolJSON, root)
	if err != nil {
		t.Fatalf("InjectEncryptionDirectives: %v", err)
	}
	var def map[string]any
	if err := json.Unmarshal(injected, &def); err != nil {
		t.Fatalf("unmarshal injected definition: %v", err)
	}

	keys, err := nodeRoleKeys(root)
	if err != nil {
		t.Fatalf("nodeRoleKeys: %v", err)
	}
	for path, jwk := range keys {
		want := injectedKeyAgreementX(t, def, path)
		if want == "" {
			t.Fatalf("real mesh protocol has no $keyAgreement at %q", path)
		}
		if jwk.X != want {
			t.Fatalf("%s: emitted x = %s, want injected %s", path, jwk.X, want)
		}
	}
}

func TestPreAuthNodeRequestDataPopulatesRoleKeys(t *testing.T) {
	node := preAuthTestDID(t)
	base := WritePreAuthNodeRequestParams{
		Invite:  invite.Payload{NetworkID: "net-1", TokenID: "tok-1"},
		NodeDID: node.URI,
		Signer:  &dwn.Signer{DID: node.URI, PrivateKey: node.SigningKey},
	}

	withKey := base
	withKey.NodeEncryptionKey = node.EncryptionPrivateKey
	data, err := preAuthNodeRequestData(withKey)
	if err != nil {
		t.Fatalf("preAuthNodeRequestData(with key): %v", err)
	}
	assertNodeHeldRoleKeys(t, node.EncryptionPrivateKey, data.RoleKeys)

	data, err = preAuthNodeRequestData(base)
	if err != nil {
		t.Fatalf("preAuthNodeRequestData(no key): %v", err)
	}
	if data.RoleKeys != nil {
		t.Fatalf("RoleKeys = %v, want nil when no encryption key supplied", data.RoleKeys)
	}
}

func TestOwnerNodeRequestDataPopulatesRoleKeys(t *testing.T) {
	node := preAuthTestDID(t)
	owner := preAuthTestDID(t)
	base := OwnerNodeRequestParams{
		OwnerEndpoint: "https://owner.example",
		OwnerDID:      owner.URI,
		NodeDID:       node.URI,
		Signer:        &dwn.Signer{DID: node.URI, PrivateKey: node.SigningKey},
	}

	withKey := base
	withKey.NodeEncryptionKey = node.EncryptionPrivateKey
	data, err := ownerNodeRequestData(withKey)
	if err != nil {
		t.Fatalf("ownerNodeRequestData(with key): %v", err)
	}
	assertNodeHeldRoleKeys(t, node.EncryptionPrivateKey, data.RoleKeys)

	data, err = ownerNodeRequestData(base)
	if err != nil {
		t.Fatalf("ownerNodeRequestData(no key): %v", err)
	}
	if data.RoleKeys != nil {
		t.Fatalf("RoleKeys = %v, want nil when no encryption key supplied", data.RoleKeys)
	}
}

// RoleKeys must survive a JSON round-trip (the record is marshaled to the DWN
// and re-read by the owner), and must be omitted from the wire when empty.
func TestNodeRequestDataRoleKeysJSONRoundTrip(t *testing.T) {
	root, _, err := dwncrypto.GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair: %v", err)
	}
	keys, err := nodeRoleKeys(root)
	if err != nil {
		t.Fatalf("nodeRoleKeys: %v", err)
	}

	in := NodeRequestData{NodeDID: "did:jwk:node", RoleKeys: keys}
	blob, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out NodeRequestData
	if err := json.Unmarshal(blob, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for path, want := range keys {
		got, ok := out.RoleKeys[path]
		if !ok {
			t.Fatalf("round-trip lost path %q", path)
		}
		if got != want {
			t.Fatalf("%s: round-trip = %+v, want %+v", path, got, want)
		}
	}

	// Empty RoleKeys must be omitted (omitempty) so the field is absent on the wire.
	empty, err := json.Marshal(NodeRequestData{NodeDID: "did:jwk:node"})
	if err != nil {
		t.Fatalf("marshal empty: %v", err)
	}
	if strings.Contains(string(empty), "roleKeys") {
		t.Fatalf("empty NodeRequestData emitted roleKeys: %s", empty)
	}
}

func assertNodeHeldRoleKeys(t *testing.T, root []byte, got map[string]dwncrypto.PublicKeyJWK) {
	t.Helper()
	want, err := nodeRoleKeys(root)
	if err != nil {
		t.Fatalf("nodeRoleKeys: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("role keys = %v, want %v", keysOf(got), keysOf(want))
	}
	for path, wantJWK := range want {
		if got[path] != wantJWK {
			t.Fatalf("%s: got %+v, want %+v", path, got[path], wantJWK)
		}
	}
}

func keysOf(m map[string]dwncrypto.PublicKeyJWK) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func mapKeys(m map[string]bool) map[string]dwncrypto.PublicKeyJWK {
	out := make(map[string]dwncrypto.PublicKeyJWK, len(m))
	for k := range m {
		out[k] = dwncrypto.PublicKeyJWK{}
	}
	return out
}

// injectedKeyAgreementX walks an injected mesh definition to the
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
			return ""
		}
		if i == len(segs)-1 {
			ka, ok := child["$keyAgreement"].(map[string]any)
			if !ok {
				return ""
			}
			pub, ok := ka["publicKeyJwk"].(map[string]any)
			if !ok {
				return ""
			}
			x, _ := pub["x"].(string)
			return x
		}
		node = child
	}
	return ""
}
