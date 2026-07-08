package crypto

import (
	"bytes"
	"encoding/json"
	"testing"
)

// AES Key Wrap known-answer vector from RFC 3394 Section 4.6
// (256-bit KEK, 256-bit key data).
func TestAESKeyWrapRFC3394Vector(t *testing.T) {
	kek := mustHex(t, "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
	keyData := mustHex(t, "00112233445566778899AABBCCDDEEFF0001020304050607")
	wantWrap := mustHex(t, "A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1")

	wrapped, err := AESKeyWrap(kek, keyData)
	if err != nil {
		t.Fatalf("AESKeyWrap: %v", err)
	}
	if !bytes.Equal(wrapped, wantWrap) {
		t.Fatalf("wrapped = %X, want %X", wrapped, wantWrap)
	}

	unwrapped, err := AESKeyUnwrap(kek, wrapped)
	if err != nil {
		t.Fatalf("AESKeyUnwrap: %v", err)
	}
	if !bytes.Equal(unwrapped, keyData) {
		t.Fatalf("unwrapped = %X, want %X", unwrapped, keyData)
	}
}

func TestAESKeyUnwrapIntegrityFailure(t *testing.T) {
	kek := make([]byte, 32)
	wrapped, err := AESKeyWrap(kek, make([]byte, 32))
	if err != nil {
		t.Fatalf("AESKeyWrap: %v", err)
	}
	wrapped[0] ^= 0xFF // corrupt
	if _, err := AESKeyUnwrap(kek, wrapped); err == nil {
		t.Fatal("expected integrity check failure on corrupted ciphertext")
	}
}

// HD derivation is deterministic and chains through path segments.
func TestDeriveKeyBytesDeterministic(t *testing.T) {
	root, _, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair: %v", err)
	}
	path := []string{"protocolPath", "https://example.com/p", "network", "node"}

	a, err := DeriveKeyBytes(root, path)
	if err != nil {
		t.Fatalf("DeriveKeyBytes: %v", err)
	}
	b, err := DeriveKeyBytes(root, path)
	if err != nil {
		t.Fatalf("DeriveKeyBytes: %v", err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("derivation is not deterministic")
	}
	if len(a) != 32 {
		t.Fatalf("derived key length = %d, want 32", len(a))
	}

	// A different path yields a different key.
	c, err := DeriveKeyBytes(root, []string{"protocolPath", "https://example.com/p", "network", "member"})
	if err != nil {
		t.Fatalf("DeriveKeyBytes: %v", err)
	}
	if bytes.Equal(a, c) {
		t.Fatal("different paths produced the same key")
	}
}

func TestJWKThumbprintX25519MatchesKnownValue(t *testing.T) {
	// Known-answer pairing generated with the @enbox SDK's
	// computeJwkThumbprint (RFC 7638).
	x := "bOFlq67TRRnDaJdDNh4GefffY5BtzaATOKbNkxnV6HU"
	want := "GWQ0SrfSGBfA_gZ55aKto0SoOP-bH4Mi8LNqRUsCOUo"
	if got := JWKThumbprintX25519(x); got != want {
		t.Fatalf("thumbprint = %q, want %q", got, want)
	}
}

// EncryptData (protocolPath) round-trips through DecryptData with a key
// derived at the record's protocol path.
func TestEncryptDecryptProtocolPathRoundTrip(t *testing.T) {
	root, _, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair: %v", err)
	}
	mgr := &EncryptionKeyManager{
		RootPrivateKey: root,
		RootKeyID:      "did:test#enc",
		ProtocolURI:    "https://example.com/proto",
	}

	// The write side wraps to the derived leaf PUBLIC key (published as the
	// rule set's $keyAgreement key).
	_, leafPub, err := DerivePrivateKey(root, BuildProtocolPathDerivation(mgr.ProtocolURI, "network", "node"))
	if err != nil {
		t.Fatalf("DerivePrivateKey: %v", err)
	}

	plaintext := []byte(`{"secret":"v1 round trip","n":7}`)
	ciphertext, enc, err := EncryptData(plaintext, []KeyEncryptionInput{
		{PublicKey: leafPub, DerivationScheme: DerivationSchemeProtocolPath},
	})
	if err != nil {
		t.Fatalf("EncryptData: %v", err)
	}
	if enc.Algorithm != EncA256CTR {
		t.Fatalf("algorithm = %q, want %q", enc.Algorithm, EncA256CTR)
	}
	if len(enc.KeyEncryption) != 1 || enc.KeyEncryption[0].DerivationScheme != DerivationSchemeProtocolPath {
		t.Fatalf("unexpected keyEncryption: %+v", enc.KeyEncryption)
	}
	if enc.KeyEncryption[0].KeyID != thumbprintForPublicKey(leafPub) {
		t.Fatalf("keyId = %q, want thumbprint of the wrap target", enc.KeyEncryption[0].KeyID)
	}
	if bytes.Equal(ciphertext, plaintext) {
		t.Fatal("ciphertext equals plaintext")
	}

	leafPriv, err := mgr.DeriveDecryptionKey("network/node")
	if err != nil {
		t.Fatalf("DeriveDecryptionKey: %v", err)
	}
	decrypted, err := DecryptData(ciphertext, enc, leafPriv)
	if err != nil {
		t.Fatalf("DecryptData: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("decrypted = %q, want %q", decrypted, plaintext)
	}

	// A wrong key fails (integrity check on AES-KW unwrap).
	wrong, _ := mgr.DeriveDecryptionKey("network/member")
	if _, err := DecryptData(ciphertext, enc, wrong); err == nil {
		t.Fatal("expected decryption with the wrong key to fail")
	}
}

func TestEncryptDataMultiRecipientSelectsByThumbprint(t *testing.T) {
	_, pub1, _ := GenerateX25519KeyPair()
	priv2, pub2, _ := GenerateX25519KeyPair()

	plaintext := []byte("multi")
	ct, enc, err := EncryptData(plaintext, []KeyEncryptionInput{
		{PublicKey: pub1, DerivationScheme: DerivationSchemeProtocolPath},
		{PublicKey: pub2, DerivationScheme: DerivationSchemeProtocolPath},
	})
	if err != nil {
		t.Fatalf("EncryptData: %v", err)
	}
	if len(enc.KeyEncryption) != 2 {
		t.Fatalf("keyEncryption entries = %d, want 2", len(enc.KeyEncryption))
	}
	got, err := DecryptData(ct, enc, priv2)
	if err != nil {
		t.Fatalf("DecryptData(recipient 2): %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("decrypted = %q, want %q", got, plaintext)
	}
}

// InjectEncryptionDirectives injects the sealed-model $keyAgreement shape:
// exactly {"publicKeyJwk": {...}} per rule set plus a top-level protocol-level
// $keyAgreement, skipping $ref attachment points.
func TestInjectEncryptionDirectivesUsesKeyAgreement(t *testing.T) {
	root, _, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair: %v", err)
	}
	definition := json.RawMessage(`{
		"protocol": "https://example.com/p",
		"structure": {
			"network": { "node": {} },
			"attachment": { "$ref": "other:thing", "child": {} }
		}
	}`)

	out, err := InjectEncryptionDirectives(definition, root)
	if err != nil {
		t.Fatalf("InjectEncryptionDirectives: %v", err)
	}

	var def map[string]any
	if err := json.Unmarshal(out, &def); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// Top-level $keyAgreement holds the protocol-level derived public key.
	topKA, ok := def["$keyAgreement"].(map[string]any)
	if !ok {
		t.Fatalf("definition missing top-level $keyAgreement: %v", def)
	}
	protoPriv, protoPub, err := DerivePrivateKey(root, []string{"protocolPath", "https://example.com/p"})
	if err != nil {
		t.Fatalf("DerivePrivateKey: %v", err)
	}
	defer clear(protoPriv)
	if got := topKA["publicKeyJwk"].(map[string]any)["x"]; got != base64URLEncode(protoPub) {
		t.Fatalf("top-level $keyAgreement x = %v, want protocol-level derived key", got)
	}

	network := def["structure"].(map[string]any)["network"].(map[string]any)
	ka, ok := network["$keyAgreement"].(map[string]any)
	if !ok {
		t.Fatalf("network missing $keyAgreement directive: %v", network)
	}
	if _, bad := network["$encryption"]; bad {
		t.Fatal("network should not contain the pre-v1 $encryption directive")
	}
	// Exactly one member: publicKeyJwk (server enforces
	// additionalProperties:false — rootKeyId must NOT be emitted).
	if len(ka) != 1 {
		t.Fatalf("$keyAgreement must contain only publicKeyJwk, got %v", ka)
	}
	pub := ka["publicKeyJwk"].(map[string]any)
	if pub["crv"] != "X25519" || pub["kty"] != "OKP" || pub["x"] == "" {
		t.Fatalf("publicKeyJwk = %v", pub)
	}

	// The injected key matches the deterministic derivation for the path.
	nodePriv, nodePub, err := DerivePrivateKey(root, []string{"protocolPath", "https://example.com/p", "network", "node"})
	if err != nil {
		t.Fatalf("DerivePrivateKey: %v", err)
	}
	defer clear(nodePriv)
	node := network["node"].(map[string]any)
	nodeKA := node["$keyAgreement"].(map[string]any)["publicKeyJwk"].(map[string]any)
	if nodeKA["x"] != base64URLEncode(nodePub) {
		t.Fatalf("node $keyAgreement x = %v, want %v", nodeKA["x"], base64URLEncode(nodePub))
	}

	// $ref nodes get no $keyAgreement, but their children do.
	attachment := def["structure"].(map[string]any)["attachment"].(map[string]any)
	if _, bad := attachment["$keyAgreement"]; bad {
		t.Fatal("$ref attachment point must not get a $keyAgreement directive")
	}
	child := attachment["child"].(map[string]any)
	if _, ok := child["$keyAgreement"]; !ok {
		t.Fatal("children of $ref attachment points must still get $keyAgreement")
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b := make([]byte, len(s)/2)
	for i := 0; i < len(b); i++ {
		var hi, lo byte
		hi = hexNibble(t, s[2*i])
		lo = hexNibble(t, s[2*i+1])
		b[i] = hi<<4 | lo
	}
	return b
}

func hexNibble(t *testing.T, c byte) byte {
	t.Helper()
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	}
	t.Fatalf("invalid hex char %q", string(c))
	return 0
}
