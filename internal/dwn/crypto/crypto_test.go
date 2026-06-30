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

func TestJWKThumbprintX25519MatchesFixture(t *testing.T) {
	// From testdata/v1/protocolpath.json ephemeralPublicKey/keyId pairing is
	// dynamic; use the reader public key whose thumbprint is the documented kid.
	x := "bOFlq67TRRnDaJdDNh4GefffY5BtzaATOKbNkxnV6HU"
	want := "GWQ0SrfSGBfA_gZ55aKto0SoOP-bH4Mi8LNqRUsCOUo"
	if got := JWKThumbprintX25519(x); got != want {
		t.Fatalf("thumbprint = %q, want %q", got, want)
	}
}

// EncryptData (protocolPath) round-trips through DecryptData.
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

	recipients, err := mgr.DeriveWriteEncryption("network/node")
	if err != nil {
		t.Fatalf("DeriveWriteEncryption: %v", err)
	}

	plaintext := []byte(`{"secret":"v1 round trip","n":7}`)
	ciphertext, enc, err := EncryptData(plaintext, recipients)
	if err != nil {
		t.Fatalf("EncryptData: %v", err)
	}
	if enc.Algorithm != EncA256CTR {
		t.Fatalf("algorithm = %q, want %q", enc.Algorithm, EncA256CTR)
	}
	if len(enc.KeyEncryption) != 1 || enc.KeyEncryption[0].DerivationScheme != DerivationSchemeProtocolPath {
		t.Fatalf("unexpected keyEncryption: %+v", enc.KeyEncryption)
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

// InjectEncryptionDirectives injects $keyAgreement (encryption-v1), not the
// pre-v1 $encryption directive, and is deterministic for a fixed root.
func TestInjectEncryptionDirectivesUsesKeyAgreement(t *testing.T) {
	root, _, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair: %v", err)
	}
	definition := json.RawMessage(`{
		"protocol": "https://example.com/p",
		"structure": { "network": { "node": {} } }
	}`)

	out, err := InjectEncryptionDirectives(definition, root, "did:test#enc")
	if err != nil {
		t.Fatalf("InjectEncryptionDirectives: %v", err)
	}

	var def map[string]any
	if err := json.Unmarshal(out, &def); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	network := def["structure"].(map[string]any)["network"].(map[string]any)
	ka, ok := network["$keyAgreement"].(map[string]any)
	if !ok {
		t.Fatalf("network missing $keyAgreement directive: %v", network)
	}
	if _, bad := network["$encryption"]; bad {
		t.Fatal("network should not contain the pre-v1 $encryption directive")
	}
	if ka["rootKeyId"] != "did:test#enc" {
		t.Fatalf("rootKeyId = %v", ka["rootKeyId"])
	}
	pub := ka["publicKeyJwk"].(map[string]any)
	if pub["crv"] != "X25519" || pub["kty"] != "OKP" || pub["x"] == "" {
		t.Fatalf("publicKeyJwk = %v", pub)
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
