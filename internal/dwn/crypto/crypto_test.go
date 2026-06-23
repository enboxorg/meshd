package crypto

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"

	"golang.org/x/crypto/curve25519"
)

// =============================================================================
// AEAD tests
// =============================================================================

func TestAEADEncryptDecryptRoundTrip(t *testing.T) {
	tests := map[string]struct {
		plaintext []byte
	}{
		"empty plaintext": {
			plaintext: []byte{},
		},
		"short message": {
			plaintext: []byte("hello, DWN!"),
		},
		"exact block size": {
			plaintext: bytes.Repeat([]byte("A"), 16),
		},
		"large message": {
			plaintext: bytes.Repeat([]byte("B"), 1<<16),
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			cek, err := GenerateCEK()
			if err != nil {
				t.Fatalf("GenerateCEK: %v", err)
			}
			iv, err := GenerateIV(EncA256GCM)
			if err != nil {
				t.Fatalf("GenerateIV: %v", err)
			}

			ct, tag, err := AEADEncrypt(EncA256GCM, cek, iv, tc.plaintext, nil)
			if err != nil {
				t.Fatalf("AEADEncrypt: %v", err)
			}

			if len(tag) != TagSize {
				t.Fatalf("tag length = %d, want %d", len(tag), TagSize)
			}

			got, err := AEADDecrypt(EncA256GCM, cek, iv, ct, tag, nil)
			if err != nil {
				t.Fatalf("AEADDecrypt: %v", err)
			}

			if !bytes.Equal(got, tc.plaintext) {
				t.Fatalf("decrypted data mismatch")
			}
		})
	}
}

func TestAEADWithAAD(t *testing.T) {
	cek, _ := GenerateCEK()
	iv, _ := GenerateIV(EncA256GCM)
	aad := []byte(`{"alg":"ECDH-ES+A256KW","enc":"A256GCM"}`)
	plaintext := []byte("authenticated associated data test")

	ct, tag, err := AEADEncrypt(EncA256GCM, cek, iv, plaintext, aad)
	if err != nil {
		t.Fatalf("AEADEncrypt with AAD: %v", err)
	}

	// Decrypt with correct AAD succeeds.
	got, err := AEADDecrypt(EncA256GCM, cek, iv, ct, tag, aad)
	if err != nil {
		t.Fatalf("AEADDecrypt with AAD: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatal("decrypted data mismatch with AAD")
	}

	// Decrypt with wrong AAD fails.
	_, err = AEADDecrypt(EncA256GCM, cek, iv, ct, tag, []byte("wrong aad"))
	if err == nil {
		t.Fatal("expected error with wrong AAD")
	}
}

func TestAEADWrongKey(t *testing.T) {
	cek1, _ := GenerateCEK()
	cek2, _ := GenerateCEK()
	iv, _ := GenerateIV(EncA256GCM)

	ct, tag, _ := AEADEncrypt(EncA256GCM, cek1, iv, []byte("secret"), nil)

	_, err := AEADDecrypt(EncA256GCM, cek2, iv, ct, tag, nil)
	if err == nil {
		t.Fatal("expected error with wrong key")
	}
}

func TestAEADTamperedTag(t *testing.T) {
	cek, _ := GenerateCEK()
	iv, _ := GenerateIV(EncA256GCM)

	ct, tag, _ := AEADEncrypt(EncA256GCM, cek, iv, []byte("secret"), nil)

	// Flip a bit in the tag.
	tag[0] ^= 0xFF

	_, err := AEADDecrypt(EncA256GCM, cek, iv, ct, tag, nil)
	if err == nil {
		t.Fatal("expected error with tampered tag")
	}
}

func TestAEADUnsupportedAlgorithm(t *testing.T) {
	_, err := GenerateIV("UNSUPPORTED")
	if err == nil {
		t.Fatal("expected error for unsupported algorithm")
	}

	_, _, err = AEADEncrypt("UNSUPPORTED", make([]byte, 32), make([]byte, 12), nil, nil)
	if err == nil {
		t.Fatal("expected error for unsupported algorithm")
	}

	_, err = AEADDecrypt("UNSUPPORTED", make([]byte, 32), make([]byte, 12), nil, nil, nil)
	if err == nil {
		t.Fatal("expected error for unsupported algorithm")
	}
}

func TestAEADInvalidKeySize(t *testing.T) {
	_, _, err := AEADEncrypt(EncA256GCM, make([]byte, 16), make([]byte, 12), []byte("x"), nil)
	if err == nil {
		t.Fatal("expected error for wrong key size")
	}
}

func TestAEADInvalidIVSize(t *testing.T) {
	_, _, err := AEADEncrypt(EncA256GCM, make([]byte, 32), make([]byte, 8), []byte("x"), nil)
	if err == nil {
		t.Fatal("expected error for wrong IV size")
	}
}

// =============================================================================
// AES Key Wrap tests
// =============================================================================

func TestAESKeyWrapRoundTrip(t *testing.T) {
	tests := map[string]struct {
		kekSize       int
		plaintextSize int
	}{
		"AES-128 wrap 128-bit key": {kekSize: 16, plaintextSize: 16},
		"AES-256 wrap 128-bit key": {kekSize: 32, plaintextSize: 16},
		"AES-256 wrap 256-bit key": {kekSize: 32, plaintextSize: 32},
		"AES-256 wrap 192-bit key": {kekSize: 32, plaintextSize: 24},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			kek := make([]byte, tc.kekSize)
			rand.Read(kek)

			key := make([]byte, tc.plaintextSize)
			rand.Read(key)

			wrapped, err := AESKeyWrap(kek, key)
			if err != nil {
				t.Fatalf("AESKeyWrap: %v", err)
			}

			// Wrapped output should be 8 bytes longer than input.
			if len(wrapped) != tc.plaintextSize+8 {
				t.Fatalf("wrapped length = %d, want %d", len(wrapped), tc.plaintextSize+8)
			}

			unwrapped, err := AESKeyUnwrap(kek, wrapped)
			if err != nil {
				t.Fatalf("AESKeyUnwrap: %v", err)
			}

			if !bytes.Equal(unwrapped, key) {
				t.Fatal("unwrapped key mismatch")
			}
		})
	}
}

// RFC 3394 Section 4.1 — AES-128 KEK with 128-bit key data.
func TestAESKeyWrapRFC3394Vector128(t *testing.T) {
	kek, _ := hex.DecodeString("000102030405060708090A0B0C0D0E0F")
	key, _ := hex.DecodeString("00112233445566778899AABBCCDDEEFF")
	expected, _ := hex.DecodeString("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5")

	wrapped, err := AESKeyWrap(kek, key)
	if err != nil {
		t.Fatalf("AESKeyWrap: %v", err)
	}

	if !bytes.Equal(wrapped, expected) {
		t.Fatalf("wrapped = %x, want %x", wrapped, expected)
	}

	unwrapped, err := AESKeyUnwrap(kek, wrapped)
	if err != nil {
		t.Fatalf("AESKeyUnwrap: %v", err)
	}

	if !bytes.Equal(unwrapped, key) {
		t.Fatal("unwrapped key mismatch")
	}
}

// RFC 3394 Section 4.6 — AES-256 KEK with 256-bit key data.
func TestAESKeyWrapRFC3394Vector256(t *testing.T) {
	kek, _ := hex.DecodeString("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
	key, _ := hex.DecodeString("00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F")
	expected, _ := hex.DecodeString("28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21")

	wrapped, err := AESKeyWrap(kek, key)
	if err != nil {
		t.Fatalf("AESKeyWrap: %v", err)
	}

	if !bytes.Equal(wrapped, expected) {
		t.Fatalf("wrapped = %x, want %x", wrapped, expected)
	}

	unwrapped, err := AESKeyUnwrap(kek, wrapped)
	if err != nil {
		t.Fatalf("AESKeyUnwrap: %v", err)
	}

	if !bytes.Equal(unwrapped, key) {
		t.Fatal("unwrapped key mismatch")
	}
}

func TestAESKeyWrapWrongKEK(t *testing.T) {
	kek1 := make([]byte, 32)
	kek2 := make([]byte, 32)
	rand.Read(kek1)
	rand.Read(kek2)

	key := make([]byte, 32)
	rand.Read(key)

	wrapped, _ := AESKeyWrap(kek1, key)

	_, err := AESKeyUnwrap(kek2, wrapped)
	if err == nil {
		t.Fatal("expected error with wrong KEK")
	}
}

func TestAESKeyWrapInvalidInputs(t *testing.T) {
	kek := make([]byte, 32)

	// Non-multiple-of-8 plaintext.
	_, err := AESKeyWrap(kek, make([]byte, 7))
	if err == nil {
		t.Fatal("expected error for non-multiple-of-8 plaintext")
	}

	// Ciphertext too short.
	_, err = AESKeyUnwrap(kek, make([]byte, 16))
	if err == nil {
		t.Fatal("expected error for short ciphertext")
	}

	// Non-multiple-of-8 ciphertext.
	_, err = AESKeyUnwrap(kek, make([]byte, 25))
	if err == nil {
		t.Fatal("expected error for non-multiple-of-8 ciphertext")
	}
}

// =============================================================================
// X25519 / ECDH tests
// =============================================================================

func TestGenerateX25519KeyPair(t *testing.T) {
	priv, pub, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair: %v", err)
	}
	if len(priv) != X25519KeySize {
		t.Fatalf("private key length = %d, want %d", len(priv), X25519KeySize)
	}
	if len(pub) != X25519KeySize {
		t.Fatalf("public key length = %d, want %d", len(pub), X25519KeySize)
	}

	// Verify public key matches.
	expectedPub, _ := curve25519.X25519(priv, curve25519.Basepoint)
	if !bytes.Equal(pub, expectedPub) {
		t.Fatal("public key does not match private key")
	}
}

func TestX25519SharedSecret(t *testing.T) {
	privA, pubA, _ := GenerateX25519KeyPair()
	privB, pubB, _ := GenerateX25519KeyPair()

	// A computes shared secret with B's public key.
	secretAB, err := X25519SharedSecret(privA, pubB)
	if err != nil {
		t.Fatalf("X25519SharedSecret(A, B): %v", err)
	}

	// B computes shared secret with A's public key.
	secretBA, err := X25519SharedSecret(privB, pubA)
	if err != nil {
		t.Fatalf("X25519SharedSecret(B, A): %v", err)
	}

	// Both shared secrets must be identical (DH property).
	if !bytes.Equal(secretAB, secretBA) {
		t.Fatal("shared secrets do not match")
	}
}

func TestX25519SharedSecretInvalidKeySize(t *testing.T) {
	_, err := X25519SharedSecret(make([]byte, 16), make([]byte, 32))
	if err == nil {
		t.Fatal("expected error for wrong private key size")
	}

	_, err = X25519SharedSecret(make([]byte, 32), make([]byte, 16))
	if err == nil {
		t.Fatal("expected error for wrong public key size")
	}
}

// =============================================================================
// Concat KDF tests
// =============================================================================

// Test vector from the @enbox/crypto test suite.
func TestConcatKDFVector(t *testing.T) {
	sharedSecret, err := base64.RawURLEncoding.DecodeString("nlbZHYFxNdNyg0KDv4QmnPsxbqPagGpI9tqneYz-kMQ")
	if err != nil {
		t.Fatalf("decoding shared secret: %v", err)
	}

	derived, err := ConcatKDF(sharedSecret, 128, ConcatKDFParams{
		AlgorithmID: "A128GCM",
		PartyUInfo:  "Alice",
		PartyVInfo:  "Bob",
		SuppPubInfo: 128,
	})
	if err != nil {
		t.Fatalf("ConcatKDF: %v", err)
	}

	expected, err := base64.RawURLEncoding.DecodeString("VqqN6vgjbSBcIijNcacQGg")
	if err != nil {
		t.Fatalf("decoding expected: %v", err)
	}

	if !bytes.Equal(derived, expected) {
		t.Fatalf("ConcatKDF result = %x, want %x", derived, expected)
	}
}

// Test the DWN-specific usage: ECDH-ES+A256KW with empty party info.
func TestConcatKDFDWNUsage(t *testing.T) {
	sharedSecret := make([]byte, 32)
	rand.Read(sharedSecret)

	kek, err := ConcatKDF(sharedSecret, 256, ConcatKDFParams{
		AlgorithmID: "A256KW",
		PartyUInfo:  "",
		PartyVInfo:  "",
		SuppPubInfo: 256,
	})
	if err != nil {
		t.Fatalf("ConcatKDF: %v", err)
	}

	if len(kek) != 32 {
		t.Fatalf("derived key length = %d, want 32", len(kek))
	}
}

// Test that the FixedInfo encoding matches the spec.
func TestConcatKDFFixedInfoEncoding(t *testing.T) {
	// Manually compute expected FixedInfo for AlgorithmID="A256KW", empty PartyU/V, SuppPubInfo=256.
	var expected []byte

	// AlgorithmID: len(5) + "A256KW" => wait, "A256KW" is 6 chars
	algID := []byte("A256KW")
	var algLen [4]byte
	binary.BigEndian.PutUint32(algLen[:], uint32(len(algID)))
	expected = append(expected, algLen[:]...)
	expected = append(expected, algID...)

	// PartyUInfo: len(0) + ""
	var emptyLen [4]byte
	expected = append(expected, emptyLen[:]...)

	// PartyVInfo: len(0) + ""
	expected = append(expected, emptyLen[:]...)

	// SuppPubInfo: 256 as uint32
	var suppPub [4]byte
	binary.BigEndian.PutUint32(suppPub[:], 256)
	expected = append(expected, suppPub[:]...)

	got := computeFixedInfo(ConcatKDFParams{
		AlgorithmID: "A256KW",
		PartyUInfo:  "",
		PartyVInfo:  "",
		SuppPubInfo: 256,
	})

	if !bytes.Equal(got, expected) {
		t.Fatalf("FixedInfo = %x, want %x", got, expected)
	}
}

func TestConcatKDFMultiRoundReject(t *testing.T) {
	_, err := ConcatKDF(make([]byte, 32), 512, ConcatKDFParams{
		AlgorithmID: "A256KW",
		SuppPubInfo: 512,
	})
	if err == nil {
		t.Fatal("expected error for keyDataLen > 256")
	}
}

// =============================================================================
// ECDH-ES+A256KW wrap/unwrap tests
// =============================================================================

func TestECDHESWrapUnwrapRoundTrip(t *testing.T) {
	// Generate recipient key pair.
	recipientPriv, recipientPub, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair: %v", err)
	}

	// Generate a CEK to wrap.
	cek, err := GenerateCEK()
	if err != nil {
		t.Fatalf("GenerateCEK: %v", err)
	}

	// Wrap.
	ephPub, wrappedKey, err := ECDHESWrapKey(recipientPub, cek)
	if err != nil {
		t.Fatalf("ECDHESWrapKey: %v", err)
	}

	if len(ephPub) != X25519KeySize {
		t.Fatalf("ephemeral public key length = %d, want %d", len(ephPub), X25519KeySize)
	}

	// Wrapped key should be CEK size + 8 (AES Key Wrap overhead).
	if len(wrappedKey) != CEKSize+8 {
		t.Fatalf("wrapped key length = %d, want %d", len(wrappedKey), CEKSize+8)
	}

	// Unwrap.
	unwrapped, err := ECDHESUnwrapKey(recipientPriv, ephPub, wrappedKey)
	if err != nil {
		t.Fatalf("ECDHESUnwrapKey: %v", err)
	}

	if !bytes.Equal(unwrapped, cek) {
		t.Fatal("unwrapped CEK mismatch")
	}
}

func TestECDHESWrapWrongRecipient(t *testing.T) {
	_, recipientPub, _ := GenerateX25519KeyPair()
	wrongPriv, _, _ := GenerateX25519KeyPair()

	cek, _ := GenerateCEK()

	ephPub, wrappedKey, err := ECDHESWrapKey(recipientPub, cek)
	if err != nil {
		t.Fatalf("ECDHESWrapKey: %v", err)
	}

	// Unwrap with wrong private key should fail (integrity check).
	_, err = ECDHESUnwrapKey(wrongPriv, ephPub, wrappedKey)
	if err == nil {
		t.Fatal("expected error with wrong recipient private key")
	}
}

func TestECDHESMultipleRecipients(t *testing.T) {
	// Generate CEK once.
	cek, _ := GenerateCEK()

	// Generate 3 recipients.
	recipients := make([][2][]byte, 3) // [priv, pub]
	for i := range recipients {
		priv, pub, _ := GenerateX25519KeyPair()
		recipients[i] = [2][]byte{priv, pub}
	}

	// Wrap CEK for each recipient.
	type wrappedResult struct {
		ephPub     []byte
		wrappedKey []byte
	}
	wrapped := make([]wrappedResult, 3)
	for i, r := range recipients {
		ephPub, wk, err := ECDHESWrapKey(r[1], cek)
		if err != nil {
			t.Fatalf("ECDHESWrapKey[%d]: %v", i, err)
		}
		wrapped[i] = wrappedResult{ephPub, wk}
	}

	// Each recipient should be able to unwrap to the same CEK.
	for i, r := range recipients {
		unwrapped, err := ECDHESUnwrapKey(r[0], wrapped[i].ephPub, wrapped[i].wrappedKey)
		if err != nil {
			t.Fatalf("ECDHESUnwrapKey[%d]: %v", i, err)
		}
		if !bytes.Equal(unwrapped, cek) {
			t.Fatalf("recipient %d: unwrapped CEK mismatch", i)
		}
	}
}

// =============================================================================
// HKDF key derivation tests
// =============================================================================

func TestDeriveKeyBytesDeterministic(t *testing.T) {
	rootKey := make([]byte, 32)
	rand.Read(rootKey)

	path := []string{"protocolPath", "https://example.com/proto", "network"}

	// Derive twice with same inputs.
	derived1, err := DeriveKeyBytes(rootKey, path)
	if err != nil {
		t.Fatalf("DeriveKeyBytes: %v", err)
	}

	derived2, err := DeriveKeyBytes(rootKey, path)
	if err != nil {
		t.Fatalf("DeriveKeyBytes: %v", err)
	}

	if !bytes.Equal(derived1, derived2) {
		t.Fatal("HKDF derivation is not deterministic")
	}

	if len(derived1) != 32 {
		t.Fatalf("derived key length = %d, want 32", len(derived1))
	}
}

func TestDeriveKeyBytesDifferentPaths(t *testing.T) {
	rootKey := make([]byte, 32)
	rand.Read(rootKey)

	d1, _ := DeriveKeyBytes(rootKey, []string{"protocolPath", "https://example.com/proto", "network"})
	d2, _ := DeriveKeyBytes(rootKey, []string{"protocolPath", "https://example.com/proto", "member"})

	if bytes.Equal(d1, d2) {
		t.Fatal("different paths should produce different keys")
	}
}

func TestDeriveKeyBytesDifferentRoots(t *testing.T) {
	root1 := make([]byte, 32)
	root2 := make([]byte, 32)
	rand.Read(root1)
	rand.Read(root2)

	path := []string{"protocolPath", "https://example.com/proto", "network"}

	d1, _ := DeriveKeyBytes(root1, path)
	d2, _ := DeriveKeyBytes(root2, path)

	if bytes.Equal(d1, d2) {
		t.Fatal("different root keys should produce different derived keys")
	}
}

func TestDeriveKeyBytesHierarchical(t *testing.T) {
	rootKey := make([]byte, 32)
	rand.Read(rootKey)

	// Derive in one step: root -> a -> b
	full, err := DeriveKeyBytes(rootKey, []string{"a", "b"})
	if err != nil {
		t.Fatalf("DeriveKeyBytes([a,b]): %v", err)
	}

	// Derive in two steps: root -> a, then a -> b
	intermediate, err := DeriveKeyBytes(rootKey, []string{"a"})
	if err != nil {
		t.Fatalf("DeriveKeyBytes([a]): %v", err)
	}

	stepwise, err := DeriveKeyBytes(intermediate, []string{"b"})
	if err != nil {
		t.Fatalf("DeriveKeyBytes([b]): %v", err)
	}

	// Both should produce the same result (hierarchical property).
	if !bytes.Equal(full, stepwise) {
		t.Fatal("hierarchical derivation should produce same result")
	}
}

func TestDeriveKeyBytesEmptySegmentRejected(t *testing.T) {
	rootKey := make([]byte, 32)
	rand.Read(rootKey)

	_, err := DeriveKeyBytes(rootKey, []string{"protocolPath", "", "network"})
	if err == nil {
		t.Fatal("expected error for empty path segment")
	}
}

func TestDerivePrivateKey(t *testing.T) {
	rootKey := make([]byte, 32)
	rand.Read(rootKey)

	path := BuildProtocolPathDerivation("https://example.com/proto", "network", "member")

	priv, pub, err := DerivePrivateKey(rootKey, path)
	if err != nil {
		t.Fatalf("DerivePrivateKey: %v", err)
	}

	if len(priv) != 32 || len(pub) != 32 {
		t.Fatal("derived key sizes incorrect")
	}

	// Public key should match the derived private key.
	expectedPub, _ := X25519PublicKey(priv)
	if !bytes.Equal(pub, expectedPub) {
		t.Fatal("derived public key does not match derived private key")
	}
}

func TestBuildProtocolPathDerivation(t *testing.T) {
	path := BuildProtocolPathDerivation("https://example.com/proto", "network", "member")
	expected := []string{"protocolPath", "https://example.com/proto", "network", "member"}

	if len(path) != len(expected) {
		t.Fatalf("path length = %d, want %d", len(path), len(expected))
	}
	for i := range path {
		if path[i] != expected[i] {
			t.Fatalf("path[%d] = %q, want %q", i, path[i], expected[i])
		}
	}
}

func TestBuildProtocolContextDerivation(t *testing.T) {
	path := BuildProtocolContextDerivation("bafyreiabc123")
	expected := []string{"protocolContext", "bafyreiabc123"}

	if len(path) != len(expected) {
		t.Fatalf("path length = %d, want %d", len(path), len(expected))
	}
	for i := range path {
		if path[i] != expected[i] {
			t.Fatalf("path[%d] = %q, want %q", i, path[i], expected[i])
		}
	}
}

// =============================================================================
// JWE / full encryption round-trip tests
// =============================================================================

func TestEncryptDataDecryptDataRoundTrip(t *testing.T) {
	tests := map[string]struct {
		plaintext     []byte
		numRecipients int
	}{
		"single recipient": {
			plaintext:     []byte("hello, encrypted world!"),
			numRecipients: 1,
		},
		"three recipients": {
			plaintext:     []byte("multi-recipient encryption"),
			numRecipients: 3,
		},
		"empty plaintext": {
			plaintext:     []byte{},
			numRecipients: 1,
		},
		"large data": {
			plaintext:     bytes.Repeat([]byte("X"), 1<<16),
			numRecipients: 2,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			// Generate recipient keys.
			type keyPair struct {
				priv []byte
				pub  []byte
				kid  string
			}
			keys := make([]keyPair, tc.numRecipients)
			recipients := make([]KeyEncryptionInput, tc.numRecipients)
			for i := range keys {
				priv, pub, _ := GenerateX25519KeyPair()
				kid := "did:example:alice#enc-" + string(rune('0'+i))
				keys[i] = keyPair{priv, pub, kid}
				recipients[i] = KeyEncryptionInput{
					PublicKeyID:      kid,
					PublicKey:        pub,
					DerivationScheme: DerivationSchemeProtocolPath,
				}
			}

			// Encrypt.
			ct, enc, err := EncryptData(tc.plaintext, recipients)
			if err != nil {
				t.Fatalf("EncryptData: %v", err)
			}

			// Verify JWE structure.
			if len(enc.Recipients) != tc.numRecipients {
				t.Fatalf("recipients count = %d, want %d", len(enc.Recipients), tc.numRecipients)
			}
			if enc.Protected == "" || enc.IV == "" || enc.Tag == "" {
				t.Fatal("missing JWE fields")
			}

			// Each recipient should be able to decrypt.
			for i, kp := range keys {
				got, err := DecryptData(ct, enc, kp.priv, kp.kid)
				if err != nil {
					t.Fatalf("DecryptData[%d]: %v", i, err)
				}
				if !bytes.Equal(got, tc.plaintext) {
					t.Fatalf("recipient %d: decrypted data mismatch", i)
				}
			}
		})
	}
}

func TestDecryptDataWrongRecipient(t *testing.T) {
	priv, pub, _ := GenerateX25519KeyPair()
	wrongPriv, _, _ := GenerateX25519KeyPair()

	ct, enc, err := EncryptData([]byte("secret"), []KeyEncryptionInput{{
		PublicKeyID:      "did:example:alice#enc",
		PublicKey:        pub,
		DerivationScheme: DerivationSchemeProtocolPath,
	}})
	if err != nil {
		t.Fatalf("EncryptData: %v", err)
	}

	// Wrong private key should fail unwrap.
	_, err = DecryptData(ct, enc, wrongPriv, "did:example:alice#enc")
	if err == nil {
		t.Fatal("expected error with wrong private key")
	}

	// Wrong KID should fail with no matching recipient.
	_, err = DecryptData(ct, enc, priv, "did:example:bob#enc")
	if err == nil {
		t.Fatal("expected error with wrong KID")
	}
}

func TestBuildJWEProtectedHeader(t *testing.T) {
	priv, pub, _ := GenerateX25519KeyPair()
	_ = priv

	cek, _ := GenerateCEK()
	iv, _ := GenerateIV(EncA256GCM)
	ct, tag, _ := AEADEncrypt(EncA256GCM, cek, iv, []byte("test"), nil)
	_ = ct

	enc, err := BuildJWE(EncryptionInput{
		Algorithm: EncA256GCM,
		CEK:       cek,
		IV:        iv,
		Tag:       tag,
		KeyEncryptionInputs: []KeyEncryptionInput{{
			PublicKeyID:      "did:example:alice#enc",
			PublicKey:        pub,
			DerivationScheme: DerivationSchemeProtocolPath,
		}},
	})
	if err != nil {
		t.Fatalf("BuildJWE: %v", err)
	}

	// Parse and verify protected header.
	header, err := ParseProtectedHeader(enc.Protected)
	if err != nil {
		t.Fatalf("ParseProtectedHeader: %v", err)
	}

	if header.Alg != AlgECDHESA256KW {
		t.Fatalf("alg = %q, want %q", header.Alg, AlgECDHESA256KW)
	}
	if header.Enc != EncA256GCM {
		t.Fatalf("enc = %q, want %q", header.Enc, EncA256GCM)
	}
}

func TestJWERecipientHeaderFields(t *testing.T) {
	_, pub, _ := GenerateX25519KeyPair()
	cek, _ := GenerateCEK()
	iv, _ := GenerateIV(EncA256GCM)
	_, tag, _ := AEADEncrypt(EncA256GCM, cek, iv, []byte("test"), nil)

	enc, err := BuildJWE(EncryptionInput{
		Algorithm: EncA256GCM,
		CEK:       cek,
		IV:        iv,
		Tag:       tag,
		KeyEncryptionInputs: []KeyEncryptionInput{{
			PublicKeyID:      "did:dht:xyz123#enc-1",
			PublicKey:        pub,
			DerivationScheme: DerivationSchemeProtocolPath,
		}},
	})
	if err != nil {
		t.Fatalf("BuildJWE: %v", err)
	}

	r := enc.Recipients[0]
	if r.Header.KID != "did:dht:xyz123#enc-1" {
		t.Fatalf("kid = %q, want %q", r.Header.KID, "did:dht:xyz123#enc-1")
	}
	if r.Header.EPK == nil {
		t.Fatal("ephemeral public key is nil")
	}
	if r.Header.EPK.KTY != "OKP" || r.Header.EPK.CRV != "X25519" {
		t.Fatalf("epk type = %s/%s, want OKP/X25519", r.Header.EPK.KTY, r.Header.EPK.CRV)
	}
	if r.Header.DerivationScheme != DerivationSchemeProtocolPath {
		t.Fatalf("derivationScheme = %q, want %q", r.Header.DerivationScheme, DerivationSchemeProtocolPath)
	}
	// protocolPath scheme should NOT have derivedPublicKey.
	if r.Header.DerivedPublicKey != nil {
		t.Fatal("protocolPath scheme should not include derivedPublicKey")
	}
}

func TestJWEProtocolContextIncludesDerivedPublicKey(t *testing.T) {
	_, pub, _ := GenerateX25519KeyPair()
	cek, _ := GenerateCEK()
	iv, _ := GenerateIV(EncA256GCM)
	_, tag, _ := AEADEncrypt(EncA256GCM, cek, iv, []byte("test"), nil)

	enc, err := BuildJWE(EncryptionInput{
		Algorithm: EncA256GCM,
		CEK:       cek,
		IV:        iv,
		Tag:       tag,
		KeyEncryptionInputs: []KeyEncryptionInput{{
			PublicKeyID:      "did:dht:xyz123#enc-1",
			PublicKey:        pub,
			DerivationScheme: DerivationSchemeProtocolContext,
		}},
	})
	if err != nil {
		t.Fatalf("BuildJWE: %v", err)
	}

	r := enc.Recipients[0]
	if r.Header.DerivedPublicKey == nil {
		t.Fatal("protocolContext scheme should include derivedPublicKey")
	}
	if r.Header.DerivedPublicKey.KTY != "OKP" || r.Header.DerivedPublicKey.CRV != "X25519" {
		t.Fatalf("derivedPublicKey type = %s/%s, want OKP/X25519",
			r.Header.DerivedPublicKey.KTY, r.Header.DerivedPublicKey.CRV)
	}
}

func TestEncryptionJSONSerialization(t *testing.T) {
	_, pub, _ := GenerateX25519KeyPair()
	cek, _ := GenerateCEK()
	iv, _ := GenerateIV(EncA256GCM)
	_, tag, _ := AEADEncrypt(EncA256GCM, cek, iv, []byte("test"), nil)

	enc, err := BuildJWE(EncryptionInput{
		Algorithm: EncA256GCM,
		CEK:       cek,
		IV:        iv,
		Tag:       tag,
		KeyEncryptionInputs: []KeyEncryptionInput{{
			PublicKeyID:      "did:dht:xyz#enc",
			PublicKey:        pub,
			DerivationScheme: DerivationSchemeProtocolPath,
		}},
	})
	if err != nil {
		t.Fatalf("BuildJWE: %v", err)
	}

	// Marshal to JSON and back.
	data, err := json.Marshal(enc)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	var decoded Encryption
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	if decoded.Protected != enc.Protected {
		t.Fatal("protected header mismatch after JSON round-trip")
	}
	if decoded.IV != enc.IV {
		t.Fatal("IV mismatch after JSON round-trip")
	}
	if decoded.Tag != enc.Tag {
		t.Fatal("tag mismatch after JSON round-trip")
	}
	if len(decoded.Recipients) != 1 {
		t.Fatalf("recipients count = %d, want 1", len(decoded.Recipients))
	}
	if decoded.Recipients[0].Header.KID != "did:dht:xyz#enc" {
		t.Fatal("recipient KID mismatch after JSON round-trip")
	}
}

func TestEncryptDataNoRecipients(t *testing.T) {
	_, _, err := EncryptData([]byte("hello"), nil)
	if err == nil {
		t.Fatal("expected error with no recipients")
	}
}

// =============================================================================
// End-to-end: HKDF derivation + JWE encryption
// =============================================================================

func TestEndToEndDerivedKeyEncryption(t *testing.T) {
	// Simulate protocol-path based encryption:
	// 1. Root key generates derived key for protocolPath
	// 2. Encrypt data for the derived key
	// 3. Decrypt using derived private key

	rootPriv, _, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair: %v", err)
	}

	protocolURI := "https://example.com/wireguard-mesh"
	path := BuildProtocolPathDerivation(protocolURI, "network", "member")

	// Derive key pair for this protocol path.
	derivedPriv, derivedPub, err := DerivePrivateKey(rootPriv, path)
	if err != nil {
		t.Fatalf("DerivePrivateKey: %v", err)
	}

	kid := "did:dht:abc123#enc-1"
	plaintext := []byte(`{"name":"test-network","cidr":"10.200.0.0/24"}`)

	// Encrypt data for the derived public key.
	ct, enc, err := EncryptData(plaintext, []KeyEncryptionInput{{
		PublicKeyID:      kid,
		PublicKey:        derivedPub,
		DerivationScheme: DerivationSchemeProtocolPath,
	}})
	if err != nil {
		t.Fatalf("EncryptData: %v", err)
	}

	// Decrypt using the derived private key.
	got, err := DecryptData(ct, enc, derivedPriv, kid)
	if err != nil {
		t.Fatalf("DecryptData: %v", err)
	}

	if !bytes.Equal(got, plaintext) {
		t.Fatal("decrypted data mismatch in end-to-end test")
	}
}

// =============================================================================
// Additional edge case tests for coverage
// =============================================================================

func TestCEKAndIVRandomness(t *testing.T) {
	// Verify that generated CEKs and IVs are unique (not zero, not repeated).
	cek1, _ := GenerateCEK()
	cek2, _ := GenerateCEK()

	if bytes.Equal(cek1, cek2) {
		t.Fatal("two generated CEKs should not be identical")
	}

	iv1, _ := GenerateIV(EncA256GCM)
	iv2, _ := GenerateIV(EncA256GCM)

	if bytes.Equal(iv1, iv2) {
		t.Fatal("two generated IVs should not be identical")
	}
}

func TestAEADCiphertextDiffersFromPlaintext(t *testing.T) {
	cek, _ := GenerateCEK()
	iv, _ := GenerateIV(EncA256GCM)
	plaintext := []byte("this is a secret message that must be encrypted")

	ct, _, err := AEADEncrypt(EncA256GCM, cek, iv, plaintext, nil)
	if err != nil {
		t.Fatalf("AEADEncrypt: %v", err)
	}

	if bytes.Equal(ct, plaintext) {
		t.Fatal("ciphertext should differ from plaintext")
	}
}

func TestAEADTamperedCiphertext(t *testing.T) {
	cek, _ := GenerateCEK()
	iv, _ := GenerateIV(EncA256GCM)

	ct, tag, _ := AEADEncrypt(EncA256GCM, cek, iv, []byte("secret"), nil)

	// Flip a bit in the ciphertext.
	ct[0] ^= 0xFF

	_, err := AEADDecrypt(EncA256GCM, cek, iv, ct, tag, nil)
	if err == nil {
		t.Fatal("expected error with tampered ciphertext")
	}
}

func TestX25519PublicKeyDeterministic(t *testing.T) {
	priv, pub1, _ := GenerateX25519KeyPair()

	pub2, err := X25519PublicKey(priv)
	if err != nil {
		t.Fatalf("X25519PublicKey: %v", err)
	}

	if !bytes.Equal(pub1, pub2) {
		t.Fatal("X25519PublicKey should return same public key as GenerateX25519KeyPair")
	}
}

func TestX25519PublicKeyInvalidSize(t *testing.T) {
	_, err := X25519PublicKey(make([]byte, 16))
	if err == nil {
		t.Fatal("expected error for wrong key size")
	}
}

func TestAESKeyWrapEmptyPlaintext(t *testing.T) {
	kek := make([]byte, 32)
	_, err := AESKeyWrap(kek, []byte{})
	if err == nil {
		t.Fatal("expected error for empty plaintext")
	}
}

func TestConcatKDFDeterministic(t *testing.T) {
	secret := make([]byte, 32)
	rand.Read(secret)

	params := ConcatKDFParams{
		AlgorithmID: "A256KW",
		PartyUInfo:  "",
		PartyVInfo:  "",
		SuppPubInfo: 256,
	}

	kek1, _ := ConcatKDF(secret, 256, params)
	kek2, _ := ConcatKDF(secret, 256, params)

	if !bytes.Equal(kek1, kek2) {
		t.Fatal("ConcatKDF should be deterministic")
	}
}

func TestConcatKDFDifferentAlgorithmIDs(t *testing.T) {
	secret := make([]byte, 32)
	rand.Read(secret)

	kek1, _ := ConcatKDF(secret, 256, ConcatKDFParams{
		AlgorithmID: "A256KW",
		SuppPubInfo: 256,
	})
	kek2, _ := ConcatKDF(secret, 256, ConcatKDFParams{
		AlgorithmID: "A128KW",
		SuppPubInfo: 256,
	})

	if bytes.Equal(kek1, kek2) {
		t.Fatal("different algorithm IDs should produce different keys")
	}
}

func TestECDHESWrapUnwrapMultipleRoundTrips(t *testing.T) {
	// Verify that wrapping the same CEK multiple times produces different
	// wrapped keys (because each wrap uses a new ephemeral key).
	recipientPriv, recipientPub, _ := GenerateX25519KeyPair()
	cek, _ := GenerateCEK()

	eph1, wrapped1, _ := ECDHESWrapKey(recipientPub, cek)
	eph2, wrapped2, _ := ECDHESWrapKey(recipientPub, cek)

	if bytes.Equal(eph1, eph2) {
		t.Fatal("ephemeral keys should be unique per wrap")
	}

	if bytes.Equal(wrapped1, wrapped2) {
		t.Fatal("wrapped keys should differ due to different ephemeral keys")
	}

	// Both should unwrap to the same CEK.
	unwrapped1, _ := ECDHESUnwrapKey(recipientPriv, eph1, wrapped1)
	unwrapped2, _ := ECDHESUnwrapKey(recipientPriv, eph2, wrapped2)

	if !bytes.Equal(unwrapped1, cek) || !bytes.Equal(unwrapped2, cek) {
		t.Fatal("both wrapped keys should unwrap to the same CEK")
	}
}

func TestBuildJWEDefaultAlgorithm(t *testing.T) {
	_, pub, _ := GenerateX25519KeyPair()
	cek, _ := GenerateCEK()
	iv, _ := GenerateIV(EncA256GCM)
	_, tag, _ := AEADEncrypt(EncA256GCM, cek, iv, []byte("test"), nil)

	// Leave Algorithm empty — should default to A256GCM.
	enc, err := BuildJWE(EncryptionInput{
		CEK: cek,
		IV:  iv,
		Tag: tag,
		KeyEncryptionInputs: []KeyEncryptionInput{{
			PublicKeyID:      "did:test:alice#enc",
			PublicKey:        pub,
			DerivationScheme: DerivationSchemeProtocolPath,
		}},
	})
	if err != nil {
		t.Fatalf("BuildJWE: %v", err)
	}

	header, _ := ParseProtectedHeader(enc.Protected)
	if header.Enc != EncA256GCM {
		t.Fatalf("default enc = %q, want %q", header.Enc, EncA256GCM)
	}
}

func TestDecryptDataMissingEPK(t *testing.T) {
	// Build a malformed encryption with missing EPK.
	enc := &Encryption{
		Protected: base64URLEncode([]byte(`{"alg":"ECDH-ES+A256KW","enc":"A256GCM"}`)),
		IV:        base64URLEncode(make([]byte, 12)),
		Tag:       base64URLEncode(make([]byte, 16)),
		Recipients: []Recipient{{
			Header: RecipientHeader{
				KID:              "did:test:alice#enc",
				EPK:              nil, // missing!
				DerivationScheme: DerivationSchemeProtocolPath,
			},
			EncryptedKey: base64URLEncode(make([]byte, 40)),
		}},
	}

	_, err := DecryptData(make([]byte, 32), enc, make([]byte, 32), "did:test:alice#enc")
	if err == nil {
		t.Fatal("expected error for missing EPK")
	}
}

func TestDecryptDataNoMatchingRecipient(t *testing.T) {
	_, pub, _ := GenerateX25519KeyPair()
	cek, _ := GenerateCEK()
	iv, _ := GenerateIV(EncA256GCM)
	_, tag, _ := AEADEncrypt(EncA256GCM, cek, iv, []byte("test"), nil)

	enc, _ := BuildJWE(EncryptionInput{
		Algorithm: EncA256GCM,
		CEK:       cek,
		IV:        iv,
		Tag:       tag,
		KeyEncryptionInputs: []KeyEncryptionInput{{
			PublicKeyID:      "did:test:alice#enc",
			PublicKey:        pub,
			DerivationScheme: DerivationSchemeProtocolPath,
		}},
	})

	_, err := DecryptData(make([]byte, 32), enc, make([]byte, 32), "did:test:bob#enc")
	if err == nil {
		t.Fatal("expected error for no matching recipient")
	}
}

func TestParseProtectedHeaderInvalidBase64(t *testing.T) {
	_, err := ParseProtectedHeader("!!!not-base64!!!")
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
}

func TestParseProtectedHeaderInvalidJSON(t *testing.T) {
	_, err := ParseProtectedHeader(base64URLEncode([]byte("not json")))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestBase64URLDecodeWithPadding(t *testing.T) {
	// Test that base64URLDecode handles both padded and unpadded input.
	data := []byte("hello world")
	encoded := base64.URLEncoding.EncodeToString(data) // with padding

	decoded, err := base64URLDecode(encoded)
	if err != nil {
		t.Fatalf("base64URLDecode with padding: %v", err)
	}
	if !bytes.Equal(decoded, data) {
		t.Fatal("decoded data mismatch")
	}
}

func TestDeriveKeyBytesEmptyPath(t *testing.T) {
	rootKey := make([]byte, 32)
	rand.Read(rootKey)

	// Empty path should return a copy of the root key.
	derived, err := DeriveKeyBytes(rootKey, []string{})
	if err != nil {
		t.Fatalf("DeriveKeyBytes(empty): %v", err)
	}

	if !bytes.Equal(derived, rootKey) {
		t.Fatal("empty derivation path should return the root key")
	}
}

func TestDeriveKeyBytesSingleSegment(t *testing.T) {
	rootKey := make([]byte, 32)
	rand.Read(rootKey)

	derived, err := DeriveKeyBytes(rootKey, []string{"segment1"})
	if err != nil {
		t.Fatalf("DeriveKeyBytes: %v", err)
	}

	// Should be different from root.
	if bytes.Equal(derived, rootKey) {
		t.Fatal("derived key should differ from root key")
	}
}

func TestDerivePrivateKeyRoundTrip(t *testing.T) {
	rootKey := make([]byte, 32)
	rand.Read(rootKey)

	path := BuildProtocolPathDerivation("https://example.com/proto", "type1")

	// Derive key pair.
	priv, pub, err := DerivePrivateKey(rootKey, path)
	if err != nil {
		t.Fatalf("DerivePrivateKey: %v", err)
	}

	// Encrypt something for the derived public key.
	plaintext := []byte("round trip via derived keys")
	ct, enc, err := EncryptData(plaintext, []KeyEncryptionInput{{
		PublicKeyID:      "did:test:derived#enc",
		PublicKey:        pub,
		DerivationScheme: DerivationSchemeProtocolPath,
	}})
	if err != nil {
		t.Fatalf("EncryptData: %v", err)
	}

	// Decrypt with the derived private key.
	got, err := DecryptData(ct, enc, priv, "did:test:derived#enc")
	if err != nil {
		t.Fatalf("DecryptData: %v", err)
	}

	if !bytes.Equal(got, plaintext) {
		t.Fatal("round-trip via derived keys failed")
	}
}

func TestEncryptionJSONFieldNames(t *testing.T) {
	// Verify that JSON field names match the DWN spec exactly.
	_, pub, _ := GenerateX25519KeyPair()
	cek, _ := GenerateCEK()
	iv, _ := GenerateIV(EncA256GCM)
	_, tag, _ := AEADEncrypt(EncA256GCM, cek, iv, []byte("test"), nil)

	enc, _ := BuildJWE(EncryptionInput{
		Algorithm: EncA256GCM,
		CEK:       cek,
		IV:        iv,
		Tag:       tag,
		KeyEncryptionInputs: []KeyEncryptionInput{{
			PublicKeyID:      "did:test:alice#enc",
			PublicKey:        pub,
			DerivationScheme: DerivationSchemeProtocolPath,
		}},
	})

	data, _ := json.Marshal(enc)
	var raw map[string]any
	json.Unmarshal(data, &raw)

	// Check top-level field names.
	requiredFields := []string{"protected", "iv", "tag", "recipients"}
	for _, f := range requiredFields {
		if _, ok := raw[f]; !ok {
			t.Errorf("missing JSON field %q", f)
		}
	}

	// Check recipient field names.
	recipients := raw["recipients"].([]any)
	r := recipients[0].(map[string]any)
	if _, ok := r["header"]; !ok {
		t.Error("missing recipient.header")
	}
	if _, ok := r["encrypted_key"]; !ok {
		t.Error("missing recipient.encrypted_key (underscore, not camelCase)")
	}

	// Check recipient header field names.
	header := r["header"].(map[string]any)
	headerFields := []string{"kid", "epk", "derivationScheme"}
	for _, f := range headerFields {
		if _, ok := header[f]; !ok {
			t.Errorf("missing header field %q", f)
		}
	}

	// For protocolPath scheme, derivedPublicKey should be absent.
	if _, ok := header["derivedPublicKey"]; ok {
		t.Error("protocolPath scheme should not include derivedPublicKey")
	}
}

func TestMultiRecipientDecryption(t *testing.T) {
	// Verify that each of N recipients can independently decrypt.
	plaintext := []byte("shared secret for all recipients")
	n := 5

	type keyPair struct {
		priv []byte
		pub  []byte
		kid  string
	}

	keys := make([]keyPair, n)
	inputs := make([]KeyEncryptionInput, n)
	for i := range keys {
		priv, pub, _ := GenerateX25519KeyPair()
		kid := fmt.Sprintf("did:test:user%d#enc", i)
		keys[i] = keyPair{priv, pub, kid}
		inputs[i] = KeyEncryptionInput{
			PublicKeyID:      kid,
			PublicKey:        pub,
			DerivationScheme: DerivationSchemeProtocolPath,
		}
	}

	ct, enc, err := EncryptData(plaintext, inputs)
	if err != nil {
		t.Fatalf("EncryptData: %v", err)
	}

	if len(enc.Recipients) != n {
		t.Fatalf("recipients = %d, want %d", len(enc.Recipients), n)
	}

	for i, kp := range keys {
		got, err := DecryptData(ct, enc, kp.priv, kp.kid)
		if err != nil {
			t.Fatalf("DecryptData[%d]: %v", i, err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("recipient %d: decrypted data mismatch", i)
		}
	}

	// Wrong recipient should fail.
	wrongPriv, _, _ := GenerateX25519KeyPair()
	_, err = DecryptData(ct, enc, wrongPriv, keys[0].kid)
	if err == nil {
		t.Fatal("expected error for wrong private key")
	}
}

func TestProtocolContextDerivationSchemeRoundTrip(t *testing.T) {
	// Test the protocolContext scheme end-to-end.
	rootPriv, _, _ := GenerateX25519KeyPair()

	contextID := "bafyreiabc123contextid"
	path := BuildProtocolContextDerivation(contextID)

	derivedPriv, derivedPub, err := DerivePrivateKey(rootPriv, path)
	if err != nil {
		t.Fatalf("DerivePrivateKey: %v", err)
	}

	kid := "did:test:context#enc"
	plaintext := []byte("context-specific secret")

	ct, enc, err := EncryptData(plaintext, []KeyEncryptionInput{{
		PublicKeyID:      kid,
		PublicKey:        derivedPub,
		DerivationScheme: DerivationSchemeProtocolContext,
	}})
	if err != nil {
		t.Fatalf("EncryptData: %v", err)
	}

	// Verify derivedPublicKey is present in recipient header.
	if enc.Recipients[0].Header.DerivedPublicKey == nil {
		t.Fatal("protocolContext should include derivedPublicKey")
	}

	// Decrypt.
	got, err := DecryptData(ct, enc, derivedPriv, kid)
	if err != nil {
		t.Fatalf("DecryptData: %v", err)
	}

	if !bytes.Equal(got, plaintext) {
		t.Fatal("decrypted data mismatch for protocolContext scheme")
	}
}

func TestConcatKDFWithNonEmptyPartyInfo(t *testing.T) {
	// Test ConcatKDF with non-empty party info (not typical for DWN,
	// but validates the encoding).
	secret := make([]byte, 32)
	rand.Read(secret)

	kek1, _ := ConcatKDF(secret, 256, ConcatKDFParams{
		AlgorithmID: "A256KW",
		PartyUInfo:  "Alice",
		PartyVInfo:  "Bob",
		SuppPubInfo: 256,
	})

	kek2, _ := ConcatKDF(secret, 256, ConcatKDFParams{
		AlgorithmID: "A256KW",
		PartyUInfo:  "Bob",
		PartyVInfo:  "Alice",
		SuppPubInfo: 256,
	})

	// Swapping partyU and partyV should produce different keys.
	if bytes.Equal(kek1, kek2) {
		t.Fatal("swapped party info should produce different keys")
	}
}

// =============================================================================
// Protocol $encryption injection tests
// =============================================================================

func TestInjectEncryptionDirectives(t *testing.T) {
	// Generate a root X25519 key pair.
	rootPriv, _, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("generating root key: %v", err)
	}
	rootKeyID := "did:dht:test123#enc"

	definition := json.RawMessage(`{
		"protocol": "https://example.com/proto",
		"published": true,
		"types": {
			"network": {"schema": "https://example.com/schemas/network", "dataFormats": ["application/json"]},
			"node": {"schema": "https://example.com/schemas/node", "dataFormats": ["application/json"], "encryptionRequired": true},
			"endpoint": {"schema": "https://example.com/schemas/endpoint", "dataFormats": ["application/json"], "encryptionRequired": true}
		},
		"structure": {
			"network": {
				"$actions": [{"who": "anyone", "can": ["read"]}],
				"node": {
					"$role": true,
					"$actions": [{"role": "network/node", "can": ["read"]}],
					"endpoint": {
						"$actions": [{"role": "network/node", "can": ["read"]}]
					}
				}
			}
		}
	}`)

	result, err := InjectEncryptionDirectives(definition, rootPriv, rootKeyID)
	if err != nil {
		t.Fatalf("InjectEncryptionDirectives: %v", err)
	}

	// Parse result to verify.
	var defMap map[string]any
	if err := json.Unmarshal(result, &defMap); err != nil {
		t.Fatalf("parsing result: %v", err)
	}

	structure := defMap["structure"].(map[string]any)
	network := structure["network"].(map[string]any)

	// network itself should have $encryption injected.
	networkEnc, ok := network["$encryption"].(map[string]any)
	if !ok {
		t.Fatal("network missing $encryption")
	}
	if networkEnc["rootKeyId"] != rootKeyID {
		t.Fatalf("network.$encryption.rootKeyId = %v, want %v", networkEnc["rootKeyId"], rootKeyID)
	}
	networkPubJwk := networkEnc["publicKeyJwk"].(map[string]any)
	if networkPubJwk["kty"] != "OKP" || networkPubJwk["crv"] != "X25519" {
		t.Fatalf("unexpected network publicKeyJwk: %v", networkPubJwk)
	}
	networkPubX := networkPubJwk["x"].(string)
	if networkPubX == "" {
		t.Fatal("network publicKeyJwk.x is empty")
	}

	// node should have $encryption.
	node := network["node"].(map[string]any)
	nodeEnc, ok := node["$encryption"].(map[string]any)
	if !ok {
		t.Fatal("node missing $encryption")
	}
	nodePubJwk := nodeEnc["publicKeyJwk"].(map[string]any)
	nodePubX := nodePubJwk["x"].(string)
	if nodePubX == "" || nodePubX == networkPubX {
		t.Fatalf("node publicKeyJwk.x should differ from network: node=%s, network=%s", nodePubX, networkPubX)
	}

	// endpoint (child of node) should have $encryption.
	endpoint := node["endpoint"].(map[string]any)
	endpointEnc, ok := endpoint["$encryption"].(map[string]any)
	if !ok {
		t.Fatal("endpoint missing $encryption")
	}
	endpointPubX := endpointEnc["publicKeyJwk"].(map[string]any)["x"].(string)
	if endpointPubX == "" || endpointPubX == nodePubX {
		t.Fatal("endpoint publicKeyJwk.x should differ from node")
	}

	// $actions should be preserved.
	if _, ok := network["$actions"]; !ok {
		t.Fatal("network.$actions was lost")
	}
	if _, ok := node["$role"]; !ok {
		t.Fatal("node.$role was lost")
	}
}

func TestInjectEncryptionDirectives_DeterministicKeys(t *testing.T) {
	rootPriv, _, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	definition := json.RawMessage(`{
		"protocol": "https://example.com/proto",
		"types": {"a": {}, "b": {}},
		"structure": {"a": {"b": {}}}
	}`)

	result1, err := InjectEncryptionDirectives(definition, rootPriv, "did:test#enc")
	if err != nil {
		t.Fatalf("first injection: %v", err)
	}

	result2, err := InjectEncryptionDirectives(definition, rootPriv, "did:test#enc")
	if err != nil {
		t.Fatalf("second injection: %v", err)
	}

	// Same root key + same definition = same derived keys.
	if !bytes.Equal(result1, result2) {
		t.Fatal("injection should be deterministic")
	}
}

func TestInjectEncryptionDirectives_HierarchicalProperty(t *testing.T) {
	// The parent private key should be able to derive the child private key.
	rootPriv, _, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	protocolURI := "https://example.com/proto"

	// Derive the "a" level key.
	aPath := BuildProtocolPathDerivation(protocolURI, "a")
	aPriv, aPub, err := DerivePrivateKey(rootPriv, aPath)
	if err != nil {
		t.Fatalf("deriving a key: %v", err)
	}

	// Derive the "a/b" level key from root.
	abPathFromRoot := BuildProtocolPathDerivation(protocolURI, "a", "b")
	_, abPubFromRoot, err := DerivePrivateKey(rootPriv, abPathFromRoot)
	if err != nil {
		t.Fatalf("deriving a/b key from root: %v", err)
	}

	// Derive the "b" level key from "a" private key (single HKDF step).
	abPrivFromParent, abPubFromParent, err := DerivePrivateKey(aPriv, []string{"b"})
	if err != nil {
		t.Fatalf("deriving b key from a: %v", err)
	}

	// The public keys should match.
	if !bytes.Equal(abPubFromRoot, abPubFromParent) {
		t.Fatal("hierarchical derivation mismatch: root->a->b != root->a/b")
	}

	// Verify the "a" public key.
	_ = aPub
	_ = abPrivFromParent
}

func TestEncryptionKeyManager_DeriveWriteEncryption(t *testing.T) {
	rootPriv, _, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	mgr := &EncryptionKeyManager{
		RootPrivateKey: rootPriv,
		RootKeyID:      "did:dht:test#enc",
		ProtocolURI:    "https://example.com/proto",
	}

	tests := map[string]struct {
		path string
	}{
		"root level":  {path: "network"},
		"child level": {path: "network/node"},
		"deep level":  {path: "network/node/endpoint"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			recipients, err := mgr.DeriveWriteEncryption(tc.path)
			if err != nil {
				t.Fatalf("DeriveWriteEncryption: %v", err)
			}

			if len(recipients) != 1 {
				t.Fatalf("expected 1 recipient, got %d", len(recipients))
			}

			r := recipients[0]
			if r.PublicKeyID != mgr.RootKeyID {
				t.Fatalf("publicKeyID = %q, want %q", r.PublicKeyID, mgr.RootKeyID)
			}
			if len(r.PublicKey) != X25519KeySize {
				t.Fatalf("public key length = %d, want %d", len(r.PublicKey), X25519KeySize)
			}
			if r.DerivationScheme != DerivationSchemeProtocolPath {
				t.Fatalf("derivationScheme = %q, want %q", r.DerivationScheme, DerivationSchemeProtocolPath)
			}
		})
	}
}

func TestEncryptionKeyManager_RoundTrip(t *testing.T) {
	// Verify that encrypting with DeriveWriteEncryption and decrypting
	// with DeriveDecryptionKey produces the original plaintext.
	rootPriv, _, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	mgr := &EncryptionKeyManager{
		RootPrivateKey: rootPriv,
		RootKeyID:      "did:dht:test#enc",
		ProtocolURI:    "https://enbox.id/protocols/wireguard-mesh",
	}

	paths := []string{
		"network",
		"network/node",
		"network/node/endpoint",
		"network/aclPolicy",
		"network/relay",
		"network/preAuthKey",
	}

	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			plaintext := []byte(fmt.Sprintf(`{"test": "data for %s"}`, path))

			// Encrypt.
			recipients, err := mgr.DeriveWriteEncryption(path)
			if err != nil {
				t.Fatalf("DeriveWriteEncryption: %v", err)
			}

			ciphertext, enc, err := EncryptData(plaintext, recipients)
			if err != nil {
				t.Fatalf("EncryptData: %v", err)
			}

			// Decrypt.
			decryptPriv, err := mgr.DeriveDecryptionKey(path)
			if err != nil {
				t.Fatalf("DeriveDecryptionKey: %v", err)
			}

			got, err := DecryptData(ciphertext, enc, decryptPriv, mgr.RootKeyID)
			if err != nil {
				t.Fatalf("DecryptData: %v", err)
			}

			if !bytes.Equal(got, plaintext) {
				t.Fatalf("decrypted = %s, want %s", got, plaintext)
			}
		})
	}
}

func TestEncryptionKeyManager_InjectedKeysMatchWriteKeys(t *testing.T) {
	// Verify that the public keys injected into the protocol definition
	// by InjectEncryptionDirectives match the keys produced by
	// DeriveWriteEncryption.
	rootPriv, _, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	rootKeyID := "did:dht:test#enc"
	protocolURI := "https://example.com/proto"

	definition := json.RawMessage(`{
		"protocol": "` + protocolURI + `",
		"types": {"a": {}, "b": {}, "c": {}},
		"structure": {"a": {"b": {"c": {}}}}
	}`)

	result, err := InjectEncryptionDirectives(definition, rootPriv, rootKeyID)
	if err != nil {
		t.Fatalf("InjectEncryptionDirectives: %v", err)
	}

	mgr := &EncryptionKeyManager{
		RootPrivateKey: rootPriv,
		RootKeyID:      rootKeyID,
		ProtocolURI:    protocolURI,
	}

	// Parse result and verify each level.
	var defMap map[string]any
	if err := json.Unmarshal(result, &defMap); err != nil {
		t.Fatalf("parsing result: %v", err)
	}

	type pathCheck struct {
		name string
		path string
		get  func() map[string]any
	}

	structure := defMap["structure"].(map[string]any)
	a := structure["a"].(map[string]any)
	b := a["b"].(map[string]any)
	c := b["c"].(map[string]any)

	checks := []pathCheck{
		{"a", "a", func() map[string]any { return a["$encryption"].(map[string]any)["publicKeyJwk"].(map[string]any) }},
		{"a/b", "a/b", func() map[string]any { return b["$encryption"].(map[string]any)["publicKeyJwk"].(map[string]any) }},
		{"a/b/c", "a/b/c", func() map[string]any { return c["$encryption"].(map[string]any)["publicKeyJwk"].(map[string]any) }},
	}

	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			// Get the public key from the injected definition.
			injectedJwk := check.get()
			injectedPubB64 := injectedJwk["x"].(string)
			injectedPub, err := base64.RawURLEncoding.DecodeString(injectedPubB64)
			if err != nil {
				t.Fatalf("decoding injected key: %v", err)
			}

			// Get the public key from DeriveWriteEncryption.
			recipients, err := mgr.DeriveWriteEncryption(check.path)
			if err != nil {
				t.Fatalf("DeriveWriteEncryption: %v", err)
			}

			if !bytes.Equal(injectedPub, recipients[0].PublicKey) {
				t.Fatalf("injected key != DeriveWriteEncryption key for path %q", check.path)
			}
		})
	}
}

func TestSplitProtocolPath(t *testing.T) {
	tests := map[string]struct {
		input    string
		expected []string
	}{
		"single segment": {input: "network", expected: []string{"network"}},
		"two segments":   {input: "network/node", expected: []string{"network", "node"}},
		"three segments": {input: "network/node/endpoint", expected: []string{"network", "node", "endpoint"}},
		"empty":          {input: "", expected: nil},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := splitProtocolPath(tc.input)
			if len(got) != len(tc.expected) {
				t.Fatalf("splitProtocolPath(%q) = %v, want %v", tc.input, got, tc.expected)
			}
			for i, s := range got {
				if s != tc.expected[i] {
					t.Fatalf("segment %d: got %q, want %q", i, s, tc.expected[i])
				}
			}
		})
	}
}

// =============================================================================
// Multi-party encryption (Protocol Context) tests
// =============================================================================

// TestContextEncryptionMultiParty verifies the full multi-party flow:
// 1. A record encrypted with Protocol Context scheme can be decrypted by the owner
// 2. A non-owner with a delivered context key can also decrypt it
// 3. A non-owner encrypts and the anchor can decrypt
// 4. A non-owner WITHOUT the context key CANNOT decrypt it
func TestContextEncryptionMultiParty(t *testing.T) {
	// Simulate the anchor (DWN owner).
	anchorPriv, _, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("generating anchor key: %v", err)
	}

	anchorMgr := &EncryptionKeyManager{
		RootPrivateKey: anchorPriv,
		RootKeyID:      "did:dht:anchor#enc",
		ProtocolURI:    "https://enbox.id/protocols/wireguard-mesh",
	}

	contextID := "bafyreiabc123networkrecordid"

	// 1. Encrypt data with Protocol Context scheme (as a non-anchor would).
	recipients, err := anchorMgr.DeriveContextWriteEncryption(contextID)
	if err != nil {
		t.Fatalf("DeriveContextWriteEncryption: %v", err)
	}

	plaintext := []byte(`{"wireguardPublicKey":"abc==","meshIP":"10.200.0.5"}`)
	ciphertext, enc, err := EncryptData(plaintext, recipients)
	if err != nil {
		t.Fatalf("EncryptData: %v", err)
	}

	// 2. Anchor (owner) decrypts using context key derived from root.
	t.Run("owner can decrypt", func(t *testing.T) {
		contextKey, err := anchorMgr.DeriveContextDecryptionKey(contextID)
		if err != nil {
			t.Fatalf("DeriveContextDecryptionKey: %v", err)
		}
		decrypted, err := DecryptDataWithScheme(ciphertext, enc, contextKey, DerivationSchemeProtocolContext)
		if err != nil {
			t.Fatalf("DecryptDataWithScheme: %v", err)
		}
		if !bytes.Equal(decrypted, plaintext) {
			t.Errorf("decrypted = %q, want %q", decrypted, plaintext)
		}
	})

	// 3. Non-owner with delivered context key can also decrypt.
	t.Run("non-owner with context key can decrypt", func(t *testing.T) {
		nonOwnerPriv, _, err := GenerateX25519KeyPair()
		if err != nil {
			t.Fatalf("generating non-owner key: %v", err)
		}

		nonOwnerMgr := &EncryptionKeyManager{
			RootPrivateKey: nonOwnerPriv,
			RootKeyID:      "did:dht:joiner#enc",
			ProtocolURI:    "https://enbox.id/protocols/wireguard-mesh",
		}

		// Simulate key delivery: anchor derives context key and delivers it.
		contextKeyJwk, err := anchorMgr.DeriveContextKeyJwk(contextID)
		if err != nil {
			t.Fatalf("DeriveContextKeyJwk: %v", err)
		}
		contextKeyBytes, err := contextKeyJwk.PrivateKeyBytes()
		if err != nil {
			t.Fatalf("PrivateKeyBytes: %v", err)
		}
		nonOwnerMgr.StoreContextKey(contextID, contextKeyBytes)

		// Non-owner decrypts.
		decryptKey, err := nonOwnerMgr.DeriveContextDecryptionKey(contextID)
		if err != nil {
			t.Fatalf("DeriveContextDecryptionKey: %v", err)
		}
		decrypted, err := DecryptDataWithScheme(ciphertext, enc, decryptKey, DerivationSchemeProtocolContext)
		if err != nil {
			t.Fatalf("DecryptDataWithScheme: %v", err)
		}
		if !bytes.Equal(decrypted, plaintext) {
			t.Errorf("decrypted = %q, want %q", decrypted, plaintext)
		}
	})

	// 4. Non-owner encrypts with delivered context key, anchor can decrypt.
	t.Run("non-owner encrypts anchor decrypts", func(t *testing.T) {
		nonOwnerPriv, _, err := GenerateX25519KeyPair()
		if err != nil {
			t.Fatalf("generating non-owner key: %v", err)
		}

		nonOwnerMgr := &EncryptionKeyManager{
			RootPrivateKey: nonOwnerPriv,
			RootKeyID:      "did:dht:joiner#enc",
			ProtocolURI:    "https://enbox.id/protocols/wireguard-mesh",
		}

		// Deliver context key to non-owner.
		contextKeyJwk, err := anchorMgr.DeriveContextKeyJwk(contextID)
		if err != nil {
			t.Fatalf("DeriveContextKeyJwk: %v", err)
		}
		contextKeyBytes, err := contextKeyJwk.PrivateKeyBytes()
		if err != nil {
			t.Fatalf("PrivateKeyBytes: %v", err)
		}
		nonOwnerMgr.StoreContextKey(contextID, contextKeyBytes)

		// Non-owner encrypts with context scheme.
		nonOwnerRecipients, err := nonOwnerMgr.DeriveContextWriteEncryption(contextID)
		if err != nil {
			t.Fatalf("DeriveContextWriteEncryption: %v", err)
		}

		data := []byte(`{"meshIP":"10.200.0.6","hostname":"joiner-node"}`)
		ct, encMeta, err := EncryptData(data, nonOwnerRecipients)
		if err != nil {
			t.Fatalf("EncryptData: %v", err)
		}

		// Anchor decrypts.
		anchorContextKey, err := anchorMgr.DeriveContextDecryptionKey(contextID)
		if err != nil {
			t.Fatalf("anchor DeriveContextDecryptionKey: %v", err)
		}
		decrypted, err := DecryptDataWithScheme(ct, encMeta, anchorContextKey, DerivationSchemeProtocolContext)
		if err != nil {
			t.Fatalf("anchor DecryptDataWithScheme: %v", err)
		}
		if !bytes.Equal(decrypted, data) {
			t.Errorf("decrypted = %q, want %q", decrypted, data)
		}
	})

	// 5. Outsider with wrong root key cannot decrypt (wrong context key derived).
	t.Run("outsider with wrong key fails to decrypt", func(t *testing.T) {
		outsiderPriv, _, err := GenerateX25519KeyPair()
		if err != nil {
			t.Fatalf("generating outsider key: %v", err)
		}

		outsiderMgr := &EncryptionKeyManager{
			RootPrivateKey: outsiderPriv,
			RootKeyID:      "did:dht:outsider#enc",
			ProtocolURI:    "https://enbox.id/protocols/wireguard-mesh",
		}

		// Outsider derives a context key from their own (wrong) root key.
		wrongContextKey, err := outsiderMgr.DeriveContextDecryptionKey(contextID)
		if err != nil {
			t.Fatalf("DeriveContextDecryptionKey: %v", err)
		}

		// Decryption should fail because the wrong key unwraps the wrong CEK.
		_, err = DecryptDataWithScheme(ciphertext, enc, wrongContextKey, DerivationSchemeProtocolContext)
		if err == nil {
			t.Error("expected decryption to fail with wrong context key")
		}
	})
}

// RFC 3394 Section 4.3 — AES-192 KEK with 192-bit key data.
func TestAESKeyWrapRFC3394Vector192(t *testing.T) {
	kek, _ := hex.DecodeString("000102030405060708090A0B0C0D0E0F1011121314151617")
	key, _ := hex.DecodeString("00112233445566778899AABBCCDDEEFF0001020304050607")
	expected, _ := hex.DecodeString("031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2")

	wrapped, err := AESKeyWrap(kek, key)
	if err != nil {
		t.Fatalf("AESKeyWrap: %v", err)
	}

	if !bytes.Equal(wrapped, expected) {
		t.Fatalf("wrapped = %x, want %x", wrapped, expected)
	}

	unwrapped, err := AESKeyUnwrap(kek, wrapped)
	if err != nil {
		t.Fatalf("AESKeyUnwrap: %v", err)
	}

	if !bytes.Equal(unwrapped, key) {
		t.Fatal("unwrapped key mismatch")
	}
}
