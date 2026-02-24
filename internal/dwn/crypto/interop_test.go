package crypto

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"golang.org/x/crypto/curve25519"
)

// Interop test vectors — verifies that our Go crypto primitives produce
// identical output to the TypeScript DWN SDK. Both sides use the same
// deterministic inputs and must agree on all outputs.

// ---- Vector types (mirror the JSON structure) ----

type interopVectors struct {
	Version     string                `json:"version"`
	GeneratedBy string                `json:"generatedBy"`
	HKDF        []hkdfVector          `json:"hkdf"`
	ConcatKDF   []concatKDFVector     `json:"concatKdf"`
	AEAD        []aeadVector          `json:"aead"`
	KeyWrap     []keyWrapVector       `json:"keyWrap"`
	ECDHES      []ecdhesVector        `json:"ecdhEs"`
	FullJWE     []fullJWEVector       `json:"fullJwe"`
	ProtocolKey []protocolKeyVector   `json:"protocolKey"`
}

type hkdfVector struct {
	Description string   `json:"description"`
	RootKey     string   `json:"rootKey"`
	Path        []string `json:"path"`
	DerivedKey  string   `json:"derivedKey"`
	PublicKey   string   `json:"publicKey"`
}

type concatKDFVector struct {
	Description  string `json:"description"`
	SharedSecret string `json:"sharedSecret"`
	KeyDataLen   uint32 `json:"keyDataLen"`
	AlgorithmID  string `json:"algorithmId"`
	PartyUInfo   string `json:"partyUInfo"`
	PartyVInfo   string `json:"partyVInfo"`
	SuppPubInfo  uint32 `json:"suppPubInfo"`
	DerivedKey   string `json:"derivedKey"`
}

type aeadVector struct {
	Description string `json:"description"`
	Algorithm   string `json:"algorithm"`
	Key         string `json:"key"`
	IV          string `json:"iv"`
	Plaintext   string `json:"plaintext"`
	Ciphertext  string `json:"ciphertext"`
	Tag         string `json:"tag"`
}

type keyWrapVector struct {
	Description string `json:"description"`
	KEK         string `json:"kek"`
	Plaintext   string `json:"plaintext"`
	Wrapped     string `json:"wrapped"`
}

type ecdhesVector struct {
	Description         string `json:"description"`
	RecipientPrivateKey string `json:"recipientPrivateKey"`
	RecipientPublicKey  string `json:"recipientPublicKey"`
	EphemeralPrivateKey string `json:"ephemeralPrivateKey"`
	EphemeralPublicKey  string `json:"ephemeralPublicKey"`
	CEK                 string `json:"cek"`
	SharedSecret        string `json:"sharedSecret"`
	KEK                 string `json:"kek"`
	WrappedKey          string `json:"wrappedKey"`
}

type fullJWEVector struct {
	Description         string          `json:"description"`
	RecipientPrivateKey string          `json:"recipientPrivateKey"`
	RecipientPublicKey  string          `json:"recipientPublicKey"`
	RecipientKID        string          `json:"recipientKid"`
	DerivationScheme    string          `json:"derivationScheme"`
	Plaintext           string          `json:"plaintext"`
	CEK                 string          `json:"cek"`
	IV                  string          `json:"iv"`
	Ciphertext          string          `json:"ciphertext"`
	JWE                 json.RawMessage `json:"jwe"`
}

type protocolKeyVector struct {
	Description  string   `json:"description"`
	RootKey      string   `json:"rootKey"`
	RootKeyID    string   `json:"rootKeyId"`
	ProtocolURI  string   `json:"protocolUri"`
	ProtocolPath string   `json:"protocolPath"`
	FullPath     []string `json:"fullPath"`
	DerivedKey   string   `json:"derivedKey"`
	PublicKey    string   `json:"publicKey"`
}

// loadVectors reads the shared test vectors from testdata/interop/vectors.json.
func loadVectors(t *testing.T) *interopVectors {
	t.Helper()

	// Find the project root (the crypto package is at internal/dwn/crypto/).
	_, thisFile, _, _ := runtime.Caller(0)
	projectRoot := filepath.Join(filepath.Dir(thisFile), "..", "..", "..")
	vectorsPath := filepath.Join(projectRoot, "testdata", "interop", "vectors.json")

	data, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatalf("loading vectors: %v (looked at %s)", err, vectorsPath)
	}

	var vectors interopVectors
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("parsing vectors: %v", err)
	}

	return &vectors
}

func b64Decode(t *testing.T, s string) []byte {
	t.Helper()
	data, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("base64url decode %q: %v", s, err)
	}
	return data
}

// ---- HKDF interop tests ----

func TestInteropHKDF(t *testing.T) {
	vectors := loadVectors(t)

	for _, v := range vectors.HKDF {
		t.Run(v.Description, func(t *testing.T) {
			rootKey := b64Decode(t, v.RootKey)

			derived, err := DeriveKeyBytes(rootKey, v.Path)
			if err != nil {
				t.Fatalf("DeriveKeyBytes: %v", err)
			}

			expected := b64Decode(t, v.DerivedKey)
			if !bytes.Equal(derived, expected) {
				t.Errorf("derived key mismatch\n  got:  %s\n  want: %s",
					base64.RawURLEncoding.EncodeToString(derived), v.DerivedKey)
			}

			// Verify public key derivation.
			pub, err := X25519PublicKey(derived)
			if err != nil {
				t.Fatalf("X25519PublicKey: %v", err)
			}
			expectedPub := b64Decode(t, v.PublicKey)
			if !bytes.Equal(pub, expectedPub) {
				t.Errorf("public key mismatch\n  got:  %s\n  want: %s",
					base64.RawURLEncoding.EncodeToString(pub), v.PublicKey)
			}
		})
	}
}

// ---- Concat KDF interop tests ----

func TestInteropConcatKDF(t *testing.T) {
	vectors := loadVectors(t)

	for _, v := range vectors.ConcatKDF {
		t.Run(v.Description, func(t *testing.T) {
			sharedSecret := b64Decode(t, v.SharedSecret)

			derived, err := ConcatKDF(sharedSecret, v.KeyDataLen, ConcatKDFParams{
				AlgorithmID: v.AlgorithmID,
				PartyUInfo:  v.PartyUInfo,
				PartyVInfo:  v.PartyVInfo,
				SuppPubInfo: v.SuppPubInfo,
			})
			if err != nil {
				t.Fatalf("ConcatKDF: %v", err)
			}

			expected := b64Decode(t, v.DerivedKey)
			if !bytes.Equal(derived, expected) {
				t.Errorf("derived key mismatch\n  got:  %s\n  want: %s",
					base64.RawURLEncoding.EncodeToString(derived), v.DerivedKey)
			}
		})
	}
}

// ---- AEAD interop tests ----

func TestInteropAEAD(t *testing.T) {
	vectors := loadVectors(t)

	for _, v := range vectors.AEAD {
		t.Run(v.Description+" encrypt", func(t *testing.T) {
			key := b64Decode(t, v.Key)
			iv := b64Decode(t, v.IV)
			plaintext := b64Decode(t, v.Plaintext)

			ct, tag, err := AEADEncrypt(v.Algorithm, key, iv, plaintext, nil)
			if err != nil {
				t.Fatalf("AEADEncrypt: %v", err)
			}

			expectedCT := b64Decode(t, v.Ciphertext)
			expectedTag := b64Decode(t, v.Tag)

			if !bytes.Equal(ct, expectedCT) {
				t.Errorf("ciphertext mismatch\n  got:  %s\n  want: %s",
					base64.RawURLEncoding.EncodeToString(ct), v.Ciphertext)
			}
			if !bytes.Equal(tag, expectedTag) {
				t.Errorf("tag mismatch\n  got:  %s\n  want: %s",
					base64.RawURLEncoding.EncodeToString(tag), v.Tag)
			}
		})

		t.Run(v.Description+" decrypt", func(t *testing.T) {
			key := b64Decode(t, v.Key)
			iv := b64Decode(t, v.IV)
			ct := b64Decode(t, v.Ciphertext)
			tag := b64Decode(t, v.Tag)
			expectedPlaintext := b64Decode(t, v.Plaintext)

			plaintext, err := AEADDecrypt(v.Algorithm, key, iv, ct, tag, nil)
			if err != nil {
				t.Fatalf("AEADDecrypt: %v", err)
			}

			if !bytes.Equal(plaintext, expectedPlaintext) {
				t.Errorf("plaintext mismatch\n  got:  %s\n  want: %s",
					base64.RawURLEncoding.EncodeToString(plaintext), v.Plaintext)
			}
		})
	}
}

// ---- AES Key Wrap interop tests ----

func TestInteropKeyWrap(t *testing.T) {
	vectors := loadVectors(t)

	for _, v := range vectors.KeyWrap {
		t.Run(v.Description+" wrap", func(t *testing.T) {
			kek := b64Decode(t, v.KEK)
			plaintext := b64Decode(t, v.Plaintext)

			wrapped, err := AESKeyWrap(kek, plaintext)
			if err != nil {
				t.Fatalf("AESKeyWrap: %v", err)
			}

			expected := b64Decode(t, v.Wrapped)
			if !bytes.Equal(wrapped, expected) {
				t.Errorf("wrapped key mismatch\n  got:  %s\n  want: %s",
					base64.RawURLEncoding.EncodeToString(wrapped), v.Wrapped)
			}
		})

		t.Run(v.Description+" unwrap", func(t *testing.T) {
			kek := b64Decode(t, v.KEK)
			wrapped := b64Decode(t, v.Wrapped)
			expected := b64Decode(t, v.Plaintext)

			unwrapped, err := AESKeyUnwrap(kek, wrapped)
			if err != nil {
				t.Fatalf("AESKeyUnwrap: %v", err)
			}

			if !bytes.Equal(unwrapped, expected) {
				t.Errorf("unwrapped key mismatch\n  got:  %s\n  want: %s",
					base64.RawURLEncoding.EncodeToString(unwrapped), v.Plaintext)
			}
		})
	}
}

// ---- ECDH-ES+A256KW interop tests ----

func TestInteropECDHES(t *testing.T) {
	vectors := loadVectors(t)

	for _, v := range vectors.ECDHES {
		t.Run(v.Description, func(t *testing.T) {
			recipientPriv := b64Decode(t, v.RecipientPrivateKey)
			recipientPub := b64Decode(t, v.RecipientPublicKey)
			ephPriv := b64Decode(t, v.EphemeralPrivateKey)
			ephPub := b64Decode(t, v.EphemeralPublicKey)
			cek := b64Decode(t, v.CEK)

			// Verify public key derivation.
			gotRecipientPub, err := curve25519.X25519(recipientPriv, curve25519.Basepoint)
			if err != nil {
				t.Fatalf("deriving recipient public key: %v", err)
			}
			if !bytes.Equal(gotRecipientPub, recipientPub) {
				t.Error("recipient public key derivation mismatch")
			}

			gotEphPub, err := curve25519.X25519(ephPriv, curve25519.Basepoint)
			if err != nil {
				t.Fatalf("deriving ephemeral public key: %v", err)
			}
			if !bytes.Equal(gotEphPub, ephPub) {
				t.Error("ephemeral public key derivation mismatch")
			}

			// Step 1: ECDH shared secret.
			sharedSecret, err := X25519SharedSecret(ephPriv, recipientPub)
			if err != nil {
				t.Fatalf("X25519SharedSecret: %v", err)
			}
			expectedShared := b64Decode(t, v.SharedSecret)
			if !bytes.Equal(sharedSecret, expectedShared) {
				t.Errorf("shared secret mismatch\n  got:  %s\n  want: %s",
					base64.RawURLEncoding.EncodeToString(sharedSecret), v.SharedSecret)
			}

			// Verify ECDH symmetry (recipient side).
			sharedSecretR, err := X25519SharedSecret(recipientPriv, ephPub)
			if err != nil {
				t.Fatalf("X25519SharedSecret (recipient): %v", err)
			}
			if !bytes.Equal(sharedSecret, sharedSecretR) {
				t.Error("ECDH shared secret not symmetric")
			}

			// Step 2: Concat KDF.
			kek, err := ConcatKDF(sharedSecret, 256, ConcatKDFParams{
				AlgorithmID: "A256KW",
				PartyUInfo:  "",
				PartyVInfo:  "",
				SuppPubInfo: 256,
			})
			if err != nil {
				t.Fatalf("ConcatKDF: %v", err)
			}
			expectedKEK := b64Decode(t, v.KEK)
			if !bytes.Equal(kek, expectedKEK) {
				t.Errorf("KEK mismatch\n  got:  %s\n  want: %s",
					base64.RawURLEncoding.EncodeToString(kek), v.KEK)
			}

			// Step 3: Key Wrap.
			wrapped, err := AESKeyWrap(kek, cek)
			if err != nil {
				t.Fatalf("AESKeyWrap: %v", err)
			}
			expectedWrapped := b64Decode(t, v.WrappedKey)
			if !bytes.Equal(wrapped, expectedWrapped) {
				t.Errorf("wrapped key mismatch\n  got:  %s\n  want: %s",
					base64.RawURLEncoding.EncodeToString(wrapped), v.WrappedKey)
			}

			// Verify unwrap.
			unwrapped, err := ECDHESUnwrapKey(recipientPriv, ephPub, wrapped)
			if err != nil {
				t.Fatalf("ECDHESUnwrapKey: %v", err)
			}
			if !bytes.Equal(unwrapped, cek) {
				t.Error("unwrapped CEK does not match original")
			}
		})
	}
}

// ---- Full JWE interop tests ----

func TestInteropFullJWE(t *testing.T) {
	vectors := loadVectors(t)

	for _, v := range vectors.FullJWE {
		t.Run(v.Description, func(t *testing.T) {
			recipientPriv := b64Decode(t, v.RecipientPrivateKey)
			ct := b64Decode(t, v.Ciphertext)

			// Parse the JWE structure.
			var enc Encryption
			if err := json.Unmarshal(v.JWE, &enc); err != nil {
				t.Fatalf("parsing JWE: %v", err)
			}

			// Decrypt using the standard DecryptData flow.
			plaintext, err := DecryptData(ct, &enc, recipientPriv, v.RecipientKID)
			if err != nil {
				t.Fatalf("DecryptData: %v", err)
			}

			expectedPlaintext := b64Decode(t, v.Plaintext)
			if !bytes.Equal(plaintext, expectedPlaintext) {
				t.Errorf("decrypted plaintext mismatch\n  got:  %q\n  want: %q",
					string(plaintext), string(expectedPlaintext))
			}

			// Also verify: re-encrypt with the same CEK/IV produces the same ciphertext.
			cek := b64Decode(t, v.CEK)
			iv := b64Decode(t, v.IV)
			gotCT, gotTag, err := AEADEncrypt(EncA256GCM, cek, iv, expectedPlaintext, nil)
			if err != nil {
				t.Fatalf("re-encrypt: %v", err)
			}
			if !bytes.Equal(gotCT, ct) {
				t.Error("re-encrypted ciphertext mismatch")
			}

			// Verify tag matches JWE.
			jweTag := b64Decode(t, enc.Tag)
			if !bytes.Equal(gotTag, jweTag) {
				t.Error("re-encrypted tag mismatch")
			}
		})
	}
}

// ---- Protocol key derivation interop tests ----

func TestInteropProtocolKey(t *testing.T) {
	vectors := loadVectors(t)

	for _, v := range vectors.ProtocolKey {
		t.Run(v.Description, func(t *testing.T) {
			rootKey := b64Decode(t, v.RootKey)

			// Test using EncryptionKeyManager.
			mgr := &EncryptionKeyManager{
				RootPrivateKey: rootKey,
				RootKeyID:      v.RootKeyID,
				ProtocolURI:    v.ProtocolURI,
			}

			// DeriveWriteEncryption should produce the same public key.
			inputs, err := mgr.DeriveWriteEncryption(v.ProtocolPath)
			if err != nil {
				t.Fatalf("DeriveWriteEncryption: %v", err)
			}
			if len(inputs) != 1 {
				t.Fatalf("expected 1 input, got %d", len(inputs))
			}

			expectedPub := b64Decode(t, v.PublicKey)
			if !bytes.Equal(inputs[0].PublicKey, expectedPub) {
				t.Errorf("write encryption public key mismatch\n  got:  %s\n  want: %s",
					base64.RawURLEncoding.EncodeToString(inputs[0].PublicKey), v.PublicKey)
			}

			// DeriveDecryptionKey should produce the matching private key.
			derivedPriv, err := mgr.DeriveDecryptionKey(v.ProtocolPath)
			if err != nil {
				t.Fatalf("DeriveDecryptionKey: %v", err)
			}

			expectedPriv := b64Decode(t, v.DerivedKey)
			if !bytes.Equal(derivedPriv, expectedPriv) {
				t.Errorf("decryption private key mismatch\n  got:  %s\n  want: %s",
					base64.RawURLEncoding.EncodeToString(derivedPriv), v.DerivedKey)
			}

			// Also test via DerivePrivateKey directly with the full path.
			directPriv, directPub, err := DerivePrivateKey(rootKey, v.FullPath)
			if err != nil {
				t.Fatalf("DerivePrivateKey: %v", err)
			}
			if !bytes.Equal(directPriv, expectedPriv) {
				t.Error("direct DerivePrivateKey private key mismatch")
			}
			if !bytes.Equal(directPub, expectedPub) {
				t.Error("direct DerivePrivateKey public key mismatch")
			}
		})
	}
}
