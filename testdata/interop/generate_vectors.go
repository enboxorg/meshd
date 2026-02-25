// Command generate_vectors produces deterministic encryption test vectors
// that can be validated by both Go and TypeScript DWN SDK implementations.
//
// Usage: go run ./testdata/interop/generate_vectors.go > testdata/interop/vectors.json
package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"

	crypto "github.com/enboxorg/meshd/internal/dwn/crypto"
)

// b64 encodes bytes as base64url (no padding).
func b64(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// deterministicKey generates a deterministic 32-byte key from a seed string.
func deterministicKey(seed string) []byte {
	h := sha256.Sum256([]byte(seed))
	return h[:]
}

// ---- Vector types ----

type HKDFVector struct {
	Description string   `json:"description"`
	RootKey     string   `json:"rootKey"`     // base64url
	Path        []string `json:"path"`        // derivation path segments
	DerivedKey  string   `json:"derivedKey"`  // base64url
	PublicKey   string   `json:"publicKey"`   // X25519 public key, base64url
}

type ConcatKDFVector struct {
	Description  string `json:"description"`
	SharedSecret string `json:"sharedSecret"` // base64url
	KeyDataLen   uint32 `json:"keyDataLen"`
	AlgorithmID  string `json:"algorithmId"`
	PartyUInfo   string `json:"partyUInfo"`
	PartyVInfo   string `json:"partyVInfo"`
	SuppPubInfo  uint32 `json:"suppPubInfo"`
	DerivedKey   string `json:"derivedKey"` // base64url
}

type AEADVector struct {
	Description string `json:"description"`
	Algorithm   string `json:"algorithm"`
	Key         string `json:"key"`        // base64url CEK
	IV          string `json:"iv"`         // base64url
	Plaintext   string `json:"plaintext"`  // base64url
	Ciphertext  string `json:"ciphertext"` // base64url (without tag)
	Tag         string `json:"tag"`        // base64url
}

type KeyWrapVector struct {
	Description string `json:"description"`
	KEK         string `json:"kek"`        // base64url
	Plaintext   string `json:"plaintext"`  // base64url (CEK to wrap)
	Wrapped     string `json:"wrapped"`    // base64url (40 bytes)
}

type ECDHESVector struct {
	Description         string `json:"description"`
	RecipientPrivateKey string `json:"recipientPrivateKey"` // base64url
	RecipientPublicKey  string `json:"recipientPublicKey"`  // base64url
	EphemeralPrivateKey string `json:"ephemeralPrivateKey"` // base64url
	EphemeralPublicKey  string `json:"ephemeralPublicKey"`  // base64url
	CEK                 string `json:"cek"`                 // base64url
	SharedSecret        string `json:"sharedSecret"`        // base64url
	KEK                 string `json:"kek"`                 // base64url
	WrappedKey          string `json:"wrappedKey"`          // base64url
}

type FullJWEVector struct {
	Description         string      `json:"description"`
	RecipientPrivateKey string      `json:"recipientPrivateKey"` // base64url
	RecipientPublicKey  string      `json:"recipientPublicKey"`  // base64url
	RecipientKID        string      `json:"recipientKid"`
	DerivationScheme    string      `json:"derivationScheme"`
	Plaintext           string      `json:"plaintext"`           // base64url
	CEK                 string      `json:"cek"`                 // base64url
	IV                  string      `json:"iv"`                  // base64url
	Ciphertext          string      `json:"ciphertext"`          // base64url (data stored separately)
	JWE                 interface{} `json:"jwe"`                 // The full JWE structure
}

type ProtocolKeyVector struct {
	Description  string   `json:"description"`
	RootKey      string   `json:"rootKey"`      // base64url
	RootKeyID    string   `json:"rootKeyId"`
	ProtocolURI  string   `json:"protocolUri"`
	ProtocolPath string   `json:"protocolPath"` // e.g., "network/member"
	FullPath     []string `json:"fullPath"`     // The complete derivation path
	DerivedKey   string   `json:"derivedKey"`   // base64url private key
	PublicKey    string   `json:"publicKey"`     // base64url X25519 public key
}

type Vectors struct {
	Version     string              `json:"version"`
	GeneratedBy string              `json:"generatedBy"`
	HKDF        []HKDFVector        `json:"hkdf"`
	ConcatKDF   []ConcatKDFVector   `json:"concatKdf"`
	AEAD        []AEADVector        `json:"aead"`
	KeyWrap     []KeyWrapVector     `json:"keyWrap"`
	ECDHES      []ECDHESVector      `json:"ecdhEs"`
	FullJWE     []FullJWEVector     `json:"fullJwe"`
	ProtocolKey []ProtocolKeyVector `json:"protocolKey"`
}

func main() {
	vectors := Vectors{
		Version:     "1.0.0",
		GeneratedBy: "go",
	}

	// ---- HKDF vectors ----
	vectors.HKDF = generateHKDFVectors()

	// ---- Concat KDF vectors ----
	vectors.ConcatKDF = generateConcatKDFVectors()

	// ---- AEAD vectors ----
	vectors.AEAD = generateAEADVectors()

	// ---- Key Wrap vectors ----
	vectors.KeyWrap = generateKeyWrapVectors()

	// ---- ECDH-ES+A256KW vectors ----
	vectors.ECDHES = generateECDHESVectors()

	// ---- Full JWE vectors ----
	vectors.FullJWE = generateFullJWEVectors()

	// ---- Protocol key derivation vectors ----
	vectors.ProtocolKey = generateProtocolKeyVectors()

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(vectors); err != nil {
		fmt.Fprintf(os.Stderr, "Error encoding vectors: %v\n", err)
		os.Exit(1)
	}
}

func generateHKDFVectors() []HKDFVector {
	rootKey := deterministicKey("hkdf-test-root-key")

	var vectors []HKDFVector

	// Single segment.
	{
		path := []string{"protocolPath"}
		derived, err := crypto.DeriveKeyBytes(rootKey, path)
		must(err)
		pub, err := crypto.X25519PublicKey(derived)
		must(err)
		vectors = append(vectors, HKDFVector{
			Description: "single segment: protocolPath",
			RootKey:     b64(rootKey),
			Path:        path,
			DerivedKey:  b64(derived),
			PublicKey:   b64(pub),
		})
	}

	// Two segments: protocol path scheme prefix + protocol URI.
	{
		path := []string{"protocolPath", "https://example.com/protocol/chat"}
		derived, err := crypto.DeriveKeyBytes(rootKey, path)
		must(err)
		pub, err := crypto.X25519PublicKey(derived)
		must(err)
		vectors = append(vectors, HKDFVector{
			Description: "two segments: protocolPath + protocol URI",
			RootKey:     b64(rootKey),
			Path:        path,
			DerivedKey:  b64(derived),
			PublicKey:   b64(pub),
		})
	}

	// Full protocol path: protocolPath / URI / type1 / type2.
	{
		path := []string{"protocolPath", "https://example.com/protocol/chat", "thread", "message"}
		derived, err := crypto.DeriveKeyBytes(rootKey, path)
		must(err)
		pub, err := crypto.X25519PublicKey(derived)
		must(err)
		vectors = append(vectors, HKDFVector{
			Description: "full protocol path: protocolPath/URI/thread/message",
			RootKey:     b64(rootKey),
			Path:        path,
			DerivedKey:  b64(derived),
			PublicKey:   b64(pub),
		})
	}

	// Protocol context scheme.
	{
		path := []string{"protocolContext", "bafyreiabc123contextid"}
		derived, err := crypto.DeriveKeyBytes(rootKey, path)
		must(err)
		pub, err := crypto.X25519PublicKey(derived)
		must(err)
		vectors = append(vectors, HKDFVector{
			Description: "protocol context scheme",
			RootKey:     b64(rootKey),
			Path:        path,
			DerivedKey:  b64(derived),
			PublicKey:   b64(pub),
		})
	}

	// Hierarchical: verify that deriving ["a", "b"] == derive "a" then derive "b".
	{
		path := []string{"step1", "step2", "step3"}
		derived, err := crypto.DeriveKeyBytes(rootKey, path)
		must(err)
		pub, err := crypto.X25519PublicKey(derived)
		must(err)
		vectors = append(vectors, HKDFVector{
			Description: "three-step hierarchical derivation",
			RootKey:     b64(rootKey),
			Path:        path,
			DerivedKey:  b64(derived),
			PublicKey:   b64(pub),
		})
	}

	return vectors
}

func generateConcatKDFVectors() []ConcatKDFVector {
	var vectors []ConcatKDFVector

	// DWN-specific parameters (what's actually used in production).
	{
		sharedSecret := deterministicKey("concat-kdf-shared-secret")
		derived, err := crypto.ConcatKDF(sharedSecret, 256, crypto.ConcatKDFParams{
			AlgorithmID: "A256KW",
			PartyUInfo:  "",
			PartyVInfo:  "",
			SuppPubInfo: 256,
		})
		must(err)
		vectors = append(vectors, ConcatKDFVector{
			Description:  "DWN standard: A256KW, empty party info, 256-bit",
			SharedSecret: b64(sharedSecret),
			KeyDataLen:   256,
			AlgorithmID:  "A256KW",
			PartyUInfo:   "",
			PartyVInfo:   "",
			SuppPubInfo:  256,
			DerivedKey:   b64(derived),
		})
	}

	// RFC 7518 reference vector (from the TS tests — A128GCM with Alice/Bob).
	{
		sharedSecret, _ := base64.RawURLEncoding.DecodeString("nlbZHYFxNdNyg0KDv4QmnPsxbqPagGpI9tqneYz-kMQ")
		derived, err := crypto.ConcatKDF(sharedSecret, 128, crypto.ConcatKDFParams{
			AlgorithmID: "A128GCM",
			PartyUInfo:  "Alice",
			PartyVInfo:  "Bob",
			SuppPubInfo: 128,
		})
		must(err)
		vectors = append(vectors, ConcatKDFVector{
			Description:  "RFC 7518 test vector: A128GCM, Alice/Bob, 128-bit",
			SharedSecret: b64(sharedSecret),
			KeyDataLen:   128,
			AlgorithmID:  "A128GCM",
			PartyUInfo:   "Alice",
			PartyVInfo:   "Bob",
			SuppPubInfo:  128,
			DerivedKey:   b64(derived),
		})
	}

	return vectors
}

func generateAEADVectors() []AEADVector {
	var vectors []AEADVector

	// Short plaintext.
	{
		cek := deterministicKey("aead-cek-1")
		// Deterministic IV: first 12 bytes of SHA-256("aead-iv-1").
		ivFull := deterministicKey("aead-iv-1")
		iv := ivFull[:12]
		plaintext := []byte("hello, DWN encryption interop!")

		ct, tag, err := crypto.AEADEncrypt(crypto.EncA256GCM, cek, iv, plaintext, nil)
		must(err)

		vectors = append(vectors, AEADVector{
			Description: "A256GCM short plaintext",
			Algorithm:   "A256GCM",
			Key:         b64(cek),
			IV:          b64(iv),
			Plaintext:   b64(plaintext),
			Ciphertext:  b64(ct),
			Tag:         b64(tag),
		})
	}

	// Empty plaintext.
	{
		cek := deterministicKey("aead-cek-2")
		ivFull := deterministicKey("aead-iv-2")
		iv := ivFull[:12]
		plaintext := []byte{}

		ct, tag, err := crypto.AEADEncrypt(crypto.EncA256GCM, cek, iv, plaintext, nil)
		must(err)

		vectors = append(vectors, AEADVector{
			Description: "A256GCM empty plaintext",
			Algorithm:   "A256GCM",
			Key:         b64(cek),
			IV:          b64(iv),
			Plaintext:   b64(plaintext),
			Ciphertext:  b64(ct),
			Tag:         b64(tag),
		})
	}

	// JSON payload (typical DWN record content).
	{
		cek := deterministicKey("aead-cek-3")
		ivFull := deterministicKey("aead-iv-3")
		iv := ivFull[:12]
		plaintext := []byte(`{"type":"nodeInfo","publicKey":"abc123","endpoint":"10.200.0.1:51820"}`)

		ct, tag, err := crypto.AEADEncrypt(crypto.EncA256GCM, cek, iv, plaintext, nil)
		must(err)

		vectors = append(vectors, AEADVector{
			Description: "A256GCM JSON payload",
			Algorithm:   "A256GCM",
			Key:         b64(cek),
			IV:          b64(iv),
			Plaintext:   b64(plaintext),
			Ciphertext:  b64(ct),
			Tag:         b64(tag),
		})
	}

	return vectors
}

func generateKeyWrapVectors() []KeyWrapVector {
	var vectors []KeyWrapVector

	// Standard 256-bit key wrapping 256-bit CEK.
	{
		kek := deterministicKey("keywrap-kek-1")
		cek := deterministicKey("keywrap-cek-1")

		wrapped, err := crypto.AESKeyWrap(kek, cek)
		must(err)

		vectors = append(vectors, KeyWrapVector{
			Description: "AES-256 Key Wrap of 256-bit CEK",
			KEK:         b64(kek),
			Plaintext:   b64(cek),
			Wrapped:     b64(wrapped),
		})
	}

	return vectors
}

func generateECDHESVectors() []ECDHESVector {
	var vectors []ECDHESVector

	// Full ECDH-ES+A256KW with deterministic keys.
	{
		recipientPriv := deterministicKey("ecdh-recipient-priv")
		recipientPub, err := curve25519.X25519(recipientPriv, curve25519.Basepoint)
		must(err)

		ephemeralPriv := deterministicKey("ecdh-ephemeral-priv")
		ephemeralPub, err := curve25519.X25519(ephemeralPriv, curve25519.Basepoint)
		must(err)

		cek := deterministicKey("ecdh-cek")

		// Compute shared secret manually.
		sharedSecret, err := curve25519.X25519(ephemeralPriv, recipientPub)
		must(err)

		// Derive KEK via ConcatKDF.
		kek, err := crypto.ConcatKDF(sharedSecret, 256, crypto.ConcatKDFParams{
			AlgorithmID: "A256KW",
			PartyUInfo:  "",
			PartyVInfo:  "",
			SuppPubInfo: 256,
		})
		must(err)

		// Wrap CEK.
		wrappedKey, err := crypto.AESKeyWrap(kek, cek)
		must(err)

		vectors = append(vectors, ECDHESVector{
			Description:         "ECDH-ES+A256KW full flow with deterministic keys",
			RecipientPrivateKey: b64(recipientPriv),
			RecipientPublicKey:  b64(recipientPub),
			EphemeralPrivateKey: b64(ephemeralPriv),
			EphemeralPublicKey:  b64(ephemeralPub),
			CEK:                 b64(cek),
			SharedSecret:        b64(sharedSecret),
			KEK:                 b64(kek),
			WrappedKey:          b64(wrappedKey),
		})
	}

	return vectors
}

func generateFullJWEVectors() []FullJWEVector {
	var vectors []FullJWEVector

	// Full JWE with deterministic inputs.
	// We manually construct the JWE to have deterministic ephemeral keys
	// (BuildJWE uses random ephemerals, so we build manually).
	{
		recipientPriv := deterministicKey("jwe-recipient-priv")
		recipientPub, err := curve25519.X25519(recipientPriv, curve25519.Basepoint)
		must(err)

		cek := deterministicKey("jwe-cek")
		ivFull := deterministicKey("jwe-iv")
		iv := ivFull[:12]

		plaintext := []byte(`{"networkId":"net-001","role":"admin"}`)

		// Encrypt data.
		ct, tag, err := crypto.AEADEncrypt(crypto.EncA256GCM, cek, iv, plaintext, nil)
		must(err)

		// Wrap CEK with deterministic ephemeral.
		ephemeralPriv := deterministicKey("jwe-ephemeral-priv")
		ephemeralPub, err := curve25519.X25519(ephemeralPriv, curve25519.Basepoint)
		must(err)

		sharedSecret, err := curve25519.X25519(ephemeralPriv, recipientPub)
		must(err)

		kek, err := crypto.ConcatKDF(sharedSecret, 256, crypto.ConcatKDFParams{
			AlgorithmID: "A256KW",
			PartyUInfo:  "",
			PartyVInfo:  "",
			SuppPubInfo: 256,
		})
		must(err)

		wrappedKey, err := crypto.AESKeyWrap(kek, cek)
		must(err)

		// Build JWE structure manually.
		protectedHeader := crypto.ProtectedHeader{
			Alg: "ECDH-ES+A256KW",
			Enc: "A256GCM",
		}
		protectedJSON, _ := json.Marshal(protectedHeader)
		protectedB64 := b64(protectedJSON)

		kid := "did:dht:interoptest123#enc"

		jwe := crypto.Encryption{
			Protected: protectedB64,
			IV:        b64(iv),
			Tag:       b64(tag),
			Recipients: []crypto.Recipient{
				{
					Header: crypto.RecipientHeader{
						KID: kid,
						EPK: &crypto.PublicKeyJWK{
							KTY: "OKP",
							CRV: "X25519",
							X:   b64(ephemeralPub),
						},
						DerivationScheme: "protocolPath",
					},
					EncryptedKey: b64(wrappedKey),
				},
			},
		}

		vectors = append(vectors, FullJWEVector{
			Description:         "full JWE A256GCM with deterministic keys",
			RecipientPrivateKey: b64(recipientPriv),
			RecipientPublicKey:  b64(recipientPub),
			RecipientKID:        kid,
			DerivationScheme:    "protocolPath",
			Plaintext:           b64(plaintext),
			CEK:                 b64(cek),
			IV:                  b64(iv),
			Ciphertext:          b64(ct),
			JWE:                 jwe,
		})
	}

	return vectors
}

func generateProtocolKeyVectors() []ProtocolKeyVector {
	var vectors []ProtocolKeyVector

	rootKey := deterministicKey("protocol-root-key")
	rootKeyID := "did:dht:interoptest123#enc"
	protocolURI := "https://example.com/protocol/wireguard-mesh"

	// Top-level type "network".
	{
		fullPath := crypto.BuildProtocolPathDerivation(protocolURI, "network")
		derived, pub, err := crypto.DerivePrivateKey(rootKey, fullPath)
		must(err)
		vectors = append(vectors, ProtocolKeyVector{
			Description:  "protocol path: network",
			RootKey:      b64(rootKey),
			RootKeyID:    rootKeyID,
			ProtocolURI:  protocolURI,
			ProtocolPath: "network",
			FullPath:     fullPath,
			DerivedKey:   b64(derived),
			PublicKey:    b64(pub),
		})
	}

	// Nested type "network/member".
	{
		fullPath := crypto.BuildProtocolPathDerivation(protocolURI, "network", "member")
		derived, pub, err := crypto.DerivePrivateKey(rootKey, fullPath)
		must(err)
		vectors = append(vectors, ProtocolKeyVector{
			Description:  "protocol path: network/member",
			RootKey:      b64(rootKey),
			RootKeyID:    rootKeyID,
			ProtocolURI:  protocolURI,
			ProtocolPath: "network/member",
			FullPath:     fullPath,
			DerivedKey:   b64(derived),
			PublicKey:    b64(pub),
		})
	}

	// Deeply nested "network/member/nodeInfo".
	{
		fullPath := crypto.BuildProtocolPathDerivation(protocolURI, "network", "member", "nodeInfo")
		derived, pub, err := crypto.DerivePrivateKey(rootKey, fullPath)
		must(err)
		vectors = append(vectors, ProtocolKeyVector{
			Description:  "protocol path: network/member/nodeInfo",
			RootKey:      b64(rootKey),
			RootKeyID:    rootKeyID,
			ProtocolURI:  protocolURI,
			ProtocolPath: "network/member/nodeInfo",
			FullPath:     fullPath,
			DerivedKey:   b64(derived),
			PublicKey:    b64(pub),
		})
	}

	return vectors
}

// hkdfDerive replicates the single-step HKDF derivation for verification.
func hkdfDerive(inputKey, info []byte) ([]byte, error) {
	r := hkdf.New(sha256.New, inputKey, nil, info)
	derived := make([]byte, 32)
	if _, err := io.ReadFull(r, derived); err != nil {
		return nil, err
	}
	return derived, nil
}

// computeFixedInfo builds Concat KDF FixedInfo for verification.
func computeFixedInfo(algorithmID, partyU, partyV string, suppPub uint32) []byte {
	var fi []byte
	fi = appendLenData(fi, []byte(algorithmID))
	fi = appendLenData(fi, []byte(partyU))
	fi = appendLenData(fi, []byte(partyV))
	var sp [4]byte
	binary.BigEndian.PutUint32(sp[:], suppPub)
	fi = append(fi, sp[:]...)
	return fi
}

func appendLenData(dst, data []byte) []byte {
	var lenBytes [4]byte
	binary.BigEndian.PutUint32(lenBytes[:], uint32(len(data)))
	dst = append(dst, lenBytes[:]...)
	dst = append(dst, data...)
	return dst
}

func must(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fatal: %v\n", err)
		os.Exit(1)
	}
}
