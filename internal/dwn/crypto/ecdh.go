package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"
)

// Key agreement algorithm identifiers (JWE "alg" values).
const (
	AlgECDHESA256KW = "ECDH-ES+A256KW" // ECDH-ES with X25519 + AES-256 Key Wrap
)

// X25519KeySize is the size of X25519 keys in bytes (32 bytes = 256 bits).
const X25519KeySize = 32

// GenerateX25519KeyPair generates a random X25519 key pair.
// Returns (privateKey, publicKey, error). Both are 32 bytes.
func GenerateX25519KeyPair() (privateKey, publicKey []byte, err error) {
	privateKey = make([]byte, X25519KeySize)
	if _, err := io.ReadFull(rand.Reader, privateKey); err != nil {
		return nil, nil, fmt.Errorf("generating X25519 private key: %w", err)
	}

	publicKey, err = curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		return nil, nil, fmt.Errorf("deriving X25519 public key: %w", err)
	}

	return privateKey, publicKey, nil
}

// X25519PublicKey derives the public key from an X25519 private key.
func X25519PublicKey(privateKey []byte) ([]byte, error) {
	if len(privateKey) != X25519KeySize {
		return nil, fmt.Errorf("X25519 private key must be %d bytes, got %d", X25519KeySize, len(privateKey))
	}
	publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("deriving X25519 public key: %w", err)
	}
	return publicKey, nil
}

// X25519SharedSecret computes the ECDH shared secret (Z) from a private key
// and a peer's public key using X25519 (RFC 7748).
func X25519SharedSecret(privateKey, publicKey []byte) ([]byte, error) {
	if len(privateKey) != X25519KeySize {
		return nil, fmt.Errorf("X25519 private key must be %d bytes, got %d", X25519KeySize, len(privateKey))
	}
	if len(publicKey) != X25519KeySize {
		return nil, fmt.Errorf("X25519 public key must be %d bytes, got %d", X25519KeySize, len(publicKey))
	}

	shared, err := curve25519.X25519(privateKey, publicKey)
	if err != nil {
		return nil, fmt.Errorf("X25519 key agreement: %w", err)
	}

	return shared, nil
}

// ConcatKDFParams contains the fixed info parameters for Concat KDF
// as defined in RFC 7518 Section 4.6.2.
type ConcatKDFParams struct {
	// AlgorithmID is the algorithm identifier (e.g., "A256KW").
	AlgorithmID string
	// PartyUInfo is the producer info (typically empty for DWN).
	PartyUInfo string
	// PartyVInfo is the consumer info (typically empty for DWN).
	PartyVInfo string
	// SuppPubInfo is the key length in bits (e.g., 256).
	SuppPubInfo uint32
}

// ConcatKDF derives key material using the Concat KDF as defined in
// NIST SP 800-56A Section 5.8.1 and RFC 7518 Section 4.6.2.
//
// The derived key is:
//
//	SHA-256(counter || Z || FixedInfo)
//
// Where FixedInfo = AlgorithmID || PartyUInfo || PartyVInfo || SuppPubInfo
// Each variable-length field is encoded as [4-byte big-endian length][data].
// SuppPubInfo is encoded as a fixed 4-byte big-endian value.
//
// Only single-round derivation is supported (keyDataLen <= 256 bits).
func ConcatKDF(sharedSecret []byte, keyDataLen uint32, params ConcatKDFParams) ([]byte, error) {
	if keyDataLen > 256 {
		return nil, fmt.Errorf("ConcatKDF: keyDataLen %d > 256 bits (multi-round not supported)", keyDataLen)
	}

	// Build FixedInfo.
	fixedInfo := computeFixedInfo(params)

	// counter = 0x00000001 (4 bytes, big-endian).
	var counter [4]byte
	binary.BigEndian.PutUint32(counter[:], 1)

	// K(1) = SHA-256(counter || Z || FixedInfo)
	h := sha256.New()
	h.Write(counter[:])
	h.Write(sharedSecret)
	h.Write(fixedInfo)
	derived := h.Sum(nil)

	// Return only the requested number of bytes.
	return derived[:keyDataLen/8], nil
}

// computeFixedInfo builds the FixedInfo per RFC 7518 Section 4.6.2.
func computeFixedInfo(params ConcatKDFParams) []byte {
	var fixedInfo []byte

	// AlgorithmID: variable-length [len][data]
	fixedInfo = append(fixedInfo, toLenData([]byte(params.AlgorithmID))...)

	// PartyUInfo: variable-length [len][data]
	fixedInfo = append(fixedInfo, toLenData([]byte(params.PartyUInfo))...)

	// PartyVInfo: variable-length [len][data]
	fixedInfo = append(fixedInfo, toLenData([]byte(params.PartyVInfo))...)

	// SuppPubInfo: fixed 4-byte big-endian uint32
	var suppPub [4]byte
	binary.BigEndian.PutUint32(suppPub[:], params.SuppPubInfo)
	fixedInfo = append(fixedInfo, suppPub[:]...)

	return fixedInfo
}

// toLenData encodes a variable-length field as [4-byte big-endian length][data].
func toLenData(data []byte) []byte {
	var lenBytes [4]byte
	binary.BigEndian.PutUint32(lenBytes[:], uint32(len(data)))
	result := make([]byte, 4+len(data))
	copy(result, lenBytes[:])
	copy(result[4:], data)
	return result
}

// ECDHESWrapKey performs ECDH-ES+A256KW key wrapping:
//  1. Generate ephemeral X25519 key pair
//  2. Compute ECDH shared secret with the recipient's public key
//  3. Derive KEK via Concat KDF
//  4. Wrap the CEK using AES-256 Key Wrap
//
// Returns the ephemeral public key and the wrapped CEK.
func ECDHESWrapKey(recipientPublicKey, cek []byte) (ephemeralPublicKey, wrappedKey []byte, err error) {
	// 1. Generate ephemeral X25519 key pair.
	ephPriv, ephPub, err := GenerateX25519KeyPair()
	if err != nil {
		return nil, nil, fmt.Errorf("generating ephemeral key: %w", err)
	}

	// 2. Compute ECDH shared secret.
	sharedSecret, err := X25519SharedSecret(ephPriv, recipientPublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("computing shared secret: %w", err)
	}

	// 3. Derive KEK via Concat KDF (RFC 7518 Section 4.6.2).
	kek, err := ConcatKDF(sharedSecret, 256, ConcatKDFParams{
		AlgorithmID: "A256KW",
		PartyUInfo:  "",
		PartyVInfo:  "",
		SuppPubInfo: 256,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("deriving KEK: %w", err)
	}

	// 4. AES-256 Key Wrap.
	wrapped, err := AESKeyWrap(kek, cek)
	if err != nil {
		return nil, nil, fmt.Errorf("wrapping CEK: %w", err)
	}

	return ephPub, wrapped, nil
}

// ECDHESUnwrapKey performs ECDH-ES+A256KW key unwrapping:
//  1. Compute ECDH shared secret using recipient's private key and the ephemeral public key
//  2. Derive KEK via Concat KDF
//  3. Unwrap the CEK using AES-256 Key Unwrap
//
// Returns the unwrapped CEK.
func ECDHESUnwrapKey(recipientPrivateKey, ephemeralPublicKey, wrappedKey []byte) ([]byte, error) {
	// 1. Compute ECDH shared secret.
	sharedSecret, err := X25519SharedSecret(recipientPrivateKey, ephemeralPublicKey)
	if err != nil {
		return nil, fmt.Errorf("computing shared secret: %w", err)
	}

	// 2. Derive KEK via Concat KDF.
	kek, err := ConcatKDF(sharedSecret, 256, ConcatKDFParams{
		AlgorithmID: "A256KW",
		PartyUInfo:  "",
		PartyVInfo:  "",
		SuppPubInfo: 256,
	})
	if err != nil {
		return nil, fmt.Errorf("deriving KEK: %w", err)
	}

	// 3. AES-256 Key Unwrap.
	cek, err := AESKeyUnwrap(kek, wrappedKey)
	if err != nil {
		return nil, fmt.Errorf("unwrapping CEK: %w", err)
	}

	return cek, nil
}
