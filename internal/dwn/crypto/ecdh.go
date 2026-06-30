package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// Key agreement algorithm identifier (encryption-v1 keyEncryption "algorithm").
const (
	// AlgX25519HKDFA256KW is X25519 ECDH -> HKDF-SHA256 KEK -> AES-256 Key Wrap.
	AlgX25519HKDFA256KW = "X25519-HKDF-SHA256+A256KW"
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

// deriveKEK derives the 256-bit Key Encryption Key from the ECDH shared secret
// using HKDF-SHA256 with an empty salt and the encryption-v1 info string.
//
//	kek = HKDF-SHA256(ikm=sharedSecret, salt="", info=info, L=32)
func deriveKEK(sharedSecret []byte, info string) ([]byte, error) {
	r := hkdf.New(sha256.New, sharedSecret, nil, []byte(info))
	kek := make([]byte, 32)
	if _, err := io.ReadFull(r, kek); err != nil {
		return nil, fmt.Errorf("deriving KEK: %w", err)
	}
	return kek, nil
}

// WrapCEK performs X25519-HKDF-SHA256+A256KW key wrapping:
//  1. Generate an ephemeral X25519 key pair.
//  2. Compute the ECDH shared secret with the recipient's public key.
//  3. Derive the KEK via HKDF-SHA256 with the given info string.
//  4. Wrap the CEK using AES-256 Key Wrap (RFC 3394).
//
// Returns the ephemeral public key and the wrapped CEK.
func WrapCEK(recipientPublicKey, cek []byte, info string) (ephemeralPublicKey, wrappedKey []byte, err error) {
	ephPriv, ephPub, err := GenerateX25519KeyPair()
	if err != nil {
		return nil, nil, fmt.Errorf("generating ephemeral key: %w", err)
	}
	defer clear(ephPriv)

	sharedSecret, err := X25519SharedSecret(ephPriv, recipientPublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("computing shared secret: %w", err)
	}
	defer clear(sharedSecret)

	kek, err := deriveKEK(sharedSecret, info)
	if err != nil {
		return nil, nil, err
	}
	defer clear(kek)

	wrapped, err := AESKeyWrap(kek, cek)
	if err != nil {
		return nil, nil, fmt.Errorf("wrapping CEK: %w", err)
	}

	return ephPub, wrapped, nil
}

// UnwrapCEK performs X25519-HKDF-SHA256+A256KW key unwrapping:
//  1. Compute the ECDH shared secret from the recipient's private key and the
//     ephemeral public key.
//  2. Derive the KEK via HKDF-SHA256 with the given info string.
//  3. Unwrap the CEK using AES-256 Key Unwrap (RFC 3394).
func UnwrapCEK(recipientPrivateKey, ephemeralPublicKey, wrappedKey []byte, info string) ([]byte, error) {
	sharedSecret, err := X25519SharedSecret(recipientPrivateKey, ephemeralPublicKey)
	if err != nil {
		return nil, fmt.Errorf("computing shared secret: %w", err)
	}
	defer clear(sharedSecret)

	kek, err := deriveKEK(sharedSecret, info)
	if err != nil {
		return nil, err
	}
	defer clear(kek)

	cek, err := AESKeyUnwrap(kek, wrappedKey)
	if err != nil {
		return nil, fmt.Errorf("unwrapping CEK: %w", err)
	}

	return cek, nil
}
