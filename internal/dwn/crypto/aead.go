// Package crypto implements DWN encryption primitives.
//
// The DWN spec uses a two-layer encryption model:
//   - Content layer: AEAD cipher (A256GCM or XC20P) encrypts record data
//   - Key agreement layer: ECDH-ES+A256KW wraps the CEK per recipient
//
// Keys are derived hierarchically via HKDF-SHA256 using the protocol path
// or protocol context derivation schemes.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

// Content encryption algorithm identifiers (JWE "enc" values).
const (
	EncA256GCM = "A256GCM" // AES-256-GCM (RFC 7518 Section 5.3)
)

const (
	// CEKSize is the size of the Content Encryption Key in bytes (256 bits).
	CEKSize = 32

	// IVSizeA256GCM is the nonce size for A256GCM (96 bits).
	IVSizeA256GCM = 12

	// TagSize is the authentication tag size (128 bits) for both ciphers.
	TagSize = 16
)

// GenerateCEK generates a random 256-bit Content Encryption Key.
func GenerateCEK() ([]byte, error) {
	cek := make([]byte, CEKSize)
	if _, err := io.ReadFull(rand.Reader, cek); err != nil {
		return nil, fmt.Errorf("generating CEK: %w", err)
	}
	return cek, nil
}

// GenerateIV generates a random initialization vector for the given algorithm.
func GenerateIV(enc string) ([]byte, error) {
	size, err := ivSize(enc)
	if err != nil {
		return nil, err
	}
	iv := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("generating IV: %w", err)
	}
	return iv, nil
}

// AEADEncrypt encrypts plaintext using the specified algorithm, key, and IV.
// Returns ciphertext and authentication tag separately.
func AEADEncrypt(enc string, key, iv, plaintext, aad []byte) (ciphertext, tag []byte, err error) {
	switch enc {
	case EncA256GCM:
		return aesGCMEncrypt(key, iv, plaintext, aad)
	default:
		return nil, nil, fmt.Errorf("unsupported content encryption: %s", enc)
	}
}

// AEADDecrypt decrypts ciphertext using the specified algorithm, key, IV, and tag.
func AEADDecrypt(enc string, key, iv, ciphertext, tag, aad []byte) ([]byte, error) {
	switch enc {
	case EncA256GCM:
		return aesGCMDecrypt(key, iv, ciphertext, tag, aad)
	default:
		return nil, fmt.Errorf("unsupported content encryption: %s", enc)
	}
}

func aesGCMEncrypt(key, nonce, plaintext, aad []byte) (ciphertext, tag []byte, err error) {
	if len(key) != CEKSize {
		return nil, nil, fmt.Errorf("AES-256-GCM key must be %d bytes, got %d", CEKSize, len(key))
	}
	if len(nonce) != IVSizeA256GCM {
		return nil, nil, fmt.Errorf("AES-256-GCM nonce must be %d bytes, got %d", IVSizeA256GCM, len(nonce))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("creating AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("creating GCM: %w", err)
	}

	// GCM Seal appends the tag to the ciphertext.
	sealed := gcm.Seal(nil, nonce, plaintext, aad)

	// Split ciphertext and tag (tag is last 16 bytes).
	ctLen := len(sealed) - gcm.Overhead()
	return sealed[:ctLen], sealed[ctLen:], nil
}

func aesGCMDecrypt(key, nonce, ciphertext, tag, aad []byte) ([]byte, error) {
	if len(key) != CEKSize {
		return nil, fmt.Errorf("AES-256-GCM key must be %d bytes, got %d", CEKSize, len(key))
	}
	if len(nonce) != IVSizeA256GCM {
		return nil, fmt.Errorf("AES-256-GCM nonce must be %d bytes, got %d", IVSizeA256GCM, len(nonce))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}

	// Reunite ciphertext and tag for GCM Open.
	sealed := make([]byte, len(ciphertext)+len(tag))
	copy(sealed, ciphertext)
	copy(sealed[len(ciphertext):], tag)

	plaintext, err := gcm.Open(nil, nonce, sealed, aad)
	if err != nil {
		return nil, fmt.Errorf("AES-GCM decrypt: %w", err)
	}

	return plaintext, nil
}

func ivSize(enc string) (int, error) {
	switch enc {
	case EncA256GCM:
		return IVSizeA256GCM, nil
	default:
		return 0, fmt.Errorf("unsupported encryption: %s", enc)
	}
}
