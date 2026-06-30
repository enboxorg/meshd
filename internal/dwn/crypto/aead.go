// Package crypto implements DWN encryption-v1 primitives.
//
// The DWN encryption-v1 model has two layers:
//   - Content layer: AES-256-CTR encrypts the record data (16-byte IV used as
//     the full 128-bit counter, no authentication tag).
//   - Key agreement layer: X25519-HKDF-SHA256+A256KW wraps the Content
//     Encryption Key (CEK) per keyEncryption entry.
//
// Protocol-path keys are derived hierarchically via HKDF-SHA256. Role-audience
// keys are random per epoch and delivered out of band via the EncryptionProtocol
// audienceKey records.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

// Content encryption algorithm identifier (encryption-v1 "algorithm" value).
const (
	// EncA256CTR is AES-256 in CTR mode. The 16-byte IV is the initial 128-bit
	// counter block and there is no authentication tag.
	EncA256CTR = "A256CTR"
)

const (
	// CEKSize is the size of the Content Encryption Key in bytes (256 bits).
	CEKSize = 32

	// IVSizeA256CTR is the IV (counter) size for A256CTR (128 bits).
	IVSizeA256CTR = 16
)

// GenerateCEK generates a random 256-bit Content Encryption Key.
func GenerateCEK() ([]byte, error) {
	cek := make([]byte, CEKSize)
	if _, err := io.ReadFull(rand.Reader, cek); err != nil {
		return nil, fmt.Errorf("generating CEK: %w", err)
	}
	return cek, nil
}

// GenerateIV generates a random 16-byte initialization vector (counter block)
// for AES-256-CTR.
func GenerateIV() ([]byte, error) {
	iv := make([]byte, IVSizeA256CTR)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("generating IV: %w", err)
	}
	return iv, nil
}

// CTRXor applies AES-256-CTR to in using key and the 16-byte counter iv.
// AES-CTR is symmetric: the same operation encrypts and decrypts.
func CTRXor(key, iv, in []byte) ([]byte, error) {
	if len(key) != CEKSize {
		return nil, fmt.Errorf("AES-256-CTR key must be %d bytes, got %d", CEKSize, len(key))
	}
	if len(iv) != IVSizeA256CTR {
		return nil, fmt.Errorf("AES-256-CTR IV must be %d bytes, got %d", IVSizeA256CTR, len(iv))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating AES cipher: %w", err)
	}

	out := make([]byte, len(in))
	cipher.NewCTR(block, iv).XORKeyStream(out, in)
	return out, nil
}
