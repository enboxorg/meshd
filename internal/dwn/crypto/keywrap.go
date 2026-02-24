package crypto

import (
	"crypto/aes"
	"encoding/binary"
	"fmt"
)

// AES Key Wrap (RFC 3394)
//
// This implements the AES-256 Key Wrap algorithm used by ECDH-ES+A256KW
// to wrap the Content Encryption Key (CEK) for each JWE recipient.

// aesKeyWrapDefaultIV is the default IV for AES Key Wrap per RFC 3394 Section 2.2.3.1.
var aesKeyWrapDefaultIV = []byte{0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6}

// AESKeyWrap wraps the plaintext key using AES Key Wrap (RFC 3394).
// kek must be 16, 24, or 32 bytes. plaintext must be a multiple of 8 bytes.
func AESKeyWrap(kek, plaintext []byte) ([]byte, error) {
	if len(plaintext)%8 != 0 {
		return nil, fmt.Errorf("plaintext must be a multiple of 8 bytes, got %d", len(plaintext))
	}
	n := len(plaintext) / 8
	if n < 1 {
		return nil, fmt.Errorf("plaintext too short")
	}

	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("creating AES cipher: %w", err)
	}

	// Initialize A and R per RFC 3394.
	a := make([]byte, 8)
	copy(a, aesKeyWrapDefaultIV)

	r := make([][]byte, n)
	for i := 0; i < n; i++ {
		r[i] = make([]byte, 8)
		copy(r[i], plaintext[i*8:(i+1)*8])
	}

	// Wrap.
	for j := 0; j < 6; j++ {
		for i := 0; i < n; i++ {
			// B = AES(K, A | R[i])
			input := make([]byte, 16)
			copy(input[:8], a)
			copy(input[8:], r[i])

			b := make([]byte, 16)
			block.Encrypt(b, input)

			// A = MSB(64, B) ^ t where t = (n*j)+i+1
			t := uint64(n*j + i + 1)
			copy(a, b[:8])
			xorUint64(a, t)

			// R[i] = LSB(64, B)
			copy(r[i], b[8:])
		}
	}

	// Output: A || R[1] || R[2] || ... || R[n]
	out := make([]byte, 0, 8+n*8)
	out = append(out, a...)
	for _, ri := range r {
		out = append(out, ri...)
	}
	return out, nil
}

// AESKeyUnwrap unwraps a key using AES Key Wrap (RFC 3394).
// kek must be 16, 24, or 32 bytes. ciphertext must be a multiple of 8 bytes
// and at least 24 bytes (8 bytes IV + at least 16 bytes data).
func AESKeyUnwrap(kek, ciphertext []byte) ([]byte, error) {
	if len(ciphertext)%8 != 0 {
		return nil, fmt.Errorf("ciphertext must be a multiple of 8 bytes, got %d", len(ciphertext))
	}
	if len(ciphertext) < 24 {
		return nil, fmt.Errorf("ciphertext too short: %d bytes", len(ciphertext))
	}

	n := (len(ciphertext) / 8) - 1

	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("creating AES cipher: %w", err)
	}

	// Initialize A and R from ciphertext.
	a := make([]byte, 8)
	copy(a, ciphertext[:8])

	r := make([][]byte, n)
	for i := 0; i < n; i++ {
		r[i] = make([]byte, 8)
		copy(r[i], ciphertext[(i+1)*8:(i+2)*8])
	}

	// Unwrap.
	for j := 5; j >= 0; j-- {
		for i := n - 1; i >= 0; i-- {
			// A ^ t
			t := uint64(n*j + i + 1)
			xorUint64(a, t)

			// B = AES-1(K, (A ^ t) | R[i])
			input := make([]byte, 16)
			copy(input[:8], a)
			copy(input[8:], r[i])

			b := make([]byte, 16)
			block.Decrypt(b, input)

			copy(a, b[:8])
			copy(r[i], b[8:])
		}
	}

	// Verify A matches the default IV.
	for i := range a {
		if a[i] != aesKeyWrapDefaultIV[i] {
			return nil, fmt.Errorf("AES Key Unwrap integrity check failed")
		}
	}

	// Output: R[1] || R[2] || ... || R[n]
	out := make([]byte, 0, n*8)
	for _, ri := range r {
		out = append(out, ri...)
	}
	return out, nil
}

// xorUint64 XORs the first 8 bytes of b with the big-endian encoding of v.
func xorUint64(b []byte, v uint64) {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], v)
	for i := 0; i < 8; i++ {
		b[i] ^= buf[i]
	}
}
