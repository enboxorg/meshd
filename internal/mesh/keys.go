// Package mesh provides mesh network operations: key generation, IP allocation,
// and node registration on DWN.
package mesh

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"
)

// WireGuardKeySize is the size of a WireGuard key in bytes (Curve25519 = 32).
const WireGuardKeySize = 32

// WireGuardKeyPair holds a WireGuard Curve25519 key pair.
type WireGuardKeyPair struct {
	PrivateKey [WireGuardKeySize]byte
	PublicKey  [WireGuardKeySize]byte
}

// GenerateWireGuardKeyPair generates a new random WireGuard Curve25519 key pair.
//
// The private key is clamped per Curve25519 convention:
//   - Bits 0-2 cleared (divisible by 8)
//   - Bit 255 cleared
//   - Bit 254 set
func GenerateWireGuardKeyPair() (*WireGuardKeyPair, error) {
	var priv [WireGuardKeySize]byte
	if _, err := io.ReadFull(rand.Reader, priv[:]); err != nil {
		return nil, fmt.Errorf("generating WireGuard private key: %w", err)
	}

	// Clamp per Curve25519 / WireGuard spec.
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("deriving WireGuard public key: %w", err)
	}

	kp := &WireGuardKeyPair{}
	copy(kp.PrivateKey[:], priv[:])
	copy(kp.PublicKey[:], pub)
	return kp, nil
}

// WireGuardKeyPairFromPrivate reconstructs a key pair from a private key.
func WireGuardKeyPairFromPrivate(priv []byte) (*WireGuardKeyPair, error) {
	if len(priv) != WireGuardKeySize {
		return nil, fmt.Errorf("WireGuard private key must be %d bytes, got %d", WireGuardKeySize, len(priv))
	}

	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("deriving WireGuard public key: %w", err)
	}

	kp := &WireGuardKeyPair{}
	copy(kp.PrivateKey[:], priv)
	copy(kp.PublicKey[:], pub)
	return kp, nil
}

// PublicKeyBase64 returns the public key as standard base64 (WireGuard convention).
func (kp *WireGuardKeyPair) PublicKeyBase64() string {
	return base64.StdEncoding.EncodeToString(kp.PublicKey[:])
}

// PrivateKeyBase64 returns the private key as standard base64.
func (kp *WireGuardKeyPair) PrivateKeyBase64() string {
	return base64.StdEncoding.EncodeToString(kp.PrivateKey[:])
}
