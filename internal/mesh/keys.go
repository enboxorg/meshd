// Package mesh provides mesh network operations: key generation, IP allocation,
// and node registration on DWN.
package mesh

import (
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/curve25519"

	"github.com/enboxorg/meshd/pkg/dids/didjwk"
)

// WireGuardKeySize is the size of a WireGuard key in bytes (Curve25519 = 32).
const WireGuardKeySize = 32

// WireGuardKeyPair holds a WireGuard Curve25519 key pair.
type WireGuardKeyPair struct {
	PrivateKey [WireGuardKeySize]byte
	PublicKey  [WireGuardKeySize]byte
}

// WireGuardKeyFromIdentity creates a WireGuard key pair from the node's
// X25519 private key (already derived from Ed25519 by the identity layer).
//
// This is the primary way to get WireGuard keys — no random generation.
// The X25519 private key comes from did.DID.EncryptionPrivateKey.
func WireGuardKeyFromIdentity(x25519PrivateKey []byte) (*WireGuardKeyPair, error) {
	if len(x25519PrivateKey) != WireGuardKeySize {
		return nil, fmt.Errorf("X25519 private key must be %d bytes, got %d", WireGuardKeySize, len(x25519PrivateKey))
	}

	pub, err := curve25519.X25519(x25519PrivateKey, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("deriving WireGuard public key: %w", err)
	}

	kp := &WireGuardKeyPair{}
	copy(kp.PrivateKey[:], x25519PrivateKey)
	copy(kp.PublicKey[:], pub)
	return kp, nil
}

// WireGuardPubKeyFromDID derives a WireGuard public key from a did:jwk URI.
// This is how peers compute each other's WireGuard public keys without
// needing a record field — the key is derivable from the DID itself.
func WireGuardPubKeyFromDID(didJWKURI string) (string, error) {
	x25519Pub, err := didjwk.DeriveX25519PublicKey(didJWKURI)
	if err != nil {
		return "", fmt.Errorf("deriving X25519 public key from DID: %w", err)
	}
	return base64.StdEncoding.EncodeToString(x25519Pub), nil
}

// PublicKeyBase64 returns the public key as standard base64 (WireGuard convention).
func (kp *WireGuardKeyPair) PublicKeyBase64() string {
	return base64.StdEncoding.EncodeToString(kp.PublicKey[:])
}

// PrivateKeyBase64 returns the private key as standard base64.
func (kp *WireGuardKeyPair) PrivateKeyBase64() string {
	return base64.StdEncoding.EncodeToString(kp.PrivateKey[:])
}
