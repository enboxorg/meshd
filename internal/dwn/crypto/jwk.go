package crypto

import (
	"crypto/sha256"
	"encoding/base64"
)

// PublicKeyJWK represents an X25519 public key in JWK format.
type PublicKeyJWK struct {
	KTY string `json:"kty"`           // Key type: "OKP"
	CRV string `json:"crv"`           // Curve: "X25519"
	X   string `json:"x"`             // Base64url-encoded public key bytes
	KID string `json:"kid,omitempty"` // Key ID (optional)
}

// PrivateKeyJWK represents an X25519 private key in JWK format.
type PrivateKeyJWK struct {
	KTY string `json:"kty"`           // "OKP"
	CRV string `json:"crv"`           // "X25519"
	X   string `json:"x"`             // base64url public key
	D   string `json:"d"`             // base64url private scalar
	KID string `json:"kid,omitempty"` // Key ID (optional)
}

// JWKThumbprintX25519 computes the RFC 7638 JWK thumbprint of an OKP/X25519
// public key from its base64url-encoded `x` member.
//
// The canonical JSON is the lexicographically-ordered, whitespace-free object
// containing only the required members:
//
//	{"crv":"X25519","kty":"OKP","x":"<x>"}
//
// The thumbprint is the unpadded base64url of its SHA-256 digest.
func JWKThumbprintX25519(xB64url string) string {
	canonical := `{"crv":"X25519","kty":"OKP","x":"` + xB64url + `"}`
	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// thumbprintForPublicKey computes the X25519 JWK thumbprint for a raw 32-byte
// public key.
func thumbprintForPublicKey(publicKey []byte) string {
	return JWKThumbprintX25519(base64.RawURLEncoding.EncodeToString(publicKey))
}
