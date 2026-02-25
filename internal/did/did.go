// Package did provides DID generation and resolution for meshd nodes.
//
// Each machine in the mesh is identified by a did:jwk (Decentralized Identifier
// wrapping a JSON Web Key). A node's identity contains:
//   - An Ed25519 signing key (for DWN message authorization)
//   - An X25519 encryption key (derived via birational map, for key agreement / WireGuard)
//
// The did:jwk identifier is self-resolving: the JWK is base64url-encoded in the
// URI itself, so no DHT or external resolution is needed.
package did

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/enboxorg/meshd/pkg/dids/didjwk"
	"github.com/enboxorg/meshd/pkg/jwk"
)

// Sentinel errors.
var (
	ErrInvalidURI    = errors.New("not a did:jwk URI")
	ErrInvalidKeyLen = errors.New("invalid key length")
)

// DID represents a did:jwk identity with its associated keys.
type DID struct {
	// URI is the full DID string, e.g. "did:jwk:eyJrdH..."
	URI string

	// SigningKey is the Ed25519 private key.
	SigningKey ed25519.PrivateKey

	// SigningPublicKey is the Ed25519 public key.
	SigningPublicKey ed25519.PublicKey

	// EncryptionPrivateKey is the X25519 private key for key agreement.
	EncryptionPrivateKey []byte

	// EncryptionPublicKey is the X25519 public key for key agreement.
	EncryptionPublicKey []byte
}

// Generate creates a new did:jwk identity.
//
// It generates an Ed25519 keypair and derives an X25519 key agreement keypair
// from it using the standard birational map from Ed25519 to X25519.
func Generate() (*DID, error) {
	id, err := didjwk.Create()
	if err != nil {
		return nil, fmt.Errorf("creating did:jwk: %w", err)
	}
	return fromIdentity(id), nil
}

// FromPrivateKey reconstructs a DID from an existing Ed25519 private key.
func FromPrivateKey(priv ed25519.PrivateKey) (*DID, error) {
	id, err := didjwk.FromPrivateKey(priv, nil)
	if err != nil {
		return nil, fmt.Errorf("reconstructing did:jwk: %w", err)
	}
	return fromIdentity(id), nil
}

// fromIdentity converts a didjwk.Identity to our internal DID type.
func fromIdentity(id *didjwk.Identity) *DID {
	return &DID{
		URI:                  id.URI,
		SigningKey:            id.PrivateKey,
		SigningPublicKey:      id.PublicKey,
		EncryptionPrivateKey: id.X25519PrivateKey,
		EncryptionPublicKey:  id.X25519PublicKey,
	}
}

// ParseURI extracts the Ed25519 public key from a did:jwk URI.
// This gives you enough to verify signatures.
func ParseURI(uri string) (ed25519.PublicKey, error) {
	const prefix = "did:jwk:"
	if len(uri) <= len(prefix) || uri[:len(prefix)] != prefix {
		return nil, fmt.Errorf("%w: %q", ErrInvalidURI, uri)
	}

	encoded := uri[len(prefix):]
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decoding base64url: %w", err)
	}

	var k jwk.JWK
	if err := json.Unmarshal(decoded, &k); err != nil {
		return nil, fmt.Errorf("unmarshaling JWK: %w", err)
	}

	if k.KTY != "OKP" || k.CRV != "Ed25519" {
		return nil, fmt.Errorf("%w: unsupported key type kty=%s crv=%s", ErrInvalidURI, k.KTY, k.CRV)
	}

	pubBytes, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil {
		return nil, fmt.Errorf("decoding public key: %w", err)
	}
	if len(pubBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: decoded %d bytes, want %d", ErrInvalidKeyLen, len(pubBytes), ed25519.PublicKeySize)
	}

	return ed25519.PublicKey(pubBytes), nil
}

// KeyID returns the DID URL for the signing key (e.g. "did:jwk:...#0").
func (d *DID) KeyID() string {
	return d.URI + "#0"
}

// EncryptionKeyID returns the DID URL for the encryption key.
// For did:jwk with Ed25519, the X25519 key agreement VM is at #1.
func (d *DID) EncryptionKeyID() string {
	return d.URI + "#1"
}

// Sign signs a message with the Ed25519 signing key.
func (d *DID) Sign(message []byte) ([]byte, error) {
	sig, err := d.SigningKey.Sign(rand.Reader, message, crypto.Hash(0))
	if err != nil {
		return nil, fmt.Errorf("signing: %w", err)
	}
	return sig, nil
}

// Verify checks an Ed25519 signature against this DID's public key.
func (d *DID) Verify(message, signature []byte) bool {
	return ed25519.Verify(d.SigningPublicKey, message, signature)
}

// VerifyWith checks an Ed25519 signature against an arbitrary public key.
func VerifyWith(pub ed25519.PublicKey, message, signature []byte) bool {
	return ed25519.Verify(pub, message, signature)
}
