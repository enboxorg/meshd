// Package didjwk implements creation and resolution of did:jwk identifiers.
//
// A did:jwk wraps a JWK (JSON Web Key) as a self-describing DID URI.
// For Ed25519 keys, this package also derives X25519 key-agreement keys
// via the birational map, enabling both signing (Ed25519) and encryption /
// WireGuard tunneling (X25519) from a single identity.
package didjwk

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/curve25519"

	"github.com/enboxorg/meshd/pkg/dids/did"
	"github.com/enboxorg/meshd/pkg/dids/didcore"
	"github.com/enboxorg/meshd/pkg/jwk"
)

// Identity holds a did:jwk identity backed by an Ed25519 keypair,
// with the derived X25519 keys for key agreement / WireGuard.
type Identity struct {
	// URI is the fully-formed did:jwk:... string.
	URI string

	// Ed25519 signing keys.
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey

	// X25519 key-agreement keys derived via the birational map.
	X25519PrivateKey []byte // 32 bytes, clamped
	X25519PublicKey  []byte // 32 bytes
}

// Create generates a new Ed25519 keypair, constructs a did:jwk URI, and
// derives the corresponding X25519 keys. The returned Identity contains
// everything needed for DWN auth (Ed25519) and WireGuard (X25519).
func Create() (*Identity, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating ed25519 key: %w", err)
	}
	return FromPrivateKey(priv, pub)
}

// FromPrivateKey reconstructs a did:jwk Identity from an existing Ed25519
// private key. The public key is derived if pub is nil.
func FromPrivateKey(priv ed25519.PrivateKey, pub ed25519.PublicKey) (*Identity, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid ed25519 private key length: %d", len(priv))
	}
	if pub == nil {
		pub = priv.Public().(ed25519.PublicKey)
	}

	// Build the public JWK and encode as did:jwk URI.
	pubJWK := jwk.JWK{
		KTY: "OKP",
		CRV: "Ed25519",
		X:   base64.RawURLEncoding.EncodeToString(pub),
	}
	jwkBytes, err := json.Marshal(pubJWK)
	if err != nil {
		return nil, fmt.Errorf("marshaling jwk: %w", err)
	}
	uri := "did:jwk:" + base64.RawURLEncoding.EncodeToString(jwkBytes)

	// Derive X25519 keys.
	x25519Pub, x25519Priv, err := ed25519ToX25519(pub, priv)
	if err != nil {
		return nil, fmt.Errorf("deriving x25519 keys: %w", err)
	}

	return &Identity{
		URI:              uri,
		PrivateKey:       priv,
		PublicKey:        pub,
		X25519PrivateKey: x25519Priv,
		X25519PublicKey:  x25519Pub,
	}, nil
}

// DeriveX25519PublicKey extracts the Ed25519 public key from a did:jwk URI
// and derives the corresponding X25519 public key via the birational map.
// This is how peers derive WireGuard public keys from a did:jwk identity
// without needing any private key material.
func DeriveX25519PublicKey(uri string) ([]byte, error) {
	d, err := did.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("parsing did uri: %w", err)
	}
	if d.Method != "jwk" {
		return nil, fmt.Errorf("expected did:jwk, got did:%s", d.Method)
	}

	decoded, err := base64.RawURLEncoding.DecodeString(d.ID)
	if err != nil {
		return nil, fmt.Errorf("decoding jwk: %w", err)
	}

	var k jwk.JWK
	if err := json.Unmarshal(decoded, &k); err != nil {
		return nil, fmt.Errorf("unmarshaling jwk: %w", err)
	}

	if k.KTY != "OKP" || k.CRV != "Ed25519" {
		return nil, fmt.Errorf("unsupported key type: kty=%s crv=%s (expected OKP/Ed25519)", k.KTY, k.CRV)
	}

	pubBytes, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil {
		return nil, fmt.Errorf("decoding public key: %w", err)
	}
	if len(pubBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid ed25519 public key length: %d", len(pubBytes))
	}

	return ed25519PubToX25519(pubBytes)
}

// Resolver implements did:jwk resolution.
type Resolver struct{}

// ResolveWithContext resolves a did:jwk URI with a context.
func (r Resolver) ResolveWithContext(ctx context.Context, uri string) (didcore.ResolutionResult, error) {
	return r.Resolve(uri)
}

// Resolve resolves a did:jwk URI into a DID Document. For Ed25519 keys,
// the resolved document includes both the Ed25519 signing verification
// method (#0) and a derived X25519 key agreement verification method (#1).
func (r Resolver) Resolve(uri string) (didcore.ResolutionResult, error) {
	d, err := did.Parse(uri)
	if err != nil {
		return didcore.ResolutionResultWithError("invalidDid"), didcore.ResolutionError{Code: "invalidDid"}
	}

	if d.Method != "jwk" {
		return didcore.ResolutionResultWithError("invalidDid"), didcore.ResolutionError{Code: "invalidDid"}
	}

	decodedID, err := base64.RawURLEncoding.DecodeString(d.ID)
	if err != nil {
		return didcore.ResolutionResultWithError("invalidDid"), didcore.ResolutionError{Code: "invalidDid"}
	}

	var k jwk.JWK
	if err := json.Unmarshal(decodedID, &k); err != nil {
		return didcore.ResolutionResultWithError("invalidDid"), didcore.ResolutionError{Code: "invalidDid"}
	}

	doc := createDocument(d, k)
	return didcore.ResolutionResultWithDocument(doc), nil
}

// createDocument builds the DID Document for the given did:jwk.
// For Ed25519 keys, it adds a derived X25519 key agreement method.
func createDocument(d did.DID, publicKey jwk.JWK) didcore.Document {
	doc := didcore.Document{
		Context: []string{"https://www.w3.org/ns/did/v1"},
		ID:      d.URI,
	}

	// #0 — the primary verification method (the JWK as-is).
	vm := didcore.VerificationMethod{
		ID:           d.URI + "#0",
		Type:         "JsonWebKey",
		Controller:   d.URI,
		PublicKeyJwk: &publicKey,
	}

	doc.AddVerificationMethod(
		vm,
		didcore.Purposes("assertionMethod", "authentication", "capabilityInvocation", "capabilityDelegation"),
	)

	// For Ed25519 keys, derive X25519 and add as #1 for key agreement.
	if publicKey.KTY == "OKP" && publicKey.CRV == "Ed25519" && publicKey.X != "" {
		pubBytes, err := base64.RawURLEncoding.DecodeString(publicKey.X)
		if err == nil && len(pubBytes) == ed25519.PublicKeySize {
			x25519Pub, err := ed25519PubToX25519(pubBytes)
			if err == nil {
				kaJWK := jwk.JWK{
					KTY: "OKP",
					CRV: "X25519",
					X:   base64.RawURLEncoding.EncodeToString(x25519Pub),
				}
				kaVM := didcore.VerificationMethod{
					ID:           d.URI + "#1",
					Type:         "JsonWebKey",
					Controller:   d.URI,
					PublicKeyJwk: &kaJWK,
				}
				doc.AddVerificationMethod(kaVM, didcore.Purposes("keyAgreement"))
			}
		}
	}

	return doc
}

// ed25519ToX25519 derives X25519 keys from Ed25519 keys.
//
// Public key: birational map from Ed25519 (twisted Edwards) to X25519
// (Montgomery) via filippo.io/edwards25519 Point.BytesMontgomery().
//
// Private key: SHA-512(seed), take first 32 bytes, clamp per RFC 7748.
func ed25519ToX25519(pub ed25519.PublicKey, priv ed25519.PrivateKey) (x25519Pub, x25519Priv []byte, err error) {
	x25519Pub, err = ed25519PubToX25519(pub)
	if err != nil {
		return nil, nil, err
	}

	h := sha512.Sum512(priv.Seed())
	x25519Priv = make([]byte, 32)
	copy(x25519Priv, h[:32])
	x25519Priv[0] &= 248
	x25519Priv[31] &= 127
	x25519Priv[31] |= 64

	// Verify: derive public from private and compare.
	derivedPub, err := curve25519.X25519(x25519Priv, curve25519.Basepoint)
	if err != nil {
		return nil, nil, fmt.Errorf("x25519 scalar mult: %w", err)
	}
	if subtle.ConstantTimeCompare(x25519Pub, derivedPub) != 1 {
		return nil, nil, fmt.Errorf("x25519 key derivation mismatch")
	}

	return x25519Pub, x25519Priv, nil
}

// ed25519PubToX25519 converts an Ed25519 public key to an X25519 public
// key using the birational map (Edwards → Montgomery).
func ed25519PubToX25519(pub ed25519.PublicKey) ([]byte, error) {
	edPoint, err := new(edwards25519.Point).SetBytes(pub)
	if err != nil {
		return nil, fmt.Errorf("parsing ed25519 public key: %w", err)
	}
	return edPoint.BytesMontgomery(), nil
}
