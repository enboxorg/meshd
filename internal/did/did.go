// Package did provides DID generation and resolution for dwn-mesh nodes.
//
// Each machine in the mesh is identified by a DID (Decentralized Identifier)
// using the did:dht method. A node's DID document contains:
//   - An Ed25519 signing key (Identity Key, for DWN message authorization)
//   - An X25519 encryption key (derived, for JWE key agreement / ECDH-ES+A256KW)
//   - A #dwn service endpoint pointing to the node's DWN instance
//
// The did:dht identifier is: did:dht:<z-base-32 encoded Ed25519 public key>
package did

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"

	"filippo.io/edwards25519"
	"github.com/tv42/zbase32"
	"golang.org/x/crypto/curve25519"
)

// Sentinel errors.
var (
	ErrInvalidURI    = errors.New("not a did:dht URI")
	ErrInvalidKeyLen = errors.New("invalid key length")
	ErrKeyMismatch   = errors.New("x25519 key derivation mismatch")
)

// DID represents a did:dht identity with its associated keys.
type DID struct {
	// URI is the full DID string, e.g. "did:dht:i9xkp8..."
	URI string

	// SigningKey is the Ed25519 private key (Identity Key).
	SigningKey ed25519.PrivateKey

	// SigningPublicKey is the Ed25519 public key.
	SigningPublicKey ed25519.PublicKey

	// EncryptionPrivateKey is the X25519 private key for key agreement.
	EncryptionPrivateKey []byte

	// EncryptionPublicKey is the X25519 public key for key agreement.
	EncryptionPublicKey []byte
}

// Generate creates a new did:dht identity.
//
// It generates an Ed25519 keypair (the Identity Key) and derives an X25519
// key agreement keypair from it using the standard birational map from
// Ed25519 to X25519.
func Generate() (*DID, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating ed25519 key: %w", err)
	}
	return fromKeys(pub, priv)
}

// FromPrivateKey reconstructs a DID from an existing Ed25519 private key.
func FromPrivateKey(priv ed25519.PrivateKey) (*DID, error) {
	pub := priv.Public().(ed25519.PublicKey)
	return fromKeys(pub, priv)
}

// ParseURI extracts the z-base-32 identifier and decodes the Ed25519 public
// key from a did:dht URI. This gives you enough to verify signatures.
func ParseURI(uri string) (ed25519.PublicKey, error) {
	const prefix = "did:dht:"
	if len(uri) <= len(prefix) || uri[:len(prefix)] != prefix {
		return nil, fmt.Errorf("%w: %q", ErrInvalidURI, uri)
	}
	id := uri[len(prefix):]
	pubBytes, err := zbase32.DecodeString(id)
	if err != nil {
		return nil, fmt.Errorf("decoding z-base-32: %w", err)
	}
	if len(pubBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: decoded %d bytes, want %d", ErrInvalidKeyLen, len(pubBytes), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(pubBytes), nil
}

func fromKeys(pub ed25519.PublicKey, priv ed25519.PrivateKey) (*DID, error) {
	encPub, encPriv, err := ed25519ToX25519(pub, priv)
	if err != nil {
		return nil, fmt.Errorf("deriving x25519 key: %w", err)
	}

	id := zbase32.EncodeToString([]byte(pub))
	uri := "did:dht:" + id

	return &DID{
		URI:                  uri,
		SigningKey:            priv,
		SigningPublicKey:      pub,
		EncryptionPrivateKey: encPriv,
		EncryptionPublicKey:  encPub,
	}, nil
}

// Identifier returns just the z-base-32 suffix (without the "did:dht:" prefix).
func (d *DID) Identifier() string {
	return d.URI[len("did:dht:"):]
}

// KeyID returns the DID URL for the signing key (e.g. "did:dht:abc...#0").
func (d *DID) KeyID() string {
	return d.URI + "#0"
}

// EncryptionKeyID returns the DID URL for the encryption key.
func (d *DID) EncryptionKeyID() string {
	return d.URI + "#enc"
}

// Sign signs a message with the Identity Key (Ed25519).
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

// Document returns the DID Document as a structured object.
// If dwnEndpoint is non-empty, a DecentralizedWebNode service is included.
func (d *DID) Document(dwnEndpoint string) *Document {
	doc := &Document{
		ID: d.URI,
		VerificationMethod: []VerificationMethod{
			{
				ID:         d.URI + "#0",
				Type:       "JsonWebKey",
				Controller: d.URI,
				PublicKeyJwk: JWK{
					KID: "0",
					KTY: "OKP",
					CRV: "Ed25519",
					ALG: "EdDSA",
					X:   base64.RawURLEncoding.EncodeToString(d.SigningPublicKey),
				},
			},
			{
				ID:         d.URI + "#enc",
				Type:       "JsonWebKey",
				Controller: d.URI,
				PublicKeyJwk: JWK{
					KID: "enc",
					KTY: "OKP",
					CRV: "X25519",
					ALG: "ECDH-ES+A256KW",
					X:   base64.RawURLEncoding.EncodeToString(d.EncryptionPublicKey),
				},
			},
		},
		Authentication:       []string{d.URI + "#0"},
		AssertionMethod:      []string{d.URI + "#0"},
		CapabilityInvocation: []string{d.URI + "#0"},
		CapabilityDelegation: []string{d.URI + "#0"},
		KeyAgreement:         []string{d.URI + "#enc"},
	}

	if dwnEndpoint != "" {
		doc.Service = []Service{
			{
				ID:              d.URI + "#dwn",
				Type:            "DecentralizedWebNode",
				ServiceEndpoint: []string{dwnEndpoint},
			},
		}
	}

	return doc
}

// Document represents a DID Document (did:dht).
type Document struct {
	ID                   string               `json:"id"`
	VerificationMethod   []VerificationMethod `json:"verificationMethod"`
	Authentication       []string             `json:"authentication"`
	AssertionMethod      []string             `json:"assertionMethod"`
	CapabilityInvocation []string             `json:"capabilityInvocation"`
	CapabilityDelegation []string             `json:"capabilityDelegation"`
	KeyAgreement         []string             `json:"keyAgreement,omitempty"`
	Service              []Service            `json:"service,omitempty"`
}

// VerificationMethod is a key in a DID document.
type VerificationMethod struct {
	ID           string `json:"id"`
	Type         string `json:"type"`
	Controller   string `json:"controller"`
	PublicKeyJwk JWK    `json:"publicKeyJwk"`
}

// JWK is a JSON Web Key.
type JWK struct {
	KID string `json:"kid"`
	KTY string `json:"kty"`
	CRV string `json:"crv"`
	ALG string `json:"alg,omitempty"`
	X   string `json:"x"`
	D   string `json:"d,omitempty"` // private key component, only in local storage
}

// Service is a service endpoint in a DID document.
type Service struct {
	ID              string   `json:"id"`
	Type            string   `json:"type"`
	ServiceEndpoint []string `json:"serviceEndpoint"`
}

// ed25519ToX25519 derives X25519 keys from Ed25519 keys.
//
// Public key: uses the birational map from Ed25519 (twisted Edwards) to
// X25519 (Montgomery) via filippo.io/edwards25519 Point.BytesMontgomery().
//
// Private key: SHA-512(seed), take first 32 bytes, clamp per RFC 7748.
func ed25519ToX25519(pub ed25519.PublicKey, priv ed25519.PrivateKey) (x25519Pub, x25519Priv []byte, err error) {
	edPoint, err := new(edwards25519.Point).SetBytes(pub)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing ed25519 public key: %w", err)
	}
	x25519Pub = edPoint.BytesMontgomery()

	h := sha512.Sum512(priv.Seed())
	x25519Priv = make([]byte, 32)
	copy(x25519Priv, h[:32])
	x25519Priv[0] &= 248
	x25519Priv[31] &= 127
	x25519Priv[31] |= 64

	derivedPub, err := curve25519.X25519(x25519Priv, curve25519.Basepoint)
	if err != nil {
		return nil, nil, fmt.Errorf("x25519 scalar mult: %w", err)
	}
	if subtle.ConstantTimeCompare(x25519Pub, derivedPub) != 1 {
		return nil, nil, ErrKeyMismatch
	}

	return x25519Pub, x25519Priv, nil
}
