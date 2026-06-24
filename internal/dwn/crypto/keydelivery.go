package crypto

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// DerivedPrivateJwk tracks the key derivation chain, enabling clients to
// derive the correct private key for decryption. This is the payload
// delivered inside contextKey records per the DWN Key Delivery Protocol.
//
// See: DWN spec §Key Delivery Protocol
type DerivedPrivateJwk struct {
	// RootKeyID is the fully qualified key ID of the root X25519 key
	// (e.g., "did:example:alice#enc-1").
	RootKeyID string `json:"rootKeyId"`

	// DerivationScheme is the key derivation scheme used
	// ("protocolPath" or "protocolContext").
	DerivationScheme string `json:"derivationScheme"`

	// DerivationPath is the full HKDF derivation path from root to this key.
	DerivationPath []string `json:"derivationPath"`

	// DerivedPrivateKey is the X25519 private key in JWK format.
	DerivedPrivateKey PrivateKeyJWK `json:"derivedPrivateKey"`
}

// PrivateKeyJWK is an X25519 private key in JWK format.
type PrivateKeyJWK struct {
	Kty string `json:"kty"` // "OKP"
	Crv string `json:"crv"` // "X25519"
	X   string `json:"x"`   // base64url public key
	D   string `json:"d"`   // base64url private key
}

// KeyDeliveryPublic is the recipient public-key material needed to encrypt a
// contextKey record to the recipient's key-delivery ProtocolPath key.
type KeyDeliveryPublic struct {
	RootKeyID    string       `json:"rootKeyId"`
	PublicKeyJWK PublicKeyJWK `json:"publicKeyJwk"`
}

// NewDerivedPrivateJwk creates a DerivedPrivateJwk from raw key bytes
// and derivation metadata.
func NewDerivedPrivateJwk(
	rootKeyID string,
	derivationScheme string,
	derivationPath []string,
	privateKey []byte,
) (*DerivedPrivateJwk, error) {
	publicKey, err := X25519PublicKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("computing public key: %w", err)
	}

	return &DerivedPrivateJwk{
		RootKeyID:        rootKeyID,
		DerivationScheme: derivationScheme,
		DerivationPath:   derivationPath,
		DerivedPrivateKey: PrivateKeyJWK{
			Kty: "OKP",
			Crv: "X25519",
			X:   base64.RawURLEncoding.EncodeToString(publicKey),
			D:   base64.RawURLEncoding.EncodeToString(privateKey),
		},
	}, nil
}

// PrivateKeyBytes returns the raw X25519 private key bytes from the JWK.
func (d *DerivedPrivateJwk) PrivateKeyBytes() ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(d.DerivedPrivateKey.D)
}

// PublicKeyBytes returns the raw X25519 public key bytes from the JWK.
func (d *DerivedPrivateJwk) PublicKeyBytes() ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(d.DerivedPrivateKey.X)
}

// MarshalPayload serializes the DerivedPrivateJwk to JSON bytes suitable
// for writing as the data payload of a contextKey record.
func (d *DerivedPrivateJwk) MarshalPayload() ([]byte, error) {
	return json.Marshal(d)
}

// ParseDerivedPrivateJwk deserializes a DerivedPrivateJwk from JSON bytes
// (as read from a contextKey record's data payload).
func ParseDerivedPrivateJwk(data []byte) (*DerivedPrivateJwk, error) {
	var dpk DerivedPrivateJwk
	if err := json.Unmarshal(data, &dpk); err != nil {
		return nil, fmt.Errorf("parsing DerivedPrivateJwk: %w", err)
	}
	if dpk.RootKeyID == "" {
		return nil, fmt.Errorf("DerivedPrivateJwk missing rootKeyId")
	}
	if dpk.DerivationScheme == "" {
		return nil, fmt.Errorf("DerivedPrivateJwk missing derivationScheme")
	}
	if dpk.DerivedPrivateKey.D == "" {
		return nil, fmt.Errorf("DerivedPrivateJwk missing derivedPrivateKey.d")
	}
	return &dpk, nil
}

// DeriveContextKey derives a Protocol Context private key for a given
// context ID from the owner's root X25519 private key.
//
// The derivation path is: ["protocolContext", contextID]
//
// This is the key that gets delivered to other participants via the
// Key Delivery Protocol so they can decrypt records in that context.
func DeriveContextKey(rootPrivateKey []byte, contextID string) (privateKey []byte, err error) {
	path := BuildProtocolContextDerivation(contextID)
	return DeriveKeyBytes(rootPrivateKey, path)
}

// DeriveContextKeyJwk derives the Protocol Context private key and wraps
// it in a DerivedPrivateJwk structure ready for delivery.
func DeriveContextKeyJwk(rootPrivateKey []byte, rootKeyID string, contextID string) (*DerivedPrivateJwk, error) {
	path := BuildProtocolContextDerivation(contextID)
	privateKey, err := DeriveKeyBytes(rootPrivateKey, path)
	if err != nil {
		return nil, fmt.Errorf("deriving context key: %w", err)
	}
	return NewDerivedPrivateJwk(rootKeyID, DerivationSchemeProtocolContext, path, privateKey)
}

// DeriveKeyDeliveryEncryption derives the encryption inputs needed to
// encrypt a contextKey record for delivery to a recipient.
//
// The contextKey record is encrypted using the Protocol Path scheme for
// the key-delivery protocol, NOT the Protocol Context scheme (which would
// create a circular dependency).
//
// recipientRootKeyID: the recipient's root encryption key ID
// DeriveKeyDeliveryDecryptionKey derives the private key for decrypting
// a contextKey record that was encrypted with Protocol Path scheme for
// the key-delivery protocol.
//
// Path: ["protocolPath", keyDeliveryProtocolURI, "contextKey"]
func DeriveKeyDeliveryDecryptionKey(
	rootPrivateKey []byte,
	keyDeliveryProtocolURI string,
) ([]byte, error) {
	fullPath := BuildProtocolPathDerivation(keyDeliveryProtocolURI, "contextKey")
	privKey, _, err := DerivePrivateKey(rootPrivateKey, fullPath)
	if err != nil {
		return nil, fmt.Errorf("deriving key-delivery decryption key: %w", err)
	}
	return privKey, nil
}

// DeriveKeyDeliveryPublicJWK derives the recipient-side ProtocolPath public
// key used by owners to encrypt future contextKey records to this identity.
func DeriveKeyDeliveryPublicJWK(rootPrivateKey []byte, rootKeyID string, keyDeliveryProtocolURI string) (PublicKeyJWK, error) {
	fullPath := BuildProtocolPathDerivation(keyDeliveryProtocolURI, "contextKey")
	_, publicKey, err := DerivePrivateKey(rootPrivateKey, fullPath)
	if err != nil {
		return PublicKeyJWK{}, fmt.Errorf("deriving key-delivery public key: %w", err)
	}
	return PublicKeyJWK{
		KTY: "OKP",
		CRV: "X25519",
		X:   base64.RawURLEncoding.EncodeToString(publicKey),
		KID: rootKeyID,
	}, nil
}

// NewKeyDeliveryPublic derives the public key descriptor that another party
// can use to encrypt contextKey records to this identity.
func NewKeyDeliveryPublic(rootPrivateKey []byte, rootKeyID string, keyDeliveryProtocolURI string) (*KeyDeliveryPublic, error) {
	publicJWK, err := DeriveKeyDeliveryPublicJWK(rootPrivateKey, rootKeyID, keyDeliveryProtocolURI)
	if err != nil {
		return nil, err
	}
	return &KeyDeliveryPublic{
		RootKeyID:    rootKeyID,
		PublicKeyJWK: publicJWK,
	}, nil
}
