package crypto

import "fmt"

// DerivationSchemeSeal marks a key wrap that seals an audience PRIVATE key to
// a role-path $keyAgreement public key inside an `$encryption/audience`
// control record.
const DerivationSchemeSeal = "seal"

// SealKeyWrap is the sealed audience private key stored in an
// `$encryption/audience` record payload (`sealedPrivateKey`). It mirrors the
// SDK's SealKeyWrap type; the wire shape is enforced server-side with
// additionalProperties:false.
type SealKeyWrap struct {
	// Algorithm is the key wrap algorithm ("X25519-HKDF-SHA256+A256KW").
	Algorithm string `json:"algorithm"`

	// DerivationScheme is always "seal".
	DerivationScheme string `json:"derivationScheme"`

	// EncryptedKey is the base64url-encoded AES-KeyWrapped raw 32-byte
	// audience private key.
	EncryptedKey string `json:"encryptedKey"`

	// EphemeralPublicKey is the ephemeral X25519 public key used for ECDH.
	EphemeralPublicKey *PublicKeyJWK `json:"ephemeralPublicKey"`

	// KeyID is the JWK thumbprint of the sealing (role-path $keyAgreement)
	// public key.
	KeyID string `json:"keyId"`
}

// SealKEKInfo returns the HKDF info string for a seal key wrap:
//
//	["X25519-HKDF-SHA256+A256KW","seal","<protocol>","<rolePath>","<contextId>","<audienceKeyId>"]
func SealKEKInfo(protocol, rolePath, contextID, audienceKeyID string) string {
	return kekInfoJSON(AlgX25519HKDFA256KW, DerivationSchemeSeal, protocol, rolePath, contextID, audienceKeyID)
}

// SealAudiencePrivateKey seals a raw 32-byte audience X25519 private key to
// the role-path $keyAgreement public key (sealingPublicKey, raw 32 bytes).
// The (protocol, rolePath, contextID, audienceKeyID) tuple binds the seal to
// its audience record via the KEK info string.
//
// This is the Go counterpart of the SDK's Encryption.wrapSeal.
func SealAudiencePrivateKey(audiencePrivateKey, sealingPublicKey []byte, protocol, rolePath, contextID, audienceKeyID string) (*SealKeyWrap, error) {
	if len(audiencePrivateKey) != X25519KeySize {
		return nil, fmt.Errorf("audience private key must be %d bytes, got %d", X25519KeySize, len(audiencePrivateKey))
	}
	if len(sealingPublicKey) != X25519KeySize {
		return nil, fmt.Errorf("sealing public key must be %d bytes, got %d", X25519KeySize, len(sealingPublicKey))
	}

	info := SealKEKInfo(protocol, rolePath, contextID, audienceKeyID)
	ephPub, wrapped, err := WrapCEK(sealingPublicKey, audiencePrivateKey, info)
	if err != nil {
		return nil, fmt.Errorf("sealing audience private key: %w", err)
	}

	return &SealKeyWrap{
		Algorithm:        AlgX25519HKDFA256KW,
		DerivationScheme: DerivationSchemeSeal,
		EncryptedKey:     base64URLEncode(wrapped),
		EphemeralPublicKey: &PublicKeyJWK{
			KTY: "OKP",
			CRV: "X25519",
			X:   base64URLEncode(ephPub),
		},
		KeyID: thumbprintForPublicKey(sealingPublicKey),
	}, nil
}

// UnsealAudiencePrivateKey opens a seal with the role-path $keyAgreement
// PRIVATE key (raw 32 bytes) and returns the raw 32-byte audience private key.
//
// This is the Go counterpart of the SDK's Encryption.unwrapSeal.
func UnsealAudiencePrivateKey(seal *SealKeyWrap, sealingPrivateKey []byte, protocol, rolePath, contextID, audienceKeyID string) ([]byte, error) {
	if seal == nil {
		return nil, fmt.Errorf("missing seal")
	}
	if seal.Algorithm != AlgX25519HKDFA256KW {
		return nil, fmt.Errorf("unsupported seal algorithm %q", seal.Algorithm)
	}
	if seal.DerivationScheme != DerivationSchemeSeal {
		return nil, fmt.Errorf("unexpected seal derivation scheme %q", seal.DerivationScheme)
	}
	if seal.EphemeralPublicKey == nil {
		return nil, fmt.Errorf("seal missing ephemeralPublicKey")
	}

	ephPub, err := base64URLDecode(seal.EphemeralPublicKey.X)
	if err != nil {
		return nil, fmt.Errorf("decoding seal ephemeralPublicKey: %w", err)
	}
	wrapped, err := base64URLDecode(seal.EncryptedKey)
	if err != nil {
		return nil, fmt.Errorf("decoding seal encryptedKey: %w", err)
	}

	info := SealKEKInfo(protocol, rolePath, contextID, audienceKeyID)
	priv, err := UnwrapCEK(sealingPrivateKey, ephPub, wrapped, info)
	if err != nil {
		return nil, fmt.Errorf("unsealing audience private key: %w", err)
	}
	if len(priv) != X25519KeySize {
		clear(priv)
		return nil, fmt.Errorf("unsealed audience private key must be %d bytes, got %d", X25519KeySize, len(priv))
	}
	return priv, nil
}
