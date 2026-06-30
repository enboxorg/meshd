package crypto

import (
	"encoding/base64"
	"fmt"
	"strconv"
)

// Encryption is the encryption-v1 envelope stored as the top-level "encryption"
// field on a RecordsWrite message. The ciphertext is NOT included here — it is
// stored separately as the record's data.
type Encryption struct {
	// Algorithm is the content encryption algorithm ("A256CTR").
	Algorithm string `json:"algorithm"`

	// InitializationVector is the base64url-encoded 16-byte AES-CTR counter.
	InitializationVector string `json:"initializationVector"`

	// KeyEncryption holds one CEK-wrapping entry per recipient / audience.
	KeyEncryption []KeyEncryption `json:"keyEncryption"`
}

// KeyEncryption is a single CEK-wrapping entry in an Encryption envelope.
type KeyEncryption struct {
	// Algorithm is the key wrap algorithm ("X25519-HKDF-SHA256+A256KW").
	Algorithm string `json:"algorithm"`

	// EncryptedKey is the base64url-encoded AES-KeyWrapped CEK.
	EncryptedKey string `json:"encryptedKey"`

	// EphemeralPublicKey is the ephemeral X25519 public key used for ECDH.
	EphemeralPublicKey *PublicKeyJWK `json:"ephemeralPublicKey"`

	// KeyID is the JWK thumbprint of the recipient public key:
	//   - protocolPath: thumbprint of the derived leaf public key.
	//   - roleAudience: thumbprint of the audience public key.
	KeyID string `json:"keyId"`

	// DerivationScheme is "protocolPath" or "roleAudience".
	DerivationScheme string `json:"derivationScheme"`

	// Protocol, Role and Epoch are present only for roleAudience entries and
	// feed the role-audience KEK info string.
	Protocol string `json:"protocol,omitempty"`
	Role     string `json:"role,omitempty"`
	Epoch    int    `json:"epoch,omitempty"`
}

// KeyEncryptionInput describes how to wrap the CEK for a single recipient on
// the write path. meshd writes protocolPath entries; roleAudience entries are
// appended by the SDK when records are authored through the agent.
type KeyEncryptionInput struct {
	// PublicKey is the recipient's derived X25519 public key (raw 32 bytes).
	PublicKey []byte

	// DerivationScheme is the key derivation scheme (protocolPath).
	DerivationScheme string
}

// protocolPathKEKInfo returns the HKDF info string for a protocolPath entry.
func protocolPathKEKInfo(keyID string) string {
	return AlgX25519HKDFA256KW + "|" + DerivationSchemeProtocolPath + "|" + keyID
}

// roleAudienceKEKInfo returns the HKDF info string for a roleAudience entry.
func roleAudienceKEKInfo(protocol, role string, epoch int, keyID string) string {
	return AlgX25519HKDFA256KW + "|" + DerivationSchemeRoleAudience + "|" +
		protocol + "|" + role + "|" + strconv.Itoa(epoch) + "|" + keyID
}

// kekInfo returns the HKDF info string for the given keyEncryption entry.
func kekInfo(entry *KeyEncryption) (string, error) {
	switch entry.DerivationScheme {
	case DerivationSchemeProtocolPath:
		return protocolPathKEKInfo(entry.KeyID), nil
	case DerivationSchemeRoleAudience:
		return roleAudienceKEKInfo(entry.Protocol, entry.Role, entry.Epoch, entry.KeyID), nil
	default:
		return "", fmt.Errorf("unsupported derivation scheme %q", entry.DerivationScheme)
	}
}

// EncryptData encrypts plaintext with AES-256-CTR and wraps the CEK for each
// recipient using X25519-HKDF-SHA256+A256KW. Returns the ciphertext and the
// encryption-v1 envelope.
func EncryptData(plaintext []byte, recipients []KeyEncryptionInput) (ciphertext []byte, enc *Encryption, err error) {
	if len(recipients) == 0 {
		return nil, nil, fmt.Errorf("at least one recipient is required")
	}

	cek, err := GenerateCEK()
	if err != nil {
		return nil, nil, err
	}
	defer clear(cek)

	iv, err := GenerateIV()
	if err != nil {
		return nil, nil, err
	}

	ct, err := CTRXor(cek, iv, plaintext)
	if err != nil {
		return nil, nil, fmt.Errorf("encrypting data: %w", err)
	}

	keyEncryption := make([]KeyEncryption, 0, len(recipients))
	for _, in := range recipients {
		scheme := in.DerivationScheme
		if scheme == "" {
			scheme = DerivationSchemeProtocolPath
		}
		if scheme != DerivationSchemeProtocolPath {
			return nil, nil, fmt.Errorf("unsupported write derivation scheme %q", scheme)
		}
		if len(in.PublicKey) != X25519KeySize {
			return nil, nil, fmt.Errorf("recipient public key must be %d bytes, got %d", X25519KeySize, len(in.PublicKey))
		}

		keyID := thumbprintForPublicKey(in.PublicKey)
		ephPub, wrapped, err := WrapCEK(in.PublicKey, cek, protocolPathKEKInfo(keyID))
		if err != nil {
			return nil, nil, fmt.Errorf("wrapping CEK: %w", err)
		}

		keyEncryption = append(keyEncryption, KeyEncryption{
			Algorithm:    AlgX25519HKDFA256KW,
			EncryptedKey: base64URLEncode(wrapped),
			EphemeralPublicKey: &PublicKeyJWK{
				KTY: "OKP",
				CRV: "X25519",
				X:   base64URLEncode(ephPub),
			},
			KeyID:            keyID,
			DerivationScheme: DerivationSchemeProtocolPath,
		})
	}

	return ct, &Encryption{
		Algorithm:            EncA256CTR,
		InitializationVector: base64URLEncode(iv),
		KeyEncryption:        keyEncryption,
	}, nil
}

// DecryptData decrypts a protocolPath-encrypted record. recipientPrivateKey is
// the X25519 private key derived for the record's protocolPath leaf.
func DecryptData(ciphertext []byte, enc *Encryption, recipientPrivateKey []byte) ([]byte, error) {
	entry, err := selectProtocolPathEntry(enc, recipientPrivateKey)
	if err != nil {
		return nil, err
	}
	cek, err := unwrapEntry(entry, recipientPrivateKey)
	if err != nil {
		return nil, err
	}
	defer clear(cek)
	return decryptContent(enc, cek, ciphertext)
}

// FindKeyEncryption returns the first keyEncryption entry with the given
// derivation scheme, or nil when none is present.
func FindKeyEncryption(enc *Encryption, scheme string) *KeyEncryption {
	if enc == nil {
		return nil
	}
	for i := range enc.KeyEncryption {
		if enc.KeyEncryption[i].DerivationScheme == scheme {
			return &enc.KeyEncryption[i]
		}
	}
	return nil
}

// selectProtocolPathEntry picks the protocolPath entry that matches the
// recipient's derived key. When several protocolPath entries exist it matches
// by keyId == thumbprint(recipient public key); otherwise it returns the only
// protocolPath entry.
func selectProtocolPathEntry(enc *Encryption, recipientPrivateKey []byte) (*KeyEncryption, error) {
	if enc == nil {
		return nil, fmt.Errorf("missing encryption envelope")
	}

	pub, err := X25519PublicKey(recipientPrivateKey)
	if err != nil {
		return nil, err
	}
	wantKeyID := thumbprintForPublicKey(pub)

	var first *KeyEncryption
	for i := range enc.KeyEncryption {
		entry := &enc.KeyEncryption[i]
		if entry.DerivationScheme != DerivationSchemeProtocolPath {
			continue
		}
		if entry.KeyID == wantKeyID {
			return entry, nil
		}
		if first == nil {
			first = entry
		}
	}
	if first != nil {
		return first, nil
	}
	return nil, fmt.Errorf("no protocolPath keyEncryption entry found")
}

// unwrapEntry unwraps the CEK from a keyEncryption entry using the recipient's
// X25519 private key.
func unwrapEntry(entry *KeyEncryption, recipientPrivateKey []byte) ([]byte, error) {
	if entry.EphemeralPublicKey == nil {
		return nil, fmt.Errorf("keyEncryption entry missing ephemeralPublicKey")
	}
	ephPub, err := base64URLDecode(entry.EphemeralPublicKey.X)
	if err != nil {
		return nil, fmt.Errorf("decoding ephemeralPublicKey: %w", err)
	}
	wrapped, err := base64URLDecode(entry.EncryptedKey)
	if err != nil {
		return nil, fmt.Errorf("decoding encryptedKey: %w", err)
	}
	info, err := kekInfo(entry)
	if err != nil {
		return nil, err
	}
	return UnwrapCEK(recipientPrivateKey, ephPub, wrapped, info)
}

// decryptContent decrypts the record ciphertext using the CEK and the
// envelope's IV. Only AES-256-CTR is supported in encryption-v1.
func decryptContent(enc *Encryption, cek, ciphertext []byte) ([]byte, error) {
	if enc.Algorithm != EncA256CTR {
		return nil, fmt.Errorf("unsupported content algorithm %q", enc.Algorithm)
	}
	iv, err := base64URLDecode(enc.InitializationVector)
	if err != nil {
		return nil, fmt.Errorf("decoding initializationVector: %w", err)
	}
	return CTRXor(cek, iv, ciphertext)
}

// base64URLEncode encodes bytes as base64url without padding.
func base64URLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// base64URLDecode decodes a base64url string (with or without padding).
func base64URLDecode(s string) ([]byte, error) {
	data, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		data, err = base64.URLEncoding.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("base64url decode: %w", err)
		}
	}
	return data, nil
}
