package crypto

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// JWE General JSON Serialization types for DWN encryption.
//
// The DWN uses a JWE-inspired structure as the "encryption" property on
// RecordsWrite messages. Unlike standard JWE, the ciphertext is NOT included
// in this structure — it is stored separately as the record's data. Only the
// key wrapping metadata, IV, and authentication tag are stored here.

// ProtectedHeader is the JWE Protected Header for DWN encryption.
type ProtectedHeader struct {
	Alg string `json:"alg"` // Key agreement algorithm (e.g., "ECDH-ES+A256KW")
	Enc string `json:"enc"` // Content encryption algorithm (e.g., "A256GCM")
}

// RecipientHeader is the per-recipient unprotected header.
type RecipientHeader struct {
	// KID is the fully qualified key ID of the root key used in derivation
	// (e.g., "did:example:alice#enc-1").
	KID string `json:"kid"`

	// EPK is the ephemeral X25519 public key used for ECDH key agreement.
	EPK *PublicKeyJWK `json:"epk"`

	// DerivationScheme is the key derivation scheme used
	// ("protocolPath" or "protocolContext").
	DerivationScheme string `json:"derivationScheme"`

	// DerivedPublicKey is the derived public key. Present when derivation
	// scheme is "protocolContext" to allow the recipient to identify which
	// derived key was used.
	DerivedPublicKey *PublicKeyJWK `json:"derivedPublicKey,omitempty"`
}

// Recipient is a single recipient entry in the JWE General JSON Serialization.
type Recipient struct {
	Header       RecipientHeader `json:"header"`
	EncryptedKey string          `json:"encrypted_key"` // Base64url-encoded wrapped CEK
}

// Encryption is the JWE-inspired structure used as the "encryption" property
// on RecordsWrite messages (JWE General JSON Serialization minus ciphertext).
type Encryption struct {
	// Protected is the base64url-encoded JWE Protected Header.
	Protected string `json:"protected"`

	// IV is the base64url-encoded initialization vector for content encryption.
	IV string `json:"iv"`

	// Tag is the base64url-encoded authentication tag from the AEAD cipher.
	Tag string `json:"tag"`

	// Recipients contains one entry per recipient or derivation path.
	Recipients []Recipient `json:"recipients"`
}

// PublicKeyJWK represents an X25519 public key in JWK format.
type PublicKeyJWK struct {
	KTY string `json:"kty"`           // Key type: "OKP"
	CRV string `json:"crv"`           // Curve: "X25519"
	X   string `json:"x"`             // Base64url-encoded public key bytes
	KID string `json:"kid,omitempty"` // Key ID (optional)
}

// KeyEncryptionInput describes how to encrypt the CEK for a single recipient.
type KeyEncryptionInput struct {
	// PublicKeyID is the fully qualified key ID of the recipient's root
	// encryption key (e.g., "did:dht:xyz#enc-1").
	PublicKeyID string

	// PublicKey is the recipient's derived X25519 public key (raw 32 bytes).
	PublicKey []byte

	// DerivationScheme is the key derivation scheme.
	DerivationScheme string
}

// EncryptionInput describes the inputs for encrypting a record.
type EncryptionInput struct {
	// Algorithm is the content encryption algorithm. Defaults to A256GCM.
	Algorithm string

	// CEK is the Content Encryption Key (32 bytes).
	CEK []byte

	// IV is the initialization vector.
	IV []byte

	// Tag is the authentication tag from the AEAD encryption of the record data.
	Tag []byte

	// KeyEncryptionInputs describes how to wrap the CEK for each recipient.
	KeyEncryptionInputs []KeyEncryptionInput
}

// EncryptData encrypts plaintext using A256GCM and wraps the CEK for all recipients.
// Returns the encrypted data (ciphertext) and the Encryption structure.
//
// This is the main entry point for encrypting a DWN record:
//  1. Generate random CEK and IV
//  2. AEAD encrypt the plaintext
//  3. Build JWE with per-recipient key wrapping
func EncryptData(plaintext []byte, recipients []KeyEncryptionInput) (ciphertext []byte, enc *Encryption, err error) {
	if len(recipients) == 0 {
		return nil, nil, fmt.Errorf("at least one recipient is required")
	}

	// Generate random CEK and IV.
	cek, err := GenerateCEK()
	if err != nil {
		return nil, nil, err
	}
	defer clear(cek) // Zero CEK after wrapping for recipients.

	iv, err := GenerateIV(EncA256GCM)
	if err != nil {
		return nil, nil, err
	}

	// Encrypt the plaintext.
	ct, tag, err := AEADEncrypt(EncA256GCM, cek, iv, plaintext, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("encrypting data: %w", err)
	}

	// Build JWE structure.
	input := EncryptionInput{
		Algorithm:           EncA256GCM,
		CEK:                 cek,
		IV:                  iv,
		Tag:                 tag,
		KeyEncryptionInputs: recipients,
	}

	jwe, err := BuildJWE(input)
	if err != nil {
		return nil, nil, err
	}

	return ct, jwe, nil
}

// DecryptData decrypts a DWN record using the recipient's private key.
// It finds the matching recipient entry, unwraps the CEK, and decrypts.
func DecryptData(ciphertext []byte, enc *Encryption, recipientPrivateKey []byte, recipientKID string) ([]byte, error) {
	// Parse protected header to get the content encryption algorithm.
	header, err := ParseProtectedHeader(enc.Protected)
	if err != nil {
		return nil, err
	}

	// Decode IV and tag.
	iv, err := base64URLDecode(enc.IV)
	if err != nil {
		return nil, fmt.Errorf("decoding IV: %w", err)
	}

	tag, err := base64URLDecode(enc.Tag)
	if err != nil {
		return nil, fmt.Errorf("decoding tag: %w", err)
	}

	// Find matching recipient and unwrap CEK.
	cek, err := unwrapCEKForRecipient(enc.Recipients, recipientPrivateKey, recipientKID)
	if err != nil {
		return nil, err
	}
	defer clear(cek) // Zero CEK after decryption.

	// Decrypt the data.
	plaintext, err := AEADDecrypt(header.Enc, cek, iv, ciphertext, tag, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypting data: %w", err)
	}

	return plaintext, nil
}

// BuildJWE constructs the JWE Encryption structure from encryption input.
// For each recipient, it generates an ephemeral X25519 key pair, performs
// ECDH-ES key agreement, and wraps the CEK.
func BuildJWE(input EncryptionInput) (*Encryption, error) {
	enc := input.Algorithm
	if enc == "" {
		enc = EncA256GCM
	}

	// Build and encode protected header.
	header := ProtectedHeader{
		Alg: AlgECDHESA256KW,
		Enc: enc,
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return nil, fmt.Errorf("marshaling protected header: %w", err)
	}
	protectedB64 := base64URLEncode(headerJSON)

	// Build recipients.
	recipients := make([]Recipient, 0, len(input.KeyEncryptionInputs))
	for _, keyInput := range input.KeyEncryptionInputs {
		// ECDH-ES+A256KW: generate ephemeral key, compute shared secret, wrap CEK.
		ephPub, wrappedKey, err := ECDHESWrapKey(keyInput.PublicKey, input.CEK)
		if err != nil {
			return nil, fmt.Errorf("wrapping CEK for recipient %s: %w", keyInput.PublicKeyID, err)
		}

		recipientHeader := RecipientHeader{
			KID: keyInput.PublicKeyID,
			EPK: &PublicKeyJWK{
				KTY: "OKP",
				CRV: "X25519",
				X:   base64URLEncode(ephPub),
			},
			DerivationScheme: keyInput.DerivationScheme,
		}

		// For protocolContext scheme, include the derived public key so
		// the recipient can identify which derived key was used.
		if keyInput.DerivationScheme == DerivationSchemeProtocolContext {
			recipientHeader.DerivedPublicKey = &PublicKeyJWK{
				KTY: "OKP",
				CRV: "X25519",
				X:   base64URLEncode(keyInput.PublicKey),
			}
		}

		recipients = append(recipients, Recipient{
			Header:       recipientHeader,
			EncryptedKey: base64URLEncode(wrappedKey),
		})
	}

	return &Encryption{
		Protected:  protectedB64,
		IV:         base64URLEncode(input.IV),
		Tag:        base64URLEncode(input.Tag),
		Recipients: recipients,
	}, nil
}

// ParseProtectedHeader decodes and parses the JWE protected header.
func ParseProtectedHeader(protectedB64 string) (*ProtectedHeader, error) {
	headerJSON, err := base64URLDecode(protectedB64)
	if err != nil {
		return nil, fmt.Errorf("decoding protected header: %w", err)
	}

	var header ProtectedHeader
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, fmt.Errorf("parsing protected header: %w", err)
	}

	return &header, nil
}

// DecryptDataWithScheme decrypts a DWN record by matching the recipient entry
// based on derivation scheme. This is useful for Protocol Context decryption
// where the recipient's KID is the DWN owner's key ID, but the decryptor
// holds a delivered context key.
//
// It tries each recipient whose derivationScheme matches, attempting to
// unwrap the CEK with the provided private key.
func DecryptDataWithScheme(ciphertext []byte, enc *Encryption, privateKey []byte, scheme string) ([]byte, error) {
	header, err := ParseProtectedHeader(enc.Protected)
	if err != nil {
		return nil, err
	}

	iv, err := base64URLDecode(enc.IV)
	if err != nil {
		return nil, fmt.Errorf("decoding IV: %w", err)
	}

	tag, err := base64URLDecode(enc.Tag)
	if err != nil {
		return nil, fmt.Errorf("decoding tag: %w", err)
	}

	cek, err := unwrapCEKByScheme(enc.Recipients, privateKey, scheme)
	if err != nil {
		return nil, err
	}
	defer clear(cek) // Zero CEK after decryption.

	plaintext, err := AEADDecrypt(header.Enc, cek, iv, ciphertext, tag, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypting data: %w", err)
	}

	return plaintext, nil
}

// unwrapCEKForRecipient finds the recipient matching the given KID and
// unwraps the CEK using ECDH-ES+A256KW.
func unwrapCEKForRecipient(recipients []Recipient, privateKey []byte, kid string) ([]byte, error) {
	for _, r := range recipients {
		if r.Header.KID != kid {
			continue
		}

		// Decode ephemeral public key.
		if r.Header.EPK == nil {
			return nil, fmt.Errorf("recipient %s: missing ephemeral public key", kid)
		}
		ephPub, err := base64URLDecode(r.Header.EPK.X)
		if err != nil {
			return nil, fmt.Errorf("recipient %s: decoding ephemeral public key: %w", kid, err)
		}

		// Decode wrapped key.
		wrappedKey, err := base64URLDecode(r.EncryptedKey)
		if err != nil {
			return nil, fmt.Errorf("recipient %s: decoding wrapped key: %w", kid, err)
		}

		// ECDH-ES+A256KW unwrap.
		cek, err := ECDHESUnwrapKey(privateKey, ephPub, wrappedKey)
		if err != nil {
			return nil, fmt.Errorf("recipient %s: unwrapping CEK: %w", kid, err)
		}

		return cek, nil
	}

	return nil, fmt.Errorf("no matching recipient found for kid %q", kid)
}

// unwrapCEKByScheme tries to unwrap the CEK from any recipient entry
// matching the given derivation scheme. This enables decryption with
// a delivered context key where the KID doesn't directly match.
func unwrapCEKByScheme(recipients []Recipient, privateKey []byte, scheme string) ([]byte, error) {
	var lastErr error
	for _, r := range recipients {
		if r.Header.DerivationScheme != scheme {
			continue
		}

		if r.Header.EPK == nil {
			lastErr = fmt.Errorf("recipient (scheme=%s): missing ephemeral public key", scheme)
			continue
		}
		ephPub, err := base64URLDecode(r.Header.EPK.X)
		if err != nil {
			lastErr = fmt.Errorf("recipient (scheme=%s): decoding ephemeral key: %w", scheme, err)
			continue
		}

		wrappedKey, err := base64URLDecode(r.EncryptedKey)
		if err != nil {
			lastErr = fmt.Errorf("recipient (scheme=%s): decoding wrapped key: %w", scheme, err)
			continue
		}

		cek, err := ECDHESUnwrapKey(privateKey, ephPub, wrappedKey)
		if err != nil {
			lastErr = fmt.Errorf("recipient (scheme=%s): unwrapping CEK: %w", scheme, err)
			continue
		}

		return cek, nil
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("no matching recipient found for scheme %q", scheme)
}

// base64URLEncode encodes bytes as base64url without padding.
func base64URLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// base64URLDecode decodes a base64url string (with or without padding).
func base64URLDecode(s string) ([]byte, error) {
	// Try without padding first (canonical), then with padding.
	data, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		data, err = base64.URLEncoding.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("base64url decode: %w", err)
		}
	}
	return data, nil
}
