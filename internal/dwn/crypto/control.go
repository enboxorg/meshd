package crypto

import (
	"encoding/json"
	"fmt"
)

// Reserved protocol paths, schema URIs and formats used by the v1-sealed
// encryption control plane. Values mirror @enbox/dwn-sdk-js
// src/core/constants.ts and src/protocols/encryption.ts.
const (
	// EncryptionProtocolURI is the DWN Encryption protocol (grantKey records).
	EncryptionProtocolURI = "https://identity.foundation/dwn/protocols/encryption"

	// GrantKeyProtocolPath is the protocolPath of grantKey records under the
	// Encryption protocol.
	GrantKeyProtocolPath = "grantKey"

	// GrantKeySchemaURI is the JSON schema of grantKey record payloads.
	GrantKeySchemaURI = "https://identity.foundation/dwn/json-schemas/encryption/grant-key.json"

	// EncryptionControlRootPath is the reserved virtual protocol path root for
	// source-protocol-native encryption control records.
	EncryptionControlRootPath = "$encryption"

	// EncryptionControlAudiencePath is the reserved protocolPath of
	// role-audience public key + owner seal records, written under the SOURCE
	// protocol (not the Encryption protocol).
	EncryptionControlAudiencePath = "$encryption/audience"

	// EncryptionControlDeliveryPath is the reserved protocolPath of
	// role-audience key delivery records, written under the SOURCE protocol.
	EncryptionControlDeliveryPath = "$encryption/delivery"

	// EncryptionControlAudienceSchemaURI is the JSON schema of audience
	// control record payloads.
	EncryptionControlAudienceSchemaURI = "https://identity.foundation/dwn/json-schemas/encryption/audience.json"

	// EncryptionControlDeliverySchemaURI is the JSON schema of delivery
	// control record payloads.
	EncryptionControlDeliverySchemaURI = "https://identity.foundation/dwn/json-schemas/encryption/delivery.json"

	// DeliveryRecipientAuthorityRoleHolder is the only supported value of the
	// delivery record's recipientAuthority tag.
	DeliveryRecipientAuthorityRoleHolder = "roleHolder"

	// WrappedGrantKeyFormat identifies a plaintext grantKey record payload
	// carrying a WrappedGrantKeyEnvelope (pre-supplied delegates).
	WrappedGrantKeyFormat = "enbox/wrapped-grant-key@1"
)

// AudienceTags are the required tags of an `$encryption/audience` record.
type AudienceTags struct {
	Protocol  string `json:"protocol"`
	RolePath  string `json:"rolePath"`
	ContextID string `json:"contextId"`
	KeyID     string `json:"keyId"`
}

// DeliveryTags are the required tags of an `$encryption/delivery` record.
type DeliveryTags struct {
	Protocol           string `json:"protocol"`
	RolePath           string `json:"rolePath"`
	ContextID          string `json:"contextId"`
	KeyID              string `json:"keyId"`
	RecipientAuthority string `json:"recipientAuthority"`
}

// GrantKeyTags are the tags of an Encryption protocol grantKey record.
// ProtocolPath is present only for path-scoped subtree keys.
type GrantKeyTags struct {
	GrantID      string `json:"grantId"`
	Protocol     string `json:"protocol"`
	ProtocolPath string `json:"protocolPath,omitempty"`
	KeyID        string `json:"keyId"`
}

// AudiencePayload is the plaintext JSON payload of an `$encryption/audience`
// control record. sealedPrivateKey seals the audience PRIVATE key to the
// tenant role-path $keyAgreement public key.
type AudiencePayload struct {
	Protocol         string       `json:"protocol"`
	RolePath         string       `json:"rolePath"`
	ContextID        string       `json:"contextId"`
	KeyID            string       `json:"keyId"`
	PublicKeyJwk     PublicKeyJWK `json:"publicKeyJwk"`
	SealedPrivateKey SealKeyWrap  `json:"sealedPrivateKey"`
}

// Tags returns the record tags matching the payload fields.
func (p *AudiencePayload) Tags() AudienceTags {
	return AudienceTags{
		Protocol:  p.Protocol,
		RolePath:  p.RolePath,
		ContextID: p.ContextID,
		KeyID:     p.KeyID,
	}
}

// RoleAudienceKeyMaterial is delivered audience key material — a random (not
// HD-derived) X25519 key pair identified by the thumbprint of its public key.
type RoleAudienceKeyMaterial struct {
	Algorithm        string        `json:"algorithm"`        // "X25519-HKDF-SHA256+A256KW"
	DerivationScheme string        `json:"derivationScheme"` // "roleAudience"
	KeyID            string        `json:"keyId"`
	PublicKeyJwk     PublicKeyJWK  `json:"publicKeyJwk"`
	PrivateKeyJwk    PrivateKeyJWK `json:"privateKeyJwk"`
}

// DeliveryPayload is the decrypted JSON payload of an `$encryption/delivery`
// control record: audience key material delivered to a role holder.
type DeliveryPayload struct {
	Protocol    string                  `json:"protocol"`
	RolePath    string                  `json:"rolePath"`
	ContextID   string                  `json:"contextId"`
	KeyID       string                  `json:"keyId"`
	KeyMaterial RoleAudienceKeyMaterial `json:"keyMaterial"`
}

// Tags returns the audience tags matching the payload fields (without the
// recipientAuthority tag, which is not part of the payload).
func (p *DeliveryPayload) Tags() AudienceTags {
	return AudienceTags{
		Protocol:  p.Protocol,
		RolePath:  p.RolePath,
		ContextID: p.ContextID,
		KeyID:     p.KeyID,
	}
}

// GrantKeyScope is the derivation scope of a delivered grant key. An absent
// ProtocolPath means the whole-protocol subtree key.
type GrantKeyScope struct {
	Scheme       string `json:"scheme"` // "protocolPath"
	Protocol     string `json:"protocol"`
	ProtocolPath string `json:"protocolPath,omitempty"`
}

// ProtocolPathKeyMaterial is an owner-derived protocolPath subtree private key
// delivered via a grantKey record.
type ProtocolPathKeyMaterial struct {
	Algorithm        string        `json:"algorithm"`        // "X25519-HKDF-SHA256+A256KW"
	DerivationScheme string        `json:"derivationScheme"` // "protocolPath"
	DerivationPath   []string      `json:"derivationPath"`   // ["protocolPath", <protocol>, ...segments]
	KeyID            string        `json:"keyId"`
	PublicKeyJwk     PublicKeyJWK  `json:"publicKeyJwk"`
	PrivateKeyJwk    PrivateKeyJWK `json:"privateKeyJwk"`
}

// GrantKeyPayload is the payload of an Encryption protocol grantKey record:
// the owner-derived subtree PRIVATE key covering a grant's scope.
type GrantKeyPayload struct {
	GrantID     string                  `json:"grantId"`
	Scope       GrantKeyScope           `json:"scope"`
	KeyMaterial ProtocolPathKeyMaterial `json:"keyMaterial"`
}

// WrappedGrantKeyKeyEncryption wraps the envelope's content encryption key to
// the delegate's ROOT X25519 key. Unlike a record keyEncryption entry it has
// no derivationScheme field on the wire (the SDK strips it), but the KEK info
// is computed with the protocolPath scheme and this keyId.
type WrappedGrantKeyKeyEncryption struct {
	Algorithm          string        `json:"algorithm"`
	KeyID              string        `json:"keyId"`
	EphemeralPublicKey *PublicKeyJWK `json:"ephemeralPublicKey"`
	EncryptedKey       string        `json:"encryptedKey"`
}

// WrappedGrantKeyContentEncryption describes the envelope's A256CTR content
// encryption.
type WrappedGrantKeyContentEncryption struct {
	Algorithm            string `json:"algorithm"`
	InitializationVector string `json:"initializationVector"`
}

// WrappedGrantKeyEnvelope is the plaintext grantKey record payload used for
// PRE-SUPPLIED delegates: the GrantKeyPayload JSON is A256CTR-encrypted and
// the content key wrapped to the delegate root X25519 public key.
type WrappedGrantKeyEnvelope struct {
	Format            string                           `json:"format"`
	KeyEncryption     WrappedGrantKeyKeyEncryption     `json:"keyEncryption"`
	ContentEncryption WrappedGrantKeyContentEncryption `json:"contentEncryption"`
	Ciphertext        string                           `json:"ciphertext"`
}

// UnwrapGrantKeyEnvelope opens a wrapped grantKey envelope (raw record data
// bytes) with the delegate's root X25519 private key and returns the verified
// GrantKeyPayload.
//
// The KEK info uses the protocolPath scheme with the envelope's keyId, which
// must be the JWK thumbprint of the delegate root X25519 public key.
func UnwrapGrantKeyEnvelope(envelope []byte, rootX25519Priv []byte) (*GrantKeyPayload, error) {
	var env WrappedGrantKeyEnvelope
	if err := json.Unmarshal(envelope, &env); err != nil {
		return nil, fmt.Errorf("parsing wrapped grantKey envelope: %w", err)
	}
	return UnwrapGrantKeyEnvelopeStruct(&env, rootX25519Priv)
}

// UnwrapGrantKeyEnvelopeStruct is UnwrapGrantKeyEnvelope for an already-parsed
// envelope.
func UnwrapGrantKeyEnvelopeStruct(env *WrappedGrantKeyEnvelope, rootX25519Priv []byte) (*GrantKeyPayload, error) {
	if env.Format != WrappedGrantKeyFormat {
		return nil, fmt.Errorf("unsupported wrapped grantKey format %q", env.Format)
	}
	if env.KeyEncryption.Algorithm != AlgX25519HKDFA256KW {
		return nil, fmt.Errorf("unsupported wrapped grantKey key algorithm %q", env.KeyEncryption.Algorithm)
	}
	if env.ContentEncryption.Algorithm != EncA256CTR {
		return nil, fmt.Errorf("unsupported wrapped grantKey content algorithm %q", env.ContentEncryption.Algorithm)
	}
	if env.KeyEncryption.EphemeralPublicKey == nil {
		return nil, fmt.Errorf("wrapped grantKey envelope missing ephemeralPublicKey")
	}

	rootPub, err := X25519PublicKey(rootX25519Priv)
	if err != nil {
		return nil, err
	}
	if want := thumbprintForPublicKey(rootPub); env.KeyEncryption.KeyID != want {
		return nil, fmt.Errorf("wrapped grantKey targets key %q, expected %q", env.KeyEncryption.KeyID, want)
	}

	ephPub, err := base64URLDecode(env.KeyEncryption.EphemeralPublicKey.X)
	if err != nil {
		return nil, fmt.Errorf("decoding envelope ephemeralPublicKey: %w", err)
	}
	wrapped, err := base64URLDecode(env.KeyEncryption.EncryptedKey)
	if err != nil {
		return nil, fmt.Errorf("decoding envelope encryptedKey: %w", err)
	}

	dek, err := UnwrapCEK(rootX25519Priv, ephPub, wrapped, protocolPathKEKInfo(env.KeyEncryption.KeyID))
	if err != nil {
		return nil, fmt.Errorf("unwrapping grantKey content key: %w", err)
	}
	defer clear(dek)

	iv, err := base64URLDecode(env.ContentEncryption.InitializationVector)
	if err != nil {
		return nil, fmt.Errorf("decoding envelope initializationVector: %w", err)
	}
	ciphertext, err := base64URLDecode(env.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decoding envelope ciphertext: %w", err)
	}
	plaintext, err := CTRXor(dek, iv, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decrypting grantKey payload: %w", err)
	}

	var payload GrantKeyPayload
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		return nil, fmt.Errorf("parsing GrantKeyPayload: %w", err)
	}
	if err := validateGrantKeyPayload(&payload); err != nil {
		return nil, err
	}
	return &payload, nil
}

// validateGrantKeyPayload performs the local integrity checks the SDK applies
// to a delivered grantKey payload (shape, scope/derivationPath consistency,
// key material consistency). Grant liveness/scope-coverage checks against the
// DWN are the control plane's responsibility.
func validateGrantKeyPayload(p *GrantKeyPayload) error {
	if p.GrantID == "" {
		return fmt.Errorf("grantKey payload missing grantId")
	}
	if p.Scope.Scheme != DerivationSchemeProtocolPath {
		return fmt.Errorf("grantKey scope scheme must be %q, got %q", DerivationSchemeProtocolPath, p.Scope.Scheme)
	}
	if p.Scope.Protocol == "" {
		return fmt.Errorf("grantKey scope missing protocol")
	}
	km := &p.KeyMaterial
	if km.Algorithm != AlgX25519HKDFA256KW {
		return fmt.Errorf("grantKey keyMaterial algorithm must be %q, got %q", AlgX25519HKDFA256KW, km.Algorithm)
	}
	if km.DerivationScheme != DerivationSchemeProtocolPath {
		return fmt.Errorf("grantKey keyMaterial derivationScheme must be %q, got %q", DerivationSchemeProtocolPath, km.DerivationScheme)
	}

	wantPath := append([]string{DerivationSchemeProtocolPath, p.Scope.Protocol}, splitProtocolPath(p.Scope.ProtocolPath)...)
	if len(km.DerivationPath) != len(wantPath) {
		return fmt.Errorf("grantKey derivationPath does not match scope")
	}
	for i := range wantPath {
		if km.DerivationPath[i] != wantPath[i] {
			return fmt.Errorf("grantKey derivationPath does not match scope")
		}
	}

	return verifyX25519KeyMaterial(km.KeyID, &km.PublicKeyJwk, &km.PrivateKeyJwk)
}

// verifyX25519KeyMaterial checks that keyID is the thumbprint of publicKeyJwk
// and that privateKeyJwk derives publicKeyJwk.
func verifyX25519KeyMaterial(keyID string, publicKeyJwk *PublicKeyJWK, privateKeyJwk *PrivateKeyJWK) error {
	if publicKeyJwk.KTY != "OKP" || publicKeyJwk.CRV != "X25519" || publicKeyJwk.X == "" {
		return fmt.Errorf("key material publicKeyJwk must be an OKP X25519 key")
	}
	if got := JWKThumbprintX25519(publicKeyJwk.X); got != keyID {
		return fmt.Errorf("key material keyId %q does not match publicKeyJwk thumbprint %q", keyID, got)
	}

	priv, err := base64URLDecode(privateKeyJwk.D)
	if err != nil {
		return fmt.Errorf("decoding key material privateKeyJwk.d: %w", err)
	}
	defer clear(priv)
	pub, err := X25519PublicKey(priv)
	if err != nil {
		return fmt.Errorf("deriving public key from key material private key: %w", err)
	}
	if base64URLEncode(pub) != publicKeyJwk.X {
		return fmt.Errorf("key material privateKeyJwk does not derive publicKeyJwk")
	}
	return nil
}
