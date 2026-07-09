package crypto

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// DeriveRolePathKey derives a role-path X25519 private key from a root #enc
// key, along ["protocolPath", <protocol>, <rolePath segments...>].
//
// Two parties derive this key from their own roots:
//   - The OWNER derives the tenant role-path key that opens audience seals
//     (the private half of the rule set's published $keyAgreement key).
//   - A role HOLDER derives their own role-path key, which is the recipient
//     key of `$encryption/delivery` records addressed to them.
func DeriveRolePathKey(rootPrivateKey []byte, protocol, rolePath string) (privateKey []byte, err error) {
	segments := splitProtocolPath(rolePath)
	path := BuildProtocolPathDerivation(protocol, segments...)
	return DeriveKeyBytes(rootPrivateKey, path)
}

// RolePathPublicKeyJWK derives the PUBLIC half of a role-path X25519 key from a
// root #enc key and returns it as a PublicKeyJWK. It is the public counterpart of
// DeriveRolePathKey and is byte-identical to the `$keyAgreement.publicKeyJwk` that
// InjectEncryptionDirectives publishes at the same protocol/rolePath (both walk
// the same HKDF chain via BuildProtocolPathDerivation).
//
// A role holder emits this so an owner can wrap an `$encryption/delivery` record
// to it WITHOUT resolving the holder's DWN — the delivery is key transport to an
// already role-authorized reader, so a self-asserted key grants no new authority.
// The `kid` member is intentionally omitted to match the injected wire shape
// ({kty, crv, x} only); consumers recompute the thumbprint from `x`.
func RolePathPublicKeyJWK(rootPrivateKey []byte, protocol, rolePath string) (PublicKeyJWK, error) {
	priv, err := DeriveRolePathKey(rootPrivateKey, protocol, rolePath)
	if err != nil {
		return PublicKeyJWK{}, err
	}
	defer clear(priv) // Only the public half is published; zero the derived private key.

	pub, err := X25519PublicKey(priv)
	if err != nil {
		return PublicKeyJWK{}, err
	}
	return PublicKeyJWK{
		KTY: "OKP",
		CRV: "X25519",
		X:   base64.RawURLEncoding.EncodeToString(pub),
	}, nil
}

// RoleAudienceDecrypter decrypts roleAudience-encrypted records with a fixed
// audience private key (obtained by unsealing an audience record or from a
// delivery record).
type RoleAudienceDecrypter struct {
	privateKey []byte
	keyID      string
}

// NewRoleAudienceDecrypter builds a decrypter from a raw 32-byte audience
// X25519 private key.
func NewRoleAudienceDecrypter(audiencePrivateKey []byte) (*RoleAudienceDecrypter, error) {
	pub, err := X25519PublicKey(audiencePrivateKey)
	if err != nil {
		return nil, err
	}
	priv := make([]byte, len(audiencePrivateKey))
	copy(priv, audiencePrivateKey)
	return &RoleAudienceDecrypter{
		privateKey: priv,
		keyID:      thumbprintForPublicKey(pub),
	}, nil
}

// KeyID returns the JWK thumbprint of the audience public key. roleAudience
// keyEncryption entries reference the audience key by this value.
func (d *RoleAudienceDecrypter) KeyID() string {
	return d.keyID
}

// Close zeros the audience private key held by the decrypter.
func (d *RoleAudienceDecrypter) Close() {
	clear(d.privateKey)
}

// Decrypt unwraps the record's roleAudience keyEncryption entry matching this
// audience key and AES-256-CTR decrypts the ciphertext.
func (d *RoleAudienceDecrypter) Decrypt(ciphertext []byte, enc *Encryption) ([]byte, error) {
	if enc == nil {
		return nil, fmt.Errorf("missing encryption envelope")
	}

	var entry *KeyEncryption
	for i := range enc.KeyEncryption {
		candidate := &enc.KeyEncryption[i]
		if candidate.DerivationScheme == DerivationSchemeRoleAudience && candidate.KeyID == d.keyID {
			entry = candidate
			break
		}
	}
	if entry == nil {
		return nil, fmt.Errorf("no roleAudience keyEncryption entry for audience key %q", d.keyID)
	}

	cek, err := unwrapEntry(entry, d.privateKey)
	if err != nil {
		return nil, fmt.Errorf("unwrapping roleAudience entry: %w", err)
	}
	defer clear(cek)

	return decryptContent(enc, cek, ciphertext)
}

// VerifyAudiencePayload checks the intrinsic consistency of an
// `$encryption/audience` record payload: the keyId must be the JWK thumbprint
// of publicKeyJwk and the seal must target the given tuple.
func VerifyAudiencePayload(payload *AudiencePayload) error {
	if payload == nil {
		return fmt.Errorf("missing audience payload")
	}
	if payload.RolePath == "" {
		return fmt.Errorf("audience payload missing rolePath")
	}
	if payload.PublicKeyJwk.KTY != "OKP" || payload.PublicKeyJwk.CRV != "X25519" || payload.PublicKeyJwk.X == "" {
		return fmt.Errorf("audience payload publicKeyJwk must be an OKP X25519 key")
	}
	if got := JWKThumbprintX25519(payload.PublicKeyJwk.X); got != payload.KeyID {
		return fmt.Errorf("audience keyId %q does not match publicKeyJwk thumbprint %q", payload.KeyID, got)
	}
	if payload.SealedPrivateKey.DerivationScheme != DerivationSchemeSeal {
		return fmt.Errorf("audience sealedPrivateKey derivationScheme must be %q", DerivationSchemeSeal)
	}
	return nil
}

// VerifyRoleAudienceKeyMaterial checks delivered audience key material: the
// algorithm and scheme identifiers, keyId == thumbprint(publicKeyJwk), and
// that privateKeyJwk derives publicKeyJwk. This is the Go counterpart of the
// SDK's verifyAudienceKeyMaterial.
func VerifyRoleAudienceKeyMaterial(km *RoleAudienceKeyMaterial) error {
	if km == nil {
		return fmt.Errorf("missing audience key material")
	}
	if km.Algorithm != AlgX25519HKDFA256KW {
		return fmt.Errorf("audience key material algorithm must be %q, got %q", AlgX25519HKDFA256KW, km.Algorithm)
	}
	if km.DerivationScheme != DerivationSchemeRoleAudience {
		return fmt.Errorf("audience key material derivationScheme must be %q, got %q", DerivationSchemeRoleAudience, km.DerivationScheme)
	}
	return verifyX25519KeyMaterial(km.KeyID, &km.PublicKeyJwk, &km.PrivateKeyJwk)
}

// UnsealAudienceRecord opens the seal of an `$encryption/audience` record
// payload with the role-path $keyAgreement PRIVATE key (raw 32 bytes) and
// returns the raw 32-byte audience private key. The sealing key is derived
// either from the owner root (DeriveRolePathKey) or from a grantKey-delivered
// subtree key (SubtreeDecrypter.RolePathKey).
//
// It verifies the payload's intrinsic consistency, that the seal targets the
// provided sealing key, and that the unsealed private key derives the
// advertised audience public key.
func UnsealAudienceRecord(payload *AudiencePayload, sealingPrivateKey []byte) ([]byte, error) {
	if err := VerifyAudiencePayload(payload); err != nil {
		return nil, err
	}

	sealingPub, err := X25519PublicKey(sealingPrivateKey)
	if err != nil {
		return nil, err
	}
	if want := thumbprintForPublicKey(sealingPub); payload.SealedPrivateKey.KeyID != want {
		return nil, fmt.Errorf("audience seal targets key %q, sealing key is %q", payload.SealedPrivateKey.KeyID, want)
	}

	audiencePriv, err := UnsealAudiencePrivateKey(
		&payload.SealedPrivateKey,
		sealingPrivateKey,
		payload.Protocol,
		payload.RolePath,
		payload.ContextID,
		payload.KeyID,
	)
	if err != nil {
		return nil, err
	}

	pub, err := X25519PublicKey(audiencePriv)
	if err != nil {
		clear(audiencePriv)
		return nil, err
	}
	if base64URLEncode(pub) != payload.PublicKeyJwk.X {
		clear(audiencePriv)
		return nil, fmt.Errorf("unsealed audience private key does not derive the advertised public key")
	}

	return audiencePriv, nil
}

// DecryptDeliveryRecord decrypts an `$encryption/delivery` record addressed
// to a role holder and returns its verified payload. recipientRootKey is the
// role holder's root #enc X25519 private key; the delivery is encrypted with
// a single protocolPath entry wrapped to the holder's role-path key derived
// from THEIR OWN installed protocol definition.
func DecryptDeliveryRecord(recipientRootKey []byte, protocol, rolePath string, enc *Encryption, ciphertext []byte) (*DeliveryPayload, error) {
	rolePriv, err := DeriveRolePathKey(recipientRootKey, protocol, rolePath)
	if err != nil {
		return nil, fmt.Errorf("deriving role-path key: %w", err)
	}
	defer clear(rolePriv)

	plaintext, err := DecryptData(ciphertext, enc, rolePriv)
	if err != nil {
		return nil, fmt.Errorf("decrypting delivery record: %w", err)
	}

	var payload DeliveryPayload
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		return nil, fmt.Errorf("parsing DeliveryPayload: %w", err)
	}
	if payload.Protocol != protocol || payload.RolePath != rolePath {
		return nil, fmt.Errorf("delivery payload tuple (%q, %q) does not match expected (%q, %q)",
			payload.Protocol, payload.RolePath, protocol, rolePath)
	}
	if payload.KeyID != payload.KeyMaterial.KeyID {
		return nil, fmt.Errorf("delivery payload keyId %q does not match keyMaterial keyId %q",
			payload.KeyID, payload.KeyMaterial.KeyID)
	}
	if err := VerifyRoleAudienceKeyMaterial(&payload.KeyMaterial); err != nil {
		return nil, err
	}
	return &payload, nil
}

// RoleAudienceInfo describes a role-audience entry on an encrypted record,
// used by the daemon to locate the matching audience / delivery records.
type RoleAudienceInfo struct {
	Protocol string
	RolePath string
	KeyID    string
}

// RoleAudienceEntryInfo extracts the first role-audience descriptor from a
// record's encryption envelope, or nil when the record is not role-readable.
// Records readable by several roles carry one entry per role — readers
// resolving their own role's key should use RoleAudienceEntryInfos.
func RoleAudienceEntryInfo(enc *Encryption) *RoleAudienceInfo {
	infos := RoleAudienceEntryInfos(enc)
	if len(infos) == 0 {
		return nil
	}
	return infos[0]
}

// RoleAudienceEntryInfos extracts every role-audience descriptor from a
// record's encryption envelope, in wire order (one per reading role).
func RoleAudienceEntryInfos(enc *Encryption) []*RoleAudienceInfo {
	if enc == nil {
		return nil
	}
	var infos []*RoleAudienceInfo
	for i := range enc.KeyEncryption {
		entry := &enc.KeyEncryption[i]
		if entry.DerivationScheme != DerivationSchemeRoleAudience {
			continue
		}
		infos = append(infos, &RoleAudienceInfo{
			Protocol: entry.Protocol,
			RolePath: entry.RolePath,
			KeyID:    entry.KeyID,
		})
	}
	return infos
}

// RoleAudienceContextID computes the audience tuple contextId for a role path
// relative to a source record's contextId, mirroring the SDK's
// getRoleAudienceContextId: a root-level role (no '/') maps to the empty
// string; a nested role maps to the first depth(rolePath)-1 segments of the
// source record's contextId. It returns an error when the contextId has too
// few segments.
func RoleAudienceContextID(rolePath, sourceContextID string) (string, error) {
	depth := len(strings.Split(rolePath, "/")) - 1
	if depth == 0 {
		return "", nil
	}
	if sourceContextID == "" {
		return "", fmt.Errorf("role %q requires %d context segment(s) but contextId is empty", rolePath, depth)
	}
	segments := strings.Split(sourceContextID, "/")
	if len(segments) < depth {
		return "", fmt.Errorf("contextId %q has %d segment(s), need %d for role %q", sourceContextID, len(segments), depth, rolePath)
	}
	return strings.Join(segments[:depth], "/"), nil
}

// RolePathSegments splits a slash-delimited role path into its segments.
func RolePathSegments(rolePath string) []string {
	return strings.Split(rolePath, "/")
}

// GenerateAudienceKey mints fresh random role-audience key material for one
// source-protocol audience tuple (the Go counterpart of the SDK's
// generateAudienceKey). Minting happens in the control plane; this helper
// only produces the key material.
func GenerateAudienceKey() (*RoleAudienceKeyMaterial, error) {
	priv, pub, err := GenerateX25519KeyPair()
	if err != nil {
		return nil, err
	}
	x := base64URLEncode(pub)
	return &RoleAudienceKeyMaterial{
		Algorithm:        AlgX25519HKDFA256KW,
		DerivationScheme: DerivationSchemeRoleAudience,
		KeyID:            JWKThumbprintX25519(x),
		PublicKeyJwk:     PublicKeyJWK{KTY: "OKP", CRV: "X25519", X: x},
		PrivateKeyJwk:    PrivateKeyJWK{KTY: "OKP", CRV: "X25519", X: x, D: base64URLEncode(priv)},
	}, nil
}

// BuildAudiencePayload seals audience key material to the role-path
// $keyAgreement public key (raw 32 bytes) and assembles the plaintext
// `$encryption/audience` record payload for the given tuple.
func BuildAudiencePayload(km *RoleAudienceKeyMaterial, sealingPublicKey []byte, protocol, rolePath, contextID string) (*AudiencePayload, error) {
	if err := VerifyRoleAudienceKeyMaterial(km); err != nil {
		return nil, err
	}
	priv, err := base64URLDecode(km.PrivateKeyJwk.D)
	if err != nil {
		return nil, fmt.Errorf("decoding audience private key: %w", err)
	}
	defer clear(priv)

	seal, err := SealAudiencePrivateKey(priv, sealingPublicKey, protocol, rolePath, contextID, km.KeyID)
	if err != nil {
		return nil, err
	}

	return &AudiencePayload{
		Protocol:         protocol,
		RolePath:         rolePath,
		ContextID:        contextID,
		KeyID:            km.KeyID,
		PublicKeyJwk:     km.PublicKeyJwk,
		SealedPrivateKey: *seal,
	}, nil
}
