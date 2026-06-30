package crypto

import (
	"encoding/json"
	"fmt"
	"strings"
)

// AudienceKeyPayload is the decrypted contents of an EncryptionProtocol
// `audienceKey` record. It delivers a per-epoch role audience keypair to a
// role holder so they can unwrap roleAudience keyEncryption entries.
//
// As of @enbox 0.8.8 (SDK #1095) the key material is nested under
// `keyMaterial`; earlier builds carried keyId/publicKeyJwk/privateKeyJwk at the
// top level.
type AudienceKeyPayload struct {
	Protocol    string                  `json:"protocol"`
	ContextID   string                  `json:"contextId"`
	Role        string                  `json:"role"`
	Epoch       int                     `json:"epoch"`
	KeyMaterial RoleAudienceKeyMaterial `json:"keyMaterial"`
}

// RoleAudienceKeyMaterial is the nested key material of an audienceKey payload
// (X25519RoleAudienceKeyMaterial in the SDK). The wire form also carries
// `algorithm` and `derivationScheme`, which the unwrap path does not need.
type RoleAudienceKeyMaterial struct {
	KeyID         string        `json:"keyId"`
	PublicKeyJwk  PublicKeyJWK  `json:"publicKeyJwk"`
	PrivateKeyJwk PrivateKeyJWK `json:"privateKeyJwk"`
}

// RoleAudienceParams bundles the inputs for role-audience decryption of a
// single mesh record.
type RoleAudienceParams struct {
	// MeshEncryption is the mesh record's encryption-v1 envelope.
	MeshEncryption *Encryption

	// MeshCiphertext is the encrypted mesh record data.
	MeshCiphertext []byte

	// NodeEncRootKey is the node identity's #enc X25519 root private key.
	NodeEncRootKey []byte

	// AudienceKeyEncryption is the EncryptionProtocol audienceKey record's
	// encryption-v1 envelope (a single protocolPath entry encrypted to the
	// node's role-path key).
	AudienceKeyEncryption *Encryption

	// AudienceKeyCiphertext is the encrypted audienceKey record data, which
	// decrypts to an AudienceKeyPayload.
	AudienceKeyCiphertext []byte
}

// DeriveRolePathKey derives the node's role-path X25519 private key from its
// #enc root, along ["protocolPath", <protocol>, <role segments...>].
//
// Example: protocol "https://enbox.id/protocols/test-mesh", role "network/node"
// derives along ["protocolPath", "https://enbox.id/protocols/test-mesh",
// "network", "node"].
func DeriveRolePathKey(nodeEncRootKey []byte, protocol, role string) (privateKey []byte, err error) {
	segments := splitProtocolPath(role)
	path := BuildProtocolPathDerivation(protocol, segments...)
	return DeriveKeyBytes(nodeEncRootKey, path)
}

// DecryptAudienceKeyRecord derives the node's role-path private key, unwraps the
// audienceKey record's protocolPath entry, and decrypts it into an
// AudienceKeyPayload.
func DecryptAudienceKeyRecord(nodeEncRootKey []byte, protocol, role string, enc *Encryption, ciphertext []byte) (*AudienceKeyPayload, error) {
	rolePriv, err := DeriveRolePathKey(nodeEncRootKey, protocol, role)
	if err != nil {
		return nil, fmt.Errorf("deriving role-path key: %w", err)
	}
	defer clear(rolePriv)

	plaintext, err := DecryptData(ciphertext, enc, rolePriv)
	if err != nil {
		return nil, fmt.Errorf("decrypting audienceKey record: %w", err)
	}

	var payload AudienceKeyPayload
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		return nil, fmt.Errorf("parsing AudienceKeyPayload: %w", err)
	}
	if payload.KeyMaterial.PrivateKeyJwk.D == "" {
		return nil, fmt.Errorf("AudienceKeyPayload missing keyMaterial.privateKeyJwk.d")
	}
	return &payload, nil
}

// DecryptRoleAudienceRecord recovers the plaintext of a role-readable mesh
// record. It:
//  1. Reads the roleAudience keyEncryption entry from the mesh record.
//  2. Derives the node's role-path key and decrypts the audienceKey record to
//     obtain the audience private key.
//  3. Unwraps the mesh record's roleAudience entry with the audience private
//     key and AES-256-CTR decrypts the mesh ciphertext.
func DecryptRoleAudienceRecord(params RoleAudienceParams) ([]byte, error) {
	raEntry := FindKeyEncryption(params.MeshEncryption, DerivationSchemeRoleAudience)
	if raEntry == nil {
		return nil, fmt.Errorf("mesh record has no roleAudience keyEncryption entry")
	}

	payload, err := DecryptAudienceKeyRecord(
		params.NodeEncRootKey,
		raEntry.Protocol,
		raEntry.Role,
		params.AudienceKeyEncryption,
		params.AudienceKeyCiphertext,
	)
	if err != nil {
		return nil, err
	}

	audiencePriv, err := base64URLDecode(payload.KeyMaterial.PrivateKeyJwk.D)
	if err != nil {
		return nil, fmt.Errorf("decoding audience private key: %w", err)
	}
	defer clear(audiencePriv)

	cek, err := unwrapEntry(raEntry, audiencePriv)
	if err != nil {
		return nil, fmt.Errorf("unwrapping roleAudience entry: %w", err)
	}
	defer clear(cek)

	return decryptContent(params.MeshEncryption, cek, params.MeshCiphertext)
}

// RoleAudienceInfo describes the role-audience entry on a mesh record, used by
// the daemon to locate the matching audienceKey delivery record.
type RoleAudienceInfo struct {
	Protocol string
	Role     string
	Epoch    int
	KeyID    string
}

// RoleAudienceEntryInfo extracts the role-audience descriptor from a mesh
// record's encryption envelope, or nil when the record is not role-readable.
func RoleAudienceEntryInfo(enc *Encryption) *RoleAudienceInfo {
	entry := FindKeyEncryption(enc, DerivationSchemeRoleAudience)
	if entry == nil {
		return nil
	}
	return &RoleAudienceInfo{
		Protocol: entry.Protocol,
		Role:     entry.Role,
		Epoch:    entry.Epoch,
		KeyID:    entry.KeyID,
	}
}

// RolePathSegments splits a slash-delimited role into its path segments.
func RolePathSegments(role string) []string {
	return strings.Split(role, "/")
}
