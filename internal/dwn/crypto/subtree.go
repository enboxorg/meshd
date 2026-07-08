package crypto

import "fmt"

// SubtreeDecrypter decrypts protocolPath-encrypted records using an
// owner-derived subtree private key delivered via a grantKey record. The
// delivered keyMaterial carries the absolute derivationPath prefix (e.g.
// ["protocolPath", <protocol>] for a whole-protocol key); leaf keys are
// derived by walking the remaining segments of a record's full derivation
// path.
type SubtreeDecrypter struct {
	privateKey     []byte
	derivationPath []string
	keyID          string
}

// NewSubtreeDecrypter builds a decrypter from delivered grantKey key
// material, verifying its internal consistency first.
func NewSubtreeDecrypter(km *ProtocolPathKeyMaterial) (*SubtreeDecrypter, error) {
	if km == nil {
		return nil, fmt.Errorf("missing key material")
	}
	if km.Algorithm != AlgX25519HKDFA256KW {
		return nil, fmt.Errorf("subtree key material algorithm must be %q, got %q", AlgX25519HKDFA256KW, km.Algorithm)
	}
	if km.DerivationScheme != DerivationSchemeProtocolPath {
		return nil, fmt.Errorf("subtree key material derivationScheme must be %q, got %q", DerivationSchemeProtocolPath, km.DerivationScheme)
	}
	if len(km.DerivationPath) < 2 || km.DerivationPath[0] != DerivationSchemeProtocolPath {
		return nil, fmt.Errorf("subtree key material derivationPath must start with [%q, <protocol>]", DerivationSchemeProtocolPath)
	}
	if err := verifyX25519KeyMaterial(km.KeyID, &km.PublicKeyJwk, &km.PrivateKeyJwk); err != nil {
		return nil, err
	}

	priv, err := base64URLDecode(km.PrivateKeyJwk.D)
	if err != nil {
		return nil, fmt.Errorf("decoding subtree private key: %w", err)
	}

	path := make([]string, len(km.DerivationPath))
	copy(path, km.DerivationPath)

	return &SubtreeDecrypter{
		privateKey:     priv,
		derivationPath: path,
		keyID:          km.KeyID,
	}, nil
}

// NewSubtreeDecrypterFromGrantKey builds a decrypter from a delivered
// GrantKeyPayload.
func NewSubtreeDecrypterFromGrantKey(payload *GrantKeyPayload) (*SubtreeDecrypter, error) {
	if payload == nil {
		return nil, fmt.Errorf("missing grantKey payload")
	}
	return NewSubtreeDecrypter(&payload.KeyMaterial)
}

// KeyID returns the JWK thumbprint of the delivered subtree public key.
func (d *SubtreeDecrypter) KeyID() string {
	return d.keyID
}

// DerivationPath returns the absolute derivation path of the delivered key.
func (d *SubtreeDecrypter) DerivationPath() []string {
	path := make([]string, len(d.derivationPath))
	copy(path, d.derivationPath)
	return path
}

// Close zeros the subtree private key held by the decrypter.
func (d *SubtreeDecrypter) Close() {
	clear(d.privateKey)
}

// Covers reports whether the delivered key covers records at (protocol,
// protocolPath).
func (d *SubtreeDecrypter) Covers(protocol, protocolPath string) bool {
	full := BuildProtocolPathDerivation(protocol, splitProtocolPath(protocolPath)...)
	return d.remainingSegments(full) != nil
}

// DeriveLeafKey derives the X25519 private key for a record at (protocol,
// protocolPath) by walking the remaining segments of the record's full
// derivation path ["protocolPath", <protocol>, ...segments] relative to the
// delivered derivationPath prefix.
func (d *SubtreeDecrypter) DeriveLeafKey(protocol, protocolPath string) ([]byte, error) {
	full := BuildProtocolPathDerivation(protocol, splitProtocolPath(protocolPath)...)
	remaining := d.remainingSegments(full)
	if remaining == nil {
		return nil, fmt.Errorf("delivered subtree key at %v does not cover derivation path %v", d.derivationPath, full)
	}
	if len(remaining) == 0 {
		leaf := make([]byte, len(d.privateKey))
		copy(leaf, d.privateKey)
		return leaf, nil
	}
	return DeriveKeyBytes(d.privateKey, remaining)
}

// RolePathKey derives the role-path $keyAgreement private key for (protocol,
// rolePath), used to open audience seals when the delivered subtree covers
// the role path. It is an alias of DeriveLeafKey with role-path semantics.
func (d *SubtreeDecrypter) RolePathKey(protocol, rolePath string) ([]byte, error) {
	return d.DeriveLeafKey(protocol, rolePath)
}

// Decrypt derives the leaf key for the record's (protocol, protocolPath),
// unwraps the record's protocolPath keyEncryption entry and AES-256-CTR
// decrypts the ciphertext.
func (d *SubtreeDecrypter) Decrypt(ciphertext []byte, enc *Encryption, protocol, protocolPath string) ([]byte, error) {
	leaf, err := d.DeriveLeafKey(protocol, protocolPath)
	if err != nil {
		return nil, err
	}
	defer clear(leaf)
	return DecryptData(ciphertext, enc, leaf)
}

// remainingSegments returns the segments of full below the delivered prefix,
// or nil when the delivered path is not a prefix of full. An empty (non-nil)
// slice means the delivered key IS the leaf key.
func (d *SubtreeDecrypter) remainingSegments(full []string) []string {
	if len(full) < len(d.derivationPath) {
		return nil
	}
	for i := range d.derivationPath {
		if full[i] != d.derivationPath[i] {
			return nil
		}
	}
	remaining := full[len(d.derivationPath):]
	if remaining == nil {
		remaining = []string{}
	}
	return remaining
}
