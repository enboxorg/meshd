package crypto

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// InjectEncryptionDirectives walks a protocol definition's "structure" and
// injects derived X25519 public keys into each `$keyAgreement` block.
//
// This must be called before ProtocolsConfigure. For each protocol path
// level that has (or should have) a `$keyAgreement` directive (the
// encryption-v1 rule-set directive, renamed from `$encryption`), it:
//  1. Derives the X25519 private key for that path level via HKDF-SHA256
//  2. Computes the corresponding X25519 public key
//  3. Populates the `$keyAgreement` block with rootKeyId and publicKeyJwk
//
// The rootPrivateKey is the DWN owner's root X25519 private key (32 bytes),
// identified by rootKeyID (e.g., "did:dht:abc...#enc").
//
// The protocol definition is modified in-place. Returns the modified definition.
func InjectEncryptionDirectives(definition json.RawMessage, rootPrivateKey []byte, rootKeyID string) (json.RawMessage, error) {
	var defMap map[string]any
	if err := json.Unmarshal(definition, &defMap); err != nil {
		return nil, fmt.Errorf("parsing protocol definition: %w", err)
	}

	protocolURI, ok := defMap["protocol"].(string)
	if !ok || protocolURI == "" {
		return nil, fmt.Errorf("protocol definition missing 'protocol' URI")
	}

	structure, ok := defMap["structure"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("protocol definition missing 'structure'")
	}

	// Derive the protocol-level key: HKDF("protocolPath") -> HKDF(protocolURI)
	protocolLevelKey, err := DeriveKeyBytes(rootPrivateKey, []string{
		DerivationSchemeProtocolPath,
		protocolURI,
	})
	if err != nil {
		return nil, fmt.Errorf("deriving protocol-level key: %w", err)
	}
	defer clear(protocolLevelKey) // Zero intermediate derivation key.

	// Recursively walk the structure and inject $keyAgreement at each level.
	if err := injectEncryptionRecursive(structure, protocolLevelKey, rootKeyID); err != nil {
		return nil, err
	}

	result, err := json.Marshal(defMap)
	if err != nil {
		return nil, fmt.Errorf("marshaling updated definition: %w", err)
	}

	return result, nil
}

// injectEncryptionRecursive walks the protocol structure tree and injects
// $keyAgreement directives at each non-$-prefixed child.
func injectEncryptionRecursive(ruleSet map[string]any, parentKey []byte, rootKeyID string) error {
	for key, value := range ruleSet {
		// Skip special $ directives — they are not type names.
		if len(key) > 0 && key[0] == '$' {
			continue
		}

		childRuleSet, ok := value.(map[string]any)
		if !ok {
			continue
		}

		// Derive the child key: HKDF(parentKey, childTypeName)
		childPrivateKey, childPublicKey, err := DerivePrivateKey(parentKey, []string{key})
		if err != nil {
			return fmt.Errorf("deriving key for path segment %q: %w", key, err)
		}

		// Build the publicKeyJwk for this level.
		publicKeyJwk := map[string]any{
			"kty": "OKP",
			"crv": "X25519",
			"x":   base64.RawURLEncoding.EncodeToString(childPublicKey),
		}

		// Inject or update the $keyAgreement directive (encryption-v1).
		childRuleSet["$keyAgreement"] = map[string]any{
			"rootKeyId":    rootKeyID,
			"publicKeyJwk": publicKeyJwk,
		}

		// Recurse into children, then zero the child private key.
		err = injectEncryptionRecursive(childRuleSet, childPrivateKey, rootKeyID)
		clear(childPrivateKey) // Zero intermediate derivation key.
		if err != nil {
			return err
		}
	}

	return nil
}

// EncryptionKeyManager holds an identity's root X25519 encryption key and
// derives the protocol-path keys used to encrypt and decrypt records.
//
// It is the Go counterpart of the TypeScript SDK's EncryptionKeyDeriver, but a
// concrete type that holds the private key material.
type EncryptionKeyManager struct {
	// RootPrivateKey is the identity's root X25519 private key (32 bytes).
	// For the network owner this is the anchor #enc key; for a node it is the
	// node identity's #enc key (used for role-audience decryption).
	RootPrivateKey []byte

	// RootKeyID is the fully qualified key ID (e.g., "did:dht:abc...#enc").
	RootKeyID string

	// ProtocolURI is the protocol URI for protocolPath derivation.
	ProtocolURI string
}

// Close zeros the key material held by the manager. Call this during graceful
// shutdown to minimize the window where keys remain in memory.
func (m *EncryptionKeyManager) Close() {
	clear(m.RootPrivateKey)
}

// IsOwner returns true if this key manager holds a root private key
// (i.e., this node can derive protocol-path keys).
func (m *EncryptionKeyManager) IsOwner() bool {
	return len(m.RootPrivateKey) > 0
}

// DeriveWriteEncryption derives the encryption inputs for a RecordsWrite at the
// given protocol path using the protocolPath scheme.
//
// The protocolPath is slash-delimited (e.g., "network/node"). The returned
// KeyEncryptionInput targets the derived PUBLIC key; the DWN owner re-derives
// the matching PRIVATE key to decrypt.
func (m *EncryptionKeyManager) DeriveWriteEncryption(protocolPath string) ([]KeyEncryptionInput, error) {
	segments := splitProtocolPath(protocolPath)
	fullPath := BuildProtocolPathDerivation(m.ProtocolURI, segments...)

	_, derivedPublicKey, err := DerivePrivateKey(m.RootPrivateKey, fullPath)
	if err != nil {
		return nil, fmt.Errorf("deriving encryption key for path %q: %w", protocolPath, err)
	}

	return []KeyEncryptionInput{
		{
			PublicKey:        derivedPublicKey,
			DerivationScheme: DerivationSchemeProtocolPath,
		},
	}, nil
}

// DeriveDecryptionKey derives the X25519 private key for decrypting a record at
// the given protocol path using the protocolPath scheme. This private key can
// be passed to DecryptData() to decrypt the record's ciphertext.
func (m *EncryptionKeyManager) DeriveDecryptionKey(protocolPath string) (privateKey []byte, err error) {
	segments := splitProtocolPath(protocolPath)
	fullPath := BuildProtocolPathDerivation(m.ProtocolURI, segments...)

	derivedPriv, _, err := DerivePrivateKey(m.RootPrivateKey, fullPath)
	if err != nil {
		return nil, fmt.Errorf("deriving decryption key for path %q: %w", protocolPath, err)
	}

	return derivedPriv, nil
}

// splitProtocolPath splits a slash-delimited protocol path into segments.
// e.g., "network/node" -> ["network", "node"]
func splitProtocolPath(path string) []string {
	if path == "" {
		return nil
	}

	var segments []string
	start := 0
	for i := 0; i <= len(path); i++ {
		if i == len(path) || path[i] == '/' {
			if i > start {
				segments = append(segments, path[start:i])
			}
			start = i + 1
		}
	}
	return segments
}
