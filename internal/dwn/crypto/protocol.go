package crypto

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// InjectEncryptionDirectives walks a protocol definition's "structure" and
// injects derived X25519 public keys into each `$keyAgreement` block, plus a
// top-level `$keyAgreement` holding the protocol-level key.
//
// This must be called before ProtocolsConfigure. It is the Go counterpart of
// the SDK's Protocols.deriveAndInjectPublicEncryptionKeys: for each protocol
// path level it (1) derives the X25519 private key for that path via
// HKDF-SHA256, (2) computes the corresponding public key and (3) sets
// `$keyAgreement` to exactly `{"publicKeyJwk": {...}}` — the server rejects
// additional members. `$ref` nodes (cross-protocol attachment points) are
// skipped but their children are still processed.
//
// The rootPrivateKey is the DWN owner's root X25519 private key (32 bytes).
//
// The protocol definition is modified in-place. Returns the modified
// definition.
func InjectEncryptionDirectives(definition json.RawMessage, rootPrivateKey []byte) (json.RawMessage, error) {
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

	// Top-level $keyAgreement carries the protocol-level public key.
	protocolLevelPub, err := X25519PublicKey(protocolLevelKey)
	if err != nil {
		return nil, fmt.Errorf("computing protocol-level public key: %w", err)
	}
	defMap["$keyAgreement"] = keyAgreementDirective(protocolLevelPub)

	// Recursively walk the structure and inject $keyAgreement at each level.
	if err := injectEncryptionRecursive(structure, protocolLevelKey); err != nil {
		return nil, err
	}

	result, err := json.Marshal(defMap)
	if err != nil {
		return nil, fmt.Errorf("marshaling updated definition: %w", err)
	}

	return result, nil
}

// keyAgreementDirective builds the `$keyAgreement` block for a derived public
// key. The wire shape is exactly {"publicKeyJwk": {...}} (server-side
// additionalProperties:false).
func keyAgreementDirective(publicKey []byte) map[string]any {
	return map[string]any{
		"publicKeyJwk": map[string]any{
			"kty": "OKP",
			"crv": "X25519",
			"x":   base64.RawURLEncoding.EncodeToString(publicKey),
		},
	}
}

// injectEncryptionRecursive walks the protocol structure tree and injects
// $keyAgreement directives at each non-$-prefixed child. Rule sets with a
// $ref member are attachment points governed by the referenced protocol's
// keys; they get no $keyAgreement of their own, but their children (which
// belong to the composing protocol) are still processed.
func injectEncryptionRecursive(ruleSet map[string]any, parentKey []byte) error {
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

		if _, isRef := childRuleSet["$ref"]; !isRef {
			childRuleSet["$keyAgreement"] = keyAgreementDirective(childPublicKey)
		}

		// Recurse into children, then zero the child private key.
		err = injectEncryptionRecursive(childRuleSet, childPrivateKey)
		clear(childPrivateKey) // Zero intermediate derivation key.
		if err != nil {
			return err
		}
	}

	return nil
}

// EncryptionKeyManager holds an identity's root X25519 encryption key and
// derives the protocol-path keys used to decrypt records (and to open
// audience seals via DeriveRolePathKey).
//
// It is the Go counterpart of the TypeScript SDK's EncryptionKeyDeriver, but a
// concrete type that holds the private key material.
type EncryptionKeyManager struct {
	// RootPrivateKey is the identity's root X25519 private key (32 bytes).
	// For the network owner this is the anchor #enc key; for a node it is the
	// node identity's #enc key (used to decrypt `$encryption/delivery`
	// records addressed to it).
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
