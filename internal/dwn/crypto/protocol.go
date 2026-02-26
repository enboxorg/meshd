package crypto

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// InjectEncryptionDirectives walks a protocol definition's "structure" and
// injects derived X25519 public keys into each `$encryption` block.
//
// This must be called before ProtocolsConfigure. For each protocol path
// level that has (or should have) an `$encryption` directive, it:
//  1. Derives the X25519 private key for that path level via HKDF-SHA256
//  2. Computes the corresponding X25519 public key
//  3. Populates the `$encryption` block with rootKeyId and publicKeyJwk
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

	// Recursively walk the structure and inject $encryption at each level.
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
// $encryption directives at each non-$-prefixed child.
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

		// Inject or update the $encryption directive.
		childRuleSet["$encryption"] = map[string]any{
			"rootKeyId":    rootKeyID,
			"publicKeyJwk": publicKeyJwk,
		}

		// Recurse into children.
		if err := injectEncryptionRecursive(childRuleSet, childPrivateKey, rootKeyID); err != nil {
			return err
		}
	}

	return nil
}

// EncryptionKeyManager manages the root encryption key and provides
// derived keys for encrypting records at specific protocol paths.
//
// This is the Go equivalent of the TypeScript SDK's EncryptionKeyDeriver
// interface, but as a concrete type that holds the private key material.
//
// It supports both Protocol Path and Protocol Context derivation schemes:
//   - Protocol Path: owner can derive all keys from root; used for single-party
//   - Protocol Context: per-conversation key; non-owners receive via key delivery
type EncryptionKeyManager struct {
	// RootPrivateKey is the DWN owner's root X25519 private key (32 bytes).
	RootPrivateKey []byte

	// RootKeyID is the fully qualified key ID (e.g., "did:dht:abc...#enc").
	RootKeyID string

	// ProtocolURI is the protocol URI for protocolPath derivation.
	ProtocolURI string

	// contextKeys caches delivered context keys (contextID → private key bytes).
	// These are keys received via the Key Delivery Protocol from the DWN owner.
	contextKeys map[string][]byte
}

// StoreContextKey stores a delivered context key for a given context ID.
// This is called after receiving and decrypting a contextKey record from
// the DWN owner (key delivery).
func (m *EncryptionKeyManager) StoreContextKey(contextID string, privateKey []byte) {
	if m.contextKeys == nil {
		m.contextKeys = make(map[string][]byte)
	}
	keyCopy := make([]byte, len(privateKey))
	copy(keyCopy, privateKey)
	m.contextKeys[contextID] = keyCopy
}

// GetContextKey retrieves a stored context key for a given context ID.
// Returns nil if no key is stored for that context.
func (m *EncryptionKeyManager) GetContextKey(contextID string) []byte {
	if m.contextKeys == nil {
		return nil
	}
	return m.contextKeys[contextID]
}

// HasContextKey returns true if a context key is stored for the given context ID.
func (m *EncryptionKeyManager) HasContextKey(contextID string) bool {
	if m.contextKeys == nil {
		return false
	}
	_, ok := m.contextKeys[contextID]
	return ok
}

// IsOwner returns true if this key manager holds the root private key
// (i.e., this node is the DWN owner / network anchor).
func (m *EncryptionKeyManager) IsOwner() bool {
	return len(m.RootPrivateKey) > 0
}

// DeriveWriteEncryption derives the encryption inputs needed for a RecordsWrite
// at the given protocol path.
//
// The protocolPath is slash-delimited (e.g., "network/node"). This method:
//  1. Builds the full derivation path: ["protocolPath", protocolURI, "network", "node"]
//  2. Derives the private key and public key at that path level
//  3. Returns a KeyEncryptionInput suitable for passing to BuildRecordsWrite
//
// The returned KeyEncryptionInput uses the derived PUBLIC key as the
// encryption target. When the DWN owner reads the record later, they
// re-derive the corresponding PRIVATE key to decrypt.
func (m *EncryptionKeyManager) DeriveWriteEncryption(protocolPath string) ([]KeyEncryptionInput, error) {
	segments := splitProtocolPath(protocolPath)

	// Build full derivation path.
	fullPath := BuildProtocolPathDerivation(m.ProtocolURI, segments...)

	// Derive the private and public key at this path level.
	_, derivedPublicKey, err := DerivePrivateKey(m.RootPrivateKey, fullPath)
	if err != nil {
		return nil, fmt.Errorf("deriving encryption key for path %q: %w", protocolPath, err)
	}

	return []KeyEncryptionInput{
		{
			PublicKeyID:      m.RootKeyID,
			PublicKey:        derivedPublicKey,
			DerivationScheme: DerivationSchemeProtocolPath,
		},
	}, nil
}

// DeriveContextWriteEncryption derives the encryption inputs for writing
// a record encrypted with the Protocol Context scheme.
//
// The contextID is the root record ID of the protocol context (conversation).
// This derives the context key and uses its public key for encryption.
//
// For DWN owners: derives from root key via HKDF.
// For non-owners: uses a previously stored context key (received via key delivery).
func (m *EncryptionKeyManager) DeriveContextWriteEncryption(contextID string) ([]KeyEncryptionInput, error) {
	contextPrivKey, err := m.resolveContextPrivateKey(contextID)
	if err != nil {
		return nil, err
	}

	contextPubKey, err := X25519PublicKey(contextPrivKey)
	if err != nil {
		return nil, fmt.Errorf("computing context public key: %w", err)
	}

	return []KeyEncryptionInput{
		{
			PublicKeyID:      m.RootKeyID,
			PublicKey:        contextPubKey,
			DerivationScheme: DerivationSchemeProtocolContext,
		},
	}, nil
}

// DeriveDecryptionKey derives the X25519 private key for decrypting a record
// at the given protocol path using the Protocol Path scheme. This private
// key can be used with crypto.DecryptData() to decrypt the record's ciphertext.
func (m *EncryptionKeyManager) DeriveDecryptionKey(protocolPath string) (privateKey []byte, err error) {
	segments := splitProtocolPath(protocolPath)
	fullPath := BuildProtocolPathDerivation(m.ProtocolURI, segments...)

	derivedPriv, _, err := DerivePrivateKey(m.RootPrivateKey, fullPath)
	if err != nil {
		return nil, fmt.Errorf("deriving decryption key for path %q: %w", protocolPath, err)
	}

	return derivedPriv, nil
}

// DeriveContextDecryptionKey derives the X25519 private key for decrypting
// a record encrypted with the Protocol Context scheme.
//
// For DWN owners: derives from root key.
// For non-owners: uses stored context key from key delivery.
func (m *EncryptionKeyManager) DeriveContextDecryptionKey(contextID string) ([]byte, error) {
	return m.resolveContextPrivateKey(contextID)
}

// resolveContextPrivateKey resolves the context private key, preferring
// a stored delivered key, then falling back to HKDF derivation from root.
func (m *EncryptionKeyManager) resolveContextPrivateKey(contextID string) ([]byte, error) {
	// First check if we have a delivered key for this context.
	if key := m.GetContextKey(contextID); key != nil {
		return key, nil
	}

	// Fall back to HKDF derivation from root (only works for DWN owner).
	if !m.IsOwner() {
		return nil, fmt.Errorf("no context key available for context %q and not the DWN owner", contextID)
	}

	return DeriveContextKey(m.RootPrivateKey, contextID)
}

// DeriveContextKeyJwk derives the Protocol Context key for a context and
// wraps it in a DerivedPrivateJwk ready for key delivery.
//
// This is only callable by the DWN owner (requires root private key).
func (m *EncryptionKeyManager) DeriveContextKeyJwk(contextID string) (*DerivedPrivateJwk, error) {
	if !m.IsOwner() {
		return nil, fmt.Errorf("context key derivation requires root private key (DWN owner only)")
	}
	return DeriveContextKeyJwk(m.RootPrivateKey, m.RootKeyID, contextID)
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
