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
type EncryptionKeyManager struct {
	// RootPrivateKey is the DWN owner's root X25519 private key (32 bytes).
	RootPrivateKey []byte

	// RootKeyID is the fully qualified key ID (e.g., "did:dht:abc...#enc").
	RootKeyID string

	// ProtocolURI is the protocol URI for protocolPath derivation.
	ProtocolURI string
}

// DeriveWriteEncryption derives the encryption inputs needed for a RecordsWrite
// at the given protocol path.
//
// The protocolPath is slash-delimited (e.g., "network/member"). This method:
//  1. Builds the full derivation path: ["protocolPath", protocolURI, "network", "member"]
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

// DeriveDecryptionKey derives the X25519 private key for decrypting a record
// at the given protocol path. This private key can be used with
// crypto.DecryptData() to decrypt the record's ciphertext.
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
// e.g., "network/member" -> ["network", "member"]
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
