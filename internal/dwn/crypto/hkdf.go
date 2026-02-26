package crypto

import (
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// Key derivation scheme identifiers used by the DWN encryption model.
const (
	// DerivationSchemeProtocolPath derives keys hierarchically through the
	// protocol's type structure. A parent key can decrypt all descendants.
	// Path: ["protocolPath", "<protocol-uri>", "<root-type>", "<child-type>", ...]
	DerivationSchemeProtocolPath = "protocolPath"

	// DerivationSchemeProtocolContext derives keys per-conversation/thread.
	// Path: ["protocolContext", "<root-context-id>"]
	DerivationSchemeProtocolContext = "protocolContext"
)

// DeriveKeyBytes derives a descendant key from an ancestor private key by
// iterating through each segment of the derivation path using HKDF-SHA256.
//
// This implements the hierarchical deterministic key derivation used by
// the DWN encryption model. Each path segment is used as the "info"
// parameter in HKDF (RFC 5869), with an empty salt.
//
// The derivation path segments are typically:
//   - protocolPath: ["protocolPath", "<protocol-uri>", "<type1>", "<type2>", ...]
//   - protocolContext: ["protocolContext", "<context-id>"]
//
// Each step: nextKey = HKDF-SHA256(salt=empty, ikm=currentKey, info=UTF8(segment), L=32)
func DeriveKeyBytes(ancestorKey []byte, derivationPath []string) ([]byte, error) {
	if err := validateDerivationPath(derivationPath); err != nil {
		return nil, err
	}

	currentKey := make([]byte, len(ancestorKey))
	copy(currentKey, ancestorKey)

	for _, segment := range derivationPath {
		derived, err := hkdfDerive(currentKey, []byte(segment))
		if err != nil {
			return nil, fmt.Errorf("deriving key for segment %q: %w", segment, err)
		}
		currentKey = derived
	}

	return currentKey, nil
}

// DerivePrivateKey derives a descendant X25519 private key and returns both
// the derived private key and its corresponding public key.
func DerivePrivateKey(ancestorPrivateKey []byte, derivationPath []string) (privateKey, publicKey []byte, err error) {
	derivedPriv, err := DeriveKeyBytes(ancestorPrivateKey, derivationPath)
	if err != nil {
		return nil, nil, err
	}

	derivedPub, err := X25519PublicKey(derivedPriv)
	if err != nil {
		return nil, nil, fmt.Errorf("computing derived public key: %w", err)
	}

	return derivedPriv, derivedPub, nil
}

// BuildProtocolPathDerivation builds the derivation path for the
// "protocolPath" scheme given a protocol URI and type path segments.
//
// Example: BuildProtocolPathDerivation("https://example.com/proto", "network", "node")
// returns ["protocolPath", "https://example.com/proto", "network", "node"]
func BuildProtocolPathDerivation(protocolURI string, typeSegments ...string) []string {
	path := make([]string, 0, 2+len(typeSegments))
	path = append(path, DerivationSchemeProtocolPath)
	path = append(path, protocolURI)
	path = append(path, typeSegments...)
	return path
}

// BuildProtocolContextDerivation builds the derivation path for the
// "protocolContext" scheme given a root context ID.
//
// Example: BuildProtocolContextDerivation("bafyreiabc123")
// returns ["protocolContext", "bafyreiabc123"]
func BuildProtocolContextDerivation(contextID string) []string {
	return []string{DerivationSchemeProtocolContext, contextID}
}

// hkdfDerive performs a single HKDF-SHA256 derivation step.
// salt is empty, info is the path segment, output length is 32 bytes.
func hkdfDerive(inputKey, info []byte) ([]byte, error) {
	// HKDF with empty salt and the segment as info.
	r := hkdf.New(sha256.New, inputKey, nil, info)

	derived := make([]byte, 32)
	if _, err := io.ReadFull(r, derived); err != nil {
		return nil, fmt.Errorf("HKDF derivation: %w", err)
	}

	return derived, nil
}

// validateDerivationPath checks that no empty strings exist in the path.
func validateDerivationPath(path []string) error {
	for i, segment := range path {
		if segment == "" {
			return fmt.Errorf("invalid key derivation path: empty segment at index %d", i)
		}
	}
	return nil
}
