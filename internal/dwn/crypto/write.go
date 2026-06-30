package crypto

import (
	"encoding/json"
	"fmt"
	"strings"
)

// AudienceEpochSource resolves the latest published role-audience epoch for a
// (protocol, contextId, role) tuple. Implementations query the owner DWN for
// EncryptionProtocol `audienceEpoch` records and return the public key the
// write path wraps the CEK to.
//
// The returned keyId MUST be the JWK thumbprint of publicKey (the same value
// the SDK stores in the audienceEpoch record and the reader uses to locate the
// matching audienceKey delivery). BuildWriteEncryption verifies this.
type AudienceEpochSource interface {
	// Latest returns the public key, epoch number and keyId of the most recent
	// audienceEpoch for the given (protocol, contextId, role). It returns an
	// error when no epoch exists — the write must fail in that case rather than
	// minting a fresh audience key (matching the SDK's "Missing audienceEpoch").
	Latest(protocol, contextID, role string) (publicKey []byte, epoch int, keyID string, err error)
}

// BuildWriteEncryption produces the keyEncryption inputs for an encrypted
// RecordsWrite at protocolPath, mirroring the @enbox SDK write path:
//
//   - One protocolPath entry wrapping the CEK to the owner's PUBLISHED
//     $keyAgreement public key at protocolPath (read from the installed protocol
//     definition), so the owner — who holds the encryption root — can decrypt.
//   - One roleAudience entry per reading role (a $actions rule whose role is set
//     and whose can list contains the literal "read"), wrapping the SAME CEK to
//     that role's per-epoch audience public key.
//
// protocolDef is the INSTALLED protocol definition (with $keyAgreement public
// keys injected). parentContextID is the record's parent context; it determines
// the audience context for each role. All returned inputs wrap the same CEK via
// EncryptData.
//
// If a reading role has no published audienceEpoch, BuildWriteEncryption fails:
// it never mints an audience key on the write path.
func BuildWriteEncryption(protocolDef json.RawMessage, protocolPath, parentContextID string, epochs AudienceEpochSource) ([]KeyEncryptionInput, error) {
	if protocolPath == "" {
		return nil, fmt.Errorf("protocolPath is required")
	}

	var defMap map[string]any
	if err := json.Unmarshal(protocolDef, &defMap); err != nil {
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

	ruleSet, err := ruleSetAtPath(structure, protocolPath)
	if err != nil {
		return nil, err
	}

	// 1. protocolPath entry → the owner's published $keyAgreement key.
	ownerPub, err := keyAgreementPublicKey(ruleSet)
	if err != nil {
		return nil, fmt.Errorf("protocol path %q: %w", protocolPath, err)
	}
	inputs := []KeyEncryptionInput{{
		PublicKey:        ownerPub,
		DerivationScheme: DerivationSchemeProtocolPath,
	}}

	// 2. roleAudience entries → each reading role's audience key.
	for _, role := range readingRoles(ruleSet) {
		contextID, err := roleAudienceContextID(role, parentContextID)
		if err != nil {
			return nil, err
		}

		pub, epoch, keyID, err := epochs.Latest(protocolURI, contextID, role)
		if err != nil {
			return nil, fmt.Errorf("resolving audienceEpoch for role %q (context %q): %w", role, contextID, err)
		}
		if len(pub) != X25519KeySize {
			return nil, fmt.Errorf("audienceEpoch public key for role %q must be %d bytes, got %d", role, X25519KeySize, len(pub))
		}
		// The advertised keyId must be the thumbprint of the audience key;
		// readers locate the audienceKey delivery by this value and recompute
		// the KEK info from it.
		if got := thumbprintForPublicKey(pub); got != keyID {
			return nil, fmt.Errorf("audienceEpoch keyId %q for role %q does not match public key thumbprint %q", keyID, role, got)
		}

		inputs = append(inputs, KeyEncryptionInput{
			PublicKey:        pub,
			DerivationScheme: DerivationSchemeRoleAudience,
			Protocol:         protocolURI,
			Role:             role,
			Epoch:            epoch,
		})
	}

	return inputs, nil
}

// ruleSetAtPath walks a protocol definition's structure tree and returns the
// rule set object at the given slash-delimited protocol path.
func ruleSetAtPath(structure map[string]any, protocolPath string) (map[string]any, error) {
	current := structure
	for _, seg := range splitProtocolPath(protocolPath) {
		next, ok := current[seg].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("protocol path %q has no rule set at segment %q", protocolPath, seg)
		}
		current = next
	}
	return current, nil
}

// keyAgreementPublicKey extracts and decodes the raw X25519 public key from a
// rule set's injected $keyAgreement.publicKeyJwk.x member.
func keyAgreementPublicKey(ruleSet map[string]any) ([]byte, error) {
	ka, ok := ruleSet["$keyAgreement"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("rule set has no $keyAgreement directive")
	}
	jwk, ok := ka["publicKeyJwk"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("$keyAgreement has no publicKeyJwk")
	}
	x, ok := jwk["x"].(string)
	if !ok || x == "" {
		return nil, fmt.Errorf("$keyAgreement publicKeyJwk has no x member")
	}
	pub, err := base64URLDecode(x)
	if err != nil {
		return nil, fmt.Errorf("decoding $keyAgreement publicKeyJwk.x: %w", err)
	}
	if len(pub) != X25519KeySize {
		return nil, fmt.Errorf("$keyAgreement publicKeyJwk.x must be %d bytes, got %d", X25519KeySize, len(pub))
	}
	return pub, nil
}

// readingRoles returns the role paths of a rule set's $actions whose can list
// contains the literal "read". Cross-protocol alias references (alias:path) are
// skipped — they are out of scope for meshd's single-protocol case. The literal
// "read" is required, so co-update / co-delete / co-prune roles are excluded.
func readingRoles(ruleSet map[string]any) []string {
	actions, ok := ruleSet["$actions"].([]any)
	if !ok {
		return nil
	}

	var roles []string
	for _, a := range actions {
		action, ok := a.(map[string]any)
		if !ok {
			continue
		}
		role, _ := action["role"].(string)
		if role == "" || strings.Contains(role, ":") {
			continue
		}
		if !actionCanRead(action["can"]) {
			continue
		}
		roles = append(roles, role)
	}
	return roles
}

// actionCanRead reports whether a $actions rule's can list contains the literal
// "read" action.
func actionCanRead(canRaw any) bool {
	can, ok := canRaw.([]any)
	if !ok {
		return false
	}
	for _, c := range can {
		if s, ok := c.(string); ok && s == "read" {
			return true
		}
	}
	return false
}

// roleAudienceContextID computes the role-audience context for a role given the
// record's parent context. The depth is the number of role path segments minus
// one; a depth-0 role (e.g. a top-level role) has an empty context. Otherwise
// the context is the first `depth` segments of the parent context.
func roleAudienceContextID(role, parentContextID string) (string, error) {
	depth := len(strings.Split(role, "/")) - 1
	if depth <= 0 {
		return "", nil
	}
	if parentContextID == "" {
		return "", fmt.Errorf("role %q requires %d context segment(s) but parentContextId is empty", role, depth)
	}
	segments := strings.Split(parentContextID, "/")
	if len(segments) < depth {
		return "", fmt.Errorf("parentContextId %q has %d segment(s), need %d for role %q", parentContextID, len(segments), depth, role)
	}
	return strings.Join(segments[:depth], "/"), nil
}
