package crypto

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// AudienceSource resolves the CURRENT audience public key for a role-audience
// tuple (protocol, rolePath, contextId). Implementations query the source DWN
// for `$encryption/audience` records — and mint one when the tuple has none —
// then return the audience public key the write path wraps the CEK to.
//
// The returned keyID MUST be the JWK thumbprint of publicKey (the same value
// stored in the audience record's keyId tag, which the server checks the
// roleAudience entry against). BuildWriteEncryption verifies this.
type AudienceSource interface {
	Current(ctx context.Context, protocol, rolePath, contextID string) (publicKey []byte, keyID string, err error)
}

// BuildWriteEncryption produces the keyEncryption inputs for an encrypted
// RecordsWrite at protocolPath, mirroring the @enbox SDK write path:
//
//   - One protocolPath entry wrapping the CEK to the rule set's PUBLISHED
//     $keyAgreement public key (read from the installed protocol definition),
//     so the owner — who holds the encryption root — can decrypt. The server
//     requires this entry's keyId to be the thumbprint of that key.
//   - One roleAudience entry per reading role (a $actions rule whose role is
//     set and whose can list contains the literal "read"), wrapping the SAME
//     CEK to that role's current audience public key. Cross-protocol alias
//     roles (alias:path) are skipped.
//
// protocolDef is the INSTALLED protocol definition (with $keyAgreement public
// keys injected). parentContextID is the parent context of the record being
// written; it determines the audience tuple contextId for each role: a
// root-level role maps to "" and a nested role maps to the first
// depth(rolePath)-1 segments. All returned inputs wrap the same CEK via
// EncryptData.
//
// The server rejects encrypted writes referencing audience tuples without an
// existing `$encryption/audience` record, so AudienceSource implementations
// must mint-and-write missing audience records BEFORE returning.
func BuildWriteEncryption(ctx context.Context, protocolDef json.RawMessage, protocolPath, parentContextID string, audiences AudienceSource) ([]KeyEncryptionInput, error) {
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

	// 1. protocolPath entry → the rule set's published $keyAgreement key.
	ownerPub, err := keyAgreementPublicKey(ruleSet)
	if err != nil {
		return nil, fmt.Errorf("protocol path %q: %w", protocolPath, err)
	}
	inputs := []KeyEncryptionInput{{
		PublicKey:        ownerPub,
		DerivationScheme: DerivationSchemeProtocolPath,
	}}

	// 2. roleAudience entries → each reading role's current audience key.
	for _, rolePath := range readingRoles(ruleSet) {
		contextID, err := RoleAudienceContextID(rolePath, parentContextID)
		if err != nil {
			return nil, err
		}

		pub, keyID, err := audiences.Current(ctx, protocolURI, rolePath, contextID)
		if err != nil {
			return nil, fmt.Errorf("resolving audience for role %q (context %q): %w", rolePath, contextID, err)
		}
		if len(pub) != X25519KeySize {
			return nil, fmt.Errorf("audience public key for role %q must be %d bytes, got %d", rolePath, X25519KeySize, len(pub))
		}
		// The advertised keyId must be the thumbprint of the audience key;
		// the server verifies the roleAudience entry against the audience
		// record tagged with this value.
		if got := thumbprintForPublicKey(pub); got != keyID {
			return nil, fmt.Errorf("audience keyId %q for role %q does not match public key thumbprint %q", keyID, rolePath, got)
		}

		inputs = append(inputs, KeyEncryptionInput{
			PublicKey:        pub,
			DerivationScheme: DerivationSchemeRoleAudience,
			Protocol:         protocolURI,
			RolePath:         rolePath,
		})
	}

	return inputs, nil
}

// KeyAgreementPublicKeyAtPath parses an INSTALLED protocol definition (with
// $keyAgreement public keys injected), walks its structure to the rule set at
// the slash-delimited protocolPath, and returns the rule set's $keyAgreement
// public key (raw 32 bytes) plus its RFC 7638 JWK thumbprint keyId.
//
// The control plane uses this when minting audience records: the audience
// private key is sealed to this role-path public key, and the seal's keyId
// must be this thumbprint.
func KeyAgreementPublicKeyAtPath(protocolDef json.RawMessage, protocolPath string) (publicKey []byte, keyID string, err error) {
	if protocolPath == "" {
		return nil, "", fmt.Errorf("protocolPath is required")
	}

	var defMap map[string]any
	if err := json.Unmarshal(protocolDef, &defMap); err != nil {
		return nil, "", fmt.Errorf("parsing protocol definition: %w", err)
	}
	structure, ok := defMap["structure"].(map[string]any)
	if !ok {
		return nil, "", fmt.Errorf("protocol definition missing 'structure'")
	}

	ruleSet, err := ruleSetAtPath(structure, protocolPath)
	if err != nil {
		return nil, "", err
	}
	pub, err := keyAgreementPublicKey(ruleSet)
	if err != nil {
		return nil, "", fmt.Errorf("protocol path %q: %w", protocolPath, err)
	}
	return pub, thumbprintForPublicKey(pub), nil
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
// contains the literal "read". Cross-protocol alias references (alias:path)
// are skipped — their audiences live under the referenced protocol, which is
// out of scope for meshd's single-protocol case. The literal "read" is
// required, so co-update / co-delete / co-prune roles are excluded.
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

// actionCanRead reports whether a $actions rule's can list contains the
// literal "read" action.
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
