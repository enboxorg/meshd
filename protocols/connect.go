package protocols

import (
	"encoding/json"
	"fmt"
)

// MeshProtocolDefinitionForConnect returns the wireguard-mesh protocol
// definition prepared for an enbox connect permission request.
//
// The embedded definition carries `$keyAgreement` placeholder nodes
// (`{"rootKeyId": "#dwn-enc", "publicKeyJwk": {}}`) that the DWN owner fills
// in at install time. The wallet installs the requested definition itself and
// injects the owner's derived public keys (`encryption: true` configure), so
// the connect request must carry the definition without the placeholders —
// an empty publicKeyJwk would fail the SDK's protocol validation.
func MeshProtocolDefinitionForConnect() (json.RawMessage, error) {
	return StripKeyAgreementPlaceholders(MeshProtocolJSON)
}

// StripKeyAgreementPlaceholders removes every `$keyAgreement` node from a
// protocol definition's structure tree (and the top level, if present) and
// returns the re-marshaled definition.
func StripKeyAgreementPlaceholders(definition json.RawMessage) (json.RawMessage, error) {
	var def map[string]any
	if err := json.Unmarshal(definition, &def); err != nil {
		return nil, fmt.Errorf("parsing protocol definition: %w", err)
	}
	delete(def, "$keyAgreement")
	if structure, ok := def["structure"].(map[string]any); ok {
		stripKeyAgreement(structure)
	}
	stripped, err := json.Marshal(def)
	if err != nil {
		return nil, fmt.Errorf("marshaling protocol definition: %w", err)
	}
	return stripped, nil
}

func stripKeyAgreement(ruleSet map[string]any) {
	delete(ruleSet, "$keyAgreement")
	for name, child := range ruleSet {
		if len(name) > 0 && name[0] == '$' {
			continue
		}
		if childSet, ok := child.(map[string]any); ok {
			stripKeyAgreement(childSet)
		}
	}
}
