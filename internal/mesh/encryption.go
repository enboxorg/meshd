package mesh

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/enboxorg/meshd/internal/control"
	"github.com/enboxorg/meshd/internal/dwn"
	dwncrypto "github.com/enboxorg/meshd/internal/dwn/crypto"
	"github.com/enboxorg/meshd/protocols"
)

// writeEncryptionParams collects what an encrypted mesh write needs to build
// its keyEncryption inputs under the sealed role-audience model.
type writeEncryptionParams struct {
	anchorEndpoint  string
	anchorDID       string
	signer          *dwn.Signer
	encMgr          *dwncrypto.EncryptionKeyManager
	protocolPath    string
	parentContextID string

	// protocolDef optionally overrides installed-definition resolution.
	protocolDef json.RawMessage

	// audienceSource optionally overrides the default DWN-backed sealed
	// audience source (mint-on-miss when the writer has seal coverage).
	audienceSource dwncrypto.AudienceSource

	// writeAuth authorizes audience mint writes (and mirrors the record
	// write's own grant invocation).
	writeAuth dwn.MessageAuth
}

// buildEncryptionRecipients resolves the installed protocol definition and
// produces the keyEncryption inputs for an encrypted write: one protocolPath
// entry to the owner's published key plus one roleAudience entry per reading
// role, minting sealed audience records when missing. It fails closed when a
// reading role's audience cannot be resolved or minted.
func buildEncryptionRecipients(ctx context.Context, p writeEncryptionParams) ([]dwncrypto.KeyEncryptionInput, error) {
	def, err := resolveInstalledDefinition(ctx, p)
	if err != nil {
		return nil, fmt.Errorf("resolving installed protocol definition: %w", err)
	}

	src := p.audienceSource
	if src == nil {
		src = control.NewSealedAudienceSource(control.SealedAudienceSourceConfig{
			Client:             dwn.NewClient(p.anchorEndpoint, p.signer),
			Tenant:             p.anchorDID,
			ProtocolDefinition: def,
			QueryAuth:          p.writeAuth,
			WriteAuth:          p.writeAuth,
			SealKeys:           ownerSealKeys(p),
		})
	}

	return dwncrypto.BuildWriteEncryption(ctx, def, p.protocolPath, p.parentContextID, src)
}

// audienceSourceOrNil converts a possibly-nil *control.SealedAudienceSource
// into a dwncrypto.AudienceSource interface without wrapping a typed nil.
func audienceSourceOrNil(src *control.SealedAudienceSource) dwncrypto.AudienceSource {
	if src == nil {
		return nil
	}
	return src
}

// ownerSealKeys returns a role-path seal key provider when the writer holds
// the network owner's encryption root, and nil otherwise (delegate writers
// pass their own grant-key-backed source explicitly).
func ownerSealKeys(p writeEncryptionParams) control.RolePathKeyProvider {
	if isOwnerRootManager(p.encMgr, p.anchorDID) {
		return control.OwnerRolePathKeys{Manager: p.encMgr}
	}
	return nil
}

// isOwnerRootManager reports whether the key manager's root is the anchor
// DID's encryption root, i.e. the writer is the network owner.
func isOwnerRootManager(encMgr *dwncrypto.EncryptionKeyManager, anchorDID string) bool {
	return encMgr != nil && anchorDID != "" && strings.HasPrefix(encMgr.RootKeyID, anchorDID+"#")
}

// resolveInstalledDefinition returns the installed mesh protocol definition
// (with the owner's published $keyAgreement keys).
//
//   - An explicit override wins.
//   - The network owner rebuilds it locally: its encryption root is the anchor
//     DID's #enc key, so InjectEncryptionDirectives reproduces the published
//     keys deterministically.
//   - Any other writer (node or delegate, which do not hold the owner's root)
//     fetches it from the anchor DWN via ProtocolsQuery.
func resolveInstalledDefinition(ctx context.Context, p writeEncryptionParams) (json.RawMessage, error) {
	if len(p.protocolDef) > 0 {
		return p.protocolDef, nil
	}
	if isOwnerRootManager(p.encMgr, p.anchorDID) {
		return dwncrypto.InjectEncryptionDirectives(protocols.MeshProtocolJSON, p.encMgr.RootPrivateKey)
	}
	return FetchInstalledProtocolDefinition(ctx, dwn.NewClient(p.anchorEndpoint, p.signer), p.anchorDID, protocols.MeshProtocolURI)
}

// FetchInstalledProtocolDefinition queries the target DWN for the installed
// definition of protocolURI. A ProtocolsConfigure message carries the
// definition in descriptor.definition.
func FetchInstalledProtocolDefinition(ctx context.Context, client *dwn.Client, target, protocolURI string) (json.RawMessage, error) {
	reply, err := client.ProtocolsQuery(ctx, target, protocolURI)
	if err != nil {
		return nil, fmt.Errorf("querying installed protocol: %w", err)
	}
	entries, err := dwn.QueryEntries(reply)
	if err != nil {
		return nil, fmt.Errorf("parsing protocol query: %w", err)
	}
	for _, entry := range entries {
		if def := extractProtocolDefinition(entry); def != nil {
			return def, nil
		}
	}
	return nil, fmt.Errorf("installed protocol definition for %q not found on %s", protocolURI, target)
}

// extractProtocolDefinition pulls descriptor.definition out of a
// ProtocolsConfigure query entry (flat or wrapped form).
func extractProtocolDefinition(entry json.RawMessage) json.RawMessage {
	type configure struct {
		Descriptor struct {
			Definition json.RawMessage `json:"definition"`
		} `json:"descriptor"`
	}
	var probe struct {
		configure
		ProtocolsConfigure configure `json:"protocolsConfigure"`
		Message            configure `json:"message"`
	}
	if err := json.Unmarshal(entry, &probe); err != nil {
		return nil
	}
	switch {
	case len(probe.Descriptor.Definition) > 0:
		return probe.Descriptor.Definition
	case len(probe.ProtocolsConfigure.Descriptor.Definition) > 0:
		return probe.ProtocolsConfigure.Descriptor.Definition
	case len(probe.Message.Descriptor.Definition) > 0:
		return probe.Message.Descriptor.Definition
	}
	return nil
}
