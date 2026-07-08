package mesh

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/enboxorg/meshd/internal/control"
	"github.com/enboxorg/meshd/internal/dwn"
	dwncrypto "github.com/enboxorg/meshd/internal/dwn/crypto"
	"github.com/enboxorg/meshd/protocols"
)

// DeliverAudienceKeyParams configures the delivery of a role-audience key to
// a role holder that cannot unseal it itself (a node without wallet grants —
// the invite / local-vault paths). It is the Go counterpart of the SDK
// agent's createAudienceDeliveryRecord.
type DeliverAudienceKeyParams struct {
	// AnchorEndpoint / AnchorDID identify the network owner's DWN tenant,
	// where the delivery record is written.
	AnchorEndpoint string
	AnchorDID      string

	// Signer signs the delivery write (the owner, or a delegate with a
	// write grant via WriteAuth).
	Signer *dwn.Signer

	// AudienceSource must be seal-capable: it resolves the tuple's current
	// audience key and recovers its private half.
	AudienceSource *control.SealedAudienceSource

	// RecipientDID is the role holder receiving the key.
	RecipientDID string

	// RecipientEndpoint is the DWN endpoint hosting the RECIPIENT's tenant,
	// whose installed protocol definition advertises the role-path
	// $keyAgreement key the delivery is wrapped to. Defaults to
	// AnchorEndpoint (single-server networks).
	RecipientEndpoint string

	// RolePath is the role the recipient holds (e.g. "network/node").
	RolePath string

	// ContextID is the audience tuple contextId (the network record ID for
	// the top-level network roles).
	ContextID string

	// WriteAuth authorizes the delivery write when the signer is not the
	// tenant.
	WriteAuth dwn.MessageAuth
}

// DeliverAudienceKey writes an encrypted `$encryption/delivery` record that
// hands the current audience key for (protocol, RolePath, ContextID) to a
// role holder, wrapped to the role-path public key the recipient publishes
// in its own installed protocol definition.
//
// The recipient must already hold the role record (the server validates
// this), so call it AFTER the role record write. The recipient must also
// have installed the mesh protocol with its own injected encryption keys on
// its tenant.
func DeliverAudienceKey(ctx context.Context, params DeliverAudienceKeyParams) error {
	if params.AudienceSource == nil {
		return fmt.Errorf("a seal-capable audience source is required")
	}
	if params.RecipientDID == "" || params.RolePath == "" {
		return fmt.Errorf("recipient DID and role path are required")
	}

	pub, keyID, err := params.AudienceSource.Current(ctx, protocols.MeshProtocolURI, params.RolePath, params.ContextID)
	if err != nil {
		return fmt.Errorf("resolving audience for %s: %w", params.RolePath, err)
	}
	audiencePriv, err := params.AudienceSource.AudiencePrivateKeyByKeyID(ctx, protocols.MeshProtocolURI, params.RolePath, keyID)
	if err != nil {
		return fmt.Errorf("unsealing audience key %s: %w", keyID, err)
	}
	defer clear(audiencePriv)

	recipientEndpoint := params.RecipientEndpoint
	if recipientEndpoint == "" {
		recipientEndpoint = params.AnchorEndpoint
	}
	recipientDef, err := FetchInstalledProtocolDefinition(ctx,
		dwn.NewClient(recipientEndpoint, params.Signer), params.RecipientDID, protocols.MeshProtocolURI)
	if err != nil {
		return fmt.Errorf("fetching recipient's installed protocol (the joiner must install the mesh protocol on its own tenant): %w", err)
	}
	recipientRolePub, _, err := dwncrypto.KeyAgreementPublicKeyAtPath(recipientDef, params.RolePath)
	if err != nil {
		return fmt.Errorf("resolving recipient role-path key: %w", err)
	}

	x := base64.RawURLEncoding.EncodeToString(pub)
	payload := dwncrypto.DeliveryPayload{
		Protocol:  protocols.MeshProtocolURI,
		RolePath:  params.RolePath,
		ContextID: params.ContextID,
		KeyID:     keyID,
		KeyMaterial: dwncrypto.RoleAudienceKeyMaterial{
			Algorithm:        dwncrypto.AlgX25519HKDFA256KW,
			DerivationScheme: dwncrypto.DerivationSchemeRoleAudience,
			KeyID:            keyID,
			PublicKeyJwk:     dwncrypto.PublicKeyJWK{KTY: "OKP", CRV: "X25519", X: x},
			PrivateKeyJwk: dwncrypto.PrivateKeyJWK{
				KTY: "OKP", CRV: "X25519", X: x,
				D: base64.RawURLEncoding.EncodeToString(audiencePriv),
			},
		},
	}
	payloadJSON, err := json.Marshal(&payload)
	if err != nil {
		return fmt.Errorf("marshaling delivery payload: %w", err)
	}

	api := dwn.NewDwnAPI(dwn.NewSimpleAgent(params.AnchorEndpoint, params.Signer))
	_, status, err := api.Write(ctx, params.AnchorDID, dwn.WriteParams{
		Protocol:     protocols.MeshProtocolURI,
		ProtocolPath: dwncrypto.EncryptionControlDeliveryPath,
		Schema:       dwncrypto.EncryptionControlDeliverySchemaURI,
		DataFormat:   "application/json",
		Recipient:    params.RecipientDID,
		Data:         payloadJSON,
		Tags: map[string]any{
			"protocol":           protocols.MeshProtocolURI,
			"rolePath":           params.RolePath,
			"contextId":          params.ContextID,
			"keyId":              keyID,
			"recipientAuthority": dwncrypto.DeliveryRecipientAuthorityRoleHolder,
		},
		EncryptionRecipients: []dwncrypto.KeyEncryptionInput{
			{PublicKey: recipientRolePub, DerivationScheme: dwncrypto.DerivationSchemeProtocolPath},
		},
		ProtocolRole:      params.WriteAuth.ProtocolRole,
		PermissionGrantID: params.WriteAuth.PermissionGrantID,
		DelegatedGrant:    params.WriteAuth.DelegatedGrant,
	})
	if err != nil {
		return fmt.Errorf("writing delivery record: %w", err)
	}
	if status.Code >= 300 {
		return fmt.Errorf("delivery write failed: %d %s", status.Code, status.Detail)
	}
	return nil
}
