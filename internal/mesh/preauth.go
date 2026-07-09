package mesh

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/enboxorg/meshd/internal/control"
	"github.com/enboxorg/meshd/internal/did"
	"github.com/enboxorg/meshd/internal/dwn"
	dwncrypto "github.com/enboxorg/meshd/internal/dwn/crypto"
	"github.com/enboxorg/meshd/internal/invite"
	"github.com/enboxorg/meshd/protocols"
)

// PreAuthKeyData is the encrypted network/preAuthKey record payload.
type PreAuthKeyData struct {
	Key       string   `json:"key"`
	CreatedAt string   `json:"createdAt"`
	ExpiresAt string   `json:"expiresAt,omitempty"`
	Reusable  bool     `json:"reusable,omitempty"`
	Ephemeral bool     `json:"ephemeral,omitempty"`
	Label     string   `json:"label,omitempty"`
	UsedBy    []string `json:"usedBy,omitempty"`
}

// NodeRequestData is the network/nodeRequest record payload written by a
// joining node that holds a preauth invite.
type NodeRequestData struct {
	NodeDID         string `json:"nodeDID"`
	MemberDID       string `json:"memberDID,omitempty"`
	OwnerDID        string `json:"ownerDID,omitempty"`
	DelegateDID     string `json:"delegateDID,omitempty"`
	RequestedBy     string `json:"requestedBy,omitempty"`
	NodeProof       string `json:"nodeProof,omitempty"`
	RequestKind     string `json:"requestKind,omitempty"`
	NetworkRecordID string `json:"networkRecordId,omitempty"`
	NetworkName     string `json:"networkName,omitempty"`
	SourceDWN       string `json:"sourceDWN,omitempty"`
	Label           string `json:"label,omitempty"`
	PreAuthKeyID    string `json:"preAuthKeyId,omitempty"`
	PreAuthProof    string `json:"preAuthProof,omitempty"`
	RequestedAt     string `json:"requestedAt,omitempty"`
	ExpiresAt       string `json:"expiresAt,omitempty"`

	// RoleKeys carries the PUBLIC halves of the node's own role-path X25519 keys,
	// keyed by full protocol role path (e.g. "network/node"). A did:jwk node
	// publishes no DWN endpoint, so an owner/dashboard cannot resolve these keys by
	// DID; the node supplies them here so the owner can wrap each
	// $encryption/delivery record to the recipient node without a DWN lookup. Each
	// value is byte-identical to the $keyAgreement.publicKeyJwk the node injects
	// into its own protocol definition (see dwncrypto.RolePathPublicKeyJWK).
	RoleKeys map[string]dwncrypto.PublicKeyJWK `json:"roleKeys,omitempty"`
}

func (r NodeRequestData) EffectiveOwnerDID() string {
	if r.OwnerDID != "" {
		return r.OwnerDID
	}
	if r.MemberDID != "" {
		return r.MemberDID
	}
	return r.NodeDID
}

// nodeRoleKeyPaths are the mesh $role paths a node HOLDS (their delivery recipient
// is the node itself). "network/member" is deliberately excluded: its recipient is
// the member/owner DID, a different identity whose key the node cannot assert. The
// node cannot know at join time whether approval places it under a member layer
// (network/member/node) or directly (network/node) — deliverJoinerAudienceKeys
// decides per-approval — so it publishes both candidate public keys.
var nodeRoleKeyPaths = []string{"network/node", "network/member/node"}

// nodeRoleKeys derives the PUBLIC halves of the node's own role-path keys from its
// root #enc key, for delivery to it without a DWN lookup. Returns nil (field
// omitted) when no encryption key is available, so nodes/paths that don't emit keys
// stay wire-compatible.
func nodeRoleKeys(encryptionKey []byte) (map[string]dwncrypto.PublicKeyJWK, error) {
	if len(encryptionKey) == 0 {
		return nil, nil
	}
	keys := make(map[string]dwncrypto.PublicKeyJWK, len(nodeRoleKeyPaths))
	for _, rolePath := range nodeRoleKeyPaths {
		jwk, err := dwncrypto.RolePathPublicKeyJWK(encryptionKey, protocols.MeshProtocolURI, rolePath)
		if err != nil {
			return nil, fmt.Errorf("deriving role-path public key for %q: %w", rolePath, err)
		}
		keys[rolePath] = jwk
	}
	return keys, nil
}

// CreatePreAuthKeyParams configures preauth token creation.
type CreatePreAuthKeyParams struct {
	AnchorEndpoint       string
	AnchorDID            string
	NetworkRecordID      string
	NetworkName          string
	Signer               *dwn.Signer
	EncryptionKeyManager *dwncrypto.EncryptionKeyManager
	Label                string
	ExpiresAt            time.Time
	Reusable             bool
	Ephemeral            bool
	PermissionGrantID    string
}

// PreAuthInvite is a created preauth key and its corresponding invite URL.
type PreAuthInvite struct {
	URL       string
	TokenID   string
	Secret    string
	ExpiresAt string
}

// CreatePreAuthKey writes an encrypted preAuthKey record and returns an invite URL.
func CreatePreAuthKey(ctx context.Context, params CreatePreAuthKeyParams) (*PreAuthInvite, error) {
	if params.EncryptionKeyManager == nil {
		return nil, fmt.Errorf("EncryptionKeyManager is required for encrypted writes")
	}

	secret, err := invite.GenerateSecret()
	if err != nil {
		return nil, err
	}

	expiresAt := ""
	if !params.ExpiresAt.IsZero() {
		expiresAt = params.ExpiresAt.UTC().Format(time.RFC3339)
	}

	data := PreAuthKeyData{
		Key:       secret,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
		ExpiresAt: expiresAt,
		Reusable:  params.Reusable,
		Ephemeral: params.Ephemeral,
		Label:     params.Label,
	}
	dataBytes, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("marshaling preauth key: %w", err)
	}

	// preAuthKey records have no reading roles, so this produces a single
	// protocolPath entry to the owner's published key.
	recipients, err := buildEncryptionRecipients(ctx, writeEncryptionParams{
		anchorEndpoint:  params.AnchorEndpoint,
		anchorDID:       params.AnchorDID,
		signer:          params.Signer,
		encMgr:          params.EncryptionKeyManager,
		protocolPath:    "network/preAuthKey",
		parentContextID: params.NetworkRecordID,
		writeAuth:       dwn.MessageAuth{PermissionGrantID: params.PermissionGrantID},
	})
	if err != nil {
		return nil, fmt.Errorf("deriving preauth encryption: %w", err)
	}

	agent := dwn.NewSimpleAgent(params.AnchorEndpoint, params.Signer)
	api := dwn.NewDwnAPI(agent)
	record, status, err := api.Write(ctx, params.AnchorDID, dwn.WriteParams{
		Protocol:             protocols.MeshProtocolURI,
		ProtocolPath:         "network/preAuthKey",
		Schema:               schemaPreAuthKey,
		DataFormat:           "application/json",
		ParentContextID:      params.NetworkRecordID,
		Data:                 dataBytes,
		EncryptionRecipients: recipients,
		PermissionGrantID:    params.PermissionGrantID,
	})
	if err != nil {
		return nil, fmt.Errorf("writing preauth key: %w", err)
	}
	if status.Code >= 300 {
		return nil, fmt.Errorf("preauth key write failed: %d %s", status.Code, status.Detail)
	}

	payload := invite.New(
		params.AnchorEndpoint,
		params.AnchorDID,
		params.NetworkRecordID,
		params.NetworkName,
		record.ID,
		secret,
		expiresAt,
	)
	url, err := invite.Encode(payload)
	if err != nil {
		return nil, err
	}

	return &PreAuthInvite{
		URL:       url,
		TokenID:   record.ID,
		Secret:    secret,
		ExpiresAt: expiresAt,
	}, nil
}

// WritePreAuthNodeRequestParams configures a preauth join request.
type WritePreAuthNodeRequestParams struct {
	Invite      invite.Payload
	NodeDID     string
	MemberDID   string
	DelegateDID string
	RequestedBy string
	Signer      *dwn.Signer
	Label       string
	SourceDWN   string
	// NodeEncryptionKey is the node's root #enc X25519 private key, used to derive
	// the PUBLIC role-path keys published in the request's roleKeys. Optional: when
	// empty, roleKeys is omitted (older behavior).
	NodeEncryptionKey []byte
}

// WritePreAuthNodeRequest writes a network/nodeRequest claim to the anchor DWN.
func WritePreAuthNodeRequest(ctx context.Context, params WritePreAuthNodeRequestParams) error {
	if err := params.Invite.ValidatePreAuth(); err != nil {
		return err
	}
	data, err := preAuthNodeRequestData(params)
	if err != nil {
		return err
	}
	dataBytes, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshaling node request: %w", err)
	}

	agent := dwn.NewSimpleAgent(params.Invite.Endpoint, params.Signer)
	api := dwn.NewDwnAPI(agent)
	_, status, err := api.Write(ctx, params.Invite.AnchorDID, dwn.WriteParams{
		Protocol:        protocols.MeshProtocolURI,
		ProtocolPath:    "network/nodeRequest",
		Schema:          schemaNodeRequest,
		DataFormat:      "application/json",
		ParentContextID: params.Invite.NetworkID,
		Data:            dataBytes,
	})
	if err != nil {
		return fmt.Errorf("writing node request: %w", err)
	}
	if status.Code >= 300 {
		return fmt.Errorf("node request write failed: %d %s", status.Code, status.Detail)
	}

	return nil
}

func preAuthNodeRequestData(params WritePreAuthNodeRequestParams) (NodeRequestData, error) {
	if params.NodeDID == "" {
		return NodeRequestData{}, fmt.Errorf("node DID is required")
	}

	memberDID := params.MemberDID
	if memberDID == "" {
		memberDID = params.NodeDID
	}
	requestedBy := params.RequestedBy
	if requestedBy == "" && params.Signer != nil {
		requestedBy = params.Signer.DID
	}

	nodeProof := ""
	if params.Signer != nil && params.Signer.DID == params.NodeDID && len(params.Signer.PrivateKey) == ed25519.PrivateKeySize {
		nodeProof = SignNodeJoinProof(params.Signer, params.Invite.NetworkID, params.NodeDID, memberDID, params.Invite.TokenID)
	}

	roleKeys, err := nodeRoleKeys(params.NodeEncryptionKey)
	if err != nil {
		return NodeRequestData{}, err
	}

	return NodeRequestData{
		NodeDID:         params.NodeDID,
		MemberDID:       memberDID,
		OwnerDID:        memberDID,
		DelegateDID:     params.DelegateDID,
		RequestedBy:     requestedBy,
		NodeProof:       nodeProof,
		RequestKind:     "network-preauth",
		NetworkRecordID: params.Invite.NetworkID,
		NetworkName:     params.Invite.NetworkName,
		SourceDWN:       params.SourceDWN,
		Label:           params.Label,
		PreAuthKeyID:    params.Invite.TokenID,
		PreAuthProof:    invite.Proof(params.Invite.Secret, params.Invite.NetworkID, params.NodeDID),
		RequestedAt:     time.Now().UTC().Format(time.RFC3339),
		RoleKeys:        roleKeys,
	}, nil
}

// ApprovePreAuthRequestsParams configures anchor-side request approval.
type ApprovePreAuthRequestsParams struct {
	AnchorEndpoint          string
	AnchorDID               string
	NetworkRecordID         string
	MeshCIDR                string
	Signer                  *dwn.Signer
	EncryptionKeyManager    *dwncrypto.EncryptionKeyManager
	ReadPermissionGrantID   string
	WritePermissionGrantID  string
	DeletePermissionGrantID string

	// ProtocolDefinition and AudienceSource are resolved/constructed once
	// per pass when empty; tests and long-running approval loops may supply
	// them to reuse caches across passes.
	ProtocolDefinition json.RawMessage
	AudienceSource     *control.SealedAudienceSource
}

// ApprovePreAuthResult summarizes processed preauth requests.
type ApprovePreAuthResult struct {
	Approved int
	Rejected int
	Pending  int
}

// ApprovePreAuthRequests processes pending preauth node requests.
func ApprovePreAuthRequests(ctx context.Context, params ApprovePreAuthRequestsParams) (*ApprovePreAuthResult, error) {
	if params.EncryptionKeyManager == nil {
		return nil, fmt.Errorf("EncryptionKeyManager is required")
	}

	agent := dwn.NewSimpleAgent(params.AnchorEndpoint, params.Signer)
	api := dwn.NewDwnAPI(agent)
	result := &ApprovePreAuthResult{}

	// One shared audience source (and resolved definition) for every write
	// and delivery in this pass: mints happen once per role and the unsealed
	// keys stay cached for delivery.
	if params.ProtocolDefinition == nil || params.AudienceSource == nil {
		def, err := resolveInstalledDefinition(ctx, writeEncryptionParams{
			anchorEndpoint: params.AnchorEndpoint,
			anchorDID:      params.AnchorDID,
			signer:         params.Signer,
			encMgr:         params.EncryptionKeyManager,
		})
		if err != nil {
			return nil, fmt.Errorf("resolving installed definition: %w", err)
		}
		params.ProtocolDefinition = def
		params.AudienceSource = control.NewSealedAudienceSource(control.SealedAudienceSourceConfig{
			Client:             dwn.NewClient(params.AnchorEndpoint, params.Signer),
			Tenant:             params.AnchorDID,
			ProtocolDefinition: def,
			WriteAuth:          dwn.MessageAuth{PermissionGrantID: params.WritePermissionGrantID},
			SealKeys:           ownerSealKeys(writeEncryptionParams{encMgr: params.EncryptionKeyManager, anchorDID: params.AnchorDID}),
		})
	}

	requests, status, err := api.Query(ctx, params.AnchorDID, dwn.QueryParams{
		Filter: dwn.RecordsFilter{
			Protocol:     protocols.MeshProtocolURI,
			ProtocolPath: "network/nodeRequest",
			ContextID:    params.NetworkRecordID,
		},
		DateSort:          "createdAscending",
		PermissionGrantID: params.ReadPermissionGrantID,
	}, "")
	if err != nil {
		return nil, fmt.Errorf("querying node requests: %w", err)
	}
	if status.Code != 200 {
		return nil, fmt.Errorf("querying node requests failed: %d %s", status.Code, status.Detail)
	}

	for _, request := range requests {
		var req NodeRequestData
		if err := request.Data().JSON(ctx, &req); err != nil {
			result.Rejected++
			_ = deleteRecord(ctx, api, params.AnchorDID, request.ID, params.DeletePermissionGrantID)
			continue
		}

		keyRecord, key, err := readPreAuthKey(ctx, api, params, req.PreAuthKeyID)
		if err != nil {
			result.Pending++
			continue
		}
		if !preAuthKeyAllows(key, req.NodeDID) || !invite.VerifyProof(key.Key, params.NetworkRecordID, req.NodeDID, req.PreAuthProof) {
			result.Rejected++
			_ = deleteRecord(ctx, api, params.AnchorDID, request.ID, params.DeletePermissionGrantID)
			continue
		}
		ownerDID := req.EffectiveOwnerDID()
		if req.NodeProof != "" && !VerifyNodeJoinProof(req.NodeDID, req.NodeProof, params.NetworkRecordID, ownerDID, req.PreAuthKeyID) {
			result.Rejected++
			_ = deleteRecord(ctx, api, params.AnchorDID, request.ID, params.DeletePermissionGrantID)
			continue
		}

		exists, err := nodeRecordExists(ctx, api, params.AnchorDID, params.NetworkRecordID, req.NodeDID, params.ReadPermissionGrantID)
		if err != nil {
			result.Pending++
			continue
		}
		memberDID := ownerDID
		memberRecordID := ""
		if ownerDID != "" && ownerDID != req.NodeDID {
			memberRecordID, err = ensureMemberRecord(ctx, api, params, memberDID, firstNonEmpty(req.Label, key.Label))
			if err != nil {
				result.Pending++
				continue
			}
		}
		if memberDID == "" {
			memberDID = req.NodeDID
		}
		if !exists {
			meshIP, err := AllocateMeshIP(params.MeshCIDR, req.NodeDID)
			if err != nil {
				result.Rejected++
				_ = deleteRecord(ctx, api, params.AnchorDID, request.ID, params.DeletePermissionGrantID)
				continue
			}
			_, err = RegisterNode(ctx, RegisterNodeParams{
				AnchorEndpoint:       params.AnchorEndpoint,
				AnchorDID:            params.AnchorDID,
				NetworkRecordID:      params.NetworkRecordID,
				MemberRecordID:       memberRecordID,
				NodeDID:              req.NodeDID,
				Signer:               params.Signer,
				EncryptionKeyManager: params.EncryptionKeyManager,
				MeshIP:               meshIP.String(),
				Label:                firstNonEmpty(req.Label, key.Label),
				OwnerDID:             memberDID,
				DelegateDID:          req.DelegateDID,
				PermissionGrantID:    params.WritePermissionGrantID,
				ProtocolDefinition:   params.ProtocolDefinition,
				AudienceSource:       audienceSourceOrNil(params.AudienceSource),
			})
			if err != nil {
				result.Pending++
				continue
			}
		}

		// Hand the joiner its role-audience key so it can decrypt the
		// network's records (sealed model: role holders read via
		// `$encryption/delivery` records). Requires the joiner to have
		// installed the mesh protocol on its own tenant; leaving the
		// request pending retries the delivery on the next approval cycle.
		if err := deliverJoinerAudienceKeys(ctx, params, memberRecordID, memberDID, req.NodeDID); err != nil {
			result.Pending++
			continue
		}

		if err := markPreAuthKeyUsed(ctx, api, params, keyRecord, key, req.NodeDID); err != nil {
			result.Pending++
			continue
		}
		if err := deleteRecord(ctx, api, params.AnchorDID, request.ID, params.DeletePermissionGrantID); err != nil {
			result.Pending++
			continue
		}
		result.Approved++
	}

	return result, nil
}

// NodeJoinProofMessage returns the stable message signed by a node DID when it
// asks to join a network on behalf of a member DID.
func NodeJoinProofMessage(networkID, nodeDID, memberDID, preAuthKeyID string) []byte {
	if memberDID == "" {
		memberDID = nodeDID
	}
	return []byte(
		"meshd node join v1\n" +
			"network=" + networkID + "\n" +
			"node=" + nodeDID + "\n" +
			"member=" + memberDID + "\n" +
			"preauth=" + preAuthKeyID + "\n",
	)
}

// SignNodeJoinProof signs a node join proof with the node DID signer.
func SignNodeJoinProof(signer *dwn.Signer, networkID, nodeDID, memberDID, preAuthKeyID string) string {
	if signer == nil || signer.DID == "" || len(signer.PrivateKey) != ed25519.PrivateKeySize {
		return ""
	}
	msg := NodeJoinProofMessage(networkID, nodeDID, memberDID, preAuthKeyID)
	sig := ed25519.Sign(signer.PrivateKey, msg)
	return base64.RawURLEncoding.EncodeToString(sig)
}

// VerifyNodeJoinProof verifies a node join proof from a did:jwk node DID.
func VerifyNodeJoinProof(nodeDID, proof, networkID, memberDID, preAuthKeyID string) bool {
	pub, err := did.ParseURI(nodeDID)
	if err != nil {
		return false
	}
	sig, err := base64.RawURLEncoding.DecodeString(proof)
	if err != nil {
		return false
	}
	msg := NodeJoinProofMessage(networkID, nodeDID, memberDID, preAuthKeyID)
	return did.VerifyWith(pub, msg, sig)
}

func readPreAuthKey(ctx context.Context, api *dwn.DwnAPI, params ApprovePreAuthRequestsParams, recordID string) (*dwn.Record, *PreAuthKeyData, error) {
	if recordID == "" {
		return nil, nil, fmt.Errorf("missing preauth key ID")
	}

	records, status, err := api.Query(ctx, params.AnchorDID, dwn.QueryParams{
		Filter: dwn.RecordsFilter{
			Protocol:     protocols.MeshProtocolURI,
			ProtocolPath: "network/preAuthKey",
			ContextID:    params.NetworkRecordID,
		},
		DateSort:          "createdDescending",
		PermissionGrantID: params.ReadPermissionGrantID,
	}, "")
	if err != nil {
		return nil, nil, err
	}
	if status.Code != 200 {
		return nil, nil, fmt.Errorf("querying preauth keys failed: %d %s", status.Code, status.Detail)
	}

	var record *dwn.Record
	for _, r := range records {
		if r.ID == recordID {
			record = r
			break
		}
	}
	if record == nil {
		return nil, nil, fmt.Errorf("preauth key %q not found", recordID)
	}

	var key PreAuthKeyData
	decryptor := preAuthDecryptor(params.EncryptionKeyManager)
	if err := control.ParseEntryData(record.RawEntry, &key, decryptor); err != nil {
		return nil, nil, err
	}
	return record, &key, nil
}

// preAuthDecryptor decrypts network/preAuthKey records for the anchor approver.
// preAuthKey records are encrypted with the protocolPath scheme (owner-readable);
// the anchor derives the leaf key from its encryption root. Role-audience
// records are not readable on this owner-side path.
func preAuthDecryptor(encMgr *dwncrypto.EncryptionKeyManager) control.EntryDecryptor {
	return func(ciphertext []byte, enc *dwncrypto.Encryption) ([]byte, error) {
		if dwncrypto.RoleAudienceEntryInfo(enc) != nil {
			return nil, fmt.Errorf("preauth key approval requires protocolPath decryption; roleAudience records are not readable by the anchor approver")
		}
		privKey, err := encMgr.DeriveDecryptionKey("network/preAuthKey")
		if err != nil {
			return nil, err
		}
		defer clear(privKey)
		return dwncrypto.DecryptData(ciphertext, enc, privKey)
	}
}

func preAuthKeyAllows(key *PreAuthKeyData, nodeDID string) bool {
	if key == nil || key.Key == "" || nodeDID == "" {
		return false
	}
	if key.ExpiresAt != "" {
		expiresAt, err := time.Parse(time.RFC3339, key.ExpiresAt)
		if err != nil || time.Now().After(expiresAt) {
			return false
		}
	}
	for _, used := range key.UsedBy {
		if used == nodeDID {
			return true
		}
	}
	return key.Reusable || len(key.UsedBy) == 0
}

func markPreAuthKeyUsed(ctx context.Context, api *dwn.DwnAPI, params ApprovePreAuthRequestsParams, record *dwn.Record, key *PreAuthKeyData, nodeDID string) error {
	for _, used := range key.UsedBy {
		if used == nodeDID {
			return nil
		}
	}
	key.UsedBy = append(key.UsedBy, nodeDID)

	data, err := json.Marshal(key)
	if err != nil {
		return fmt.Errorf("marshaling used preauth key: %w", err)
	}
	recipients, err := buildEncryptionRecipients(ctx, writeEncryptionParams{
		anchorEndpoint:  params.AnchorEndpoint,
		anchorDID:       params.AnchorDID,
		signer:          params.Signer,
		encMgr:          params.EncryptionKeyManager,
		protocolPath:    "network/preAuthKey",
		parentContextID: params.NetworkRecordID,
		writeAuth:       dwn.MessageAuth{PermissionGrantID: params.WritePermissionGrantID},
	})
	if err != nil {
		return fmt.Errorf("deriving preauth update encryption: %w", err)
	}

	_, status, err := api.Write(ctx, params.AnchorDID, dwn.WriteParams{
		Protocol:             protocols.MeshProtocolURI,
		ProtocolPath:         "network/preAuthKey",
		Schema:               schemaPreAuthKey,
		DataFormat:           "application/json",
		ParentContextID:      params.NetworkRecordID,
		RecordID:             record.ID,
		DateCreated:          record.DateCreated,
		Data:                 data,
		EncryptionRecipients: recipients,
		PermissionGrantID:    params.WritePermissionGrantID,
	})
	if err != nil {
		return fmt.Errorf("updating preauth key: %w", err)
	}
	if status.Code >= 300 {
		return fmt.Errorf("preauth key update failed: %d %s", status.Code, status.Detail)
	}
	return nil
}

func ensureMemberRecord(ctx context.Context, api *dwn.DwnAPI, params ApprovePreAuthRequestsParams, memberDID, label string) (string, error) {
	records, status, err := api.Query(ctx, params.AnchorDID, dwn.QueryParams{
		Filter: dwn.RecordsFilter{
			Protocol:     protocols.MeshProtocolURI,
			ProtocolPath: "network/member",
			ContextID:    params.NetworkRecordID,
			Recipient:    memberDID,
		},
		DateSort:          "createdDescending",
		PermissionGrantID: params.ReadPermissionGrantID,
	}, "")
	if err != nil {
		return "", err
	}
	if status.Code != 200 {
		return "", fmt.Errorf("member query failed: %d %s", status.Code, status.Detail)
	}
	if len(records) > 0 {
		return records[0].ID, nil
	}

	reg, err := CreateMember(ctx, CreateMemberParams{
		AnchorEndpoint:       params.AnchorEndpoint,
		AnchorDID:            params.AnchorDID,
		NetworkRecordID:      params.NetworkRecordID,
		MemberDID:            memberDID,
		Signer:               params.Signer,
		EncryptionKeyManager: params.EncryptionKeyManager,
		Label:                label,
		PermissionGrantID:    params.WritePermissionGrantID,
	})
	if err != nil {
		return "", err
	}
	return reg.MemberRecordID, nil
}

func nodeRecordExists(ctx context.Context, api *dwn.DwnAPI, anchorDID, networkID, nodeDID string, permissionGrantID string) (bool, error) {
	records, status, err := api.Query(ctx, anchorDID, dwn.QueryParams{
		Filter: dwn.RecordsFilter{
			Protocol:     protocols.MeshProtocolURI,
			ProtocolPath: "network/node",
			ContextID:    networkID,
			Recipient:    nodeDID,
		},
		DateSort:          "createdDescending",
		PermissionGrantID: permissionGrantID,
	}, "")
	if err != nil {
		return false, err
	}
	if status.Code != 200 {
		return false, fmt.Errorf("node query failed: %d %s", status.Code, status.Detail)
	}
	if len(records) > 0 {
		return true, nil
	}

	memberRecords, status, err := api.Query(ctx, anchorDID, dwn.QueryParams{
		Filter: dwn.RecordsFilter{
			Protocol:     protocols.MeshProtocolURI,
			ProtocolPath: "network/member",
			ContextID:    networkID,
		},
		DateSort:          "createdDescending",
		PermissionGrantID: permissionGrantID,
	}, "")
	if err != nil {
		return false, err
	}
	if status.Code != 200 {
		return false, fmt.Errorf("member query failed: %d %s", status.Code, status.Detail)
	}
	for _, memberRecord := range memberRecords {
		memberNodes, status, err := api.Query(ctx, anchorDID, dwn.QueryParams{
			Filter: dwn.RecordsFilter{
				Protocol:     protocols.MeshProtocolURI,
				ProtocolPath: "network/member/node",
				ContextID:    networkID + "/" + memberRecord.ID,
				Recipient:    nodeDID,
			},
			DateSort:          "createdDescending",
			PermissionGrantID: permissionGrantID,
		}, "")
		if err != nil {
			return false, err
		}
		if status.Code != 200 {
			return false, fmt.Errorf("member node query failed: %d %s", status.Code, status.Detail)
		}
		if len(memberNodes) > 0 {
			return true, nil
		}
	}
	return false, nil
}

func deleteRecord(ctx context.Context, api *dwn.DwnAPI, target, recordID string, permissionGrantID string) error {
	status, err := api.Delete(ctx, target, recordID, false, "", permissionGrantID)
	if err != nil {
		return err
	}
	if status.Code >= 300 {
		return fmt.Errorf("delete failed: %d %s", status.Code, status.Detail)
	}
	return nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// deliverJoinerAudienceKeys hands an approved joiner (and its member, when a
// member layer exists) the sealed role-audience keys for the roles they were
// just assigned, via `$encryption/delivery` records. Node-role delivery is
// required (the joiner cannot decrypt network state without it); member-role
// delivery is best-effort, since a member DID may not host a DWN tenant with
// the protocol installed. Existing deliveries are detected and skipped, so
// retries are idempotent.
func deliverJoinerAudienceKeys(ctx context.Context, params ApprovePreAuthRequestsParams, memberRecordID, memberDID, nodeDID string) error {
	if !isOwnerRootManager(params.EncryptionKeyManager, params.AnchorDID) {
		// Only the owner can unseal audience keys for delivery. Wallet-owned
		// networks approve through the dashboard, which delivers keys itself.
		return nil
	}
	src := params.AudienceSource
	if src == nil {
		return fmt.Errorf("audience source is required for delivery")
	}
	client := dwn.NewClient(params.AnchorEndpoint, params.Signer)

	type target struct {
		rolePath  string
		recipient string
		contextID string
		required  bool
	}
	var targets []target
	if memberRecordID != "" {
		targets = append(targets,
			target{"network/member", memberDID, params.NetworkRecordID, false},
			target{"network/member/node", nodeDID, params.NetworkRecordID + "/" + memberRecordID, true},
		)
	} else {
		targets = append(targets, target{"network/node", nodeDID, params.NetworkRecordID, true})
	}

	for _, tgt := range targets {
		delivered, err := deliveryRecordExists(ctx, client, params.AnchorDID, tgt.rolePath, tgt.contextID, tgt.recipient)
		if err == nil && delivered {
			continue
		}
		err = DeliverAudienceKey(ctx, DeliverAudienceKeyParams{
			AnchorEndpoint: params.AnchorEndpoint,
			AnchorDID:      params.AnchorDID,
			Signer:         params.Signer,
			AudienceSource: src,
			RecipientDID:   tgt.recipient,
			RolePath:       tgt.rolePath,
			ContextID:      tgt.contextID,
			WriteAuth:      dwn.MessageAuth{PermissionGrantID: params.WritePermissionGrantID},
		})
		if err != nil && tgt.required {
			return fmt.Errorf("delivering %s audience key to %s: %w", tgt.rolePath, tgt.recipient, err)
		}
	}
	return nil
}

// deliveryRecordExists reports whether a `$encryption/delivery` record for
// the tuple already reached the recipient.
func deliveryRecordExists(ctx context.Context, client *dwn.Client, tenant, rolePath, contextID, recipient string) (bool, error) {
	reply, err := client.RecordsQuery(ctx, tenant, dwn.RecordsFilter{
		Protocol:     protocols.MeshProtocolURI,
		ProtocolPath: dwncrypto.EncryptionControlDeliveryPath,
		Recipient:    recipient,
		Tags: map[string]any{
			"protocol":  protocols.MeshProtocolURI,
			"rolePath":  rolePath,
			"contextId": contextID,
		},
	}, "createdDescending", nil, "")
	if err != nil {
		return false, err
	}
	entries, err := dwn.QueryEntries(reply)
	if err != nil {
		return false, err
	}
	return len(entries) > 0, nil
}
