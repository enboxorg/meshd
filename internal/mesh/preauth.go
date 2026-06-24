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
	NodeDID         string                       `json:"nodeDID"`
	MemberDID       string                       `json:"memberDID,omitempty"`
	OwnerDID        string                       `json:"ownerDID,omitempty"`
	DelegateDID     string                       `json:"delegateDID,omitempty"`
	RequestedBy     string                       `json:"requestedBy,omitempty"`
	NodeProof       string                       `json:"nodeProof,omitempty"`
	RequestKind     string                       `json:"requestKind,omitempty"`
	NetworkRecordID string                       `json:"networkRecordId,omitempty"`
	NetworkName     string                       `json:"networkName,omitempty"`
	SourceDWN       string                       `json:"sourceDWN,omitempty"`
	Label           string                       `json:"label,omitempty"`
	NodeKeyDelivery *dwncrypto.KeyDeliveryPublic `json:"nodeKeyDelivery,omitempty"`
	PreAuthKeyID    string                       `json:"preAuthKeyId,omitempty"`
	PreAuthProof    string                       `json:"preAuthProof,omitempty"`
	RequestedAt     string                       `json:"requestedAt,omitempty"`
	ExpiresAt       string                       `json:"expiresAt,omitempty"`
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
	UseContextEncryption bool
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

	var recipients []dwncrypto.KeyEncryptionInput
	if params.UseContextEncryption {
		recipients, err = params.EncryptionKeyManager.DeriveContextWriteEncryption(params.NetworkRecordID)
		if err != nil {
			return nil, fmt.Errorf("deriving preauth context encryption: %w", err)
		}
	} else {
		recipients, err = params.EncryptionKeyManager.DeriveWriteEncryption("network/preAuthKey")
		if err != nil {
			return nil, fmt.Errorf("deriving preauth encryption: %w", err)
		}
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
	Invite          invite.Payload
	NodeDID         string
	MemberDID       string
	DelegateDID     string
	RequestedBy     string
	Signer          *dwn.Signer
	Label           string
	SourceDWN       string
	NodeKeyDelivery *dwncrypto.KeyDeliveryPublic
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
	if err := validateNodeKeyDelivery(params.NodeDID, params.NodeKeyDelivery); err != nil {
		return NodeRequestData{}, err
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
		NodeKeyDelivery: params.NodeKeyDelivery,
		PreAuthKeyID:    params.Invite.TokenID,
		PreAuthProof:    invite.Proof(params.Invite.Secret, params.Invite.NetworkID, params.NodeDID),
		RequestedAt:     time.Now().UTC().Format(time.RFC3339),
	}, nil
}

func validateNodeKeyDelivery(nodeDID string, key *dwncrypto.KeyDeliveryPublic) error {
	if key == nil {
		return nil
	}
	if nodeDID == "" {
		return fmt.Errorf("node DID is required for key delivery validation")
	}
	rootKeyID := key.RootKeyID
	if rootKeyID == "" {
		rootKeyID = key.PublicKeyJWK.KID
	}
	if rootKeyID == "" {
		return fmt.Errorf("node key delivery rootKeyId is required")
	}
	expectedRootKeyID := nodeDID + "#1"
	if rootKeyID != expectedRootKeyID {
		return fmt.Errorf("node key delivery rootKeyId %q does not match node DID %q", rootKeyID, nodeDID)
	}
	if key.PublicKeyJWK.KID != "" && key.PublicKeyJWK.KID != rootKeyID {
		return fmt.Errorf("node key delivery publicKeyJwk.kid %q does not match rootKeyId %q", key.PublicKeyJWK.KID, rootKeyID)
	}
	if key.PublicKeyJWK.KTY != "OKP" {
		return fmt.Errorf("node key delivery publicKeyJwk.kty must be OKP")
	}
	if key.PublicKeyJWK.CRV != "X25519" {
		return fmt.Errorf("node key delivery publicKeyJwk.crv must be X25519")
	}
	if key.PublicKeyJWK.X == "" {
		return fmt.Errorf("node key delivery publicKeyJwk.x is required")
	}
	publicKey, err := base64.RawURLEncoding.DecodeString(key.PublicKeyJWK.X)
	if err != nil {
		return fmt.Errorf("decoding node key delivery public key: %w", err)
	}
	if len(publicKey) != 32 {
		return fmt.Errorf("node key delivery public key is %d bytes, want 32", len(publicKey))
	}
	return nil
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
	KeyDeliveryGrantID      string
	UseContextEncryption    bool
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
		if err := validateNodeKeyDelivery(req.NodeDID, req.NodeKeyDelivery); err != nil {
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
		if !exists {
			memberDID := ownerDID
			memberRecordID := ""
			if memberDID != "" && memberDID != req.NodeDID {
				memberRecordID, err = ensureMemberRecord(ctx, api, params, memberDID, firstNonEmpty(req.Label, key.Label))
				if err != nil {
					result.Pending++
					continue
				}
			}
			if memberDID == "" {
				memberDID = req.NodeDID
			}

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
				NodeKeyDelivery:      req.NodeKeyDelivery,
				UseContextEncryption: true,
				PermissionGrantID:    params.WritePermissionGrantID,
			})
			if err != nil {
				result.Pending++
				continue
			}
		}

		kdm := &KeyDeliveryManager{
			Endpoint:             params.AnchorEndpoint,
			Signer:               params.Signer,
			EncryptionKeyManager: params.EncryptionKeyManager,
		}
		if err := kdm.DeliverContextKey(ctx, DeliverContextKeyParams{
			AnchorDID:            params.AnchorDID,
			RecipientDID:         req.NodeDID,
			SourceProtocol:       protocols.MeshProtocolURI,
			ContextID:            params.NetworkRecordID,
			PermissionGrantID:    params.KeyDeliveryGrantID,
			RecipientKeyDelivery: req.NodeKeyDelivery,
		}); err != nil {
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
	decryptor := preAuthDecryptor(params.EncryptionKeyManager, params.NetworkRecordID)
	if err := control.ParseEntryData(record.RawEntry, &key, decryptor); err != nil {
		return nil, nil, err
	}
	return record, &key, nil
}

func preAuthDecryptor(encMgr *dwncrypto.EncryptionKeyManager, contextID string) control.EntryDecryptor {
	return func(ciphertext []byte, enc *dwncrypto.Encryption) ([]byte, error) {
		if encryptedDerivationScheme(enc) == dwncrypto.DerivationSchemeProtocolContext {
			privKey, err := encMgr.DeriveContextDecryptionKey(contextID)
			if err != nil {
				return nil, err
			}
			return dwncrypto.DecryptDataWithScheme(ciphertext, enc, privKey, dwncrypto.DerivationSchemeProtocolContext)
		}
		privKey, err := encMgr.DeriveDecryptionKey("network/preAuthKey")
		if err != nil {
			return nil, err
		}
		return dwncrypto.DecryptData(ciphertext, enc, privKey, encMgr.RootKeyID)
	}
}

func encryptedDerivationScheme(enc *dwncrypto.Encryption) string {
	if enc == nil {
		return dwncrypto.DerivationSchemeProtocolPath
	}
	for _, recipient := range enc.Recipients {
		if recipient.Header.DerivationScheme != "" {
			return recipient.Header.DerivationScheme
		}
	}
	return dwncrypto.DerivationSchemeProtocolPath
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
	var recipients []dwncrypto.KeyEncryptionInput
	if params.UseContextEncryption {
		recipients, err = params.EncryptionKeyManager.DeriveContextWriteEncryption(params.NetworkRecordID)
		if err != nil {
			return fmt.Errorf("deriving preauth context update encryption: %w", err)
		}
	} else {
		recipients, err = params.EncryptionKeyManager.DeriveWriteEncryption("network/preAuthKey")
		if err != nil {
			return fmt.Errorf("deriving preauth update encryption: %w", err)
		}
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
		UseContextEncryption: params.UseContextEncryption,
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
