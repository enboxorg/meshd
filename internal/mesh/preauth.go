package mesh

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/enboxorg/meshd/internal/control"
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
	NodeDID      string `json:"nodeDID"`
	SourceDWN    string `json:"sourceDWN,omitempty"`
	Label        string `json:"label,omitempty"`
	PreAuthKeyID string `json:"preAuthKeyId,omitempty"`
	PreAuthProof string `json:"preAuthProof,omitempty"`
	RequestedAt  string `json:"requestedAt,omitempty"`
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

	recipients, err := params.EncryptionKeyManager.DeriveWriteEncryption("network/preAuthKey")
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
	Invite    invite.Payload
	NodeDID   string
	Signer    *dwn.Signer
	Label     string
	SourceDWN string
}

// WritePreAuthNodeRequest writes a network/nodeRequest claim to the anchor DWN.
func WritePreAuthNodeRequest(ctx context.Context, params WritePreAuthNodeRequestParams) error {
	if err := params.Invite.ValidatePreAuth(); err != nil {
		return err
	}
	if params.NodeDID == "" {
		return fmt.Errorf("node DID is required")
	}

	data := NodeRequestData{
		NodeDID:      params.NodeDID,
		SourceDWN:    params.SourceDWN,
		Label:        params.Label,
		PreAuthKeyID: params.Invite.TokenID,
		PreAuthProof: invite.Proof(params.Invite.Secret, params.Invite.NetworkID, params.NodeDID),
		RequestedAt:  time.Now().UTC().Format(time.RFC3339),
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

// ApprovePreAuthRequestsParams configures anchor-side request approval.
type ApprovePreAuthRequestsParams struct {
	AnchorEndpoint       string
	AnchorDID            string
	NetworkRecordID      string
	MeshCIDR             string
	Signer               *dwn.Signer
	EncryptionKeyManager *dwncrypto.EncryptionKeyManager
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
		DateSort: "createdAscending",
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
			_ = deleteRecord(ctx, api, params.AnchorDID, request.ID)
			continue
		}

		keyRecord, key, err := readPreAuthKey(ctx, api, params, req.PreAuthKeyID)
		if err != nil {
			result.Pending++
			continue
		}
		if !preAuthKeyAllows(key, req.NodeDID) || !invite.VerifyProof(key.Key, params.NetworkRecordID, req.NodeDID, req.PreAuthProof) {
			result.Rejected++
			_ = deleteRecord(ctx, api, params.AnchorDID, request.ID)
			continue
		}

		exists, err := nodeRecordExists(ctx, api, params.AnchorDID, params.NetworkRecordID, req.NodeDID)
		if err != nil {
			result.Pending++
			continue
		}
		if !exists {
			meshIP, err := AllocateMeshIP(params.MeshCIDR, req.NodeDID)
			if err != nil {
				result.Rejected++
				_ = deleteRecord(ctx, api, params.AnchorDID, request.ID)
				continue
			}
			_, err = RegisterNode(ctx, RegisterNodeParams{
				AnchorEndpoint:       params.AnchorEndpoint,
				AnchorDID:            params.AnchorDID,
				NetworkRecordID:      params.NetworkRecordID,
				NodeDID:              req.NodeDID,
				Signer:               params.Signer,
				EncryptionKeyManager: params.EncryptionKeyManager,
				MeshIP:               meshIP.String(),
				Label:                firstNonEmpty(req.Label, key.Label),
				UseContextEncryption: true,
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
			AnchorDID:      params.AnchorDID,
			RecipientDID:   req.NodeDID,
			SourceProtocol: protocols.MeshProtocolURI,
			ContextID:      params.NetworkRecordID,
		}); err != nil {
			result.Pending++
			continue
		}

		if err := markPreAuthKeyUsed(ctx, api, params, keyRecord, key, req.NodeDID); err != nil {
			result.Pending++
			continue
		}
		if err := deleteRecord(ctx, api, params.AnchorDID, request.ID); err != nil {
			result.Pending++
			continue
		}
		result.Approved++
	}

	return result, nil
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
		DateSort: "createdDescending",
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

func preAuthDecryptor(encMgr *dwncrypto.EncryptionKeyManager) control.EntryDecryptor {
	return func(ciphertext []byte, enc *dwncrypto.Encryption) ([]byte, error) {
		privKey, err := encMgr.DeriveDecryptionKey("network/preAuthKey")
		if err != nil {
			return nil, err
		}
		return dwncrypto.DecryptData(ciphertext, enc, privKey, encMgr.RootKeyID)
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
	recipients, err := params.EncryptionKeyManager.DeriveWriteEncryption("network/preAuthKey")
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
	})
	if err != nil {
		return fmt.Errorf("updating preauth key: %w", err)
	}
	if status.Code >= 300 {
		return fmt.Errorf("preauth key update failed: %d %s", status.Code, status.Detail)
	}
	return nil
}

func nodeRecordExists(ctx context.Context, api *dwn.DwnAPI, anchorDID, networkID, nodeDID string) (bool, error) {
	records, status, err := api.Query(ctx, anchorDID, dwn.QueryParams{
		Filter: dwn.RecordsFilter{
			Protocol:     protocols.MeshProtocolURI,
			ProtocolPath: "network/node",
			ContextID:    networkID,
			Recipient:    nodeDID,
		},
		DateSort: "createdDescending",
	}, "")
	if err != nil {
		return false, err
	}
	if status.Code != 200 {
		return false, fmt.Errorf("node query failed: %d %s", status.Code, status.Detail)
	}
	return len(records) > 0, nil
}

func deleteRecord(ctx context.Context, api *dwn.DwnAPI, target, recordID string) error {
	status, err := api.Delete(ctx, target, recordID, false, "")
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
