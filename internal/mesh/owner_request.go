package mesh

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/enboxorg/meshd/internal/did"
	"github.com/enboxorg/meshd/internal/dwn"
	"github.com/enboxorg/meshd/protocols"
)

// OwnerNodeRequestParams configures a root nodeRequest sent to an owner's DWN.
type OwnerNodeRequestParams struct {
	OwnerEndpoint string
	OwnerDID      string
	NodeDID       string
	Signer        *dwn.Signer
	Label         string
	SourceDWN     string
	// NodeEncryptionKey is the node's root #enc X25519 private key. When set, the
	// node's role-path public keys are derived and emitted so a DWN-less owner can
	// deliver role-audience keys to it (see issue #187). Never leaves the node.
	NodeEncryptionKey []byte
}

// NodeApprovalData is the root nodeApproval payload written by the owner
// dashboard after accepting a node into a network.
type NodeApprovalData struct {
	OwnerDID          string `json:"ownerDID"`
	NodeDID           string `json:"nodeDID"`
	NetworkRecordID   string `json:"networkRecordId"`
	NetworkName       string `json:"networkName,omitempty"`
	MeshCIDR          string `json:"meshCIDR,omitempty"`
	MeshIP            string `json:"meshIP"`
	AnchorEndpoint    string `json:"anchorEndpoint,omitempty"`
	MemberRecordID    string `json:"memberRecordId,omitempty"`
	MemberDateCreated string `json:"memberDateCreated,omitempty"`
	NodeRecordID      string `json:"nodeRecordId"`
	NodeDateCreated   string `json:"nodeDateCreated,omitempty"`
	Label             string `json:"label,omitempty"`
	ExpiresAt         string `json:"expiresAt,omitempty"`
	ApprovedAt        string `json:"approvedAt"`
	RequestRecordID   string `json:"requestRecordId,omitempty"`
}

// WriteOwnerNodeRequest writes a root nodeRequest to the owner DWN. This is the
// default enrollment request used when a CLI node asks a wallet/account owner to
// approve it from the dashboard.
func WriteOwnerNodeRequest(ctx context.Context, params OwnerNodeRequestParams) (string, error) {
	data, err := ownerNodeRequestData(params)
	if err != nil {
		return "", err
	}
	dataBytes, err := json.Marshal(data)
	if err != nil {
		return "", fmt.Errorf("marshaling owner node request: %w", err)
	}

	agent := dwn.NewSimpleAgent(params.OwnerEndpoint, params.Signer)
	api := dwn.NewDwnAPI(agent)
	record, status, err := api.Write(ctx, params.OwnerDID, dwn.WriteParams{
		Protocol:     protocols.MeshProtocolURI,
		ProtocolPath: "nodeRequest",
		Schema:       schemaNodeRequest,
		DataFormat:   "application/json",
		Recipient:    params.OwnerDID,
		Data:         dataBytes,
	})
	if err != nil {
		return "", fmt.Errorf("writing owner node request: %w", err)
	}
	if status.Code >= 300 {
		return "", fmt.Errorf("owner node request write failed: %d %s", status.Code, status.Detail)
	}
	return record.ID, nil
}

func ownerNodeRequestData(params OwnerNodeRequestParams) (NodeRequestData, error) {
	if params.OwnerEndpoint == "" {
		return NodeRequestData{}, fmt.Errorf("owner DWN endpoint is required")
	}
	if params.OwnerDID == "" {
		return NodeRequestData{}, fmt.Errorf("owner DID is required")
	}
	if params.NodeDID == "" {
		return NodeRequestData{}, fmt.Errorf("node DID is required")
	}
	if params.Signer == nil || params.Signer.DID == "" || len(params.Signer.PrivateKey) != ed25519.PrivateKeySize {
		return NodeRequestData{}, fmt.Errorf("node signer is required")
	}
	if params.Signer.DID != params.NodeDID {
		return NodeRequestData{}, fmt.Errorf("node signer DID %s does not match node DID %s", params.Signer.DID, params.NodeDID)
	}

	roleKeys, err := nodeRoleKeys(params.NodeEncryptionKey)
	if err != nil {
		return NodeRequestData{}, err
	}

	requestedAt := time.Now().UTC().Format(time.RFC3339)
	return NodeRequestData{
		NodeDID:     params.NodeDID,
		MemberDID:   params.OwnerDID,
		OwnerDID:    params.OwnerDID,
		RequestedBy: params.NodeDID,
		NodeProof:   SignOwnerNodeRequestProof(params.Signer, params.OwnerDID, params.NodeDID, params.SourceDWN, requestedAt),
		RequestKind: "owner-node",
		SourceDWN:   params.SourceDWN,
		Label:       params.Label,
		RequestedAt: requestedAt,
		RoleKeys:    roleKeys,
	}, nil
}

// OwnerNodeRequestProofMessage returns the stable message signed by a node DID
// when it asks an owner DID to approve the device from the dashboard.
func OwnerNodeRequestProofMessage(ownerDID, nodeDID, sourceDWN, requestedAt string) []byte {
	return []byte(
		"meshd owner node request v1\n" +
			"owner=" + ownerDID + "\n" +
			"node=" + nodeDID + "\n" +
			"sourceDWN=" + sourceDWN + "\n" +
			"requestedAt=" + requestedAt + "\n",
	)
}

// SignOwnerNodeRequestProof signs an owner-scoped node request with the node DID.
func SignOwnerNodeRequestProof(signer *dwn.Signer, ownerDID, nodeDID, sourceDWN, requestedAt string) string {
	if signer == nil || signer.DID == "" || len(signer.PrivateKey) != ed25519.PrivateKeySize {
		return ""
	}
	msg := OwnerNodeRequestProofMessage(ownerDID, nodeDID, sourceDWN, requestedAt)
	sig := ed25519.Sign(signer.PrivateKey, msg)
	return base64.RawURLEncoding.EncodeToString(sig)
}

// VerifyOwnerNodeRequestProof verifies an owner-scoped request proof from a
// did:jwk node DID.
func VerifyOwnerNodeRequestProof(request NodeRequestData) bool {
	if request.NodeDID == "" || request.OwnerDID == "" || request.NodeProof == "" || request.RequestedAt == "" {
		return false
	}
	pub, err := did.ParseURI(request.NodeDID)
	if err != nil {
		return false
	}
	sig, err := base64.RawURLEncoding.DecodeString(request.NodeProof)
	if err != nil {
		return false
	}
	msg := OwnerNodeRequestProofMessage(request.OwnerDID, request.NodeDID, request.SourceDWN, request.RequestedAt)
	return did.VerifyWith(pub, msg, sig)
}

// FindOwnerNodeApproval returns the newest owner approval addressed to nodeDID.
func FindOwnerNodeApproval(ctx context.Context, ownerEndpoint, ownerDID, nodeDID string, signer *dwn.Signer) (*NodeApprovalData, string, error) {
	if ownerEndpoint == "" {
		return nil, "", fmt.Errorf("owner DWN endpoint is required")
	}
	if ownerDID == "" {
		return nil, "", fmt.Errorf("owner DID is required")
	}
	if nodeDID == "" {
		return nil, "", fmt.Errorf("node DID is required")
	}

	agent := dwn.NewSimpleAgent(ownerEndpoint, signer)
	api := dwn.NewDwnAPI(agent)
	records, status, err := api.Query(ctx, ownerDID, dwn.QueryParams{
		Filter: dwn.RecordsFilter{
			Protocol:     protocols.MeshProtocolURI,
			ProtocolPath: "nodeApproval",
			Recipient:    nodeDID,
		},
		DateSort: "createdDescending",
	}, "")
	if err != nil {
		return nil, "", fmt.Errorf("querying owner node approvals: %w", err)
	}
	if status.Code != 200 {
		return nil, "", fmt.Errorf("querying owner node approvals failed: %d %s", status.Code, status.Detail)
	}

	for _, record := range records {
		var approval NodeApprovalData
		if err := record.Data().JSON(ctx, &approval); err != nil {
			continue
		}
		if approval.OwnerDID != ownerDID || approval.NodeDID != nodeDID {
			continue
		}
		if approval.NetworkRecordID == "" || approval.NodeRecordID == "" || approval.MeshIP == "" {
			continue
		}
		return &approval, record.ID, nil
	}
	return nil, "", nil
}
