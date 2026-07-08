package mesh

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/enboxorg/meshd/internal/did"
	"github.com/enboxorg/meshd/internal/dwn"
	dwncrypto "github.com/enboxorg/meshd/internal/dwn/crypto"
	"github.com/enboxorg/meshd/internal/invite"
	"github.com/enboxorg/meshd/protocols"
)

func TestApprovePreAuthRequestsRegistersWalletOwnedNodeUnderMember(t *testing.T) {
	anchor := preAuthTestDID(t)
	member := preAuthTestDID(t)
	node := preAuthTestDID(t)

	const (
		networkID       = "network-record"
		requestRecordID = "request-record"
		preAuthRecordID = "preauth-record"
		preAuthSecret   = "preauth-secret"
	)

	nodeSigner := &dwn.Signer{DID: node.URI, PrivateKey: node.SigningKey}
	nodeRequest := NodeRequestData{
		NodeDID:      node.URI,
		MemberDID:    member.URI,
		RequestedBy:  member.URI,
		NodeProof:    SignNodeJoinProof(nodeSigner, networkID, node.URI, member.URI, preAuthRecordID),
		Label:        "wallet-owned-node",
		PreAuthKeyID: preAuthRecordID,
		PreAuthProof: invite.Proof(preAuthSecret, networkID, node.URI),
		RequestedAt:  time.Now().UTC().Format(time.RFC3339),
	}
	preAuthKey := PreAuthKeyData{
		Key:       preAuthSecret,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
		Label:     "wallet-owned-node",
	}

	// The joiner has the mesh protocol installed on its own tenant (as
	// `meshd join` ensures) — the delivery record is wrapped to the
	// role-path key it publishes there.
	nodeInstalledDef, err := dwncrypto.InjectEncryptionDirectives(protocols.MeshProtocolJSON, node.EncryptionPrivateKey)
	if err != nil {
		t.Fatalf("injecting node encryption keys: %v", err)
	}

	var (
		mu                  sync.Mutex
		memberRecordID      string
		memberNodeWrite     *dwn.Message
		topLevelNodeWritten bool
		deleteRecordID      string
		deliveryWrites      []*dwn.Message
		deliveryBodies      [][]byte
	)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var rpcReq dwn.JsonRpcRequest
		if err := json.Unmarshal([]byte(r.Header.Get("dwn-request")), &rpcReq); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if rpcReq.Params == nil || rpcReq.Params.Message == nil {
			http.Error(w, "missing DWN message", http.StatusBadRequest)
			return
		}

		msg := rpcReq.Params.Message
		if descriptorString(msg.Descriptor, "interface") == "Protocols" {
			// The delivery flow fetches the RECIPIENT's installed protocol
			// definition to find its role-path $keyAgreement key.
			entry, err := json.Marshal(map[string]any{
				"descriptor": map[string]any{"definition": json.RawMessage(nodeInstalledDef)},
			})
			if err != nil {
				t.Fatalf("marshal protocols entry: %v", err)
			}
			writeDWNTestReply(t, w, rpcReq.ID, dwn.Status{Code: 200, Detail: "OK"}, []json.RawMessage{entry})
			return
		}
		switch descriptorString(msg.Descriptor, "method") {
		case "Query":
			filter, _ := msg.Descriptor["filter"].(map[string]any)
			var entries []json.RawMessage
			switch descriptorString(filter, "protocolPath") {
			case "network/node":
				entries = nil
			case "network/member":
				entries = nil
			case "network/nodeRequest":
				entries = []json.RawMessage{
					recordsWriteEntry(t, requestRecordID, networkID+"/"+requestRecordID, "network/nodeRequest", "", nodeRequest),
				}
			case "network/preAuthKey":
				entries = []json.RawMessage{
					recordsWriteEntry(t, preAuthRecordID, networkID+"/"+preAuthRecordID, "network/preAuthKey", "", preAuthKey),
				}
			default:
				entries = nil
			}
			writeDWNTestReply(t, w, rpcReq.ID, dwn.Status{Code: 200, Detail: "OK"}, entries)
		case "Write":
			mu.Lock()
			switch descriptorString(msg.Descriptor, "protocolPath") {
			case "network/member":
				memberRecordID = msg.RecordID
			case "network/member/node":
				copyMsg := *msg
				memberNodeWrite = &copyMsg
			case "network/node":
				topLevelNodeWritten = true
			case dwncrypto.EncryptionControlDeliveryPath:
				copyMsg := *msg
				body, _ := io.ReadAll(r.Body)
				deliveryWrites = append(deliveryWrites, &copyMsg)
				deliveryBodies = append(deliveryBodies, body)
			}
			mu.Unlock()
			writeDWNTestReply(t, w, rpcReq.ID, dwn.Status{Code: 202, Detail: "Accepted"}, nil)
		case "Delete":
			mu.Lock()
			deleteRecordID = descriptorString(msg.Descriptor, "recordId")
			mu.Unlock()
			writeDWNTestReply(t, w, rpcReq.ID, dwn.Status{Code: 202, Detail: "Accepted"}, nil)
		default:
			t.Errorf("unexpected DWN method %q", descriptorString(msg.Descriptor, "method"))
			writeDWNTestReply(t, w, rpcReq.ID, dwn.Status{Code: 400, Detail: "Unexpected method"}, nil)
		}
	}))
	defer server.Close()

	ctx := context.Background()
	result, err := ApprovePreAuthRequests(ctx, ApprovePreAuthRequestsParams{
		AnchorEndpoint:  server.URL,
		AnchorDID:       anchor.URI,
		NetworkRecordID: networkID,
		MeshCIDR:        "10.200.0.0/16",
		Signer: &dwn.Signer{
			DID:        anchor.URI,
			PrivateKey: anchor.SigningKey,
		},
		EncryptionKeyManager: &dwncrypto.EncryptionKeyManager{
			RootPrivateKey: anchor.EncryptionPrivateKey,
			RootKeyID:      anchor.EncryptionKeyID(),
			ProtocolURI:    protocols.MeshProtocolURI,
		},
	})
	if err != nil {
		t.Fatalf("ApprovePreAuthRequests: %v", err)
	}
	if result.Approved != 1 || result.Pending != 0 || result.Rejected != 0 {
		t.Fatalf("result = %#v, want one approved request", result)
	}

	mu.Lock()
	defer mu.Unlock()
	if memberRecordID == "" {
		t.Fatal("member record was not created")
	}
	if memberNodeWrite == nil {
		t.Fatal("member-associated node record was not written")
	}
	if topLevelNodeWritten {
		t.Fatal("approved wallet-owned node was written as top-level network/node")
	}
	if got := descriptorString(memberNodeWrite.Descriptor, "protocolPath"); got != "network/member/node" {
		t.Fatalf("node protocolPath = %q, want network/member/node", got)
	}
	if got := descriptorString(memberNodeWrite.Descriptor, "recipient"); got != node.URI {
		t.Fatalf("node recipient = %q, want node DID", got)
	}
	if got := descriptorString(memberNodeWrite.Descriptor, "parentId"); got != memberRecordID {
		t.Fatalf("node parentId = %q, want member record %q", got, memberRecordID)
	}
	if wantPrefix := networkID + "/" + memberRecordID + "/"; !strings.HasPrefix(memberNodeWrite.ContextID, wantPrefix) {
		t.Fatalf("node contextId = %q, want prefix %q", memberNodeWrite.ContextID, wantPrefix)
	}
	if deleteRecordID != requestRecordID {
		t.Fatalf("deleted record = %q, want node request %q", deleteRecordID, requestRecordID)
	}

	// The approval must hand the joiner its role-audience key: a delivery
	// record for the required network/member/node role wrapped to the
	// node's role-path key, decryptable with the node's own root.
	var nodeDelivery *dwn.Message
	var deliveryData []byte
	for i, delivery := range deliveryWrites {
		if descriptorString(delivery.Descriptor, "recipient") != node.URI {
			continue
		}
		tags, _ := delivery.Descriptor["tags"].(map[string]any)
		if descriptorString(tags, "rolePath") == "network/member/node" {
			nodeDelivery = delivery
			deliveryData = deliveryBodies[i]
			break
		}
	}
	if nodeDelivery == nil {
		t.Fatalf("no network/member/node delivery record written for the joiner (deliveries: %d)", len(deliveryWrites))
	}
	tags, _ := nodeDelivery.Descriptor["tags"].(map[string]any)
	if got, want := descriptorString(tags, "contextId"), networkID+"/"+memberRecordID; got != want {
		t.Fatalf("delivery contextId = %q, want %q", got, want)
	}
	payload, err := dwncrypto.DecryptDeliveryRecord(node.EncryptionPrivateKey, protocols.MeshProtocolURI, "network/member/node", nodeDelivery.Encryption, deliveryData)
	if err != nil {
		t.Fatalf("joiner cannot decrypt its delivery record: %v", err)
	}
	if payload.RolePath != "network/member/node" || payload.KeyMaterial.PrivateKeyJwk.D == "" {
		t.Fatalf("delivery payload incomplete: %+v", payload)
	}
}

func preAuthTestDID(t *testing.T) *did.DID {
	t.Helper()
	id, err := did.Generate()
	if err != nil {
		t.Fatalf("Generate DID: %v", err)
	}
	return id
}

func recordsWriteEntry(t *testing.T, recordID, contextID, protocolPath, recipient string, data any) json.RawMessage {
	t.Helper()

	dataBytes, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("marshal entry data: %v", err)
	}

	descriptor := map[string]any{
		"interface":        "Records",
		"method":           "Write",
		"protocol":         protocols.MeshProtocolURI,
		"protocolPath":     protocolPath,
		"dataFormat":       "application/json",
		"dateCreated":      dwn.Now(),
		"messageTimestamp": dwn.Now(),
	}
	if recipient != "" {
		descriptor["recipient"] = recipient
	}

	entry := map[string]any{
		"recordId":    recordID,
		"contextId":   contextID,
		"descriptor":  descriptor,
		"encodedData": base64.RawURLEncoding.EncodeToString(dataBytes),
	}
	entryBytes, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("marshal entry: %v", err)
	}
	return entryBytes
}

func writeDWNTestReply(t *testing.T, w http.ResponseWriter, id string, status dwn.Status, entries []json.RawMessage) {
	t.Helper()

	var entriesJSON json.RawMessage
	if entries != nil {
		var err error
		entriesJSON, err = json.Marshal(entries)
		if err != nil {
			t.Fatalf("marshal entries: %v", err)
		}
	}

	reply := &dwn.JsonRpcResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result: &dwn.JsonRpcResult{
			Reply: &dwn.DwnReply{
				Status:  status,
				Entries: entriesJSON,
			},
		},
	}
	if err := json.NewEncoder(w).Encode(reply); err != nil {
		t.Fatalf("write DWN reply: %v", err)
	}
}

func descriptorString(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	v, _ := m[key].(string)
	return v
}
