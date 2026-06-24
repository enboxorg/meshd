package walletconnect

import (
	"encoding/json"
	"testing"

	"github.com/enboxorg/meshd/internal/did"
)

func TestRequestEncodeDecodeVerifiesNodeProof(t *testing.T) {
	node, err := did.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	req, err := NewRequest("personal", node)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if req.NodeProof == "" {
		t.Fatal("node proof is empty")
	}
	if req.NodeKeyDelivery == nil || req.NodeKeyDelivery.RootKeyID != node.EncryptionKeyID() {
		t.Fatalf("node key delivery = %+v, want root %s", req.NodeKeyDelivery, node.EncryptionKeyID())
	}

	encoded, err := EncodeRequest(req)
	if err != nil {
		t.Fatalf("EncodeRequest: %v", err)
	}
	decoded, err := DecodeRequest(encoded)
	if err != nil {
		t.Fatalf("DecodeRequest: %v", err)
	}
	if decoded.NodeDID != node.URI {
		t.Fatalf("node DID = %q, want %q", decoded.NodeDID, node.URI)
	}
	if len(decoded.Permissions) != 1 || decoded.Permissions[0] != "mesh-node" {
		t.Fatalf("permissions = %v, want [mesh-node]", decoded.Permissions)
	}
	if !VerifyNodeProof(decoded.NodeDID, decoded.NodeProof, decoded.Challenge, "", "", "", permissionsProofValue(decoded.Permissions)) {
		t.Fatal("node proof did not verify")
	}
}

func TestRequestRejectsTamperedChallenge(t *testing.T) {
	node, err := did.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	req, err := NewRequest("personal", node)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Challenge = "tampered"
	if err := req.Validate(); err == nil {
		t.Fatal("expected tampered request to fail validation")
	}
}

func TestRequestRejectsTamperedResponseEndpoint(t *testing.T) {
	node, err := did.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	req, err := NewRequest("personal", node)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.CallbackURL = "http://127.0.0.1:1234/meshd/wallet-callback/token"
	req.ResponseEndpoint = "https://dev.aws.dwn.enbox.id"
	req.ResponseToken = "response-token"
	if err := SignRequest(node, &req); err != nil {
		t.Fatalf("SignRequest: %v", err)
	}
	if err := req.Validate(); err != nil {
		t.Fatalf("Validate signed request: %v", err)
	}

	req.ResponseEndpoint = "https://attacker.example"
	if err := req.Validate(); err == nil {
		t.Fatal("expected tampered response endpoint to fail validation")
	}
}

func TestRequestRejectsTamperedPermissions(t *testing.T) {
	node, err := did.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	req, err := NewRequest("personal", node)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Permissions = append(req.Permissions, "mesh-admin")
	if err := req.Validate(); err == nil {
		t.Fatal("expected tampered permissions to fail validation")
	}
}

func TestNetworkCreateRequestEncodeDecodeVerifiesNodeProof(t *testing.T) {
	node, err := did.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	req, err := NewNetworkCreateRequest(
		"personal",
		node,
		"home",
		"https://dev.aws.dwn.enbox.id",
		"10.200.0.0/16",
	)
	if err != nil {
		t.Fatalf("NewNetworkCreateRequest: %v", err)
	}
	if req.NodeProof == "" {
		t.Fatal("node proof is empty")
	}
	if req.NodeKeyDelivery == nil || req.NodeKeyDelivery.RootKeyID != node.EncryptionKeyID() {
		t.Fatalf("node key delivery = %+v, want root %s", req.NodeKeyDelivery, node.EncryptionKeyID())
	}

	encoded, err := EncodeNetworkCreateRequest(req)
	if err != nil {
		t.Fatalf("EncodeNetworkCreateRequest: %v", err)
	}
	decoded, err := DecodeNetworkCreateRequest(encoded)
	if err != nil {
		t.Fatalf("DecodeNetworkCreateRequest: %v", err)
	}
	if decoded.NodeDID != node.URI {
		t.Fatalf("node DID = %q, want %q", decoded.NodeDID, node.URI)
	}
	if decoded.NetworkName != "home" || decoded.RequestedEndpoint != "https://dev.aws.dwn.enbox.id" {
		t.Fatalf("decoded network request = %+v", decoded)
	}
	if !VerifyNetworkCreateProof(decoded.NodeDID, decoded.NodeProof, decoded.Challenge, decoded.NetworkName, decoded.RequestedEndpoint, decoded.MeshCIDR) {
		t.Fatal("network create node proof did not verify")
	}
}

func TestResponseEnvelopeRoundTrip(t *testing.T) {
	response := json.RawMessage(`{"version":1,"type":"meshd-cli-connect-response","connectedDid":"did:jwk:wallet","nodeDid":"did:jwk:node"}`)
	env, err := NewResponseEnvelope("response-token", response)
	if err != nil {
		t.Fatalf("NewResponseEnvelope: %v", err)
	}
	data, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	got, err := DecodeResponseEnvelope(data, "response-token")
	if err != nil {
		t.Fatalf("DecodeResponseEnvelope: %v", err)
	}
	if string(got) != string(response) {
		t.Fatalf("response = %s, want %s", got, response)
	}
	if _, err := DecodeResponseEnvelope(data, "wrong-token"); err == nil {
		t.Fatal("expected token mismatch to fail")
	}
}

func TestResponseOwnerDIDCompatibility(t *testing.T) {
	resp := Response{
		Version:  1,
		Type:     ResponseType,
		OwnerDID: "did:jwk:wallet",
		NodeDID:  "did:jwk:node",
	}
	if err := resp.Validate(); err != nil {
		t.Fatalf("ownerDID response Validate: %v", err)
	}
	resp.NormalizeOwnerDID()
	if resp.ConnectedDID != "did:jwk:wallet" || resp.EffectiveOwnerDID() != "did:jwk:wallet" {
		t.Fatalf("owner aliases = owner %q connected %q", resp.OwnerDID, resp.ConnectedDID)
	}

	legacy := Response{
		Version:      1,
		Type:         ResponseType,
		ConnectedDID: "did:jwk:wallet",
		NodeDID:      "did:jwk:node",
	}
	if err := legacy.Validate(); err != nil {
		t.Fatalf("legacy response Validate: %v", err)
	}
	legacy.NormalizeOwnerDID()
	if legacy.OwnerDID != "did:jwk:wallet" || legacy.EffectiveOwnerDID() != "did:jwk:wallet" {
		t.Fatalf("legacy owner aliases = owner %q connected %q", legacy.OwnerDID, legacy.ConnectedDID)
	}
}

func TestNetworkCreateResponseOwnerDIDCompatibility(t *testing.T) {
	resp := NetworkCreateResponse{
		Version:         1,
		Type:            NetworkCreateResponseType,
		OwnerDID:        "did:jwk:wallet",
		NodeDID:         "did:jwk:node",
		AnchorEndpoint:  "https://dev.aws.dwn.enbox.id",
		NetworkRecordID: "network-1",
		NetworkName:     "home",
		MeshCIDR:        "10.200.0.0/16",
		MeshIP:          "10.200.1.2",
	}
	if err := resp.Validate(); err != nil {
		t.Fatalf("ownerDID network response Validate: %v", err)
	}
	resp.NormalizeOwnerDID()
	if resp.ConnectedDID != "did:jwk:wallet" || resp.EffectiveOwnerDID() != "did:jwk:wallet" {
		t.Fatalf("network owner aliases = owner %q connected %q", resp.OwnerDID, resp.ConnectedDID)
	}
}

func TestResponseNodeContextKeysPreferNodeFieldsWithDelegateFallback(t *testing.T) {
	nodeKey := json.RawMessage(`{"contextId":"node"}`)
	delegateKey := json.RawMessage(`{"contextId":"legacy"}`)

	resp := Response{
		NodeContextKeys:             []json.RawMessage{nodeKey},
		NodeMultiPartyProtocols:     []string{"node-protocol"},
		DelegateContextKeys:         []json.RawMessage{delegateKey},
		DelegateMultiPartyProtocols: []string{"legacy-protocol"},
	}
	if got := resp.EffectiveNodeContextKeys(); len(got) != 1 || string(got[0]) != string(nodeKey) {
		t.Fatalf("response node context keys = %v", got)
	}
	if got := resp.EffectiveNodeMultiPartyProtocols(); len(got) != 1 || got[0] != "node-protocol" {
		t.Fatalf("response node protocols = %v", got)
	}

	legacy := NetworkCreateResponse{
		DelegateContextKeys:         []json.RawMessage{delegateKey},
		DelegateMultiPartyProtocols: []string{"legacy-protocol"},
	}
	if got := legacy.EffectiveNodeContextKeys(); len(got) != 1 || string(got[0]) != string(delegateKey) {
		t.Fatalf("legacy network response context keys = %v", got)
	}
	if got := legacy.EffectiveNodeMultiPartyProtocols(); len(got) != 1 || got[0] != "legacy-protocol" {
		t.Fatalf("legacy network response protocols = %v", got)
	}
}

func TestNetworkCreateRequestRejectsTamperedNetworkName(t *testing.T) {
	node, err := did.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	req, err := NewNetworkCreateRequest(
		"personal",
		node,
		"home",
		"https://dev.aws.dwn.enbox.id",
		"10.200.0.0/16",
	)
	if err != nil {
		t.Fatalf("NewNetworkCreateRequest: %v", err)
	}
	req.NetworkName = "tampered"
	if err := req.Validate(); err == nil {
		t.Fatal("expected tampered request to fail validation")
	}
}
