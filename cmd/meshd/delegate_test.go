package main

import (
	"encoding/json"
	"testing"

	"github.com/enboxorg/meshd/internal/mesh"
	"github.com/enboxorg/meshd/internal/profile"
	"github.com/enboxorg/meshd/internal/state"
	"github.com/enboxorg/meshd/protocols"
)

func TestWalletSessionHasDelegatedMeshGrants(t *testing.T) {
	meta := identityMetadata{
		AuthType:    profile.AuthTypeWalletAuthorizedNode,
		OwnerDID:    "did:dht:wallet",
		NodeDID:     "did:jwk:node",
		DelegateDID: "did:jwk:delegate",
	}
	readGrant := testWalletPermissionGrant(t, "grant-read", "did:dht:wallet", "did:jwk:delegate", map[string]any{
		"interface": "Records",
		"method":    "Read",
		"protocol":  protocols.MeshProtocolURI,
	})
	writeGrant := testWalletPermissionGrant(t, "grant-write", "did:dht:wallet", "did:jwk:delegate", map[string]any{
		"interface": "Records",
		"method":    "Write",
		"protocol":  protocols.MeshProtocolURI,
	})
	plainReadGrant := testWalletGrantMessage(t, "plain-read", "did:dht:wallet", "did:jwk:delegate", false, map[string]any{
		"interface": "Records",
		"method":    "Read",
		"protocol":  protocols.MeshProtocolURI,
	})
	plainWriteGrant := testWalletGrantMessage(t, "plain-write", "did:dht:wallet", "did:jwk:delegate", false, map[string]any{
		"interface": "Records",
		"method":    "Write",
		"protocol":  protocols.MeshProtocolURI,
	})

	session := &state.WalletSession{
		Version:     1,
		OwnerDID:    "did:dht:wallet",
		NodeDID:     "did:jwk:node",
		DelegateDID: "did:jwk:delegate",
		Grants:      []json.RawMessage{readGrant, writeGrant},
	}
	if !walletSessionHasDelegatedMeshGrants(session, meta) {
		t.Fatal("delegated read+write session should be detected as an enbox session")
	}

	session.Grants = []json.RawMessage{readGrant}
	if walletSessionHasDelegatedMeshGrants(session, meta) {
		t.Fatal("session without a delegated write grant must not be detected as an enbox session")
	}

	session.Grants = []json.RawMessage{plainReadGrant, plainWriteGrant}
	if walletSessionHasDelegatedMeshGrants(session, meta) {
		t.Fatal("plain (legacy) grants must not be detected as an enbox session")
	}

	if walletSessionHasDelegatedMeshGrants(nil, meta) {
		t.Fatal("nil session must not be detected as an enbox session")
	}
}

func TestDelegateNetworkState(t *testing.T) {
	result := &mesh.DelegateNetworkResult{
		NetworkRecordID: "network-1",
		NetworkName:     "home",
		MeshCIDR:        "10.200.0.0/16",
		MeshIP:          "10.200.4.5",
		NodeRecordID:    "node-1",
		NodeDateCreated: "2026-07-01T00:00:00Z",
	}
	ns := delegateNetworkState(result, "did:dht:wallet", "https://dwn.example", "did:jwk:node", "did:jwk:delegate")
	if ns == nil {
		t.Fatal("delegateNetworkState returned nil")
	}
	if ns.NetworkRecordID != "network-1" || ns.NetworkName != "home" ||
		ns.MeshCIDR != "10.200.0.0/16" || ns.MeshIP != "10.200.4.5" ||
		ns.NodeRecordID != "node-1" || ns.NodeDateCreated != "2026-07-01T00:00:00Z" {
		t.Fatalf("network fields = %+v", ns)
	}
	// The wallet owner anchors the network and is recorded as the member.
	if ns.AnchorDID != "did:dht:wallet" || ns.OwnerDID != "did:dht:wallet" || ns.MemberDID != "did:dht:wallet" {
		t.Fatalf("owner fields = %+v", ns)
	}
	if ns.AnchorEndpoint != "https://dwn.example" {
		t.Fatalf("anchor endpoint = %q", ns.AnchorEndpoint)
	}
	if ns.NodeDID != "did:jwk:node" || ns.DelegateDID != "did:jwk:delegate" {
		t.Fatalf("node/delegate fields = %+v", ns)
	}

	if delegateNetworkState(nil, "o", "e", "n", "d") != nil {
		t.Fatal("nil result must map to nil state")
	}
}

func TestDelegateOwnerEndpoint(t *testing.T) {
	t.Setenv(walletResponseEndpointEnv, "")
	t.Setenv("DWN_ENDPOINT", "")

	if got := delegateOwnerEndpoint("https://explicit.example/"); got != "https://explicit.example/" {
		t.Fatalf("explicit endpoint = %q", got)
	}
	if got := delegateOwnerEndpoint(""); got != defaultWalletResponseEndpoint {
		t.Fatalf("default endpoint = %q, want %q", got, defaultWalletResponseEndpoint)
	}

	t.Setenv("DWN_ENDPOINT", "https://dwn-env.example/")
	if got := delegateOwnerEndpoint(""); got != "https://dwn-env.example" {
		t.Fatalf("DWN_ENDPOINT endpoint = %q", got)
	}

	t.Setenv(walletResponseEndpointEnv, "https://relay-env.example/")
	if got := delegateOwnerEndpoint(""); got != "https://relay-env.example" {
		t.Fatalf("wallet response endpoint = %q", got)
	}
}
