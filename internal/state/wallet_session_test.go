package state

import (
	"encoding/json"
	"testing"
)

func TestWalletSessionRoundTrip(t *testing.T) {
	dir := t.TempDir()
	session := &WalletSession{
		OwnerDID:                "did:dht:wallet",
		DelegateDID:             "did:jwk:delegate",
		NodeDID:                 "did:jwk:node",
		WalletOrigin:            "https://wallet.enbox.id",
		ExpiresAt:               "2026-07-23T00:00:00Z",
		Grants:                  []json.RawMessage{json.RawMessage(`{"id":"grant-1"}`)},
		NodeContextKeys:         []json.RawMessage{json.RawMessage(`{"contextId":"network-1"}`)},
		NodeMultiPartyProtocols: []string{"https://enbox.id/protocols/wireguard-mesh"},
	}
	if err := StoreWalletSession(dir, "password", session); err != nil {
		t.Fatalf("StoreWalletSession: %v", err)
	}
	if !WalletSessionExists(dir) {
		t.Fatal("wallet session file not found")
	}

	got, err := LoadWalletSession(dir, "password")
	if err != nil {
		t.Fatalf("LoadWalletSession: %v", err)
	}
	if got.EffectiveOwnerDID() != session.OwnerDID {
		t.Fatalf("owner DID = %q", got.EffectiveOwnerDID())
	}
	if got.ConnectedDID != session.OwnerDID {
		t.Fatalf("legacy connected DID = %q", got.ConnectedDID)
	}
	if got.NodeDID != session.NodeDID {
		t.Fatalf("node DID = %q", got.NodeDID)
	}
	if len(got.Grants) != 1 || string(got.Grants[0]) != `{"id":"grant-1"}` {
		t.Fatalf("grants = %v", got.Grants)
	}
	if len(got.EffectiveNodeContextKeys()) != 1 {
		t.Fatalf("node context keys = %v", got.EffectiveNodeContextKeys())
	}
	if len(got.EffectiveNodeMultiPartyProtocols()) != 1 {
		t.Fatalf("node protocols = %v", got.EffectiveNodeMultiPartyProtocols())
	}
}

func TestWalletSessionLegacyConnectedDIDFallback(t *testing.T) {
	dir := t.TempDir()
	session := &WalletSession{
		ConnectedDID: "did:dht:wallet",
		NodeDID:      "did:jwk:node",
	}
	if err := StoreWalletSession(dir, "password", session); err != nil {
		t.Fatalf("StoreWalletSession: %v", err)
	}

	got, err := LoadWalletSession(dir, "password")
	if err != nil {
		t.Fatalf("LoadWalletSession: %v", err)
	}
	if got.OwnerDID != "did:dht:wallet" || got.ConnectedDID != "did:dht:wallet" {
		t.Fatalf("owner aliases = owner %q connected %q", got.OwnerDID, got.ConnectedDID)
	}
}

func TestWalletSessionLegacyDelegateContextKeysFallback(t *testing.T) {
	dir := t.TempDir()
	session := &WalletSession{
		ConnectedDID:                "did:dht:wallet",
		NodeDID:                     "did:jwk:node",
		DelegateContextKeys:         []json.RawMessage{json.RawMessage(`{"contextId":"network-1"}`)},
		DelegateMultiPartyProtocols: []string{"https://enbox.id/protocols/wireguard-mesh"},
	}
	if err := StoreWalletSession(dir, "password", session); err != nil {
		t.Fatalf("StoreWalletSession: %v", err)
	}

	got, err := LoadWalletSession(dir, "password")
	if err != nil {
		t.Fatalf("LoadWalletSession: %v", err)
	}
	if len(got.NodeContextKeys) != 1 || len(got.EffectiveNodeContextKeys()) != 1 {
		t.Fatalf("node context keys = direct %v effective %v", got.NodeContextKeys, got.EffectiveNodeContextKeys())
	}
	if len(got.NodeMultiPartyProtocols) != 1 || len(got.EffectiveNodeMultiPartyProtocols()) != 1 {
		t.Fatalf("node protocols = direct %v effective %v", got.NodeMultiPartyProtocols, got.EffectiveNodeMultiPartyProtocols())
	}
}
