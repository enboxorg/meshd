package state

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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
		NodeMultiPartyProtocols: []string{"https://enbox.id/protocols/wireguard-mesh"},
	}
	if err := StoreWalletSession(dir, session); err != nil {
		t.Fatalf("StoreWalletSession: %v", err)
	}
	if !WalletSessionExists(dir) {
		t.Fatal("wallet session file not found")
	}
	info, err := os.Stat(filepath.Join(dir, walletSessionFile))
	if err != nil {
		t.Fatalf("stat session file: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("session file mode = %o, want 0600", info.Mode().Perm())
	}

	got, err := LoadWalletSession(dir)
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
	if err := StoreWalletSession(dir, session); err != nil {
		t.Fatalf("StoreWalletSession: %v", err)
	}

	got, err := LoadWalletSession(dir)
	if err != nil {
		t.Fatalf("LoadWalletSession: %v", err)
	}
	if got.OwnerDID != "did:dht:wallet" || got.ConnectedDID != "did:dht:wallet" {
		t.Fatalf("owner aliases = owner %q connected %q", got.OwnerDID, got.ConnectedDID)
	}
}

func TestWalletSessionLegacyDelegateMultiPartyProtocolsFallback(t *testing.T) {
	dir := t.TempDir()
	session := &WalletSession{
		ConnectedDID:                "did:dht:wallet",
		NodeDID:                     "did:jwk:node",
		DelegateMultiPartyProtocols: []string{"https://enbox.id/protocols/wireguard-mesh"},
	}
	if err := StoreWalletSession(dir, session); err != nil {
		t.Fatalf("StoreWalletSession: %v", err)
	}

	got, err := LoadWalletSession(dir)
	if err != nil {
		t.Fatalf("LoadWalletSession: %v", err)
	}
	if len(got.NodeMultiPartyProtocols) != 1 || len(got.EffectiveNodeMultiPartyProtocols()) != 1 {
		t.Fatalf("node protocols = direct %v effective %v", got.NodeMultiPartyProtocols, got.EffectiveNodeMultiPartyProtocols())
	}
}

func TestWalletSessionFailsOnLegacyVault(t *testing.T) {
	dir := t.TempDir()
	legacyPath := filepath.Join(dir, "session.vault.json")
	if err := os.WriteFile(legacyPath, []byte(`{"version":1,"kdf":"argon2id"}`), 0o600); err != nil {
		t.Fatalf("write legacy vault: %v", err)
	}

	if !WalletSessionExists(dir) {
		t.Fatal("WalletSessionExists = false with a legacy vault present; callers would treat the profile as never connected")
	}
	_, err := LoadWalletSession(dir)
	if err == nil || !strings.Contains(err.Error(), "encrypted vaults were removed") {
		t.Fatalf("LoadWalletSession error = %v, want vaults-removed guidance", err)
	}
	if !strings.Contains(err.Error(), legacyPath) {
		t.Fatalf("LoadWalletSession error = %v, want legacy path %s", err, legacyPath)
	}
	err = StoreWalletSession(dir, &WalletSession{OwnerDID: "did:dht:wallet", NodeDID: "did:jwk:node"})
	if err == nil || !strings.Contains(err.Error(), "encrypted vaults were removed") {
		t.Fatalf("StoreWalletSession error = %v, want vaults-removed guidance", err)
	}
}
