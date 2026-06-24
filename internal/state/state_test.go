package state

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestNetworkStateOwnerDIDCompatibility(t *testing.T) {
	t.Run("save writes owner and legacy member aliases", func(t *testing.T) {
		dir := t.TempDir()
		if err := SaveNetworkState(dir, &NetworkState{
			NetworkRecordID: "network-1",
			OwnerDID:        "did:dht:wallet",
			NodeDID:         "did:jwk:node",
			NodeExpiresAt:   "2026-07-01T00:00:00Z",
			NodeLabel:       "server-01",
		}); err != nil {
			t.Fatalf("SaveNetworkState: %v", err)
		}

		data, err := os.ReadFile(filepath.Join(dir, networkFile))
		if err != nil {
			t.Fatalf("ReadFile: %v", err)
		}
		var raw map[string]any
		if err := json.Unmarshal(data, &raw); err != nil {
			t.Fatalf("Unmarshal: %v", err)
		}
		if raw["ownerDid"] != "did:dht:wallet" || raw["memberDid"] != "did:dht:wallet" {
			t.Fatalf("raw aliases = owner %v member %v", raw["ownerDid"], raw["memberDid"])
		}
		if raw["nodeExpiresAt"] != "2026-07-01T00:00:00Z" {
			t.Fatalf("raw nodeExpiresAt = %v", raw["nodeExpiresAt"])
		}
		if raw["nodeLabel"] != "server-01" {
			t.Fatalf("raw nodeLabel = %v", raw["nodeLabel"])
		}
	})

	t.Run("load old member state populates owner", func(t *testing.T) {
		dir := t.TempDir()
		data := []byte(`{"networkRecordId":"network-1","memberDid":"did:dht:wallet","nodeDid":"did:jwk:node"}`)
		if err := os.WriteFile(filepath.Join(dir, networkFile), data, 0600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}

		ns, err := LoadNetworkState(dir)
		if err != nil {
			t.Fatalf("LoadNetworkState: %v", err)
		}
		if ns.OwnerDID != "did:dht:wallet" || ns.MemberDID != "did:dht:wallet" {
			t.Fatalf("state aliases = owner %q member %q", ns.OwnerDID, ns.MemberDID)
		}
		if got := ns.EffectiveOwnerDID("fallback"); got != "did:dht:wallet" {
			t.Fatalf("EffectiveOwnerDID = %q", got)
		}
	})
}
