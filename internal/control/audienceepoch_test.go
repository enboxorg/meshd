package control

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

func encodeAudienceEpochEntry(t *testing.T, payload map[string]any, wrapped bool) json.RawMessage {
	t.Helper()
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(data)
	if wrapped {
		return mustJSON(t, map[string]any{
			"recordsWrite": map[string]any{"encodedData": encoded},
		})
	}
	return mustJSON(t, map[string]any{"encodedData": encoded})
}

func mustJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func TestParseAudienceEpochEntry(t *testing.T) {
	payload := map[string]any{
		"protocol":  "https://enbox.id/protocols/test-mesh",
		"contextId": "ctx-root",
		"role":      "network/node",
		"epoch":     2,
		"keyId":     "kid-2",
		"publicKeyJwk": map[string]any{
			"kty": "OKP",
			"crv": "X25519",
			"x":   "uWBSQ-LMmc5Krs4QF5DQhDx9Kc2o_J0LoTTHygMd1GY",
			"kid": "kid-2",
		},
	}

	for _, wrapped := range []bool{false, true} {
		entry := encodeAudienceEpochEntry(t, payload, wrapped)
		got, ok := parseAudienceEpochEntry(entry)
		if !ok {
			t.Fatalf("parseAudienceEpochEntry(wrapped=%v) returned ok=false", wrapped)
		}
		if got.Role != "network/node" || got.Epoch != 2 || got.KeyID != "kid-2" {
			t.Fatalf("parsed payload = %+v", got)
		}
		if got.PublicKeyJwk.X != "uWBSQ-LMmc5Krs4QF5DQhDx9Kc2o_J0LoTTHygMd1GY" {
			t.Fatalf("publicKeyJwk.x = %q", got.PublicKeyJwk.X)
		}
	}

	if _, ok := parseAudienceEpochEntry(json.RawMessage(`{"foo":"bar"}`)); ok {
		t.Fatal("expected ok=false for entry without encodedData")
	}
}

func TestSelectLatestAudienceEpoch(t *testing.T) {
	const proto = "https://enbox.id/protocols/test-mesh"
	mk := func(role string, epoch int, x string) audienceEpochPayload {
		p := audienceEpochPayload{Protocol: proto, ContextID: "ctx", Role: role, Epoch: epoch, KeyID: "k"}
		p.PublicKeyJwk.X = x
		return p
	}

	payloads := []audienceEpochPayload{
		mk("network/node", 1, "aaa"),
		mk("network/node", 3, "ccc"), // highest for network/node
		mk("network/node", 2, "bbb"),
		mk("network/member", 9, "zzz"),                                       // different role
		{Protocol: proto, ContextID: "ctx", Role: "network/node", Epoch: 99}, // no public key — must be ignored
	}

	best, ok := selectLatestAudienceEpoch(payloads, proto, "ctx", "network/node")
	if !ok {
		t.Fatal("expected a match")
	}
	if best.Epoch != 3 || best.PublicKeyJwk.X != "ccc" {
		t.Fatalf("selected epoch = %d (x=%q), want 3 (ccc)", best.Epoch, best.PublicKeyJwk.X)
	}

	// Wrong context -> no match.
	if _, ok := selectLatestAudienceEpoch(payloads, proto, "other", "network/node"); ok {
		t.Fatal("expected no match for unknown context")
	}
	// Empty set -> no match.
	if _, ok := selectLatestAudienceEpoch(nil, proto, "ctx", "network/node"); ok {
		t.Fatal("expected no match for empty payloads")
	}
}
