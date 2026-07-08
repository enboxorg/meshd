package dwn

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

// testPermissionGrantMessage builds a plain (non-delegated) grant message.
func testPermissionGrantMessage(t *testing.T, id string, grantor string, grantee string, scope PermissionScope, expires string) json.RawMessage {
	t.Helper()
	return testGrantMessage(t, id, grantor, grantee, scope, expires, false)
}

// testDelegatedGrantMessage builds a grant message with delegated:true.
func testDelegatedGrantMessage(t *testing.T, id string, grantor string, grantee string, scope PermissionScope, expires string) json.RawMessage {
	t.Helper()
	return testGrantMessage(t, id, grantor, grantee, scope, expires, true)
}

func testGrantMessage(t *testing.T, id string, grantor string, grantee string, scope PermissionScope, expires string, delegated bool) json.RawMessage {
	t.Helper()
	header, err := json.Marshal(map[string]string{
		"alg": "EdDSA",
		"kid": grantor + "#0",
	})
	if err != nil {
		t.Fatal(err)
	}
	grantData := map[string]any{
		"dateExpires": expires,
		"scope":       scope,
	}
	if delegated {
		grantData["delegated"] = true
	}
	data, err := json.Marshal(grantData)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := json.Marshal(map[string]any{
		"recordId":    id,
		"encodedData": base64.RawURLEncoding.EncodeToString(data),
		"descriptor": map[string]any{
			"recipient":   grantee,
			"dateCreated": "2026-06-23T00:00:00Z",
		},
		"authorization": map[string]any{
			"signature": map[string]any{
				"payload": "",
				"signatures": []map[string]any{{
					"protected": base64.RawURLEncoding.EncodeToString(header),
					"signature": "",
				}},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

func TestParsePermissionGrant(t *testing.T) {
	raw := testPermissionGrantMessage(t, "grant-read", "did:jwk:wallet", "did:jwk:node", PermissionScope{
		Interface: DwnScopeInterfaceRecords,
		Method:    DwnScopeMethodRead,
		Protocol:  "https://enbox.id/protocols/wireguard-mesh",
	}, "2026-06-24T00:00:00Z")

	grant, err := ParsePermissionGrant(raw)
	if err != nil {
		t.Fatalf("ParsePermissionGrant: %v", err)
	}
	if grant.ID != "grant-read" || grant.Grantor != "did:jwk:wallet" || grant.Grantee != "did:jwk:node" {
		t.Fatalf("grant identity fields = %+v", grant)
	}
	if grant.Scope.Interface != DwnScopeInterfaceRecords || grant.Scope.Method != DwnScopeMethodRead {
		t.Fatalf("scope = %+v", grant.Scope)
	}
}

func TestFindPermissionGrantID(t *testing.T) {
	grants := []json.RawMessage{
		testPermissionGrantMessage(t, "grant-read", "did:jwk:wallet", "did:jwk:node", PermissionScope{
			Interface: DwnScopeInterfaceRecords,
			Method:    DwnScopeMethodRead,
			Protocol:  "https://enbox.id/protocols/wireguard-mesh",
		}, "2026-06-24T00:00:00Z"),
		testPermissionGrantMessage(t, "grant-write", "did:jwk:wallet", "did:jwk:node", PermissionScope{
			Interface: DwnScopeInterfaceRecords,
			Method:    DwnScopeMethodWrite,
			Protocol:  "https://enbox.id/protocols/wireguard-mesh",
		}, "2026-06-24T00:00:00Z"),
		testPermissionGrantMessage(t, "grant-key-delivery-write", "did:jwk:wallet", "did:jwk:node", PermissionScope{
			Interface: DwnScopeInterfaceRecords,
			Method:    DwnScopeMethodWrite,
			Protocol:  "https://identity.foundation/protocols/key-delivery",
		}, "2026-06-24T00:00:00Z"),
	}

	now := time.Date(2026, 6, 23, 12, 0, 0, 0, time.UTC)
	got, err := FindPermissionGrantID(grants, PermissionGrantMatch{
		Grantor:     "did:jwk:wallet",
		Grantee:     "did:jwk:node",
		MessageType: InterfaceRecordsQuery,
		Protocol:    "https://enbox.id/protocols/wireguard-mesh",
		Now:         now,
	})
	if err != nil {
		t.Fatalf("FindPermissionGrantID: %v", err)
	}
	if got != "grant-read" {
		t.Fatalf("query grant = %q, want grant-read", got)
	}

	got, err = FindPermissionGrantID(grants, PermissionGrantMatch{
		Grantor:     "did:jwk:wallet",
		Grantee:     "did:jwk:node",
		MessageType: InterfaceRecordsWrite,
		Protocol:    "https://enbox.id/protocols/wireguard-mesh",
		Now:         now,
	})
	if err != nil {
		t.Fatalf("FindPermissionGrantID: %v", err)
	}
	if got != "grant-write" {
		t.Fatalf("write grant = %q, want grant-write", got)
	}

	got, err = FindPermissionGrantID(grants, PermissionGrantMatch{
		Grantor:     "did:jwk:wallet",
		Grantee:     "did:jwk:node",
		MessageType: InterfaceRecordsWrite,
		Protocol:    "https://identity.foundation/protocols/key-delivery",
		Now:         now,
	})
	if err != nil {
		t.Fatalf("FindPermissionGrantID: %v", err)
	}
	if got != "grant-key-delivery-write" {
		t.Fatalf("key-delivery write grant = %q, want grant-key-delivery-write", got)
	}
}

func TestFindPermissionGrantIDMatchesProtocolPathSpecificGrants(t *testing.T) {
	grants := []json.RawMessage{
		testPermissionGrantMessage(t, "grant-endpoint", "did:jwk:wallet", "did:jwk:node", PermissionScope{
			Interface:    DwnScopeInterfaceRecords,
			Method:       DwnScopeMethodWrite,
			Protocol:     "https://enbox.id/protocols/wireguard-mesh",
			ProtocolPath: "network/member/node/endpoint",
		}, "2026-06-24T00:00:00Z"),
		testPermissionGrantMessage(t, "grant-broad", "did:jwk:wallet", "did:jwk:node", PermissionScope{
			Interface: DwnScopeInterfaceRecords,
			Method:    DwnScopeMethodWrite,
			Protocol:  "https://enbox.id/protocols/wireguard-mesh",
		}, "2026-06-24T00:00:00Z"),
	}
	now := time.Date(2026, 6, 23, 12, 0, 0, 0, time.UTC)

	got, err := FindPermissionGrantID(grants, PermissionGrantMatch{
		Grantor:      "did:jwk:wallet",
		Grantee:      "did:jwk:node",
		MessageType:  InterfaceRecordsWrite,
		Protocol:     "https://enbox.id/protocols/wireguard-mesh",
		ProtocolPath: "network/member/node/endpoint",
		Now:          now,
	})
	if err != nil {
		t.Fatalf("FindPermissionGrantID endpoint: %v", err)
	}
	if got != "grant-endpoint" {
		t.Fatalf("endpoint grant = %q, want grant-endpoint", got)
	}

	got, err = FindPermissionGrantID(grants[:1], PermissionGrantMatch{
		Grantor:      "did:jwk:wallet",
		Grantee:      "did:jwk:node",
		MessageType:  InterfaceRecordsWrite,
		Protocol:     "https://enbox.id/protocols/wireguard-mesh",
		ProtocolPath: "network/preAuthKey",
		Now:          now,
	})
	if err != nil {
		t.Fatalf("FindPermissionGrantID preAuthKey: %v", err)
	}
	if got != "" {
		t.Fatalf("preAuthKey grant = %q, want none", got)
	}

	got, err = FindPermissionGrantID(grants[1:], PermissionGrantMatch{
		Grantor:      "did:jwk:wallet",
		Grantee:      "did:jwk:node",
		MessageType:  InterfaceRecordsWrite,
		Protocol:     "https://enbox.id/protocols/wireguard-mesh",
		ProtocolPath: "network/member/node/endpoint",
		Now:          now,
	})
	if err != nil {
		t.Fatalf("FindPermissionGrantID broad fallback: %v", err)
	}
	if got != "grant-broad" {
		t.Fatalf("broad fallback grant = %q, want grant-broad", got)
	}
}

func TestFindPermissionGrantIDRejectsExpiredAndWrongGrantee(t *testing.T) {
	grants := []json.RawMessage{
		testPermissionGrantMessage(t, "grant-expired", "did:jwk:wallet", "did:jwk:node", PermissionScope{
			Interface: DwnScopeInterfaceRecords,
			Method:    DwnScopeMethodRead,
			Protocol:  "https://enbox.id/protocols/wireguard-mesh",
		}, "2026-06-22T00:00:00Z"),
		testPermissionGrantMessage(t, "grant-other-node", "did:jwk:wallet", "did:jwk:other", PermissionScope{
			Interface: DwnScopeInterfaceRecords,
			Method:    DwnScopeMethodRead,
			Protocol:  "https://enbox.id/protocols/wireguard-mesh",
		}, "2026-06-24T00:00:00Z"),
	}

	got, err := FindPermissionGrantID(grants, PermissionGrantMatch{
		Grantor:     "did:jwk:wallet",
		Grantee:     "did:jwk:node",
		MessageType: InterfaceRecordsQuery,
		Protocol:    "https://enbox.id/protocols/wireguard-mesh",
		Now:         time.Date(2026, 6, 23, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("FindPermissionGrantID: %v", err)
	}
	if got != "" {
		t.Fatalf("grant = %q, want none", got)
	}
}

func TestParseDelegatedPermissionGrant(t *testing.T) {
	raw := testDelegatedGrantMessage(t, "grant-delegated", "did:jwk:wallet", "did:jwk:node", PermissionScope{
		Interface: DwnScopeInterfaceRecords,
		Method:    DwnScopeMethodWrite,
		Protocol:  "https://enbox.id/protocols/wireguard-mesh",
	}, "2026-06-24T00:00:00Z")

	grant, err := ParsePermissionGrant(raw)
	if err != nil {
		t.Fatalf("ParsePermissionGrant: %v", err)
	}
	if !grant.Delegated {
		t.Fatal("grant.Delegated = false, want true")
	}

	plain := testPermissionGrantMessage(t, "grant-plain", "did:jwk:wallet", "did:jwk:node", PermissionScope{
		Interface: DwnScopeInterfaceRecords,
		Method:    DwnScopeMethodWrite,
		Protocol:  "https://enbox.id/protocols/wireguard-mesh",
	}, "2026-06-24T00:00:00Z")

	grant, err = ParsePermissionGrant(plain)
	if err != nil {
		t.Fatalf("ParsePermissionGrant: %v", err)
	}
	if grant.Delegated {
		t.Fatal("grant.Delegated = true, want false")
	}
}

func TestFindPermissionGrantIDSkipsDelegatedGrants(t *testing.T) {
	scope := PermissionScope{
		Interface: DwnScopeInterfaceRecords,
		Method:    DwnScopeMethodWrite,
		Protocol:  "https://enbox.id/protocols/wireguard-mesh",
	}
	grants := []json.RawMessage{
		testDelegatedGrantMessage(t, "grant-delegated", "did:jwk:wallet", "did:jwk:node", scope, "2026-06-24T00:00:00Z"),
	}
	match := PermissionGrantMatch{
		Grantor:     "did:jwk:wallet",
		Grantee:     "did:jwk:node",
		MessageType: InterfaceRecordsWrite,
		Protocol:    "https://enbox.id/protocols/wireguard-mesh",
		Now:         time.Date(2026, 6, 23, 12, 0, 0, 0, time.UTC),
	}

	got, err := FindPermissionGrantID(grants, match)
	if err != nil {
		t.Fatalf("FindPermissionGrantID: %v", err)
	}
	if got != "" {
		t.Fatalf("grant = %q, want none (delegated grants must not match as plain grants)", got)
	}

	// Compatibility escape hatch for legacy call sites.
	match.AllowDelegated = true
	got, err = FindPermissionGrantID(grants, match)
	if err != nil {
		t.Fatalf("FindPermissionGrantID (AllowDelegated): %v", err)
	}
	if got != "grant-delegated" {
		t.Fatalf("grant = %q, want grant-delegated with AllowDelegated", got)
	}
}

func TestFindDelegatedGrant(t *testing.T) {
	now := time.Date(2026, 6, 23, 12, 0, 0, 0, time.UTC)
	writeScope := PermissionScope{
		Interface: DwnScopeInterfaceRecords,
		Method:    DwnScopeMethodWrite,
		Protocol:  "https://enbox.id/protocols/wireguard-mesh",
	}
	readScope := PermissionScope{
		Interface: DwnScopeInterfaceRecords,
		Method:    DwnScopeMethodRead,
		Protocol:  "https://enbox.id/protocols/wireguard-mesh",
	}
	grants := []json.RawMessage{
		testPermissionGrantMessage(t, "grant-plain-write", "did:jwk:wallet", "did:jwk:node", writeScope, "2026-06-24T00:00:00Z"),
		testDelegatedGrantMessage(t, "grant-delegated-write", "did:jwk:wallet", "did:jwk:node", writeScope, "2026-06-24T00:00:00Z"),
		testDelegatedGrantMessage(t, "grant-delegated-read", "did:jwk:wallet", "did:jwk:node", readScope, "2026-06-24T00:00:00Z"),
	}

	t.Run("requires delegated flag", func(t *testing.T) {
		raw, grant, err := FindDelegatedGrant(grants[:1], PermissionGrantMatch{
			Grantor:     "did:jwk:wallet",
			Grantee:     "did:jwk:node",
			MessageType: InterfaceRecordsWrite,
			Protocol:    "https://enbox.id/protocols/wireguard-mesh",
			Now:         now,
		})
		if err != nil {
			t.Fatalf("FindDelegatedGrant: %v", err)
		}
		if raw != nil || grant != nil {
			t.Fatalf("matched plain grant %+v, want none", grant)
		}
	})

	t.Run("matches exact scope and returns raw bytes", func(t *testing.T) {
		raw, grant, err := FindDelegatedGrant(grants, PermissionGrantMatch{
			Grantor:     "did:jwk:wallet",
			Grantee:     "did:jwk:node",
			MessageType: InterfaceRecordsWrite,
			Protocol:    "https://enbox.id/protocols/wireguard-mesh",
			Now:         now,
		})
		if err != nil {
			t.Fatalf("FindDelegatedGrant: %v", err)
		}
		if grant == nil || grant.ID != "grant-delegated-write" {
			t.Fatalf("grant = %+v, want grant-delegated-write", grant)
		}
		if !bytes.Equal(raw, grants[1]) {
			t.Fatal("raw grant bytes not returned verbatim")
		}
	})

	t.Run("RecordsQuery matches Records/Read scope", func(t *testing.T) {
		_, grant, err := FindDelegatedGrant(grants, PermissionGrantMatch{
			Grantor:     "did:jwk:wallet",
			Grantee:     "did:jwk:node",
			MessageType: InterfaceRecordsQuery,
			Protocol:    "https://enbox.id/protocols/wireguard-mesh",
			Now:         now,
		})
		if err != nil {
			t.Fatalf("FindDelegatedGrant: %v", err)
		}
		if grant == nil || grant.ID != "grant-delegated-read" {
			t.Fatalf("grant = %+v, want grant-delegated-read", grant)
		}
	})

	t.Run("rejects expired grants", func(t *testing.T) {
		expired := []json.RawMessage{
			testDelegatedGrantMessage(t, "grant-expired", "did:jwk:wallet", "did:jwk:node", writeScope, "2026-06-22T00:00:00Z"),
		}
		raw, grant, err := FindDelegatedGrant(expired, PermissionGrantMatch{
			Grantor:     "did:jwk:wallet",
			Grantee:     "did:jwk:node",
			MessageType: InterfaceRecordsWrite,
			Protocol:    "https://enbox.id/protocols/wireguard-mesh",
			Now:         now,
		})
		if err != nil {
			t.Fatalf("FindDelegatedGrant: %v", err)
		}
		if raw != nil || grant != nil {
			t.Fatalf("matched expired grant %+v, want none", grant)
		}
	})

	t.Run("rejects wrong grantee", func(t *testing.T) {
		raw, grant, err := FindDelegatedGrant(grants, PermissionGrantMatch{
			Grantor:     "did:jwk:wallet",
			Grantee:     "did:jwk:other",
			MessageType: InterfaceRecordsWrite,
			Protocol:    "https://enbox.id/protocols/wireguard-mesh",
			Now:         now,
		})
		if err != nil {
			t.Fatalf("FindDelegatedGrant: %v", err)
		}
		if raw != nil || grant != nil {
			t.Fatalf("matched wrong-grantee grant %+v, want none", grant)
		}
	})

	t.Run("falls back to broader scope", func(t *testing.T) {
		pathScoped := testDelegatedGrantMessage(t, "grant-path", "did:jwk:wallet", "did:jwk:node", PermissionScope{
			Interface:    DwnScopeInterfaceRecords,
			Method:       DwnScopeMethodRead,
			Protocol:     "https://enbox.id/protocols/wireguard-mesh",
			ProtocolPath: "network/config",
		}, "2026-06-24T00:00:00Z")
		_, grant, err := FindDelegatedGrant([]json.RawMessage{pathScoped}, PermissionGrantMatch{
			Grantor:      "did:jwk:wallet",
			Grantee:      "did:jwk:node",
			MessageType:  InterfaceRecordsQuery,
			Protocol:     "https://enbox.id/protocols/wireguard-mesh",
			ProtocolPath: "network/config",
			Now:          now,
		})
		if err != nil {
			t.Fatalf("FindDelegatedGrant: %v", err)
		}
		if grant == nil || grant.ID != "grant-path" {
			t.Fatalf("grant = %+v, want grant-path via Records/Read fallback", grant)
		}
	})
}
