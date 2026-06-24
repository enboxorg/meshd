package dwn

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

func testPermissionGrantMessage(t *testing.T, id string, grantor string, grantee string, scope PermissionScope, expires string) json.RawMessage {
	t.Helper()
	header, err := json.Marshal(map[string]string{
		"alg": "EdDSA",
		"kid": grantor + "#0",
	})
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(map[string]any{
		"dateExpires": expires,
		"delegated":   true,
		"scope":       scope,
	})
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
