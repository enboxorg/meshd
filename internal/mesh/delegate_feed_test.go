package mesh

import (
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"reflect"
	"testing"
	"time"

	"github.com/enboxorg/meshd/internal/dwn"
	"github.com/enboxorg/meshd/protocols"
)

const (
	feedTestOwner    = "did:dht:owner"
	feedTestDelegate = "did:jwk:delegate"
)

var feedTestNow = time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)

// feedTestGrantMessage builds a raw grant message in the shape
// dwn.ParsePermissionGrant expects (mirrors the wallet's grant records).
func feedTestGrantMessage(t *testing.T, id string, scope dwn.PermissionScope, expires string) json.RawMessage {
	t.Helper()
	header, err := json.Marshal(map[string]string{"alg": "EdDSA", "kid": feedTestOwner + "#0"})
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(map[string]any{
		"dateExpires": expires,
		"scope":       scope,
	})
	if err != nil {
		t.Fatal(err)
	}
	msg, err := json.Marshal(map[string]any{
		"recordId":    id,
		"encodedData": base64.RawURLEncoding.EncodeToString(data),
		"descriptor": map[string]any{
			"recipient":   feedTestDelegate,
			"dateCreated": "2026-07-01T00:00:00.000000Z",
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

func messagesReadScope(protocol string) dwn.PermissionScope {
	return dwn.PermissionScope{
		Interface: dwn.DwnScopeInterfaceMessages,
		Method:    dwn.DwnScopeMethodRead,
		Protocol:  protocol,
	}
}

func TestResolveFeedGrantsSelectsProtocolRootMessagesRead(t *testing.T) {
	grants := []json.RawMessage{
		// Records grants never authorize feed scopes.
		feedTestGrantMessage(t, "grant-records-read", dwn.PermissionScope{
			Interface: dwn.DwnScopeInterfaceRecords,
			Method:    dwn.DwnScopeMethodRead,
			Protocol:  protocols.MeshProtocolURI,
		}, "2026-08-01T00:00:00.000000Z"),
		// Two protocol-root Messages.Read grants participate, sorted by ID.
		feedTestGrantMessage(t, "grant-b", messagesReadScope(protocols.MeshProtocolURI), "2026-08-01T00:00:00.000000Z"),
		feedTestGrantMessage(t, "grant-a", messagesReadScope(protocols.MeshProtocolURI), "2026-08-15T00:00:00.000000Z"),
		// Expired grants are excluded.
		feedTestGrantMessage(t, "grant-expired", messagesReadScope(protocols.MeshProtocolURI), "2026-07-01T00:00:00.000000Z"),
		// Path-scoped Messages grants cover a strict subset and are excluded.
		feedTestGrantMessage(t, "grant-scoped", dwn.PermissionScope{
			Interface:    dwn.DwnScopeInterfaceMessages,
			Method:       dwn.DwnScopeMethodRead,
			Protocol:     protocols.MeshProtocolURI,
			ProtocolPath: "network/node",
		}, "2026-08-01T00:00:00.000000Z"),
		// Non-grant session records are skipped.
		json.RawMessage(`{"kind":"not-a-grant"}`),
	}

	ids, tuples := resolveFeedGrants(grants, feedTestOwner, feedTestDelegate, feedTestNow, slog.Default())
	if !reflect.DeepEqual(ids, []string{"grant-a", "grant-b"}) {
		t.Fatalf("feed grant IDs = %v, want [grant-a grant-b]", ids)
	}
	if len(tuples) != 2 {
		t.Fatalf("feed grant tuples = %+v, want 2", tuples)
	}
	if tuples[0].ID != "grant-a" || tuples[0].DateExpires != "2026-08-15T00:00:00.000000Z" ||
		tuples[0].DateGranted != "2026-07-01T00:00:00.000000Z" {
		t.Fatalf("tuple[0] = %+v, want grant-a epoch fields", tuples[0])
	}
	if tuples[1].ID != "grant-b" || tuples[1].DateExpires != "2026-08-01T00:00:00.000000Z" {
		t.Fatalf("tuple[1] = %+v, want grant-b epoch fields", tuples[1])
	}
}

func TestResolveFeedGrantsWithoutCoverageReturnsEmpty(t *testing.T) {
	tests := []struct {
		name   string
		grants []json.RawMessage
	}{
		{name: "no grants"},
		{
			name: "records grants only",
			grants: []json.RawMessage{
				feedTestGrantMessage(t, "grant-records", dwn.PermissionScope{
					Interface: dwn.DwnScopeInterfaceRecords,
					Method:    dwn.DwnScopeMethodRead,
					Protocol:  protocols.MeshProtocolURI,
				}, "2026-08-01T00:00:00.000000Z"),
			},
		},
		{
			name: "messages grant for a different protocol",
			grants: []json.RawMessage{
				feedTestGrantMessage(t, "grant-other", messagesReadScope("https://example.com/protocols/other"), "2026-08-01T00:00:00.000000Z"),
			},
		},
		{
			name: "expired messages grant",
			grants: []json.RawMessage{
				feedTestGrantMessage(t, "grant-expired", messagesReadScope(protocols.MeshProtocolURI), "2026-07-01T00:00:00.000000Z"),
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ids, tuples := resolveFeedGrants(test.grants, feedTestOwner, feedTestDelegate, feedTestNow, slog.Default())
			if len(ids) != 0 || len(tuples) != 0 {
				t.Fatalf("resolveFeedGrants = %v/%v, want empty (records mode fallback)", ids, tuples)
			}
		})
	}
}
