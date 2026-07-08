package enboxconnect

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func testRequested(t *testing.T) []ConnectPermissionRequest {
	t.Helper()
	cpr, err := BuildConnectPermissionRequest(PermissionRequest{
		ProtocolDefinition: testProtocolDefinition,
		Permissions:        []string{"read", "write"},
	})
	if err != nil {
		t.Fatalf("building permission request: %v", err)
	}
	return []ConnectPermissionRequest{cpr}
}

func TestIsScopeSubset(t *testing.T) {
	requested := map[string]any{"interface": "Records", "method": "Read", "protocol": testProtocolURI}

	cases := []struct {
		name    string
		granted map[string]any
		want    bool
	}{
		{
			name:    "identical scope",
			granted: map[string]any{"interface": "Records", "method": "Read", "protocol": testProtocolURI},
			want:    true,
		},
		{
			name: "narrower grant with extra field is a subset",
			granted: map[string]any{
				"interface": "Records", "method": "Read", "protocol": testProtocolURI, "contextId": "ctx-1",
			},
			want: true,
		},
		{
			name:    "different method",
			granted: map[string]any{"interface": "Records", "method": "Write", "protocol": testProtocolURI},
			want:    false,
		},
		{
			name:    "different interface",
			granted: map[string]any{"interface": "Messages", "method": "Read", "protocol": testProtocolURI},
			want:    false,
		},
		{
			name:    "missing requested field",
			granted: map[string]any{"interface": "Records", "method": "Read"},
			want:    false,
		},
		{
			name:    "different protocol",
			granted: map[string]any{"interface": "Records", "method": "Read", "protocol": "https://other.example"},
			want:    false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isScopeSubset(tc.granted, requested); got != tc.want {
				t.Errorf("isScopeSubset = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestValidateGrantsRevocationMatching(t *testing.T) {
	delegate := "did:jwk:delegate"
	kid := "did:jwk:owner#0"
	revocations := []SessionRevocation{{GrantID: "grant-1", RevocationGrantID: "rev-1"}}

	goodScope := map[string]any{
		"interface": "Records", "method": "Write",
		"protocol": permissionsProtocolURI, "contextId": "grant-1",
	}
	good := makeGrantMessage(t, "rev-1", delegate, kid, goodScope, true)
	if err := validateGrants([]json.RawMessage{good}, delegate, testRequested(t), revocations); err != nil {
		t.Errorf("valid revocation grant rejected: %v", err)
	}

	// Same grant id but the contextId names a different grant: not a
	// recognized revocation, and not a requested scope either.
	badScope := map[string]any{
		"interface": "Records", "method": "Write",
		"protocol": permissionsProtocolURI, "contextId": "grant-other",
	}
	bad := makeGrantMessage(t, "rev-1", delegate, kid, badScope, true)
	err := validateGrants([]json.RawMessage{bad}, delegate, testRequested(t), revocations)
	if err == nil || !strings.Contains(err.Error(), "outside the requested permission scope") {
		t.Errorf("error = %v, want out-of-scope rejection", err)
	}

	// Revocation-shaped grant that is not listed in sessionRevocations.
	unlisted := makeGrantMessage(t, "rev-9", delegate, kid, goodScope, true)
	err = validateGrants([]json.RawMessage{unlisted}, delegate, testRequested(t), revocations)
	if err == nil || !strings.Contains(err.Error(), "outside the requested permission scope") {
		t.Errorf("error = %v, want out-of-scope rejection", err)
	}
}

func TestValidateGrantsWrongGrantee(t *testing.T) {
	kid := "did:jwk:owner#0"
	scope := map[string]any{"interface": "Records", "method": "Read", "protocol": testProtocolURI}
	grant := makeGrantMessage(t, "grant-1", "did:jwk:intruder", kid, scope, true)

	err := validateGrants([]json.RawMessage{grant}, "did:jwk:delegate", testRequested(t), nil)
	if err == nil || !strings.Contains(err.Error(), "wallet returned a grant for") {
		t.Errorf("error = %v, want wrong-grantee rejection", err)
	}
}

func TestParseGrantStructuralErrors(t *testing.T) {
	kid := "did:jwk:owner#0"
	scope := map[string]any{"interface": "Records", "method": "Read", "protocol": testProtocolURI}
	valid := makeGrantMessage(t, "grant-1", "did:jwk:delegate", kid, scope, true)

	mutate := func(t *testing.T, mutator func(map[string]any)) json.RawMessage {
		t.Helper()
		var msg map[string]any
		if err := json.Unmarshal(valid, &msg); err != nil {
			t.Fatalf("unmarshaling grant: %v", err)
		}
		mutator(msg)
		out, err := json.Marshal(msg)
		if err != nil {
			t.Fatalf("marshaling grant: %v", err)
		}
		return out
	}

	encode := func(t *testing.T, v any) string {
		t.Helper()
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return base64.RawURLEncoding.EncodeToString(b)
	}

	cases := map[string]struct {
		mutator func(map[string]any)
		wantErr string
	}{
		"missing encodedData": {
			mutator: func(m map[string]any) { delete(m, "encodedData") },
			wantErr: "missing encodedData",
		},
		"missing authorization": {
			mutator: func(m map[string]any) { delete(m, "authorization") },
			wantErr: "missing authorization",
		},
		"missing recipient": {
			mutator: func(m map[string]any) {
				delete(m["descriptor"].(map[string]any), "recipient")
			},
			wantErr: "missing descriptor.recipient",
		},
		"missing scope": {
			mutator: func(m map[string]any) {
				m["encodedData"] = encode(t, map[string]any{"dateExpires": "2100-01-01T00:00:00.000000Z"})
			},
			wantErr: "missing required property `scope`",
		},
		"missing dateExpires": {
			mutator: func(m map[string]any) {
				m["encodedData"] = encode(t, map[string]any{"scope": map[string]any{"interface": "Records"}})
			},
			wantErr: "missing required property `dateExpires`",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := parseGrant(mutate(t, tc.mutator)); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %v, want %q", err, tc.wantErr)
			}
		})
	}

	if _, err := parseGrant(valid); err != nil {
		t.Errorf("valid grant rejected: %v", err)
	}
}
