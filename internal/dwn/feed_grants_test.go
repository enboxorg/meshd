package dwn

import (
	"errors"
	"testing"
	"time"
)

const (
	feedGrantor = "did:dht:owner"
	feedGrantee = "did:jwk:delegate"
	meshProto   = "https://example.com/protocols/mesh"
	auditProto  = "https://example.com/protocols/audit"
)

var feedNow = time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)

func feedGrant(id, protocol, protocolPath, contextID string) *PermissionGrant {
	return &PermissionGrant{
		ID:          id,
		Grantor:     feedGrantor,
		Grantee:     feedGrantee,
		DateGranted: "2026-07-01T00:00:00.000000Z",
		DateExpires: "2026-08-01T00:00:00.000000Z",
		Scope: PermissionScope{
			Interface:    DwnScopeInterfaceMessages,
			Method:       DwnScopeMethodRead,
			Protocol:     protocol,
			ProtocolPath: protocolPath,
			ContextID:    contextID,
		},
	}
}

func grantIDsOf(grants []*PermissionGrant) []string {
	ids := make([]string, len(grants))
	for i, g := range grants {
		ids[i] = g.ID
	}
	return ids
}

func TestSelectFeedGrantsFullScope(t *testing.T) {
	unscoped := feedGrant("grant-unscoped", "", "", "")
	protocolScoped := feedGrant("grant-mesh", meshProto, "", "")

	selected, err := SelectFeedGrants(
		[]*PermissionGrant{protocolScoped, unscoped},
		feedGrantor, feedGrantee, feedNow, FullSyncScope(),
	)
	if err != nil {
		t.Fatalf("SelectFeedGrants: %v", err)
	}
	// Full scope invokes only unscoped grants; protocol-scoped ones cover a
	// strict subset and do not participate.
	if got := grantIDsOf(selected); len(got) != 1 || got[0] != "grant-unscoped" {
		t.Errorf("selected = %v, want [grant-unscoped]", got)
	}

	_, err = SelectFeedGrants(
		[]*PermissionGrant{protocolScoped},
		feedGrantor, feedGrantee, feedNow, FullSyncScope(),
	)
	var coverage *FeedGrantCoverageError
	if !errors.As(err, &coverage) || coverage.Protocol != "" {
		t.Fatalf("error = %v, want full-scope FeedGrantCoverageError", err)
	}
}

func TestSelectFeedGrantsProtocolSet(t *testing.T) {
	scope, err := ProtocolSetSyncScope([]string{meshProto, auditProto})
	if err != nil {
		t.Fatalf("ProtocolSetSyncScope: %v", err)
	}

	t.Run("protocol roots cover the set and all participants are invoked", func(t *testing.T) {
		mesh := feedGrant("b-mesh", meshProto, "", "")
		audit := feedGrant("a-audit", auditProto, "", "")
		unrelated := feedGrant("c-other", "https://example.com/protocols/unrelated", "", "")

		selected, err := SelectFeedGrants(
			[]*PermissionGrant{mesh, audit, unrelated},
			feedGrantor, feedGrantee, feedNow, scope,
		)
		if err != nil {
			t.Fatalf("SelectFeedGrants: %v", err)
		}
		got := grantIDsOf(selected)
		if len(got) != 2 || got[0] != "a-audit" || got[1] != "b-mesh" {
			t.Errorf("selected = %v, want [a-audit b-mesh] sorted by id", got)
		}
	})

	t.Run("unscoped grant covers every protocol and participates", func(t *testing.T) {
		unscoped := feedGrant("only-unscoped", "", "", "")
		selected, err := SelectFeedGrants(
			[]*PermissionGrant{unscoped},
			feedGrantor, feedGrantee, feedNow, scope,
		)
		if err != nil {
			t.Fatalf("SelectFeedGrants: %v", err)
		}
		if got := grantIDsOf(selected); len(got) != 1 || got[0] != "only-unscoped" {
			t.Errorf("selected = %v, want [only-unscoped]", got)
		}
	})

	t.Run("missing coverage names the uncovered protocol", func(t *testing.T) {
		mesh := feedGrant("b-mesh", meshProto, "", "")
		_, err := SelectFeedGrants(
			[]*PermissionGrant{mesh},
			feedGrantor, feedGrantee, feedNow, scope,
		)
		var coverage *FeedGrantCoverageError
		if !errors.As(err, &coverage) || coverage.Protocol != auditProto {
			t.Fatalf("error = %v, want FeedGrantCoverageError{Protocol: %q}", err, auditProto)
		}
	})

	t.Run("subtree-scoped grants never authorize feed scopes", func(t *testing.T) {
		pathScoped := feedGrant("path-scoped", meshProto, "network/node", "")
		contextScoped := feedGrant("ctx-scoped", auditProto, "", "ctx-root")
		_, err := SelectFeedGrants(
			[]*PermissionGrant{pathScoped, contextScoped},
			feedGrantor, feedGrantee, feedNow, scope,
		)
		var coverage *FeedGrantCoverageError
		if !errors.As(err, &coverage) {
			t.Fatalf("error = %v, want FeedGrantCoverageError", err)
		}
	})

	t.Run("selected IDs use UTF-16 code-unit order", func(t *testing.T) {
		// U+1F600 encodes as a surrogate pair and sorts BEFORE U+FFFD in
		// UTF-16 order, unlike UTF-8 byte order.
		astral := feedGrant("\U0001F600-grant", meshProto, "", "")
		replacement := feedGrant("�-grant", auditProto, "", "")
		selected, err := SelectFeedGrants(
			[]*PermissionGrant{replacement, astral},
			feedGrantor, feedGrantee, feedNow, scope,
		)
		if err != nil {
			t.Fatalf("SelectFeedGrants: %v", err)
		}
		got := grantIDsOf(selected)
		if len(got) != 2 || got[0] != "\U0001F600-grant" || got[1] != "�-grant" {
			t.Errorf("selected = %q, want astral grant first (UTF-16 order)", got)
		}
	})
}

func TestSelectFeedGrantsActiveWindow(t *testing.T) {
	scope, err := ProtocolSetSyncScope([]string{meshProto})
	if err != nil {
		t.Fatalf("ProtocolSetSyncScope: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*PermissionGrant)
	}{
		{"expired (dateExpires == now excluded)", func(g *PermissionGrant) {
			g.DateExpires = Timestamp(feedNow)
		}},
		{"not yet active", func(g *PermissionGrant) {
			g.DateGranted = "2026-07-27T00:00:00.000000Z"
		}},
		{"wrong grantor", func(g *PermissionGrant) { g.Grantor = "did:dht:someone-else" }},
		{"wrong grantee", func(g *PermissionGrant) { g.Grantee = "did:jwk:someone-else" }},
		{"records scope excluded", func(g *PermissionGrant) { g.Scope.Interface = DwnScopeInterfaceRecords }},
		{"messages query method excluded", func(g *PermissionGrant) { g.Scope.Method = DwnScopeMethodQuery }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			grant := feedGrant("g", meshProto, "", "")
			tc.mutate(grant)
			_, err := SelectFeedGrants([]*PermissionGrant{grant}, feedGrantor, feedGrantee, feedNow, scope)
			var coverage *FeedGrantCoverageError
			if !errors.As(err, &coverage) {
				t.Fatalf("error = %v, want FeedGrantCoverageError (grant must be inactive)", err)
			}
		})
	}

	t.Run("dateGranted == now is active", func(t *testing.T) {
		grant := feedGrant("g", meshProto, "", "")
		grant.DateGranted = Timestamp(feedNow)
		selected, err := SelectFeedGrants([]*PermissionGrant{grant}, feedGrantor, feedGrantee, feedNow, scope)
		if err != nil || len(selected) != 1 {
			t.Fatalf("selected, err = %v, %v; want the boundary grant active", grantIDsOf(selected), err)
		}
	})
}

func TestFeedGrantIDs(t *testing.T) {
	grants := []*PermissionGrant{
		feedGrant("b", meshProto, "", ""),
		feedGrant("a", meshProto, "", ""),
	}
	ids := FeedGrantIDs(grants)
	if len(ids) != 2 || ids[0] != "a" || ids[1] != "b" {
		t.Errorf("FeedGrantIDs = %v, want [a b]", ids)
	}
	if FeedGrantIDs(nil) != nil {
		t.Error("FeedGrantIDs(nil) must be nil")
	}
}
