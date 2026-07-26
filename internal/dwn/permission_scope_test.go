package dwn

import "testing"

// Table tests mirroring dwn-sdk-js PermissionScopeMatcher.matches and
// FilterUtility.matchesSubtree.
func TestMatchesPermissionScope(t *testing.T) {
	const (
		mesh  = "https://example.com/protocols/mesh"
		other = "https://example.com/protocols/other"
	)

	tests := []struct {
		name   string
		scope  ProtocolScope
		target ProtocolScope
		want   bool
	}{
		{
			name:   "unscoped matches anything",
			scope:  ProtocolScope{},
			target: ProtocolScope{Protocol: mesh, ProtocolPath: "a/b", ContextID: "ctx/1"},
			want:   true,
		},
		{
			name:   "unscoped matches empty target",
			scope:  ProtocolScope{},
			target: ProtocolScope{},
			want:   true,
		},
		{
			name:   "protocol exact equality match",
			scope:  ProtocolScope{Protocol: mesh},
			target: ProtocolScope{Protocol: mesh},
			want:   true,
		},
		{
			name:   "protocol mismatch",
			scope:  ProtocolScope{Protocol: mesh},
			target: ProtocolScope{Protocol: other},
			want:   false,
		},
		{
			name:   "protocol scope vs unset target protocol",
			scope:  ProtocolScope{Protocol: mesh},
			target: ProtocolScope{},
			want:   false,
		},
		{
			name:   "protocol scope ignores target path and context",
			scope:  ProtocolScope{Protocol: mesh},
			target: ProtocolScope{Protocol: mesh, ProtocolPath: "a/b", ContextID: "ctx"},
			want:   true,
		},
		{
			name:   "protocolPath and contextId together fail closed",
			scope:  ProtocolScope{Protocol: mesh, ProtocolPath: "a", ContextID: "ctx"},
			target: ProtocolScope{Protocol: mesh, ProtocolPath: "a", ContextID: "ctx"},
			want:   false,
		},
		{
			name:   "protocolPath without protocol fails closed",
			scope:  ProtocolScope{ProtocolPath: "a"},
			target: ProtocolScope{Protocol: mesh, ProtocolPath: "a"},
			want:   false,
		},
		{
			name:   "contextId without protocol fails closed",
			scope:  ProtocolScope{ContextID: "ctx"},
			target: ProtocolScope{Protocol: mesh, ContextID: "ctx"},
			want:   false,
		},
		{
			name:   "protocolPath exact match",
			scope:  ProtocolScope{Protocol: mesh, ProtocolPath: "network/node"},
			target: ProtocolScope{Protocol: mesh, ProtocolPath: "network/node"},
			want:   true,
		},
		{
			name:   "protocolPath subtree descendant",
			scope:  ProtocolScope{Protocol: mesh, ProtocolPath: "network/node"},
			target: ProtocolScope{Protocol: mesh, ProtocolPath: "network/node/endpoint"},
			want:   true,
		},
		{
			name:   "protocolPath boundary-aware: sibling prefix does not match",
			scope:  ProtocolScope{Protocol: mesh, ProtocolPath: "network/node"},
			target: ProtocolScope{Protocol: mesh, ProtocolPath: "network/nodeInfo"},
			want:   false,
		},
		{
			name:   "protocolPath parent not covered",
			scope:  ProtocolScope{Protocol: mesh, ProtocolPath: "network/node"},
			target: ProtocolScope{Protocol: mesh, ProtocolPath: "network"},
			want:   false,
		},
		{
			name:   "protocolPath scope vs unset target path",
			scope:  ProtocolScope{Protocol: mesh, ProtocolPath: "network/node"},
			target: ProtocolScope{Protocol: mesh},
			want:   false,
		},
		{
			name:   "contextId exact match",
			scope:  ProtocolScope{Protocol: mesh, ContextID: "root/child"},
			target: ProtocolScope{Protocol: mesh, ContextID: "root/child"},
			want:   true,
		},
		{
			name:   "contextId subtree descendant",
			scope:  ProtocolScope{Protocol: mesh, ContextID: "root"},
			target: ProtocolScope{Protocol: mesh, ContextID: "root/child/grandchild"},
			want:   true,
		},
		{
			name:   "contextId boundary-aware: sibling prefix does not match",
			scope:  ProtocolScope{Protocol: mesh, ContextID: "root"},
			target: ProtocolScope{Protocol: mesh, ContextID: "rooted"},
			want:   false,
		},
		{
			name:   "contextId scope vs unset target context",
			scope:  ProtocolScope{Protocol: mesh, ContextID: "root"},
			target: ProtocolScope{Protocol: mesh},
			want:   false,
		},
		{
			name:   "contextId scope with wrong protocol",
			scope:  ProtocolScope{Protocol: mesh, ContextID: "root"},
			target: ProtocolScope{Protocol: other, ContextID: "root"},
			want:   false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := MatchesPermissionScope(tc.scope, tc.target); got != tc.want {
				t.Errorf("MatchesPermissionScope(%+v, %+v) = %v, want %v", tc.scope, tc.target, got, tc.want)
			}
		})
	}
}

func TestMatchesSubtree(t *testing.T) {
	tests := []struct {
		subtree   string
		candidate string
		want      bool
	}{
		{"a/b", "a/b", true},
		{"a/b", "a/b/c", true},
		{"a/b", "a/bc", false},
		{"a/b", "a", false},
		{"a/b", "", false},
		{"a", "a/b/c", true},
	}
	for _, tc := range tests {
		if got := MatchesSubtree(tc.subtree, tc.candidate); got != tc.want {
			t.Errorf("MatchesSubtree(%q, %q) = %v, want %v", tc.subtree, tc.candidate, got, tc.want)
		}
	}
}
