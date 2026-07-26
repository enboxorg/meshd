package dwn

import "strings"

// ProtocolScope is the minimal protocol-bound scope shape shared by
// permission grant authorization. Permission grants and candidate
// records/filters are projected down to these fields before matching so
// grant selection and server enforcement use the same rules.
//
// An empty string means "unset" (the SDK's undefined).
type ProtocolScope struct {
	Protocol     string
	ProtocolPath string
	ContextID    string
}

// MatchesPermissionScope determines whether a candidate target is within a
// grant scope, porting the SDK's PermissionScopeMatcher.matches exactly.
//
// Matching fails closed for invalid combinations: protocolPath and contextId
// are mutually exclusive, and either field requires protocol. protocol
// matches by exact equality. protocolPath and contextId scopes match
// subtrees: the target value must equal the scoped value or begin with the
// scoped value followed by "/".
func MatchesPermissionScope(scope, target ProtocolScope) bool {
	if scope.ProtocolPath != "" && scope.ContextID != "" {
		return false
	}

	if (scope.ProtocolPath != "" || scope.ContextID != "") && scope.Protocol == "" {
		return false
	}

	if scope.Protocol != "" && scope.Protocol != target.Protocol {
		return false
	}

	if scope.ProtocolPath != "" {
		return MatchesSubtree(scope.ProtocolPath, target.ProtocolPath)
	}

	if scope.ContextID != "" {
		return MatchesSubtree(scope.ContextID, target.ContextID)
	}

	return true
}

// MatchesSubtree reports whether candidate is the selected hierarchical path
// or one of its proper "/"-delimited descendants, porting the SDK's
// FilterUtility.matchesSubtree. An unset (empty) candidate never matches.
func MatchesSubtree(subtree, candidate string) bool {
	return candidate != "" &&
		(candidate == subtree || strings.HasPrefix(candidate, subtree+"/"))
}
