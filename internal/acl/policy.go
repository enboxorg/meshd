// Package acl handles ACL policy parsing and evaluation.
//
// ACL policies are stored as encrypted records in the wireguard-mesh protocol.
// The policy format is inspired by Tailscale's ACL syntax but uses DIDs
// instead of email addresses for identity.
//
// Policy elements:
//   - groups: named sets of DIDs (e.g., "developers": ["did:dht:abc", ...])
//   - tagOwners: which DIDs can assign which tags to their nodes
//   - rules: ordered list of accept/drop rules with src/dst matchers
//
// Matchers can reference:
//   - Specific DIDs
//   - Groups (group:name)
//   - Tags (tag:name)
//   - Mesh IPs or CIDRs
//   - Wildcard (*)
//
// Rules can filter by protocol (tcp/udp/icmp) and port ranges.
package acl
