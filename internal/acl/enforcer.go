// Package acl - enforcer.go translates ACL policies into local packet filters.
//
// ACL enforcement happens at each node (distributed enforcement):
//   1. The ACL policy is received from the anchor DWN (encrypted)
//   2. The policy is evaluated against the current peer list
//   3. Packet filter rules are generated and applied locally
//
// Implementation:
//   - Linux: nftables rules on the wg0 interface
//   - macOS: pf rules
//   - Windows: Windows Filtering Platform (WFP) rules
//
// The enforcer watches for ACL policy changes via DWN subscription
// and automatically updates the local packet filter rules.
//
// Default policy: deny all. Only explicitly allowed traffic passes.
package acl
