// Package mesh - peers.go manages peer discovery and lifecycle.
//
// Peer discovery flow:
//   1. Query anchor DWN for member records (filtered by status: "active")
//   2. For each member, resolve their DID to get DWN service endpoint
//   3. Read their nodeInfo from their DWN (WireGuard pubkey, mesh IP)
//   4. Subscribe to their endpoint updates
//   5. Configure WireGuard peer with discovered info
//
// Peer lifecycle events:
//   - member.joined: new peer discovered, start connection
//   - member.left / member.suspended: peer removed, tear down tunnel
//   - endpoint.changed: peer moved, update WireGuard endpoint
//   - key.rotated: peer rotated WireGuard key, update config
package mesh
