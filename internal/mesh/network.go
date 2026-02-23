// Package mesh - network.go handles network creation, joining, and leaving.
//
// Network creation:
//   1. Generate encryption keypair (X25519) for Protocol Path encryption
//   2. Install wireguard-mesh protocol on the anchor DWN
//   3. Write the network record with mesh CIDR, name, DNS config
//   4. Write initial ACL policy (default deny)
//   5. Write default relay records
//
// Joining a network:
//   1. Read network record from anchor DWN (requires context key)
//   2. Write nodeInfo record with WireGuard public key
//   3. Subscribe to member list and ACL changes
//   4. Discover and connect to all peers
//
// Leaving a network:
//   1. Delete own nodeInfo record
//   2. Close all subscriptions
//   3. Tear down WireGuard interface
package mesh
