// Package nat - holepunch.go implements UDP hole punching for NAT traversal.
//
// Hole punching technique (simultaneous transmission):
//   1. Both peers know each other's public endpoint (from DWN records)
//   2. Both peers start sending UDP packets to each other simultaneously
//   3. Outbound packets create NAT mappings and firewall state
//   4. When a peer's packet arrives matching existing state, it gets through
//   5. Bidirectional communication is established
//
// The DWN subscription system acts as the "side channel" for coordinating
// hole punching -- both peers learn of each other's endpoints at roughly
// the same time via EventLog subscriptions.
//
// For hard NATs (endpoint-dependent mapping), the birthday paradox
// technique is used: open multiple ports and probe random targets to
// find a collision in O(sqrt(N)) attempts.
package nat
