// Package mesh implements the core mesh agent daemon.
//
// The agent coordinates all subsystems:
//   - DWN client for reading/writing records
//   - Subscription manager for real-time peer updates
//   - WireGuard configurator for tunnel management
//   - STUN client for endpoint discovery
//   - DERP client for relay fallback
//   - ACL enforcer for packet filtering
//   - Health monitor for peer status tracking
//
// The agent runs as a long-lived daemon (dwn-mesh up) and manages
// the full lifecycle of mesh participation.
package mesh
