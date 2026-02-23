// Package wg manages WireGuard interface configuration.
//
// Uses the wgctrl library to configure WireGuard interfaces programmatically:
//   - Create/destroy wg0 interface
//   - Set private key and listen port
//   - Add/remove/update peers (public key, endpoint, allowed IPs)
//   - Set persistent keepalive interval (25s for NAT traversal)
//
// The WireGuard interface is configured as a point-to-point mesh:
//   - Each peer has AllowedIPs set to their mesh IP (/32)
//   - Subnet routers additionally have their advertised CIDRs
//   - Exit nodes have 0.0.0.0/0 in their AllowedIPs
package wg
