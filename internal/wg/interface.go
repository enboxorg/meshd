// Package wg - interface.go manages the WireGuard network interface lifecycle.
//
// Interface management:
//   - Create TUN device (wg0) via netlink or wireguard-go userspace
//   - Assign mesh IP address to the interface
//   - Set MTU (default 1280 for safe traversal through tunnels)
//   - Bring interface up/down
//   - Add routes for peer AllowedIPs
//
// Platform support:
//   - Linux: kernel module preferred, wireguard-go fallback
//   - macOS: wireguard-go via utun
//   - Windows: wireguard-go via wintun
//   - FreeBSD: kernel module
package wg
