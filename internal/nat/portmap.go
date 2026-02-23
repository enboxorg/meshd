// Package nat - portmap.go implements UPnP IGD, NAT-PMP, and PCP clients.
//
// Port mapping protocols request the NAT gateway to forward a public port
// to our local WireGuard listen port. This effectively makes the NAT
// transparent for inbound WireGuard traffic.
//
// Protocols tried in order:
//   1. PCP (Port Control Protocol) - RFC 6887, modern and simple
//   2. NAT-PMP - RFC 6886, Apple's predecessor to PCP
//   3. UPnP IGD - older, XML/SOAP-based, widely deployed
//
// If a port mapping is obtained, the mapped public endpoint is included
// in the endpoint record with source: "upnp", "natpmp", or "pcp".
// These endpoints are preferred over STUN-discovered ones because they
// bypass firewall state requirements.
package nat
