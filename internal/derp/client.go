// Package derp implements the DERP (Designated Encrypted Relay for Packets)
// client for dwn-mesh.
//
// DERP serves two purposes:
//   1. Relay: when direct peer-to-peer connection fails (hard NATs, UDP
//      blocked), encrypted WireGuard packets are relayed through DERP
//      servers over HTTPS.
//   2. Side channel: DERP connections facilitate initial peer contact
//      and NAT traversal coordination before direct tunnels are established.
//
// DERP relay servers are registered in the wireguard-mesh protocol as
// encrypted relay records. Any network member can run and register a
// DERP server.
//
// Security: DERP servers never see plaintext traffic. They relay
// already-encrypted WireGuard packets based on destination public key.
package derp
