// Package nat provides NAT traversal utilities for dwn-mesh.
//
// stun.go implements STUN (Session Traversal Utilities for NAT) client
// functionality for discovering the node's public-facing endpoint.
//
// STUN flow:
//   1. Send a STUN Binding Request from the WireGuard listen socket
//   2. The STUN server responds with the observed source ip:port
//   3. This gives us our public endpoint as seen from the internet
//
// Multiple STUN servers are queried for reliability and to detect
// NAT mapping behavior (endpoint-independent vs endpoint-dependent).
//
// The discovered endpoint is written to the node's DWN as an encrypted
// endpoint record, which peers receive via subscription.
package nat
