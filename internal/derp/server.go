// Package derp - server.go provides an optional embedded DERP relay server.
//
// Any dwn-mesh node can optionally run an embedded DERP relay server,
// making it available to other nodes in the mesh. This is useful for:
//   - Self-hosted relay infrastructure (no dependency on third-party relays)
//   - Low-latency relaying for nodes in the same region
//   - Fully self-contained mesh deployments
//
// The embedded DERP server runs over HTTPS and can also provide STUN
// service on a configurable UDP port.
//
// When a node runs a DERP server, it registers itself as a relay in the
// wireguard-mesh protocol on the anchor DWN, so other members discover it.
package derp
