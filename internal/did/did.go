// Package did provides DID generation and resolution for dwn-mesh nodes.
//
// Each machine in the mesh is identified by a DID (Decentralized Identifier).
// We use did:dht as the primary method -- it's decentralized (uses the
// Mainline DHT), requires no DNS or web hosting, and supports key rotation.
//
// A node's DID document contains:
//   - An Ed25519 signing key (for DWN message authorization)
//   - An X25519 encryption key (for Protocol Path / Protocol Context encryption)
//   - A #dwn service endpoint pointing to the node's DWN instance
package did
