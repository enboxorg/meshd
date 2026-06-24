// Package protocols provides embedded protocol definitions for meshd.
package protocols

import _ "embed"

//go:embed wireguard-mesh.json
var MeshProtocolJSON []byte

//go:embed key-delivery.json
var KeyDeliveryProtocolJSON []byte

//go:embed wallet-response.json
var WalletResponseProtocolJSON []byte

// MeshProtocolURI is the canonical URI of the wireguard-mesh protocol.
const MeshProtocolURI = "https://enbox.id/protocols/wireguard-mesh"

// KeyDeliveryProtocolURI is the canonical URI of the DID/Web5 key delivery
// protocol used for encrypted Protocol Context key records.
const KeyDeliveryProtocolURI = "https://identity.foundation/protocols/key-delivery"

// WalletResponseProtocolURI is the canonical URI for CLI wallet response
// handoff records.
const WalletResponseProtocolURI = "https://enbox.id/protocols/meshd-wallet-response"
