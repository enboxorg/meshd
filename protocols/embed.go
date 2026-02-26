// Package protocols provides embedded protocol definitions for meshd.
package protocols

import _ "embed"

//go:embed wireguard-mesh.json
var MeshProtocolJSON []byte

//go:embed key-delivery.json
var KeyDeliveryProtocolJSON []byte

// MeshProtocolURI is the canonical URI of the wireguard-mesh protocol.
const MeshProtocolURI = "https://enbox.org/protocols/wireguard-mesh"

// KeyDeliveryProtocolURI is the canonical URI of the key delivery protocol.
const KeyDeliveryProtocolURI = "https://enbox.org/protocols/key-delivery"
