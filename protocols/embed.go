// Package protocols provides embedded protocol definitions for dwn-mesh.
package protocols

import _ "embed"

//go:embed wireguard-mesh.json
var MeshProtocolJSON []byte

//go:embed wireguard-node.json
var NodeProtocolJSON []byte

//go:embed key-delivery.json
var KeyDeliveryProtocolJSON []byte

// KeyDeliveryProtocolURI is the canonical URI of the key delivery protocol.
const KeyDeliveryProtocolURI = "https://enbox.org/protocols/key-delivery"
