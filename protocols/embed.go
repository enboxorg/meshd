// Package protocols provides embedded protocol definitions for dwn-mesh.
package protocols

import _ "embed"

//go:embed wireguard-mesh.json
var MeshProtocolJSON []byte

//go:embed wireguard-node.json
var NodeProtocolJSON []byte
