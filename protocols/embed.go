// Package protocols provides embedded protocol definitions for meshd.
package protocols

import _ "embed"

//go:embed wireguard-mesh.json
var MeshProtocolJSON []byte

//go:embed wallet-response.json
var WalletResponseProtocolJSON []byte

// MeshProtocolURI is the canonical URI of the wireguard-mesh protocol.
const MeshProtocolURI = "https://enbox.id/protocols/wireguard-mesh"

// EncryptionProtocolURI is the canonical URI of the DWN EncryptionProtocol that
// hosts role-audience audienceKey and audienceEpoch records (encryption-v1).
const EncryptionProtocolURI = "https://identity.foundation/dwn/protocols/encryption"

// WalletResponseProtocolURI is the canonical URI for CLI wallet response
// handoff records.
const WalletResponseProtocolURI = "https://enbox.id/protocols/meshd-wallet-response"
