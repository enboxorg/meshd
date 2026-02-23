# dwn-mesh

A private encrypted mesh for your [DWN](https://github.com/enboxorg/dwn-spec) infrastructure.

**Status:** Design phase. See [DESIGN.md](DESIGN.md) for the full design document.

## The problem

Your DID document publicly lists your DWN endpoints. If you want backup
replicas, local-first access on your laptop, or a NAS at home syncing your
DWN -- every one of those needs either a public IP or manual VPN setup.
Your DWN collaboration traffic with others goes over the public internet.
Your infrastructure topology is visible to anyone who resolves your DID.

## What dwn-mesh does

dwn-mesh creates an encrypted WireGuard overlay network that connects your
DWN instances and the DWN instances of people you collaborate with.

```
Public (what the world sees):

    DID Document: serviceEndpoint: ["https://dwn.alice.com"]

Private (the mesh, invisible to outsiders):

     dwn.alice.com       nas.alice          laptop.alice
     (VPS, public)    (home, behind NAT)   (roaming)
     100.64.0.1        100.64.0.2          100.64.0.3
          |                 |                    |
          +-- WireGuard ----+---- WireGuard -----+
                   encrypted mesh
                   DWN sync runs here
```

- **Private DWN replicas.** Your NAS and laptop sync with your public DWN
  over the mesh. No public IPs needed. No DID document changes. NAT
  traversal is automatic.

- **Encrypted collaboration.** Invite others into your mesh. Their DWNs
  talk to yours over WireGuard tunnels. Private, fast, no middleman.

- **Self-sovereign coordination.** Mesh coordination runs on DWN itself.
  Every record is signed with DIDs and encrypted with JWE. No central
  server. No company to trust.

## How it works

Mesh coordination uses two DWN protocols:

- **`wireguard-mesh`** -- installed on an anchor DWN (any member's DWN).
  Stores encrypted membership, ACL policies, relay servers, and audit events.

- **`wireguard-node`** -- installed on each node's DWN. Stores encrypted
  WireGuard public key and current network endpoint. Only authorized mesh
  peers can read it.

Nodes discover each other by reading the member list from the anchor DWN,
resolving each member's DID to find their DWN, and subscribing to real-time
endpoint updates via `RecordsSubscribe`. When a peer's IP changes, all
members learn about it in real-time and update their WireGuard config.

All coordination data is encrypted. Even the anchor DWN operator cannot
read the plaintext without the decryption keys.

## Quick start (planned)

```bash
# Initialize (generates DID + WireGuard keys + local DWN)
dwn-mesh init

# Create a mesh network
dwn-mesh network create --name "my-infra" --cidr 100.64.0.0/24

# Add your NAS
dwn-mesh peer add did:dht:nas-device...

# On the NAS:
dwn-mesh network join did:dht:you... <network-id>
dwn-mesh up

# Your NAS now has mesh IP 100.64.0.2.
# Point your NAS DWN sync at 100.64.0.1 (your VPS mesh IP).
# Sync runs over the encrypted tunnel. Done.
```

## Project structure

```
cmd/dwn-mesh/           CLI entrypoint
internal/
  did/                  DID generation and resolution (did:dht)
  dwn/                  DWN HTTP client + WebSocket subscriptions
  mesh/                 Network/peer management, discovery, IP allocation
  wg/                   WireGuard interface configuration (wgctrl)
  nat/                  STUN, UDP hole punching, UPnP/NAT-PMP/PCP
  derp/                 DERP relay client + optional embedded server
  acl/                  ACL policy parsing + local enforcement
protocols/              DWN protocol definitions (all paths encrypted)
schemas/                JSON schemas for record data
```

## Design

See [DESIGN.md](DESIGN.md) for the complete design document covering:

- Product scenarios (personal infra, collaboration, organizations)
- Architecture (anchor DWN + per-node DWNs, hybrid model)
- Encryption architecture (Protocol Path + Context key delivery)
- Protocol definitions with full access control
- Threat model analysis
- Implementation roadmap

## License

TBD
