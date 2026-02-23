# dwn-mesh

Decentralized WireGuard mesh networking, coordinated by [Decentralized Web Nodes](https://github.com/enboxorg/dwn-spec).

**Status:** Design phase. See [DESIGN.md](DESIGN.md) for the full design document.

## What is this?

dwn-mesh replaces Tailscale's centralized coordination server with DWN
protocol records. Each machine has a DID (Decentralized Identifier), stores
its own data on its own DWN, and coordinates with peers using cryptographically
signed, encrypted protocol messages.

The result: a fully decentralized WireGuard mesh where **no single company
or server controls your network**.

## How it works

```
  Tailscale                          dwn-mesh
  --------                          --------
  Central coord server    ->    Anchor DWN (replicated, encrypted)
  OAuth2/OIDC login       ->    DID-based identity (self-sovereign)
  Key upload to server    ->    RecordsWrite to DWN (signed + encrypted)
  Polling for peer keys   ->    RecordsSubscribe (real-time push)
  Tailscale ACL policies  ->    DWN protocol $actions + ACL records
  Tailscale DERP relays   ->    Community-run DERP relays (registered in DWN)
```

All coordination data (WireGuard public keys, IP endpoints, ACL policies,
membership) is encrypted at rest on the DWN. Even the DWN operator cannot
read the plaintext without the decryption keys.

## Architecture

```
                    +---------------+
                    |  Anchor DWN   |  <- encrypted: members, ACLs, relays
                    |  (replicated) |
                    +-------+-------+
                            |
               +------------+------------+
               v            v            v
         +-----------++-----------++-----------+
         | Node DWN  || Node DWN  || Node DWN  |  <- encrypted: nodeInfo,
         |  Alice    ||   Bob     ||  Carol    |     endpoints
         +-----------++-----------++-----------+
               ^            ^            ^
               +-----WireGuard mesh------+
```

## Quick start (planned)

```bash
# Initialize a node (generates DID + WireGuard keys + local DWN)
dwn-mesh init

# Create a new mesh network
dwn-mesh network create --name "my-mesh" --cidr 100.64.0.0/10

# Add a peer (admin)
dwn-mesh peer add did:dht:abc123...

# On the peer's machine: join the network
dwn-mesh network join did:dht:owner... <network-id>

# Start the mesh daemon
dwn-mesh up

# Check status
dwn-mesh status
dwn-mesh peer list
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
  acl/                  ACL policy parsing + nftables/pf enforcement
protocols/              DWN protocol definitions
schemas/                JSON schemas for record data
```

## Design

See [DESIGN.md](DESIGN.md) for the complete design document covering:

- Architecture and DWN primitive mapping
- Encryption architecture (Protocol Path + Context key delivery)
- Full protocol definitions with access control
- Multi-owner federation models
- Threat model analysis (comparison with Tailscale)
- Implementation plan and phases

## License

TBD
