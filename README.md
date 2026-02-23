# dwn-mesh

Mesh VPN with no accounts, no servers, no company.

Your identity is a cryptographic key. Your devices coordinate directly.
Invite others with a single command. Everything is encrypted. Nothing to
sign up for. Nothing to self-host. Nothing to trust.

**Status:** Design phase. See [DESIGN.md](DESIGN.md) for the full design document.

## What is this?

dwn-mesh is a WireGuard mesh network where there is no coordination server.
No Tailscale account. No self-hosted Headscale. Your devices discover each
other, exchange keys, and establish encrypted tunnels -- all coordinated
through cryptographically signed records on a
[Decentralized Web Node](https://github.com/enboxorg/dwn-spec).

You don't need to know what that means. `dwn-mesh init` handles everything.

## Quick start (planned)

```bash
# On your first machine
dwn-mesh init
dwn-mesh network create --name "my-network"

# On your second machine
dwn-mesh init
# prints: Your device identity: did:dht:k5f8...

# Back on the first machine, add the second
dwn-mesh peer add did:dht:k5f8...

# On the second machine, join
dwn-mesh network join did:dht:abc1... <network-id>
dwn-mesh up

# That's it. The machines can reach each other at 100.64.0.x
# through encrypted WireGuard tunnels. NAT traversal is automatic.
```

## How is this different?

```
                You give up         You manage          You trust
               ─────────────      ─────────────       ───────────
Tailscale       control            nothing             Tailscale Inc.
Headscale       less control       a server            your server
WireGuard       nothing            everything          yourself
dwn-mesh        nothing            nothing             cryptography
```

**vs Tailscale / Headscale:** No account. No server. No company in the
loop. Your coordination data is encrypted -- even if someone compromises
the storage, they can't read your keys or endpoints.

**vs raw WireGuard:** No manual key distribution. No editing config files.
No figuring out NAT traversal. Add a peer with one command. Endpoint
changes propagate automatically in real-time.

## What you get

**Encrypted mesh in minutes.** Connect your devices across any network.
Behind NATs, on different continents, on cellular -- it just works.

**No infrastructure to run.** There is no coordination server. Your
devices coordinate directly using signed, encrypted records. The
"server" is an embedded component that starts when you run `dwn-mesh up`.

**Add people, not just devices.** Invite collaborators into your mesh.
They bring their own devices. You control access with ACL policies.
Remove someone and their access is revoked across every node immediately.

**Privacy by default.** All mesh coordination data (keys, endpoints,
membership, policies) is encrypted at rest. Not just the tunnel traffic --
the metadata too. Nobody can see who's in your network, where they are,
or what the rules are.

## If you already have a DID and DWN

dwn-mesh becomes something more: **private infrastructure for your DWN
identity**.

Your DID document lists your public DWN. But what about your backup
NAS, your laptop, your staging instance? They shouldn't be in your DID
document. They shouldn't have public IPs. But they need to sync.

dwn-mesh creates the private layer underneath your public identity:

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

Your private DWN replicas sync with your public DWN over the encrypted
mesh. They never need a public IP. They never appear in your DID document.
DWN's built-in `MessagesSync` runs transparently over mesh IPs.

Invite collaborators and their DWNs can reach your private endpoints.
All traffic stays on the mesh -- private, encrypted, no middleman.

See [DESIGN.md](DESIGN.md) for the complete architecture.

## How it works under the hood

Every device gets a **DID** (Decentralized Identifier) -- a cryptographic
identity that doesn't depend on any company. Think of it as a self-signed
certificate that the whole internet can verify.

Every device runs an embedded **DWN** (Decentralized Web Node) -- a tiny
personal data store. It holds the device's WireGuard public key, current
network endpoint, and mesh membership info. All encrypted.

Devices discover each other by reading records from each other's DWNs,
subscribing to real-time updates, and configuring WireGuard accordingly.
When a device's IP changes, it writes a new endpoint record. All peers
receive the update instantly and reconfigure their tunnels.

The mesh uses two DWN protocols:

- **`wireguard-mesh`** on an anchor DWN: network membership, ACLs, relays
- **`wireguard-node`** on each device: WireGuard public key + endpoint

All records are signed with DIDs and encrypted with JWE. The protocols
enforce access control declaratively -- no application code needed.

## Project structure

```
cmd/dwn-mesh/           CLI entrypoint
internal/
  did/                  DID generation and resolution
  dwn/                  DWN client + WebSocket subscriptions
  mesh/                 Network, peers, discovery, IP allocation
  wg/                   WireGuard interface configuration
  nat/                  STUN, UDP hole punching, UPnP/NAT-PMP/PCP
  derp/                 Relay client + optional embedded server
  acl/                  ACL policy parsing + local enforcement
protocols/              DWN protocol definitions (encrypted)
schemas/                JSON schemas for record data
```

## License

TBD
