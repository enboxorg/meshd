# meshd

Mesh VPN with no accounts, no servers, no company.

Your identity is a cryptographic key. Your devices coordinate directly.
Invite others with a single command. Everything is encrypted. Nothing to
sign up for. Nothing to self-host. Nothing to trust.

**Status:** Design phase. See [DESIGN.md](DESIGN.md) for the full design document.

## Installation

```bash
curl -fsSL https://meshd.sh/install | bash
```

The installer works on Linux, macOS, and Windows (Git Bash/WSL). It installs
the latest prebuilt `meshd` release binary.

```bash
# Manual install (if you prefer to run steps yourself)
go install github.com/enboxorg/meshd/cmd/meshd@latest
```

## What is this?

meshd is a WireGuard mesh network where there is no coordination server.
No Tailscale account. No self-hosted Headscale. Your devices discover each
other, exchange keys, and establish encrypted tunnels -- all coordinated
through cryptographically signed records on a
[Decentralized Web Node](https://github.com/enboxorg/dwn-spec).

You don't need to know what that means. `meshd init` handles everything.

## Quick start (planned)

```bash
# On your first machine
meshd init
meshd network create --name "my-network"

# On your second machine
meshd init
# prints: Your device identity: did:dht:k5f8...

# Back on the first machine, add the second
meshd peer add did:dht:k5f8...

# On the second machine, join
meshd network join did:dht:abc1... <network-id>
meshd up

# That's it. The machines can reach each other at 100.64.0.x
# through encrypted WireGuard tunnels. NAT traversal is automatic.
```

## How is this different?

|             | You give up    | You manage  | You trust      |
|-------------|----------------|-------------|----------------|
| Tailscale   | control        | nothing     | Tailscale Inc. |
| Headscale   | less control   | a server    | your server    |
| WireGuard   | nothing        | everything  | yourself       |
| **meshd**   | nothing        | nothing     | cryptography   |

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
"server" is an embedded component that starts when you run `meshd up`.

**Add people, not just devices.** Invite collaborators into your mesh.
They bring their own devices. You control access with ACL policies.
Remove someone and their access is revoked across every node immediately.

**Privacy by default.** All mesh coordination data (keys, endpoints,
membership, policies) is encrypted at rest. Not just the tunnel traffic --
the metadata too. Nobody can see who's in your network, where they are,
or what the rules are.

## If you already have a DID and DWN

meshd becomes something more: **private infrastructure for your DWN
identity**.

Your DID document lists your public DWN. But what about your backup
NAS, your laptop, your staging instance? They shouldn't be in your DID
document. They shouldn't have public IPs. But they need to sync.

meshd creates the private layer underneath your public identity:

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

**Networking:** meshd uses [dexnet](https://github.com/WebP2P/dexnet)
as its networking engine -- a fork of Tailscale's open-source client with
its own IP space (`10.200.0.0/16`) so it runs side-by-side with Tailscale.
This gives us battle-tested WireGuard management, NAT traversal, STUN,
DERP relay, and UDP hole punching out of the box.

**Coordination:** meshd replaces Tailscale's coordination server with
DWN protocols. Every device gets a **DID** (a cryptographic identity --
think self-signed certificate the whole internet can verify) and runs an
embedded **DWN** (a tiny personal data store). Devices discover each other
by reading cryptographically signed, encrypted records from each other's
DWNs and subscribing to real-time updates.

**The glue:** A DWN-based control client translates DWN records into the
data structures dexnet's WireGuard engine expects. This means we get the
entire Tailscale data plane without modification -- we only replace the
part that answers "who are my peers and how do I reach them?"

```
meshd = DWN coordination (identity, membership, ACLs, encryption)
         + dexnet engine (WireGuard, NAT traversal, DERP, hole punching)
```

The mesh uses two DWN protocols:

- **`wireguard-mesh`** on an anchor DWN: network membership, ACLs, relays
- **`wireguard-node`** on each device: WireGuard public key + endpoint

All records are signed with DIDs and encrypted with JWE. The protocols
enforce access control declaratively.

## Coexistence with Tailscale

dexnet uses `10.200.0.0/16` (IPv4) and `fd0d:e100:d3c5::/48` (IPv6),
while Tailscale uses `100.64.0.0/10` and `fd7a:115c:a1e0::/48`. Different
socket names (`dexnetd` vs `tailscaled`), different state directories.
You can run both simultaneously on the same machine -- Tailscale for work,
meshd for your personal infrastructure.

## Project structure

```
cmd/meshd/           CLI entrypoint
internal/
  did/                  DID generation (did:dht), key derivation, persistence
  dwn/                  DWN HTTP client, JWS signing, CID computation, subscriptions
  control/              DWN-based control client → MapResponse for networking engine
  state/                On-disk state management (identity, network membership)
protocols/              DWN protocol definitions (encrypted)
schemas/                JSON schemas for record data

External dependency (not yet integrated):
  github.com/enboxorg/dexnet   (Tailscale fork -- WireGuard, NAT, DERP)
```

## License

TBD
