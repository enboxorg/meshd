# meshd

[![CI](https://github.com/enboxorg/meshd/actions/workflows/ci.yml/badge.svg)](https://github.com/enboxorg/meshd/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/enboxorg/meshd/graph/badge.svg)](https://codecov.io/gh/enboxorg/meshd)

Mesh VPN with no accounts, no servers, no company.

Your identity is a cryptographic key. Your devices coordinate through
encrypted records on a [Decentralized Web Node](https://github.com/enboxorg/dwn-spec).
Invite others with a single command. Everything is encrypted. Nothing to
sign up for. Nothing to self-host. Nothing to trust.

**Status:** Pre-release. The core engine works (WireGuard tunnels via DWN
coordination), CLI is functional, and integration tests pass against a live
DWN. See [DESIGN.md](DESIGN.md) for the full architecture.

## Quick start

```bash
# On your first machine
meshd up --create my-network --endpoint https://dwn.example.com
# prompts once to create a local vault password, creates the network, then starts meshd

# In another terminal on the first machine, create an invite URL
meshd invite create
# prints: meshd://invite/eyJ...

# On your second machine, join from the invite
meshd join meshd://invite/eyJ...
# prompts once to create a local vault password and submits a join request

# Start meshd on the second machine
meshd up

# That's it. After the anchor approves the invite, the machines can reach each other at 10.200.x.x
# through encrypted WireGuard tunnels. NAT traversal is automatic.
```

## What is this?

meshd is a WireGuard mesh network where there is no coordination server.
No Tailscale account. No self-hosted Headscale. Your devices discover each
other, exchange keys, and establish encrypted tunnels -- all coordinated
through cryptographically signed records on a
[Decentralized Web Node](https://github.com/enboxorg/dwn-spec).

You don't need to know what that means. `meshd up --create` handles everything.

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
changes propagate automatically.

## What you get

**Encrypted mesh in minutes.** Connect your devices across any network.
Behind NATs, on different continents, on cellular -- it just works.

**No infrastructure to run.** There is no coordination server. Devices
coordinate through signed, encrypted records on a DWN. The control plane
is a protocol, not a service.

**Add people, not just devices.** Invite collaborators into your mesh.
They bring their own devices. You control access with ACL policies.
Remove someone and their access is revoked across every node.

**Privacy by default.** All mesh coordination data (keys, endpoints,
membership, policies) is encrypted at rest using JWE (ECDH-ES+A256KW
with A256GCM). Not just the tunnel traffic -- the metadata too. Nobody
can see who's in your network, where they are, or what the rules are.

## CLI

```
meshd <command> [arguments]

Identity:
  init              Generate DID identity and store locally
  auth login        Create a named identity profile
  auth list         List all profiles
  auth use <name>   Set the default profile
  auth logout       Remove a profile from config
  vault status      Show local vault state
  vault init        Encrypt a legacy plaintext identity
  vault unlock      Verify the vault password and show identity

Network:
  network create    Create a new mesh network on a DWN
  network join      Join an existing mesh network
  network leave     Leave the current mesh network
  invite create     Create an invite URL for joining this network
  join <url>        Join a network from a meshd://invite URL
  peer add          Add a peer to the mesh (anchor only)
  peer list         List all peers in the mesh
  peer approve      Deliver encryption keys to a peer (anchor only)
  acl set <file>    Set ACL policy from a JSON file (anchor only)
  acl show          Show the current ACL policy
  status            Show mesh status and identity info
  up                Start the mesh agent daemon
  down              Stop the mesh agent daemon
```

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
     10.200.0.1        10.200.0.2          10.200.0.3
          |                 |                    |
          +-- WireGuard ----+---- WireGuard -----+
                   encrypted mesh
                   DWN sync runs here
```

Your private DWN replicas sync with your public DWN over the encrypted
mesh. They never need a public IP. They never appear in your DID document.

## How it works under the hood

**Identity:** Each device gets a `did:jwk` identity -- an Ed25519 key pair
encoded as a DID. The private key is stored in a password-encrypted local
vault, and delivered network context keys are stored in encrypted local
secrets. The WireGuard key is derived from the same identity (Ed25519 to
X25519 birational map), so there is exactly one identity key to manage.

**Networking:** meshd uses [meshnet](https://github.com/enboxorg/meshnet),
a fork of Tailscale's open-source networking engine. This gives us
battle-tested WireGuard management, NAT traversal, STUN, DERP relay,
and UDP hole punching. meshd uses `10.200.0.0/16` for its mesh IP space.

**Coordination:** meshd replaces Tailscale's coordination server with a
DWN protocol (`wireguard-mesh`). Devices discover each other by reading
encrypted records from the anchor's DWN. The DWN-based control client
translates these records into the data structures the WireGuard engine
expects.

**Encryption:** All sensitive records (node membership, endpoints, ACL
policies) are encrypted with JWE using ECDH-ES+A256KW key agreement
and A256GCM content encryption. Encryption keys are derived
hierarchically via HKDF from the protocol root key.

```
meshd = DWN coordination (identity, membership, ACLs, encryption)
       + meshnet engine (WireGuard, NAT traversal, DERP, hole punching)
```

### Protocol structure

The mesh is coordinated through a single DWN protocol (`wireguard-mesh`)
on the anchor's DWN:

```
network
  +-- node ($role, recipient = device DID)    -- owner-provisioned devices
  |     +-- nodeInfo                          -- device writes: hostname, OS
  |     +-- endpoint                          -- device writes: IPs, NAT type
  |
  +-- member ($role, recipient = member DID)  -- invited members
  |     +-- nodeRequest                       -- member proposes a device
  |     +-- node ($role, recipient = device DID)
  |           +-- nodeInfo
  |           +-- endpoint
  |
  +-- aclPolicy                               -- packet filter rules
  +-- relay                                   -- custom DERP relays
```

Devices write their own `nodeInfo` and `endpoint` records using
recipient-based authorization. The network owner manages membership
and node records.

## Coexistence with Tailscale

meshd uses `10.200.0.0/16` (IPv4) and `fd0d:e100:d3c5::/48` (IPv6).
Tailscale uses `100.64.0.0/10` and `fd7a:115c:a1e0::/48`. Different
socket names, different state directories. You can run both simultaneously
on the same machine.

## Project structure

```
cmd/meshd/              CLI entrypoint
internal/
  control/              DWN-based control client -> MapResponse for engine
  dwn/                  DWN HTTP client, JWS signing, CID, subscriptions
    crypto/             JWE encryption, HKDF key derivation, key delivery
  engine/               WireGuard engine integration (meshnet)
  mesh/                 Mesh registration, node/endpoint/ACL writes
  did/                  DID generation (did:jwk), key derivation, persistence
  vault/                Password-encrypted local secret storage
  state/                On-disk state management
  daemon/               Unix socket daemon for up/down/status
  profile/              Multi-identity profile management
pkg/
  dids/                 DID resolution (did:jwk, did:web, did:dht)
  jwk/                  JWK key operations
  crypto/               DSA helpers (Ed25519, ECDSA)
protocols/              DWN protocol definitions (wireguard-mesh, key-delivery)
schemas/                JSON schemas for record data
vendor/                 Vendored dependencies (including meshnet fork)
```

## Development

```bash
# Build
GOFLAGS=-mod=vendor go build ./...

# Run tests (unit tests only; integration tests need DWN_ENDPOINT)
GOFLAGS=-mod=vendor go test ./... -count=1 -race

# Run integration tests (requires a DWN server)
DWN_ENDPOINT=https://your-dwn.example.com GOFLAGS=-mod=vendor \
  go test ./internal/mesh/ -run TestE2E -v -count=1 -timeout 180s
```

See [CLAUDE.md](CLAUDE.md) for development conventions.

## License

TBD
