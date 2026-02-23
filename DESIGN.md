# dwn-mesh Design Document

A private encrypted mesh for DWN infrastructure and collaboration.

## Two Audiences, One Product

dwn-mesh serves two audiences that converge on the same product:

### Audience 1: "I want a mesh VPN that nobody controls"

These are developers, sysadmins, homelabbers, and privacy-conscious
people who want WireGuard mesh networking without:

- An account on a company's service (Tailscale)
- A server to self-host and maintain (Headscale)
- Manual key distribution and config management (raw WireGuard)

They don't know what DIDs or DWNs are. They don't care. They want to
run `dwn-mesh init` on two machines and have them connected.

**For this audience, dwn-mesh is a zero-account, zero-server mesh VPN.**

The DID is "your device identity." The DWN is "an embedded component that
handles coordination." The user never types either acronym.

```
$ dwn-mesh init
Device identity: did:dht:3fk8...xj2m
WireGuard keys generated
Coordination node started on port 8787
Ready. Run 'dwn-mesh network create' to start a mesh.
```

### Audience 2: "I have DWNs and need private infrastructure"

These are people already in the DWN ecosystem. They have DIDs, run DWNs,
use protocols. They have a specific unmet need: private DWN replicas and
encrypted cross-DWN collaboration.

**For this audience, dwn-mesh is the private layer underneath their
public DWN identity.**

### Where They Converge

The first audience comes for the mesh VPN and discovers they now have a
DID and a DWN. The second audience comes for DWN infrastructure and gets
a mesh VPN. Both end up in the same place: a private encrypted network
coordinated by decentralized protocols.

This is the strategic value: **dwn-mesh is a gateway into the DWN
ecosystem.** People come for the mesh VPN. They stay because they now
have a decentralized identity and personal data node that works with
everything else in the ecosystem.

```
Tailscale user journey:
  "I need a VPN" -> Tailscale -> locked into Tailscale's ecosystem

dwn-mesh user journey:
  "I need a mesh VPN" -> dwn-mesh -> they now have a DID and a DWN
  -> "my device has a decentralized identity?"
  -> "I can store data on this and share it with protocols?"
  -> "other apps can use this identity too?"
```

The mesh VPN is the trojan horse. The DID/DWN is the payload.

## The Product Problem (DWN-Native Audience)

If you have a DID and a DWN today, you face several unsolved problems:

### 1. Your DWN Endpoints Are Public

Your DID document publicly lists your DWN service endpoints. Anyone
resolving your DID sees `https://dwn.alice.com`. This leaks:

- Your hosting infrastructure (IP addresses, cloud providers)
- Traffic patterns (who talks to your DWN, when, how often)
- The existence and location of your DWN replicas

### 2. No Private DWN Replicas

DWN supports multiple `serviceEndpoint` URLs for replication, and uses
SMT-based sync (`MessagesSync`) to keep them consistent. But every endpoint
in your DID document is public. What if you want:

- A NAS at home as a private backup of your DWN
- A local-first copy on your laptop that syncs when you're online
- A staging DWN for development that isn't exposed to the world

Today there's no clean way to keep a DWN instance private but still synced.
You'd need to manually configure VPN tunnels or rely on LAN-only access.

### 3. Cross-DWN Collaboration Goes Over the Public Internet

When Alice and Bob collaborate using a shared DWN protocol, Bob's DWN talks
to Alice's DWN over the public internet. Even though DWN encrypts the record
data, the transport metadata (who, when, how much) is visible to network
observers.

### 4. DWN Hosting Creates Trust Dependencies

If you use a hosted DWN service, you trust that provider with availability.
DWN encryption protects data at rest, but the provider controls uptime and
could observe traffic patterns. Self-hosting on a single VPS is a single
point of failure.

## The Product: Private Infrastructure Mesh for DWN

dwn-mesh creates an **encrypted WireGuard overlay network** that connects
your DWN instances -- and the DWN instances of people you collaborate with --
into a private mesh. Traffic between mesh members never touches the public
internet unprotected.

### What It Gives You

**Private DWN Sync.** Run DWN replicas on your home NAS, your laptop, a VPS,
wherever -- they sync over the encrypted mesh. None of these need to be in
your DID document. None need a public IP. No hole punching configuration.
The mesh handles NAT traversal automatically.

**Selective Sharing.** Invite collaborators into your mesh. Their DWNs can
reach your private DWN endpoints over the mesh. You control exactly who gets
in and what they can reach via ACL policies.

**No Central Authority.** Mesh coordination runs on DWN itself -- the same
infrastructure it's protecting. Each machine has a DID. Membership, keys,
endpoints, and policies are DWN protocol records. Cryptographically signed.
Encrypted. Replicated via DWN sync.

**Your Public DWN Stays Public.** Your DID document still lists your public
DWN endpoint. The outside world talks to you through that. Behind the scenes,
your public DWN syncs with private replicas over the mesh. The mesh is
invisible to anyone who isn't a member.

### The Architecture

```
The internet sees this:

    DID Document for did:dht:alice
      serviceEndpoint: ["https://dwn.alice.com"]
                              |
                              v
                     +------------------+
                     | dwn.alice.com    |  Public DWN
                     | (VPS, 5.5.5.5)  |  (the only thing visible)
                     +------------------+

Behind the scenes, the mesh:

     dwn.alice.com          nas.alice         laptop.alice
     (VPS, public)       (home, NAT'd)     (roaming, NAT'd)
     100.64.0.1           100.64.0.2         100.64.0.3
          |                    |                   |
          +--- WireGuard ------+--- WireGuard -----+
          |    encrypted       |    encrypted       |
          |                    |                    |
          |   DWN sync over mesh (private, fast)    |
          +--------------------+--------------------+

     Bob (collaborator)       Carol (collaborator)
     100.64.0.10              100.64.0.11
          |                        |
          +---- WireGuard ---------+
          |     encrypted          |
          |                        |
          Can reach Alice's private DWN endpoints
          that aren't in any DID document
```

Alice's NAS and laptop are never in her DID document. They have no public
IPs. But they sync with her public DWN over the mesh, and Bob and Carol can
reach them if Alice's ACLs allow it.

### Who This Is For

**Anyone who wants a mesh VPN.** You don't need to know about DIDs or DWNs.
Install dwn-mesh on your devices, create a network, add peers. It works like
Tailscale but with no account, no server, and no company.

**Individual DWN operators.** You run your own DWN infrastructure. You want
private replicas, local-first access, and encrypted sync between your
devices. You don't want to expose every replica to the internet.

**Collaborators.** You work with others using shared DWN protocols. You want
a private channel between your DWN infrastructure and theirs. You want to
control exactly who has access and what they can reach.

**Organizations.** You run DWN infrastructure for a team. You want internal
DWN services that are only accessible to team members. You want centralized
policy control with distributed enforcement. New members onboard with a
pre-auth key; revoked members lose access immediately.

### Why Share Your Mesh

You'd invite someone into your mesh when:

- **You collaborate on shared DWN protocols.** Your DWNs need to talk to
  each other. The mesh gives them a private, encrypted channel. Faster and
  more private than the public internet.

- **You want to offer someone access to a private DWN endpoint.** Maybe you
  run a service on a DWN that isn't public. The mesh lets you grant access
  to specific people without exposing the endpoint to the world.

- **You're building a team/organization.** Everyone's devices join the mesh.
  Internal DWN services are mesh-only. ACL policies control who can reach
  what. It's a zero-trust network for DWN infrastructure.

- **You want redundancy without exposure.** You and a friend each run a DWN
  replica for the other. Both are on the mesh, syncing over encrypted
  tunnels. Neither replica needs to be public.

## Technical Design

### DWN Primitive Mapping

| Mesh Concept            | DWN Primitive                                                    |
| ----------------------- | ---------------------------------------------------------------- |
| Node identity           | DID (`did:dht`)                                                  |
| Mesh coordination       | Anchor DWN + per-node DWNs                                       |
| Key exchange             | `RecordsWrite` (encrypted)                                       |
| Key distribution        | Protocol `$actions` + Protocol Context key delivery              |
| Membership              | Protocol roles (`$role: true`)                                   |
| ACL policies            | Protocol `$actions` rules + encrypted ACL records                |
| Endpoint updates        | `RecordsWrite` updates (mutable, encrypted)                      |
| Real-time peer discovery| `RecordsSubscribe` (live event streams via EventLog)             |
| Relay registry          | Encrypted relay records in the mesh protocol                     |
| Authentication          | DID-based cryptographic signatures                               |

### Hybrid Architecture

```
                    +---------------+
                    |  Anchor DWN   |  <- encrypted: members, ACLs, relays
                    |  (replicated) |     can be any member's existing DWN
                    +-------+-------+
                            | member list (encrypted)
               +------------+------------+
               v            v            v
         +-----------++-----------++-----------+
         | Alice DWN || Bob DWN   || Carol DWN |  <- each stores own
         |  (local)  ||  (local)  ||  (local)  |    nodeInfo + endpoints
         +-----------++-----------++-----------+    encrypted, peers
               ^            ^            ^          get context keys
               +------------+------------+
                     mutual subscriptions
                     for endpoint updates
```

The **anchor DWN** is just a regular DWN -- it can be any member's existing
DWN. It doesn't need to be a dedicated server. It hosts the mesh protocol
records (network definition, membership, ACLs). It can be replicated across
multiple endpoints for availability.

Each node also runs its own DWN (or uses its existing one) for its own
nodeInfo and endpoint data.

**Key insight:** the anchor DWN doesn't need to be in anyone's DID document
either. It can itself be a mesh-only endpoint, bootstrapped by sharing its
DID + network record ID out-of-band (e.g., a QR code, a message, a link).

### DID Document Relationship

Nodes in the mesh fall into two categories:

**Public nodes** have their DWN in their DID document. They are reachable
by anyone on the internet. They serve as the "front door" for your DWN
identity. They are also on the mesh, where they sync with private nodes.

**Private nodes** are mesh-only. Their DWN is NOT in any DID document.
They have no public IP. They are only reachable by other mesh members
over the encrypted WireGuard tunnels. They sync with public nodes (or
other private nodes) over the mesh.

```
DID Document (public)               Mesh (private)
  serviceEndpoint: [                   100.64.0.1  dwn.alice.com  (public)
    "https://dwn.alice.com"            100.64.0.2  nas.alice      (private)
  ]                                    100.64.0.3  laptop.alice   (private)
```

This separation is the core product value. Your public identity is
minimal. Your private infrastructure is invisible.

### DWN Sync Over the Mesh

Once the mesh is established, DWN's built-in `MessagesSync` (SMT-based
set reconciliation) works transparently over the mesh IPs:

1. Public DWN (`dwn.alice.com`) has mesh IP `100.64.0.1`
2. NAS DWN has mesh IP `100.64.0.2`
3. The NAS DWN is configured to sync with `100.64.0.1` (mesh IP, not public)
4. Sync traffic flows over the WireGuard tunnel -- encrypted, NAT-traversed
5. The NAS never needs a public IP or open firewall port

This means DWN sync "just works" over the mesh with zero additional
configuration. The mesh handles connectivity; DWN handles data sync.

## Encryption Architecture

All mesh coordination data is encrypted at rest in the DWN. The DWN
operator cannot read the plaintext without the appropriate decryption keys.

### What Is Encrypted

| Record Type  | Encrypted | Rationale                                                  |
| ------------ | --------- | ---------------------------------------------------------- |
| `network`    | Yes       | Network name, CIDR, DNS config are operational detail      |
| `admin`      | Yes       | Admin identities reveal who controls the network           |
| `member`     | Yes       | Membership list reveals the network's participants         |
| `nodeInfo`   | Yes       | WireGuard public keys + mesh IPs reveal topology           |
| `endpoint`   | Yes       | Public IPs and ports reveal physical locations              |
| `aclPolicy`  | Yes       | Security posture; reveals internal structure                |
| `relay`      | Yes       | Relay infrastructure is operational detail                  |
| `preAuthKey` | Yes       | Auth keys are secrets                                      |
| `event`      | Yes       | Audit events reveal operational patterns                   |

### Key Derivation: Protocol Path Scheme

The `wireguard-mesh` protocol uses the **Protocol Path** key derivation
scheme. Keys are derived hierarchically via HKDF-SHA-256 from a root X25519
key identified in the DWN owner's DID document.

```
Root Key (#dwn-enc from DID document)
  |
  +-- HKDF("protocolPath")
       |
       +-- HKDF("https://enbox.org/protocols/wireguard-mesh")
            |
            +-- HKDF("network")           -> encrypts network records
                 |
                 +-- HKDF("member")       -> encrypts member records
                 +-- HKDF("admin")        -> encrypts admin records
                 +-- HKDF("nodeInfo")     -> encrypts nodeInfo records
                 |    |
                 |    +-- HKDF("endpoint") -> encrypts endpoint records
                 +-- HKDF("aclPolicy")    -> encrypts ACL records
                 +-- HKDF("relay")        -> encrypts relay records
                 +-- HKDF("preAuthKey")   -> encrypts pre-auth keys
                 +-- HKDF("event")        -> encrypts event records
```

**Hierarchical property:** A private key at a given level can derive keys
for all descending levels. The network owner, possessing the root key, can
decrypt everything.

### Multi-Party Decryption: Context Key Delivery

Since all members need to read each other's encrypted data, the DWN owner
distributes **context keys** to members using the key-delivery protocol
(`https://enbox.org/protocols/key-delivery`):

1. When a new member is added, the anchor DWN owner derives the context
   private key using the Protocol Context scheme for that network's context.
2. The owner writes a `contextKey` record encrypted with the Protocol Path
   key for the key-delivery protocol, with `recipient` set to the new member.
3. The member reads the contextKey, decrypts it using their own Protocol Path
   key for key-delivery, and caches the context key locally.
4. The member uses the context key to decrypt all records in that network
   context.

### Per-Node DWN Encryption

Each node's own DWN also encrypts nodeInfo and endpoint records. Access is
controlled via the `peerAuth` role -- only members who have been granted
this role can read and decrypt the node's coordination data. This means even
if someone discovers a node's DWN URL, they cannot read its WireGuard
configuration without being an authorized peer.

## Protocol Definitions

### `wireguard-mesh` Protocol

Installed on the **anchor DWN**. Manages network-wide state.

See [`protocols/wireguard-mesh.json`](protocols/wireguard-mesh.json).

**Record hierarchy:**

```
network                        (root: network definition, encrypted)
  +-- admin           [$role]  (admin role assignments, encrypted)
  +-- member          [$role]  (member role assignments, encrypted)
  +-- nodeInfo                 (WireGuard public key + mesh IP, encrypted)
  |    +-- endpoint            (current ip:port + NAT type, encrypted)
  +-- aclPolicy                (network ACL rules, encrypted)
  +-- relay                    (DERP relay server registry, encrypted)
  +-- preAuthKey               (pre-authentication keys, encrypted)
  +-- event                    (immutable audit log w/ squash, encrypted)
```

### `wireguard-node` Protocol

Installed on **each node's DWN**. Publishes per-node state to authorized
peers.

See [`protocols/wireguard-node.json`](protocols/wireguard-node.json).

**Record hierarchy:**

```
peerAuth              [$role]  (authorized peers who can read node data)
nodeInfo                       (WireGuard public key + mesh IP, encrypted)
  +-- endpoint                 (current ip:port, encrypted)
```

## Security & Access Control

### Authorization Model

Every write to a DWN is cryptographically signed by the author's DID key.
The DWN validates signatures and protocol rules before accepting any record.

| Operation               | Who Can Do It                          |
| ----------------------- | -------------------------------------- |
| Create network          | Anyone (on their own DWN)              |
| Add/remove admins       | Network owner only                     |
| Add/remove members      | Network owner or admins                |
| Write nodeInfo          | Members (for their own node)           |
| Update endpoint         | Author of the parent nodeInfo only     |
| Read nodeInfo/endpoint  | Members only (encrypted + role-gated)  |
| Write ACL policy        | Network owner or admins                |
| Read ACL policy         | Members only (encrypted)               |
| Register relay          | Any member                             |
| Remove any relay        | Network owner                          |
| Create pre-auth keys    | Network owner or admins                |
| Write audit events      | Any member                             |
| Squash audit events     | Admins only                            |

### Revocation

When a member is removed:

1. Admin deletes (or updates status to `suspended`) the member's role record
2. All members receive this change via `RecordsSubscribe`
3. Each member removes the revoked peer from their WireGuard configuration
4. The revoked peer's `peerAuth` role on each node's DWN is deleted
5. Context keys should be rotated for forward secrecy

### Threat Model

| Attack                       | Tailscale          | dwn-mesh                                |
| ---------------------------- | ------------------ | --------------------------------------- |
| Coordination server tampered | Can inject keys    | Signatures prevent forgery              |
| Storage compromised          | Data exposed       | Data encrypted; keys not on server      |
| Admin key stolen             | OAuth recovery     | DID key rotation; multi-admin quorum    |
| Rogue member                 | ACLs limit scope   | Same + cryptographic enforcement        |
| MITM on control plane        | TLS only           | TLS + DID signatures + JWE encryption   |
| Endpoint poisoning           | WG handshake fails | Same (WG pubkey = identity)             |
| Metadata surveillance        | Tailscale sees all | Encrypted; distributed across DWNs      |
| Sybil attack                 | Admin approval     | Same (explicit membership grants)       |

## User Scenarios

### Scenario 0: Just a Mesh VPN

Dave is a developer. He has a laptop, a home server, and a VPS. He wants
them all connected. He's used Tailscale but doesn't love depending on a
company. He tried Headscale but doesn't want to maintain a server.

```bash
# On Dave's laptop
dwn-mesh init
dwn-mesh network create --name "dave-net"

# On Dave's home server
dwn-mesh init
# prints: Device identity: did:dht:srv1...

# On Dave's laptop
dwn-mesh peer add did:dht:srv1...

# On the home server
dwn-mesh network join did:dht:dave... <network-id>
dwn-mesh up

# Same for the VPS. Now all three machines can reach each other
# at 100.64.0.x over encrypted WireGuard tunnels.
# No accounts. No servers. No firewall configuration.
```

Dave doesn't know he's using DIDs or DWNs. He just knows it works.

Six months later, Dave sees a project that uses DIDs for authentication.
He realizes his dwn-mesh identity works there too. He starts using his
DWN for other things. The mesh was the entry point.

### Scenario 1: Personal DWN Infrastructure

Alice runs a public DWN on a VPS. She wants a backup on her home NAS and
local-first access on her laptop.

```bash
# On Alice's VPS (has her public DWN already running)
dwn-mesh init                    # Uses her existing DID
dwn-mesh network create \
  --name "alice-infra" \
  --cidr 100.64.0.0/24

# On Alice's NAS
dwn-mesh init                    # Generates a device DID
# Alice adds the NAS from her VPS:
dwn-mesh peer add did:dht:nas...

# On the NAS:
dwn-mesh network join did:dht:alice... <network-id>
dwn-mesh up

# The NAS now has a mesh IP. Alice configures her NAS DWN to sync
# with 100.64.0.1 (VPS mesh IP). Sync runs over the encrypted tunnel.
# The NAS never needs a public IP or open firewall port.
```

Same for her laptop. Three DWN instances, all synced, only one public.

### Scenario 2: Collaboration Mesh

Alice and Bob work together using a shared DWN protocol for project
management. They want their DWNs to communicate privately.

```bash
# Alice adds Bob to her mesh
dwn-mesh peer add did:dht:bob...

# Bob joins
dwn-mesh network join did:dht:alice... <network-id>
dwn-mesh up

# Bob's DWN can now reach Alice's DWN (including private endpoints)
# over the encrypted mesh. Protocol-level communication between their
# DWNs runs over WireGuard tunnels.
```

### Scenario 3: Organization

A small company uses DIDs for identity and DWNs for data. They create
a mesh for their infrastructure.

```bash
# IT admin creates the org mesh
dwn-mesh network create --name "acme-corp" --cidr 100.64.0.0/16

# Add team members
dwn-mesh peer add did:dht:employee1...
dwn-mesh peer add did:dht:employee2...

# Set ACL: developers can reach dev DWN, only ops can reach prod
dwn-mesh acl set --file acl-policy.json

# Distribute pre-auth keys for headless servers
dwn-mesh preauth create --label "ci-runner" --ephemeral

# On CI runner:
dwn-mesh network join --auth-key tskey-abc123...
```

Internal DWN services are mesh-only. The public DWN handles external
interactions. ACLs enforce who can reach what.

## Operational Flow

### Bootstrap: Creating a Network

```
1. Admin runs `dwn-mesh init` (uses existing DID or generates one)
2. Admin runs `dwn-mesh network create`
   a. Installs wireguard-mesh protocol on their DWN (anchor)
   b. Generates X25519 encryption keypair for Protocol Path encryption
   c. Writes network record (name, CIDR, relays)
   d. Writes initial ACL policy (default deny)
3. The admin's DWN is now the anchor. It can be replicated for HA.
```

### Joining a Node

```
1. Node runs `dwn-mesh init` (generates device DID + WireGuard keys)
2. Node starts local DWN, installs wireguard-node protocol
3. Admin runs `dwn-mesh peer add <node-did>` on anchor
   a. Writes member role record (recipient = node DID)
   b. Delivers context encryption key to the new member
4. Node runs `dwn-mesh network join <admin-did> <network-id>`
   a. Reads network config from anchor DWN (decrypts with context key)
   b. Reads member list, discovers peer DIDs
   c. Reads ACL policy
   d. Writes own nodeInfo to anchor DWN
5. For each peer:
   a. Resolve peer DID -> get DWN endpoint
   b. Read peer's nodeInfo (WG pubkey, mesh IP)
   c. Subscribe to peer's endpoint updates
6. Configures WireGuard interface with all peer pubkeys
7. Runs STUN, discovers public endpoint
8. Writes endpoint record to own DWN
9. All peers receive endpoint update, configure WireGuard
10. Mesh tunnels establish. DWN sync can now run over mesh IPs.
```

### Ongoing Operation

```
- STUN runs periodically; endpoint changes trigger RecordsWrite
- RecordsSubscribe delivers peer changes in real-time
- ACL/membership changes propagate via subscription
- WireGuard keepalives maintain NAT mappings (25s interval)
- DERP relay used as fallback when direct connection fails
- EventLog cursors enable crash-safe reconnection
- DWN sync between replicas runs over mesh IPs transparently
```

## Infrastructure Dependencies: STUN, DERP, and Why There's No Provider

A common question: does dwn-mesh require someone to run relay
infrastructure? The short answer is no. Here's the breakdown:

### STUN: Fully Commoditized (No Action Needed)

STUN servers are stateless -- they receive a UDP packet and reply with
"here's the ip:port I saw your packet coming from." They handle no data,
store nothing, and cost almost nothing to run. There are hundreds of free
public STUN servers:

- `stun.l.google.com:19302`
- `stun.cloudflare.com:3478`
- Many others maintained by the WebRTC/VoIP community

dwn-mesh ships with a hardcoded list of well-known public STUN servers.
Users can add their own. No dwn-mesh-specific STUN infrastructure is
needed.

### TURN: Not Needed

TURN is the traditional relay protocol. dwn-mesh doesn't use it. DERP
serves the same role but better: it works over HTTPS (gets through more
restrictive networks) and routes by WireGuard public key instead of
allocated ports.

### DERP: Decentralized by Design

DERP (Designated Encrypted Relay for Packets) is the only component where
someone needs to run a server. When two peers can't establish a direct
WireGuard tunnel (hard NATs, UDP blocked entirely), encrypted packets
flow through a DERP relay.

**But DERP servers don't need to be trusted.** They relay already-encrypted
WireGuard packets. They can't read the content. The worst a rogue DERP
server can do is drop packets (peers will try other relays or retry
direct connections) or log connection metadata (who connected, when --
but not what was said).

**DERP is already commoditized:**

1. **Tailscale's DERP server is open source** (Apache 2.0). About 2000
   lines of Go. Anyone can run one on a $5/month VPS.

2. **The Headscale community runs hundreds of independent DERP servers.**
   There's a well-established culture of community-operated relays.

3. **Any dwn-mesh node with a public IP can be a DERP relay.** An
   embedded DERP server is part of the design. Running a relay is one
   flag:

   ```bash
   dwn-mesh up --relay
   ```

   The node registers itself as a relay in the mesh protocol. Other
   members discover it automatically.

**How relay discovery works in dwn-mesh:**

In Tailscale, the DERP server list is hardcoded and controlled by
Tailscale Inc. In dwn-mesh, relays are `relay` records in the mesh
protocol -- encrypted, signed, and discoverable by members:

```
network
  +-- relay    (any member can register; encrypted records)
```

When a member starts a relay, they write a `relay` record with the
server's URL, geographic region, and STUN port. All members see it via
their subscription to the anchor DWN and can use it for relay fallback.

**The result: no dwn-mesh service provider is needed.** The combination
of free public STUN servers, open-source DERP, and the ability for any
mesh node to become a relay means the infrastructure is fully
self-sustaining. This is a concrete difference from Tailscale, where
Tailscale Inc. operates all relay infrastructure.

| Component | Tailscale                     | dwn-mesh                           |
| --------- | ----------------------------- | ---------------------------------- |
| STUN      | Tailscale-operated            | Public servers (Google, CF, etc.)  |
| TURN      | Not used                      | Not used                           |
| DERP      | Tailscale-operated (12+ PoPs) | Self-hosted / community / embedded |
| Discovery | Hardcoded by Tailscale        | DWN protocol records (decentralized)|

## Implementation Plan

### Phase 0: Foundation (Weeks 1-2)

- Go project setup with module structure
- DID generation and management (`did:dht`)
- DWN HTTP client (RecordsWrite, RecordsRead, RecordsQuery, RecordsSubscribe)
- WireGuard interface management via `wgctrl`

### Phase 1: Two-Node Mesh (Weeks 3-4)

- `dwn-mesh init` and `dwn-mesh network create`
- Protocol installation on DWNs (with encryption)
- nodeInfo/endpoint record writing
- Peer discovery (member list -> DID resolution -> nodeInfo read)
- WireGuard tunnel establishment between two nodes

### Phase 2: Dynamic Mesh (Weeks 5-6)

- `RecordsSubscribe` for real-time updates
- `dwn-mesh peer add` / `peer remove`
- Daemon mode (`dwn-mesh up`) with subscription manager
- STUN-based endpoint discovery
- Endpoint propagation via encrypted DWN subscriptions

### Phase 3: NAT Traversal (Weeks 7-8)

- STUN (multiple servers)
- NAT type detection
- UDP hole punching
- DERP relay integration

### Phase 4: ACLs & DWN Sync Integration (Weeks 9-10)

- ACL policy distribution (encrypted)
- Local ACL enforcement (nftables/iptables)
- Member revocation with key rotation
- DWN-to-DWN sync over mesh IPs (transparent to DWN)

### Phase 5: Production Hardening (Weeks 11-12)

- Anchor DWN replication
- Cursor-based reconnection (EventLog catch-up)
- IP address allocation
- DNS integration (mesh-local hostnames)
- systemd service files
- Pre-auth keys for headless onboarding

## Gateway to the DWN Ecosystem

### The Onramp

`dwn-mesh init` creates a DID and starts an embedded DWN. The user doesn't
need to understand either concept. They see "device identity" and "the mesh
works." But under the hood, they now have:

- **A DID** that works with any DID-compatible system. Their mesh identity
  is also their identity for any other decentralized application.

- **A DWN** that can store any kind of data, follow any protocol, and sync
  with any other DWN. The mesh is just one protocol running on it.

- **Protocols** they can inspect, extend, and compose with. The mesh
  protocol is a standard DWN protocol definition. Other protocols can
  reference it via cross-protocol composition.

### The Aha Moment

The aha moment comes when the user realizes their dwn-mesh identity works
outside of dwn-mesh:

1. **"I can use my mesh identity to log into things."** DIDs work as
   authentication. No passwords. No OAuth. The same keypair that
   authenticates you to the mesh authenticates you everywhere.

2. **"I can store other data on my node."** The embedded DWN isn't just
   for mesh coordination. Install another protocol and it stores your
   notes, your files, your app data. All encrypted. All yours.

3. **"Other people can write to my node using protocols."** The same
   permission model that controls mesh membership can control who writes
   what data to your DWN. It's a personal API server you own.

4. **"I can sync this with a bigger DWN."** The embedded DWN can sync
   with a full DWN instance on a VPS. The user graduates from "mesh VPN
   tool" to "decentralized identity + data infrastructure."

### Product Expansion Path

```
Stage 1: Mesh VPN user
  - Installs dwn-mesh for the VPN
  - Gets a DID and embedded DWN (doesn't know/care)
  - Uses it to connect their devices

Stage 2: Identity-aware user
  - Discovers their DID works as a universal identity
  - Uses it to authenticate to other services
  - Shares their DID with collaborators

Stage 3: DWN-native user
  - Installs additional protocols on their DWN
  - Stores personal data, syncs across devices
  - Participates in protocol-based collaboration

Stage 4: Infrastructure operator
  - Runs a full DWN, lists it in their DID document
  - Uses dwn-mesh for private replication and collaboration
  - Builds applications on DWN protocols
```

Not every user will progress through all stages. But the path exists, and
each stage is a natural extension of the previous one. The mesh VPN is
the foot in the door.

## Comparison with Alternatives

| Aspect          | Tailscale       | Headscale        | dwn-mesh                     |
| --------------- | --------------- | ---------------- | ---------------------------- |
| Coordination    | Centralized SaaS| Self-hosted      | Decentralized (DWN)          |
| Identity        | OAuth2/OIDC     | OAuth2/OIDC      | DIDs (self-sovereign)        |
| Data sovereignty| Tailscale Inc.  | Your server      | Your DWN(s), encrypted       |
| Single point    | login.tailscale | Your headscale   | None (replicated anchor DWN) |
| Trust model     | Trust Tailscale | Trust your infra | Trust cryptography           |
| Data at rest    | Plaintext*      | Plaintext*       | Encrypted (JWE)              |
| Primary use     | General VPN     | General VPN      | DWN infrastructure mesh      |
| DWN-native      | No              | No               | Yes (protocols, sync, DIDs)  |

*Coordination data (keys, endpoints) stored in plaintext on the server.

## References

- [DWN Specification](https://github.com/enboxorg/dwn-spec)
- [How Tailscale Works](https://tailscale.com/blog/how-tailscale-works)
- [How NAT Traversal Works](https://tailscale.com/blog/how-nat-traversal-works)
- [Headscale](https://github.com/juanfont/headscale)
- [WireGuard Protocol](https://www.wireguard.com/protocol/)
- [DID DHT Method](https://did-dht.com/)
