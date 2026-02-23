# dwn-mesh Design Document

A decentralized WireGuard mesh network coordinator built on Decentralized Web Nodes (DWN).

## Motivation

Tailscale provides an excellent WireGuard mesh networking experience, but its
coordination server is centralized. You must trust Tailscale Inc. to:

- Store and distribute your WireGuard public keys honestly
- Not inject rogue keys or members
- Not modify your ACL policies
- Maintain uptime for new peer connections
- Not surveil your network topology and connection patterns

**dwn-mesh** replaces Tailscale's coordination server with DWN protocol
records. Each machine has a DID, writes cryptographically signed records,
follows protocols, and uses DWN's built-in permissions, encryption, and
real-time subscriptions.

## Architecture Overview

### What Tailscale's Coordinator Does

The Tailscale coordination server (control plane) performs:

1. **Key Exchange** -- Nodes upload WireGuard public keys; the server distributes them to authorized peers
2. **Endpoint Discovery** -- Nodes report their `ip:port` (via STUN); the server distributes to peers
3. **Identity & Authentication** -- Nodes authenticate via OAuth2/OIDC/SAML
4. **ACL Policy Distribution** -- Central ACL policies pushed to every node for local enforcement
5. **DERP Relay Coordination** -- Tells nodes which relay servers to use
6. **Network Membership** -- Defines the "tailnet" boundary

The coordination server carries virtually no data traffic. It exchanges
metadata: public keys, IP addresses, policies. This is exactly what DWN is
designed for.

### DWN Primitive Mapping

| Tailscale Concept       | DWN Primitive                                                    |
| ----------------------- | ---------------------------------------------------------------- |
| Node identity           | DID (`did:dht`)                                                  |
| Coordination server     | Anchor DWN + per-node DWNs (no central server)                   |
| Public key upload       | `RecordsWrite` (encrypted)                                       |
| Key distribution        | Protocol `$actions` with `read` permissions + context encryption |
| Tailnet membership      | Protocol roles (`$role: true`)                                   |
| ACL policies            | Protocol `$actions` rules + encrypted ACL records                |
| Endpoint updates        | `RecordsWrite` updates (mutable, encrypted)                      |
| Real-time peer discovery| `RecordsSubscribe` (live event streams via EventLog)             |
| DERP server list        | Encrypted relay records in the mesh protocol                     |
| Authentication          | DID-based cryptographic signatures (replaces OAuth)              |

### Hybrid Architecture (Recommended)

```
                    +---------------+
                    |  Anchor DWN   |  <- network, members, ACLs, relays
                    |  (replicated) |     all encrypted with Protocol Path keys
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

1. **Anchor DWN(s)** host canonical mesh state (network definition,
   membership, ACLs). Run by admin(s), replicated across endpoints.
2. **Each node runs a lightweight DWN** for its own nodeInfo/endpoint data.
3. **All sensitive data is encrypted** using DWN's JWE encryption with
   hierarchical HKDF key derivation. Only authorized members can decrypt.
4. **Peers discover each other** by reading the member list from the anchor
   DWN, resolving each member's DID to their DWN endpoint, and subscribing
   to encrypted endpoint updates.

## Encryption Architecture

All mesh coordination data is encrypted at rest in the DWN. The DWN operator
(who may host the anchor DWN) cannot read the plaintext without the
appropriate decryption keys.

### What Is Encrypted

| Record Type  | Encrypted | Rationale                                                  |
| ------------ | --------- | ---------------------------------------------------------- |
| `network`    | Yes       | Network name, CIDR, DNS config are sensitive               |
| `admin`      | Yes       | Admin identities reveal who controls the network           |
| `member`     | Yes       | Membership list reveals the network's participants         |
| `nodeInfo`   | Yes       | WireGuard public keys + mesh IPs reveal topology           |
| `endpoint`   | Yes       | Public IPs and ports reveal physical locations             |
| `aclPolicy`  | Yes       | Security posture; reveals internal structure               |
| `relay`      | Yes       | Relay infrastructure is operational detail                 |
| `preAuthKey` | Yes       | Auth keys are secrets (also has `encryptionRequired: true`)|
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
decrypt everything. An entity with only the `nodeInfo` key can decrypt
nodeInfo and endpoint records but nothing else.

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

### Per-Node DWN Encryption (wireguard-node protocol)

Each node's own DWN also encrypts nodeInfo and endpoint records. Access is
controlled via the `peerAuth` role:

1. When node A learns that node B is a fellow member (from the anchor DWN),
   node A writes a `peerAuth` role record on node B's DWN (if B's protocol
   allows it), or node B proactively writes `peerAuth` role records for all
   fellow members.
2. The node owner delivers context keys to authorized peers via key-delivery.
3. Authorized peers can then read and decrypt nodeInfo/endpoint data.

This means even if someone discovers a node's DWN URL, they cannot read its
WireGuard configuration without being an authorized peer.

## Protocol Definitions

### `wireguard-mesh` Protocol

Installed on the **anchor DWN**. Manages network-wide state.

See [`protocols/wireguard-mesh.json`](protocols/wireguard-mesh.json) for the
full definition.

**Record hierarchy:**

```
network                        (root: network definition)
  +-- admin           [$role]  (admin role assignments)
  +-- member          [$role]  (member role assignments)
  +-- nodeInfo                 (WireGuard public key + mesh IP)
  |    +-- endpoint            (current ip:port, NAT type, DERP preference)
  +-- aclPolicy                (network ACL rules)
  +-- relay                    (DERP relay server registry)
  +-- preAuthKey               (pre-authentication keys for headless onboarding)
  +-- event                    (immutable audit log with squash compaction)
```

### `wireguard-node` Protocol

Installed on **each node's DWN**. Publishes per-node state.

See [`protocols/wireguard-node.json`](protocols/wireguard-node.json) for the
full definition.

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
| Read nodeInfo/endpoint  | Members only (encrypted)               |
| Write ACL policy        | Network owner or admins                |
| Read ACL policy         | Members only (encrypted)               |
| Register relay          | Any member                             |
| Remove any relay        | Network owner                          |
| Create pre-auth keys    | Network owner or admins                |
| Write audit events      | Any member                             |
| Squash audit events     | Admins only                            |

### Endpoint Data Privacy

Unlike Tailscale where endpoint data passes through a central server,
dwn-mesh encrypts endpoint data so that:

- The **anchor DWN operator** cannot read plaintext endpoints without the
  decryption key, even though the data is stored on their infrastructure
- Only **network members** with the context key can decrypt and read
  endpoint data
- A **passive network observer** sees only encrypted DWN protocol messages
  over HTTPS

### Revocation

When a member is removed:

1. Admin deletes (or updates status to `suspended`) the member's role record
   on the anchor DWN
2. All members receive this change via `RecordsSubscribe`
3. Each member removes the revoked peer from their WireGuard configuration
4. The revoked peer's `peerAuth` role on each node's DWN is deleted
5. Context keys should be rotated (the owner generates new context keys and
   distributes to remaining members)

### Threat Model Summary

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

## Operational Flow

### Bootstrap: Creating a Network

```
1. Admin generates a DID (did:dht) and provisions an anchor DWN
2. Admin installs the wireguard-mesh protocol on the anchor DWN
3. Admin generates X25519 encryption keypair for Protocol Path encryption
4. Admin writes a `network` record:
   { name: "my-mesh", meshCIDR: "100.64.0.0/10", ... }
5. Admin writes default `relay` records for DERP servers
6. Admin writes initial `aclPolicy` record
```

### Joining a Node

```
1. Node generates a DID and WireGuard keypair
2. Node starts a local DWN daemon, installs wireguard-node protocol
3. Admin writes a `member` role record on the anchor DWN
   (recipient = node's DID, tags: { status: "active" })
4. Admin delivers context encryption key to the new member
5. Node reads the anchor DWN:
   a. Reads network config (meshCIDR, relays, DNS)
   b. Reads member list -> discovers peer DIDs
   c. Reads ACL policy
6. Node writes its `nodeInfo` to the anchor DWN
7. For each peer:
   a. Resolve peer DID -> get DWN endpoint
   b. Write peerAuth role on peer's DWN (or receive one)
   c. Read peer's nodeInfo (WG pubkey, mesh IP)
   d. Subscribe to peer's endpoint updates
8. Node configures WireGuard interface with all peer pubkeys
9. Node runs STUN, discovers public endpoint
10. Node writes endpoint record to its own DWN
11. All peers receive endpoint update, add to WireGuard config
12. Mesh tunnels establish
```

### Ongoing Operation

```
- STUN runs periodically; endpoint changes trigger RecordsWrite
- RecordsSubscribe delivers peer endpoint changes in real-time
- ACL policy changes propagate via subscription
- Member additions/removals propagate via subscription
- WireGuard keepalives maintain NAT mappings (25s interval)
- DERP relay used as fallback when direct connection fails
- EventLog cursors enable crash-safe reconnection (no missed events)
```

## Implementation Plan

### Phase 0: Foundation (Weeks 1-2)

- Go project setup with module structure
- DID generation and management (`did:dht`)
- DWN HTTP client (RecordsWrite, RecordsRead, RecordsQuery, RecordsSubscribe)
- WireGuard interface management via `wgctrl`

### Phase 1: Two-Node Mesh (Weeks 3-4)

- `dwn-mesh init` and `dwn-mesh network create`
- Protocol installation on DWNs
- nodeInfo/endpoint record writing (with encryption)
- Peer discovery (member list -> DID resolution -> nodeInfo read)
- WireGuard tunnel establishment

### Phase 2: Dynamic Mesh (Weeks 5-6)

- `RecordsSubscribe` for real-time updates
- `dwn-mesh peer add` / `peer remove`
- Daemon mode with subscription manager
- STUN-based endpoint discovery
- Endpoint propagation via encrypted DWN subscriptions

### Phase 3: NAT Traversal (Weeks 7-8)

- STUN (multiple servers)
- NAT type detection
- UDP hole punching
- DERP relay integration
- DWN subscriptions as NAT traversal side channel

### Phase 4: ACLs & Security (Weeks 9-10)

- ACL policy distribution (encrypted)
- Local ACL enforcement (nftables/iptables)
- Member revocation with key rotation
- WireGuard key rotation

### Phase 5: Production Hardening (Weeks 11-12)

- Anchor DWN replication
- Cursor-based reconnection (EventLog catch-up)
- IP address allocation
- DNS integration (mesh-local hostnames)
- systemd service files

## Project Structure

```
dwn-mesh/
+-- cmd/dwn-mesh/           CLI entrypoint
+-- internal/
|   +-- did/                DID generation and resolution
|   +-- dwn/                DWN HTTP client + subscriptions
|   +-- mesh/               Network/peer management, discovery
|   +-- wg/                 WireGuard interface configuration
|   +-- nat/                STUN, hole punching, port mapping
|   +-- derp/               DERP relay client
|   +-- acl/                ACL policy parsing + enforcement
+-- protocols/              DWN protocol definitions (JSON)
+-- schemas/                JSON schemas for record data
```

## Comparison with Alternatives

| Aspect          | Tailscale       | Headscale        | dwn-mesh                    |
| --------------- | --------------- | ---------------- | --------------------------- |
| Coordination    | Centralized SaaS| Self-hosted      | Decentralized (DWN)         |
| Identity        | OAuth2/OIDC     | OAuth2/OIDC      | DIDs (self-sovereign)       |
| Data sovereignty| Tailscale Inc.  | Your server      | Your DWN(s), encrypted      |
| Single point    | login.tailscale | Your headscale   | None (replicated DWN)       |
| Trust model     | Trust Tailscale | Trust your infra | Trust cryptography           |
| Open source     | Client only     | Server + client  | Everything                  |
| Multi-network   | 1 per account   | 1 per instance   | Unlimited per DID           |
| Data at rest    | Plaintext*      | Plaintext*       | Encrypted (JWE)             |

*Coordination data (keys, endpoints) stored in plaintext on the server side.

## References

- [DWN Specification](https://github.com/enboxorg/dwn-spec)
- [How Tailscale Works](https://tailscale.com/blog/how-tailscale-works)
- [How NAT Traversal Works](https://tailscale.com/blog/how-nat-traversal-works)
- [Headscale](https://github.com/juanfont/headscale)
- [WireGuard Protocol](https://www.wireguard.com/protocol/)
- [DID DHT Method](https://did-dht.com/)
