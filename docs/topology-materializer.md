# Topology materialization

`meshd` treats the daemon's in-memory network map as the local read model.
Peer-list, tray, and status requests read that model over the daemon socket;
they never query the DWN in the request path. If the daemon is unavailable or
its first snapshot is not ready, the CLI reports that state immediately instead
of starting a second control-plane load.

The control-plane update path has two modes:

1. A full reconciliation establishes an authoritative raw-record baseline.
2. A live DWN subscription stages ordered record changes and applies them to a
   clone of that baseline.

The incremental path is transactional. It deep-copies an event before the
subscription acknowledges it, applies DWN write/delete ordering and squash
semantics, hydrates only a winning write whose payload was not inlined, builds
the parsed mesh response, converts it to a meshnet network map, and commits the
raw and parsed states together. A failed conversion leaves the last-good map
and staged prefix unchanged for retry. A failed projection also preserves the
last-good map, but invalidates the baseline so the next retry repairs it with a
full reconciliation.

## Full reconciliation triggers

A full load is the repair path, not the normal event path. It is required at
startup, for delivery-key changes, after a subscription cursor gap or terminal
failure, when the bounded event queue overflows, when an event is ambiguous or
invalid, or when no complete baseline exists. A slow periodic full load remains
as anti-entropy protection against missed server events. Rate limits and
transport failures retain pending work and honor coordinator backoff before a
repair is attempted.

The full-load cut is captured before remote reads begin. Events staged after
that cut survive baseline installation, so a snapshot cannot overwrite a
concurrent update. A newer repair marker aborts publication because the load
cannot prove that it covered the missing tail. Query entries with out-of-line
payloads are completed with a targeted authenticated `RecordsRead`; inline
entries require no extra request.

Every topology query is cursor-paginated. Parent-scoped member and node-child
queries run through a bounded worker pool and are assembled deterministically.
A reconciliation is bounded to 64 pages per logical query, 25,000 requests,
10,000 records, and 64 MiB of retained record/cursor data. Exceeding any bound,
repeating a cursor, or receiving an incomplete response fails the transaction
and leaves the last-good map installed.

## Bounds and recovery

The staged queue is bounded by both event count and retained bytes, and inbound
WebSocket messages have a separate hard size limit. DWN HTTP responses are
also rejected above 128 MiB before JSON or binary payload decoding. Overflow
or poison data is
acknowledged to avoid a reconnect loop, but invalidates the incremental
baseline and schedules a full repair. The raw baseline is replaced by each
anti-entropy load, which also bounds tombstone lifetime.

Parsed contributions are cached by canonical record identity. Successful
outcomes are immutable for that CID and are reused across unrelated updates and
anti-entropy runs. Opaque/key-unavailable outcomes are retried after key-cache
invalidation while their same logical slot can continue contributing a
last-good member, node, node-info, endpoint, relay, or ACL. A cold unreadable
ACL or configured relay fails closed; an authoritative empty set remains a
valid deletion. Descriptor-only node ghosts never receive fallback addresses or
keys: opaque peers stay out of the engine map, while opaque self fails unless a
recipient-matched typed last-good membership exists. Missing or deleted self
membership commits an epoch-expired, zero-peer down map so meshnet tears down
WireGuard while subscriptions remain available for renewal.

The local materializer follows the DWN base-state lattice:

- writes are ordered by `(messageTimestamp, messageCID)`;
- only a strictly newer delete can transition a live write to a tombstone;
- a plain tombstone can only become a strictly newer prune, and prune is
  terminal;
- squash records replace strictly older records in the same protocol path and
  parent context while retaining equal or newer records.

The nearest future peer-membership expiry has its own lifecycle-owned timer. It
reprojects the raw baseline locally, without a DWN request, so expired peers are
removed from the engine map at the deadline. Self expiry remains owned by
meshnet's generation-fenced key-expiry timer, which fails the engine closed.

Cold starts deliberately rebuild from the authoritative DWN instead of loading
a persistent disk cache. Persisting encrypted raw records would add cache
versioning and stale-secret handling without reducing steady-state requests;
the subscription-backed in-memory baseline removes those requests while the
daemon is running.

Delivery records addressed to this node have their own live subscription.
Audience records and encryption-protocol grant-key records are not covered by
the network-context subscription today. A new audience key referenced by a
topology record is resolved on demand, and independent audience changes are
retried by anti-entropy. Grant-key sets are currently loaded with the delegate
session; independent grant-key changes require a session reload until a
dedicated subscription and atomic key-set replacement are implemented.
