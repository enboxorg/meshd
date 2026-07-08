# gen-crypto-fixtures

Generates the GENUINE `@enbox` SDK test fixtures consumed by the meshd Go
tests:

| fixture | contents |
| --- | --- |
| `internal/dwn/crypto/testdata/v1/protocolpath.json` | encrypted RecordsWrite on wireguard-mesh `network/preAuthKey` — single `protocolPath` keyEncryption entry, decryptable from the owner X25519 root |
| `internal/dwn/crypto/testdata/v1/sealed_roleaudience.json` | v1-sealed role-audience bundle: `$encryption/audience` records (real seals), an encrypted `network/node` source record with `roleAudience` entries, and a `$encryption/delivery` record wrapped to the role holder's own role-path key |
| `internal/dwn/crypto/testdata/v1/wrapped_grantkey.json` | pre-supplied-delegate flow (enbox #1189): delegated Records.Read grant + plaintext grantKey record carrying a `WrappedGrantKeyEnvelope` wrapped to the delegate root X25519 key, plus an encrypted record the delivered subtree key decrypts |
| `internal/dwn/crypto/testdata/v1/delegated_grant.json` | delegated grant messages + their CIDs + delegate-signed RecordsWrite/RecordsQuery invocations (`authorDelegatedGrant` + `delegatedGrantId`) |
| `internal/enboxconnect/testdata/connect_request.json` | genuine Enbox Connect request JWE (client-side construction) + expected JWT/payload |
| `internal/enboxconnect/testdata/connect_response.json` | genuine Enbox Connect response JWE (wallet-side construction, pre-supplied delegate, PIN-bound AAD) + DWN-validated delegate grants + sessionRevocations |

Every DWN record in the fixtures was processed by a **real in-process DWN**
(`Dwn.processMessage`, level stores in a temp dir) and therefore passed full
server-side validation, including the v1-sealed encryption enforcement
(protocolPath entry keyId match + roleAudience entries referencing existing
audience records). The audience, delivery, and grantKey records are produced
by the agent's own functions (`createAudienceRecord`,
`createAudienceDeliveryRecord`, `createGrantKeyRecordsForGrants` from
`packages/agent/src/dwn-encryption.ts`) running unmodified against a minimal
agent stand-in backed by that DWN. The connect JWEs are built with
`EnboxConnectProtocol`'s own exported functions (`createConnectRequest`,
`signJwt`, `encryptRequest`, `createConnectResponse`, `deriveSharedKey`,
`encryptResponse` from `packages/agent/src/enbox-connect-protocol.ts`).

Before writing each fixture the script decrypts every encrypted payload back
with the SDK and asserts plaintext equality (owner root, role-audience,
delivered-key, seal/unseal, wrapped-envelope, and JWE round trips), so the
fixtures are self-proving.

## Regenerating

Requirements: `bun` (>= 1.3), a checkout of the enbox monorepo.

```sh
# 1. point at the monorepo (default: ~/src/enboxorg/enbox)
export ENBOX_REPO=~/src/enboxorg/enbox

# 2. build the workspace dist artifacts — the generator imports the agent
#    package by source path, and agent source resolves its own
#    `@enbox/dwn-sdk-js` / `@enbox/crypto` / ... imports to workspace dist
#    builds. Also refresh the SDK's precompiled JSON-schema validators, which
#    the source imports use directly.
cd "$ENBOX_REPO"
bunx turbo run build --filter=@enbox/agent
(cd packages/dwn-sdk-js && bun run compile-validators)

# 3. generate (from the meshd repo root)
cd <meshd>
bun scripts/gen-crypto-fixtures/generate.ts
```

The generator hard-fails if the dwn-sdk-js dist is stale (it probes the
HEAD-only `WRAPPED_GRANT_KEY_FORMAT` export), records the monorepo commit in
every fixture (`sdkCommit`), and prints it on success.

Fixtures are currently generated at enbox monorepo commit:

```
6b5b9786ee931f8d80d84e5f2865166c39568eb6
```

Determinism is NOT required — fixtures embed every key (as JWKs), all
plaintexts, and all derived values needed to verify; regeneration produces
new random keys/records but the same shapes.

## Identity model

All fixture identities are `did:jwk` (Ed25519). The X25519 encryption root of
each identity is the Ed25519→X25519 conversion of its signing key — exactly
how the enbox agent treats did:jwk identities (`getEncryptionKeyInfo`) and how
meshd derives its delegate encryption key (`internal/did`
`EncryptionPrivateKey`). Protocol `$keyAgreement` keys are injected with
`Protocols.deriveAndInjectPublicEncryptionKeys` from that root, using meshd's
real `protocols/wireguard-mesh.json` definition.

## Files

- `harness.ts` — monorepo loading (absolute-path source imports), real DWN
  over level stores, did:jwk identity factory, minimal agent stand-in, write
  helpers.
- `generate.ts` — the five fixture flows + in-script verification.
