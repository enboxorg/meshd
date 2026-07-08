# e2e helpers — headless wallet approver

Bun/TypeScript helpers for exercising meshd's enbox-connect onboarding
end-to-end against a local enbox dev stack. The centerpiece is a **headless
wallet approver** that stands in for the Enbox web wallet: given a wallet URI
(containing `request_uri` + `encryption_key`), it fetches the connect request
from the relay, approves it as a persistent "owner" identity, and prints the
PIN.

These scripts import the `@enbox/*` packages **by absolute path from a local
checkout of the enbox monorepo** (they are not vendored). Nothing here is
built into meshd; the Go e2e tests spawn `approver.ts` as a subprocess.

## Prerequisites

- [bun](https://bun.sh) (>= 1.3)
- A checkout of the enbox monorepo with build output:

  ```sh
  git clone https://github.com/enboxorg/enbox ~/src/enboxorg/enbox
  cd ~/src/enboxorg/enbox
  bun install && bun run build
  ```

- The enbox dev stack running (dwn-server + connect relay on `:3000`):

  ```sh
  cd $ENBOX_REPO && bun run dev:ensure    # idempotent
  # if ports look busy:  bun run dev:status
  # to stop it later:    bun run dev:down
  ```

## Environment

| Variable     | Default                   | Meaning                              |
| ------------ | ------------------------- | ------------------------------------ |
| `ENBOX_REPO` | `~/src/enboxorg/enbox`    | Path to the enbox monorepo checkout. |

## `approver.ts` — headless wallet approver

```sh
bun scripts/e2e/approver.ts --uri '<wallet URI>' \
  [--data <dir>] [--password <pw>] [--endpoint <dwn url>] [--pin-file <path>]
```

| Flag           | Default              | Meaning                                                        |
| -------------- | -------------------- | -------------------------------------------------------------- |
| `--uri`        | (required)           | Wallet URI with `request_uri` + `encryption_key` query params. Any scheme works (`https://…`, `enbox://connect?…`). |
| `--data`       | `.e2e-approver`      | Agent data directory. Persistent: reusing it approves as the **same owner** (two devices, one owner). |
| `--password`   | `meshd-e2e-approver` | Vault password protecting the data directory.                  |
| `--endpoint`   | `http://localhost:3000` | DWN server / relay endpoint the owner tenant lives on.      |
| `--pin-file`   | (none)               | Also write the stdout lines to this file.                      |
| `--owner-name` | `meshd-e2e-owner`    | Identity metadata name used to find/create the owner.          |

**stdout contract** (everything else — progress, warnings, agent logs — goes
to stderr):

```
PIN=<4 digits>
OWNER_DID=<did:jwk:...>
```

**Exit codes**: `0` success, `1` failure (with a `approver: FAILED: …` line on
stderr; set `DEBUG=1` for stack traces), `2` usage error.

### What it does

1. Opens (first run: creates) a password-protected `EnboxUserAgent` at
   `--data`. The owner identity is a **did:jwk** (self-resolving — no DHT
   dependency, fully hermetic) with the Ed25519→X25519 converted key imported
   into the agent KMS so DWN protocol encryption works.
2. Points the agent's DWN endpoint resolution at `--endpoint` (validated via
   `GET /info` — must be an `@enbox/dwn-server`) and registers the owner
   tenant there when the server advertises registration requirements (PoW;
   the local dev server is open, so this is a no-op).
3. Fetches, decrypts, and verifies the connect request
   (`EnboxConnectProtocol.getConnectRequest`).
4. **Strips placeholder `$keyAgreement` nodes** (empty `publicKeyJwk`, as in
   meshd's `protocols/wireguard-mesh.json`) from the requested protocol
   definitions, then installs each protocol on the owner tenant — local agent
   DWN **and** every owner DWN endpoint — with `encryption: true` whenever any
   type declares `encryptionRequired`, so the agent derives and injects real
   owner X25519 `$keyAgreement` keys.
5. Generates a 4-digit PIN and calls
   `EnboxConnectProtocol.submitConnectResponse(ownerDid, request, pin, agent)`,
   which creates the delegated grants (plus wrapped grantKey records for the
   pre-supplied delegate and per-grant session revocation grants), fans them
   out to the owner DWN endpoints, and POSTs the PIN-bound encrypted response
   to the relay callback.
6. Prints `PIN=` / `OWNER_DID=` and shuts the agent down cleanly.

## `selfcheck.ts` — approver validation (client role)

Plays the app/client side using the monorepo's own `WalletConnect.initClient`
(pre-supplied delegate DID) with meshd's real `protocols/wireguard-mesh.json`
(placeholders included), spawns the approver, and asserts the whole loop:

```sh
cd $ENBOX_REPO && bun run dev:ensure     # stack must be up
bun scripts/e2e/selfcheck.ts [--endpoint http://localhost:3000] [--keep]
```

It runs **two** connect rounds against the same approver data dir and checks,
among ~38 assertions: PIN-bound response decryption, grant validation via the
monorepo's `validateConnectResultGrants`, `delegated: true` on Records grants,
contextId-scoped session revocations, the wireguard-mesh protocol installed on
the remote dwn-server with derived `$keyAgreement` keys on every
`encryptionRequired` path (no placeholders left), and a stable owner DID
across rounds. `--keep` preserves the temp data dir for inspection.

## `install-smoke.sh` — public installer release smoke

Exercises the same public install path users run:

```sh
scripts/e2e/install-smoke.sh
```

The script curls `https://meshd.sh/install`, runs it with a temporary HOME and
`--no-modify-path`, asserts that `~/.meshd/bin/meshd` exists, and checks that
`meshd --help` starts. Release CI sets `MESHD_INSTALL_EXPECTED_VERSION` to the
published tag, so the smoke also proves the installer resolved and unpacked the
new release artifact.

Useful environment variables:

| Variable                         | Default                  | Meaning                                         |
| -------------------------------- | ------------------------ | ----------------------------------------------- |
| `MESHD_INSTALL_URL`              | `https://meshd.sh/install` | Installer URL to curl.                        |
| `MESHD_INSTALL_REQUESTED_VERSION` | (empty)                 | Optional `--version` argument for the installer. |
| `MESHD_INSTALL_EXPECTED_VERSION` | (empty)                  | Expected `meshd --version` value (`v` optional). |
| `MESHD_INSTALL_TMP_DIR`          | auto-created             | Keep temp install state for debugging.          |

## Files

- `approver.ts` — the headless approver CLI.
- `selfcheck.ts` — end-to-end validation of the approver (client role).
- `install-smoke.sh` — public curl installer smoke test.
- `enbox-repo.ts` — resolves `ENBOX_REPO` and imports the monorepo packages.
- `definition-utils.ts` — pure protocol-definition helpers (placeholder
  stripping, definition matching, structure walking).

See `docs/e2e-local.md` for the full local loop including the meshd (Go) side.
