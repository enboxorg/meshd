# Local e2e: enbox connect onboarding

How to run meshd's enbox-connect onboarding end-to-end on one machine, with
no external services. Three moving parts:

1. **enbox dev stack** — `@enbox/dwn-server` with the connect relay, on
   `http://localhost:3000` (serves both the DWN JSON-RPC API and the
   `/connect/*` relay routes: `par`, `authorize`, `callback`, `token`).
2. **headless wallet approver** (`scripts/e2e/approver.ts`) — stands in for
   the Enbox web wallet. Approves connect requests as a persistent owner
   identity and prints the PIN.
3. **meshd (Go)** — the connect client: builds the request, pushes it to the
   relay, prints/hands off the wallet URI, polls for the response, and
   decrypts it with the PIN.

The Go e2e test orchestrates all of this automatically (it spawns the
approver and reads its `PIN=` output). Manual usage is documented below.

## One-time setup

```sh
# enbox monorepo checkout (import source for the bun scripts)
git clone https://github.com/enboxorg/enbox ~/src/enboxorg/enbox
cd ~/src/enboxorg/enbox
bun install && bun run build
```

If the checkout lives elsewhere, export `ENBOX_REPO=/path/to/enbox` — every
script and test honors it (default: `~/src/enboxorg/enbox`).

## 1. Start the dev stack

```sh
cd $ENBOX_REPO
bun run dev:ensure       # idempotent: dwn-server + relay on http://localhost:3000
bun run dev:status       # inspect if something looks off
```

The dev server is **open** (no registration requirements) and ephemeral
(LevelDB under `$ENBOX_REPO/.dev`). `bun run dev:down` stops it.

## 2. Validate the approver on its own (optional)

```sh
cd <meshd worktree>
bun scripts/e2e/selfcheck.ts
```

This plays the client role with the monorepo's `WalletConnect.initClient`,
runs two full connect rounds through the real relay, and asserts grants,
grantKey delivery preconditions, protocol installation with derived
`$keyAgreement` keys, and owner persistence. See `scripts/e2e/README.md`.

## 3. The full loop with meshd

### Automated (Go e2e test)

The Go e2e test drives the loop: it starts the connect flow, receives the
wallet URI from the `OnWalletURI` callback, spawns

```sh
bun scripts/e2e/approver.ts --uri "$WALLET_URI" \
  --data <test tmp dir> --endpoint http://localhost:3000
```

waits for the process to exit `0`, parses `PIN=` / `OWNER_DID=` from stdout
(or from `--pin-file`), and feeds the PIN back into the client's PIN prompt.
Because the approver's `--data` directory is persistent, pointing a second
meshd node's connect flow at the same directory enrolls it under the **same
owner** — the "two devices, one owner" topology.

### Manual

1. Run the meshd side so it prints a wallet URI (the enbox-connect client
   flow; see `internal/enboxconnect`). It will then poll the relay and wait
   for a PIN.
2. In another terminal, approve it:

   ```sh
   bun scripts/e2e/approver.ts --uri '<wallet URI printed by meshd>'
   ```

3. The approver prints the PIN:

   ```
   PIN=1234
   OWNER_DID=did:jwk:...
   ```

4. Enter the PIN at the meshd prompt. meshd decrypts the response, validates
   the grants, and proceeds with the delegated session.

## Notes and caveats

- **Owner identity is a did:jwk** — self-resolving, so the local dwn-server
  verifies its signatures without any DHT/gateway dependency. It is created
  on the approver's first run and reused afterwards (`--owner-name` selects
  it within the data dir).
- **`$keyAgreement` placeholders**: meshd's `protocols/wireguard-mesh.json`
  ships placeholder `$keyAgreement` nodes (`"publicKeyJwk": {}`) on encrypted
  record paths. The approver strips these from the requested definition and
  installs the protocol with `encryption: true`, so the agent derives and
  injects the owner's real X25519 keys at every path. The installed
  definition on the server therefore differs from the requested one exactly
  by those injected keys.
- **Where state lands**: grants, revocation grants, wrapped grantKey records,
  and the protocol install are all written to the owner tenant on
  `--endpoint` (plus the approver's local agent DWN). meshd reads them from
  the endpoint.
- **PIN timing**: the approver prints the PIN only after the encrypted
  response has been POSTed to the relay callback, so the client's next poll
  can already succeed by the time the PIN is available.
- **Registration**: if a non-dev dwn-server advertises registration
  requirements, the approver registers the owner tenant via the PoW flow
  before writing anything.
- **Leave the stack running** between test runs; `dev:ensure` is idempotent
  and the Go e2e test assumes the endpoint is already up (or starts it the
  same way).
