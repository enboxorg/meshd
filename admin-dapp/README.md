# meshd Admin dapp

Standalone dashboard for wallet-owned meshd networks.

The CLI creates and runs local node DIDs. The owner wallet acts as the mesh
account. This dapp connects to that wallet, receives delegated DWN grants, and
then manages networks, invites, pending node approvals, and removals on behalf
of the owner.

Production dashboard:

```text
https://meshd-admin.pages.dev
```

## Local development

```bash
npm ci
npm run dev
```

Use Node.js 20.19.0 or newer Node 20, or Node.js 22.12.0+.

Open the printed Vite URL, connect an Enbox Wallet, and approve the requested
meshd permissions.

The default local Vite URL is usually:

```text
http://127.0.0.1:5173/
```

## Wallet connect model

The dapp requests access with:

- `https://enbox.id/protocols/wireguard-mesh`
- `https://identity.foundation/protocols/key-delivery`

For each protocol it asks for read, write, and delete record permissions. The
wallet installs/configures the protocols during approval and grants this dapp a
local delegate session. The dapp does not ask for delegated
`Protocols.Configure` access and does not need the wallet's private keys.

On startup, the dapp runs the SDK readiness/import path for both protocols and
verifies that the installed wallet-owned definitions contain the expected meshd
types and paths before enabling dashboard actions.

## Environment

All variables are optional.

```bash
VITE_ENBOX_DAPP_NAME="meshd Admin"
VITE_ENBOX_WALLET_URL="https://enbox-wallet.pages.dev"
VITE_ENBOX_BLUE_WALLET_URL="https://blue-enbox-wallet.pages.dev"
VITE_ENBOX_DWN_ENDPOINTS="https://dev.aws.dwn.enbox.id,https://enbox-dwn.fly.dev"
```

## Checks

```bash
npm test
npm run build
```

`npm test` covers the wallet-connect permission request shape and the delegated
protocol readiness checks. `npm run build` typechecks and builds the static app.

## Cloudflare Pages

The repository workflow `.github/workflows/admin-dapp.yml` builds this app on
PRs and on pushes to `main`. On `main`, it deploys only when the Cloudflare
secrets below are configured; otherwise it leaves build/test green and skips
the Pages deployment step.

Required GitHub secrets:

```text
CLOUDFLARE_API_TOKEN
CLOUDFLARE_ACCOUNT_ID
```

The workflow deploys `admin-dapp/dist` to the Cloudflare Pages project:

```text
meshd-admin
```

For a manual deploy with a locally authenticated Wrangler CLI:

```bash
npm ci
npm test
npm run build
wrangler pages deploy dist --project-name=meshd-admin --branch=main
```
