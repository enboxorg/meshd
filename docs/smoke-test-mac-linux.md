# Mac/Linux beta smoke test

Use this runbook to validate the current wallet-owned, dashboard-approved flow,
including dashboard-managed node membership expiry.

Assumptions:

- The Mac is the owner/admin device.
- The Linux server is the joining mesh node.
- Both machines may already run Tailscale. meshd uses `10.200.0.0/16`, so it
  should not overlap Tailscale's `100.64.0.0/10` address space.
- The beta DWN endpoint is `https://dev.aws.dwn.enbox.id`.
  `meshd up <owner-did>` uses it automatically when the owner DID does not
  advertise a DWN endpoint. The dashboard uses the same default when creating
  a network for that owner.
- The released CLI is installed on both machines.
- The standalone meshd Admin dapp is deployed at
  `https://meshd-admin.pages.dev`.

## 0. Install or update meshd

On both the Mac and the Linux server:

```bash
curl -fsSL https://meshd.sh/install | bash
meshd --version
```

Expected result:

```text
meshd <latest release>
```

If your shell has not picked up the installer PATH update yet, run:

```bash
~/.meshd/bin/meshd --version
```

## 1. Open the admin dashboard on the Mac

Use the deployed dashboard:

```bash
meshd admin
```

If you only want the URL, for example over SSH, use:

```bash
meshd admin --print
```

The dashboard URL should use:

```text
https://meshd-admin.pages.dev
```

If you are opening the dashboard from a machine without the owner profile,
target the owner explicitly:

```bash
meshd admin --owner '<OWNER_DID>' --print
```

Connect the owner wallet and approve meshd Admin. Create a network if one does
not already exist. Click `Copy Setup Command` in the network header.

If the deployed dashboard is unavailable, run the local fallback from a repo
checkout:

```bash
cd ~/src/enboxorg/meshd/admin-dapp
npm ci
npm run dev -- --host 127.0.0.1
meshd admin --dashboard http://127.0.0.1:5173 --print
```

## 2. Submit the Linux node request

On the Linux server, paste the setup command copied from the dashboard:

```bash
meshd down || true
meshd up '<OWNER_DID>'
```

The older `meshd up --owner '<OWNER_DID>'` form still works. You can also run
`meshd up` without arguments and paste the owner DID at the setup prompt.

Expected result:

- If the node has no local identity, meshd creates one and asks for a vault
  password.
- meshd writes a signed owner-node request to the owner's DWN.
- meshd exits cleanly or reports that it is waiting for dashboard approval.

## 3. Approve from the dashboard

On the Mac dashboard:

1. Select the target network.
2. Refresh if the pending request is not visible yet.
3. Pick an `Approve for` expiry such as `30 days`.
4. Approve the Linux node.
5. Confirm the node appears under `Nodes` with the selected expiry.

The dashboard should write the member/node record, deliver the network context
key to the node, and write a node approval response.

## 4. Start both mesh daemons

On the Linux server:

```bash
meshd up
meshd status
meshd peer list
```

On the Mac:

```bash
meshd up
meshd status
meshd peer list
```

Expected result:

- `meshd status` shows `Daemon: Running: yes`.
- If an approval expiry was selected, the joining node's `meshd status` shows
  `Membership Expires`.
- Both machines show the same network name.
- `meshd peer list` shows both peers with `10.200.x.x` mesh IPs and an
  `EXPIRES` column. Non-expiring nodes show `never`.

If you renew a node or switch it to `Never` in the dashboard, run `meshd up` or
`meshd peer list` on that node. Both commands refresh the local membership
metadata from the DWN map, so `meshd status` should then show the updated
`Membership Expires` value or omit it for non-expiring membership.

## 5. Ping both directions

From Linux, ping the Mac mesh IP:

```bash
ping -c 4 <MAC_MESH_IP>
```

From Mac, ping the Linux mesh IP:

```bash
ping -c 4 <LINUX_MESH_IP>
```

Expected result: both pings receive replies.

## 6. Validate invite flow

After the owner-request path works, validate invites.

On the dashboard:

1. Select the network.
2. Create an invite.
3. Copy the `meshd://invite/...` URL.

On a fresh profile or another node:

```bash
meshd down || true
meshd up '<meshd://invite/...>'
meshd up
meshd status
meshd peer list
```

You can also run `meshd up` without flags and paste the `meshd://invite/...`
URL at the setup prompt.

If the invite request appears pending in the dashboard, approve it and run
`meshd up` again on the joining node.

## Troubleshooting

Run:

```bash
meshd doctor
meshd status
meshd peer list
```

Check these conditions first:

- Both machines are in the same meshd network.
- Both machines have a `10.200.x.x` mesh IP.
- The daemon is running on both machines.
- Routes for the peer mesh IP point to the meshd TUN device.
- The dashboard shows the node under `Nodes`, not just under `Pending`.

If `peer list` shows encrypted rows without mesh IPs, refresh the dashboard and
run `meshd up` again on the joining node so it can consume the approval record.

If pings fail but peers and routes look correct, run `meshd down` and then
`meshd up` on both machines to force the daemon to rebuild the WireGuard state.
