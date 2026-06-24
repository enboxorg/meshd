# Mac/Linux beta smoke test

Use this runbook to validate the current wallet-owned, dashboard-approved flow
before adding node membership expiry or edit controls.

Assumptions:

- The Mac is the owner/admin device.
- The Linux server is the joining mesh node.
- Both machines may already run Tailscale. meshd uses `10.200.0.0/16`, so it
  should not overlap Tailscale's `100.64.0.0/10` address space.
- The beta DWN endpoint is `https://dev.aws.dwn.enbox.id`.
- You have the standalone meshd Admin dapp available locally or deployed.

## 1. Start the admin dashboard on the Mac

From the repository checkout:

```bash
cd ~/src/enboxorg/meshd/admin-dapp
npm ci
npm run dev -- --host 127.0.0.1
```

Open the printed Vite URL, usually:

```text
http://127.0.0.1:5173/
```

Connect the owner wallet and approve meshd Admin. Create a network if one does
not already exist. Copy the owner DID from the wallet or dashboard header.

## 2. Submit the Linux node request

On the Linux server:

```bash
meshd down || true
meshd up --owner '<OWNER_DID>' --endpoint https://dev.aws.dwn.enbox.id
```

Expected result:

- If the node has no local identity, meshd creates one and asks for a vault
  password.
- meshd writes a signed owner-node request to the owner's DWN.
- meshd exits cleanly or reports that it is waiting for dashboard approval.

## 3. Approve from the dashboard

On the Mac dashboard:

1. Select the target network.
2. Refresh if the pending request is not visible yet.
3. Approve the Linux node.
4. Confirm the node appears under `Nodes`.

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
- Both machines show the same network name.
- `meshd peer list` shows both peers with `10.200.x.x` mesh IPs.

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
