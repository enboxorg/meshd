import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  CheckIcon,
  ClipboardIcon,
  KeyRoundIcon,
  Loader2Icon,
  LogOutIcon,
  NetworkIcon,
  PlusIcon,
  RefreshCwIcon,
  SaveIcon,
  ServerIcon,
  ShieldCheckIcon,
  TerminalIcon,
  Trash2Icon,
  UserPlusIcon,
  XIcon
} from "lucide-react";
import { toast } from "sonner";

import { useEnbox } from "./enbox/use-enbox";
import {
  dashboardContextFromSearch,
  ownerMatchesDashboardContext,
  type MeshdDashboardURLContext
} from "./meshd/dashboard-url";
import { ownerSetupCommand } from "./meshd/commands";
import {
  approveMeshdNodeRequest,
  buildMeshdInviteURL,
  createMeshdInvite,
  createMeshdNetwork,
  fetchMeshdNetworkTopology,
  fetchMeshdNetworks,
  rejectMeshdNodeRequest,
  removeMeshdNode,
  revokeMeshdInvite,
  updateMeshdNodeExpiry,
  updateMeshdNodeLabel,
  type CreateMeshdInviteResult,
  type MeshdAdminSession,
  type MeshdNetworkSummary,
  type MeshdNetworkTopology,
  type MeshdNodeRequestSummary,
  type MeshdNodeSummary,
  type MeshdPreAuthKeySummary
} from "./meshd/admin";

type LoadState = "idle" | "loading" | "ready" | "error";
type ExpiryValue = "1h" | "24h" | "7d" | "30d" | "never";

const EXPIRY_OPTIONS: Array<{ value: ExpiryValue; label: string; durationMs?: number }> = [
  { value: "1h", label: "1 hour", durationMs: 60 * 60 * 1000 },
  { value: "24h", label: "24 hours", durationMs: 24 * 60 * 60 * 1000 },
  { value: "7d", label: "7 days", durationMs: 7 * 24 * 60 * 60 * 1000 },
  { value: "30d", label: "30 days", durationMs: 30 * 24 * 60 * 60 * 1000 },
  { value: "never", label: "Never" }
];

const TOPOLOGY_AUTO_REFRESH_MS = 10_000;

function truncateDid(did: string, head = 18, tail = 10) {
  if (did.length <= head + tail + 3) return did;
  return `${did.slice(0, head)}...${did.slice(-tail)}`;
}

function formatTime(value?: string) {
  if (!value) return "";
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) return value;
  return new Intl.DateTimeFormat(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit"
  }).format(date);
}

function expiryState(value?: string) {
  if (!value) return "none";
  const time = new Date(value).getTime();
  if (!Number.isFinite(time)) return "unknown";
  const remaining = time - Date.now();
  if (remaining <= 0) return "expired";
  if (remaining <= 24 * 60 * 60 * 1000) return "soon";
  return "active";
}

async function copyToClipboard(value: string) {
  await navigator.clipboard.writeText(value);
  toast.success("Copied");
}

function expiryTimestamp(value: ExpiryValue) {
  const option = EXPIRY_OPTIONS.find((item) => item.value === value);
  if (!option?.durationMs) {
    return undefined;
  }
  return new Date(Date.now() + option.durationMs).toISOString();
}

export function App() {
  const enboxState = useEnbox();
  const [dashboardContext] = useState(() => dashboardContextFromSearch(window.location.search));

  return (
    <div className="app-shell">
      <header className="topbar">
        <button className="brand" type="button" aria-label="meshd Admin">
          <span className="brand-mark"><NetworkIcon size={20} /></span>
          <span className="brand-copy">
            <span>meshd</span>
            <small>Admin</small>
          </span>
        </button>
        <div className="topbar-actions">
          {enboxState.did ? (
            <>
              <span className="identity-pill" title={enboxState.did}>
                <ShieldCheckIcon size={15} />
                {truncateDid(enboxState.did, 14, 8)}
              </span>
              <button
                className="icon-button"
                type="button"
                aria-label="Disconnect"
                title="Disconnect"
                onClick={() => void enboxState.disconnect({ clearStorage: true })}
              >
                <LogOutIcon size={17} />
              </button>
            </>
          ) : null}
        </div>
      </header>

      <main className="workspace">
        {!enboxState.isConnected ? <ConnectPanel context={dashboardContext} /> : <Dashboard context={dashboardContext} />}
      </main>
    </div>
  );
}

function ConnectPanel({ context }: { context: MeshdDashboardURLContext }) {
  const { connectWallet, isConnecting } = useEnbox();
  const [error, setError] = useState<string>();

  async function connect() {
    setError(undefined);
    try {
      await connectWallet();
    } catch (err) {
      const message = err instanceof Error ? err.message : "Wallet connection failed.";
      if (!message.toLowerCase().includes("cancel")) {
        setError(message);
      }
    }
  }

  return (
    <section className="connect-panel">
      <div className="connect-title">
        <span className="panel-icon"><KeyRoundIcon size={22} /></span>
        <div>
          <h1>meshd Admin</h1>
          <p>Connect an owner wallet to manage networks and node approvals.</p>
        </div>
      </div>
      {context.ownerDID ? (
        <div className="target-owner">
          <span>Owner</span>
          <code title={context.ownerDID}>{truncateDid(context.ownerDID)}</code>
        </div>
      ) : null}
      {error ? <div className="error-banner">{error}</div> : null}
      <button className="primary-button" type="button" disabled={isConnecting} onClick={() => void connect()}>
        {isConnecting ? <Loader2Icon className="spin" size={17} /> : <ShieldCheckIcon size={17} />}
        Connect Wallet
      </button>
    </section>
  );
}

function Dashboard({ context }: { context: MeshdDashboardURLContext }) {
  const { did, delegateDid, enbox, protocolsInitialized, protocolSetupError } = useEnbox();
  const session = useMemo<MeshdAdminSession | undefined>(() => {
    if (!did || !enbox) return undefined;
    return {
      ownerDid: did,
      delegateDid,
      agent: enbox.agent as never
    };
  }, [delegateDid, did, enbox]);

  const [networks, setNetworks] = useState<MeshdNetworkSummary[]>([]);
  const [selectedNetworkId, setSelectedNetworkId] = useState(() => context.networkRecordID ?? "");
  const [topology, setTopology] = useState<MeshdNetworkTopology>();
  const [loadState, setLoadState] = useState<LoadState>("idle");
  const [error, setError] = useState<string>();
  const [inviteResult, setInviteResult] = useState<CreateMeshdInviteResult>();
  const [inviteLabel, setInviteLabel] = useState("");
  const [inviteExpiry, setInviteExpiry] = useState<ExpiryValue>("24h");
  const [approvalExpiry, setApprovalExpiry] = useState<ExpiryValue>("never");
  const [inviteReusable, setInviteReusable] = useState(false);
  const [networkName, setNetworkName] = useState("");
  const [networkCIDR, setNetworkCIDR] = useState("10.200.0.0/16");
  const [busyAction, setBusyAction] = useState<string>();
  const [topologyRefreshing, setTopologyRefreshing] = useState(false);
  const topologyRefreshInFlight = useRef(false);

  const selectedNetwork = useMemo(() => {
    if (networks.length === 0) return undefined;
    return networks.find((network) => network.recordId === selectedNetworkId) ?? networks[0];
  }, [networks, selectedNetworkId]);

  const refreshNetworks = useCallback(async () => {
    if (!session || !protocolsInitialized || !ownerMatchesDashboardContext(context, did)) return;
    setLoadState("loading");
    setError(undefined);
    try {
      const nextNetworks = await fetchMeshdNetworks(session);
      setNetworks(nextNetworks);
      if (!selectedNetworkId && nextNetworks[0]) {
        setSelectedNetworkId(nextNetworks[0].recordId);
      }
      setLoadState("ready");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not load networks.");
      setLoadState("error");
    }
  }, [context, did, protocolsInitialized, selectedNetworkId, session]);

  const refreshTopology = useCallback(async (options?: { silent?: boolean }) => {
    if (!session || !protocolsInitialized || !selectedNetwork || !ownerMatchesDashboardContext(context, did)) return;
    if (topologyRefreshInFlight.current) return;
    topologyRefreshInFlight.current = true;
    setTopologyRefreshing(true);
    if (!options?.silent) {
      setError(undefined);
    }
    try {
      const nextTopology = await fetchMeshdNetworkTopology(session, selectedNetwork);
      setTopology(nextTopology);
      setError(undefined);
    } catch (err) {
      if (!options?.silent) {
        setError(err instanceof Error ? err.message : "Could not load network topology.");
      }
    } finally {
      topologyRefreshInFlight.current = false;
      setTopologyRefreshing(false);
    }
  }, [context, did, protocolsInitialized, selectedNetwork, session]);

  useEffect(() => {
    void refreshNetworks();
  }, [refreshNetworks]);

  useEffect(() => {
    void refreshTopology();
  }, [refreshTopology]);

  useEffect(() => {
    if (!session || !protocolsInitialized || !selectedNetwork || !ownerMatchesDashboardContext(context, did)) return;

    const tick = () => {
      if (document.visibilityState !== "visible" || busyAction) return;
      void refreshTopology({ silent: true });
    };

    const interval = window.setInterval(tick, TOPOLOGY_AUTO_REFRESH_MS);
    const handleVisibilityChange = () => {
      if (document.visibilityState === "visible" && !busyAction) {
        void refreshTopology({ silent: true });
      }
    };
    document.addEventListener("visibilitychange", handleVisibilityChange);

    return () => {
      window.clearInterval(interval);
      document.removeEventListener("visibilitychange", handleVisibilityChange);
    };
  }, [busyAction, context, did, protocolsInitialized, refreshTopology, selectedNetwork, session]);

  useEffect(() => {
    if (!selectedNetwork) return;
    const params = new URLSearchParams(window.location.search);
    params.set("network", selectedNetwork.recordId);
    if (did) params.set("owner", did);
    window.history.replaceState(null, "", `?${params.toString()}`);
  }, [did, selectedNetwork]);

  async function runAction(label: string, action: () => Promise<void>) {
    setBusyAction(label);
    setError(undefined);
    try {
      await action();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Action failed.");
    } finally {
      setBusyAction(undefined);
    }
  }

  async function handleCreateNetwork() {
    if (!session) return;
    await runAction("create-network", async () => {
      const network = await createMeshdNetwork(session, { name: networkName, meshCIDR: networkCIDR });
      setNetworkName("");
      setNetworks((current) => [network, ...current]);
      setSelectedNetworkId(network.recordId);
      toast.success("Network created");
    });
  }

  async function handleCreateInvite() {
    if (!session || !selectedNetwork) return;
    await runAction("create-invite", async () => {
      const result = await createMeshdInvite(session, selectedNetwork, {
        label: inviteLabel.trim() || selectedNetwork.name,
        expiresAt: expiryTimestamp(inviteExpiry),
        reusable: inviteReusable
      });
      setInviteLabel("");
      setInviteResult(result);
      toast.success("Invite created");
      await refreshTopology();
    });
  }

  async function handleApprove(request: MeshdNodeRequestSummary) {
    if (!session || !selectedNetwork) return;
    await runAction(`approve-${request.recordId}`, async () => {
      const result = await approveMeshdNodeRequest(session, selectedNetwork, request, {
        expiresAt: expiryTimestamp(approvalExpiry)
      });
      toast.success(`Node approved at ${result.meshIP}`);
      await refreshTopology();
    });
  }

  async function handleReject(request: MeshdNodeRequestSummary) {
    if (!session) return;
    await runAction(`reject-${request.recordId}`, async () => {
      await rejectMeshdNodeRequest(session, request);
      toast.success("Request rejected");
      await refreshTopology();
    });
  }

  async function handleUpdateNodeExpiry(node: MeshdNodeSummary, value: ExpiryValue) {
    if (!session || !selectedNetwork) return;
    await runAction(`expiry-${node.recordId}`, async () => {
      await updateMeshdNodeExpiry(session, selectedNetwork, node, expiryTimestamp(value));
      toast.success(value === "never" ? "Node expiry cleared" : "Node expiry updated");
      await refreshTopology();
    });
  }

  async function handleUpdateNodeLabel(node: MeshdNodeSummary, label: string) {
    if (!session || !selectedNetwork) return;
    await runAction(`label-${node.recordId}`, async () => {
      await updateMeshdNodeLabel(session, selectedNetwork, node, label);
      toast.success(label.trim() ? "Node label updated" : "Node label cleared");
      await refreshTopology();
    });
  }

  async function handleRevokeInvite(key: MeshdPreAuthKeySummary) {
    if (!session) return;
    await runAction(`revoke-${key.recordId}`, async () => {
      await revokeMeshdInvite(session, key);
      toast.success("Invite revoked");
      await refreshTopology();
    });
  }

  async function handleCopyExistingInvite(key: MeshdPreAuthKeySummary) {
    if (!session || !selectedNetwork) return;
    const url = await buildMeshdInviteURL(session, selectedNetwork, key);
    await copyToClipboard(url);
  }

  async function handleCopyOwnerSetupCommand() {
    if (!did) return;
    await copyToClipboard(ownerSetupCommand(did));
  }

  async function handleRemoveNode(node: MeshdNodeSummary) {
    if (!session || !selectedNetwork) return;
    await runAction(`remove-${node.recordId}`, async () => {
      await removeMeshdNode(session, selectedNetwork, node);
      toast.success("Node removed");
      await refreshTopology();
    });
  }

  if (!ownerMatchesDashboardContext(context, did)) {
    return (
      <StatePanel
        title="Wrong owner wallet"
        detail={`This dashboard URL targets ${context.ownerDID}, but the connected wallet is ${did ?? "unknown"}. Disconnect and connect the owner wallet.`}
      />
    );
  }

  if (protocolSetupError) {
    return <StatePanel title="Protocol setup failed" detail={protocolSetupError} />;
  }

  if (!protocolsInitialized) {
    return <StatePanel title="Initializing" detail="Preparing meshd protocols for this wallet session." loading />;
  }

  const allNodes = [
    ...(topology?.members.flatMap((member) => member.nodes.map((node) => ({ node, member }))) ?? []),
    ...(topology?.legacyNodes.map((node) => ({ node, member: undefined })) ?? [])
  ];

  return (
    <div className="dashboard-grid">
      <aside className="sidebar">
        <div className="section-heading">
          <span>Networks</span>
          <button className="icon-button small" type="button" aria-label="Refresh networks" title="Refresh" onClick={() => void refreshNetworks()}>
            <RefreshCwIcon size={15} />
          </button>
        </div>
        {loadState === "loading" ? <div className="muted-row"><Loader2Icon className="spin" size={15} /> Loading</div> : null}
        <div className="network-list">
          {networks.map((network) => (
            <button
              key={network.recordId}
              type="button"
              className={`network-row ${network.recordId === selectedNetwork?.recordId ? "active" : ""}`}
              onClick={() => setSelectedNetworkId(network.recordId)}
            >
              <NetworkIcon size={16} />
              <span>
                <strong>{network.name}</strong>
                <small>{network.meshCIDR}</small>
              </span>
            </button>
          ))}
        </div>

        <div className="create-box">
          <div className="section-heading">
            <span>Create</span>
          </div>
          <label>
            Name
            <input value={networkName} onChange={(event) => setNetworkName(event.target.value)} placeholder="home" />
          </label>
          <label>
            CIDR
            <input value={networkCIDR} onChange={(event) => setNetworkCIDR(event.target.value)} />
          </label>
          <button
            className="secondary-button"
            type="button"
            disabled={busyAction === "create-network" || networkName.trim() === ""}
            onClick={() => void handleCreateNetwork()}
          >
            {busyAction === "create-network" ? <Loader2Icon className="spin" size={16} /> : <PlusIcon size={16} />}
            Create Network
          </button>
        </div>
      </aside>

      <section className="main-panel">
        {error ? <div className="error-banner">{error}</div> : null}
        {!selectedNetwork ? (
          <StatePanel title="No networks" detail="Create a mesh network to start approving nodes." />
        ) : (
          <>
            <div className="network-header">
              <div>
                <h1>{selectedNetwork.name}</h1>
                <p>{selectedNetwork.meshCIDR}</p>
              </div>
              <div className="header-buttons">
                <button className="secondary-button" type="button" onClick={() => void handleCopyOwnerSetupCommand()}>
                  <TerminalIcon size={16} />
                  Copy Setup Command
                </button>
                <button className="secondary-button" type="button" disabled={topologyRefreshing} onClick={() => void refreshTopology()}>
                  <RefreshCwIcon className={topologyRefreshing ? "spin" : undefined} size={16} />
                  Refresh
                </button>
              </div>
            </div>

            <section className="invite-composer">
              <div className="section-heading">
                <span>New Invite</span>
              </div>
              <div className="invite-fields">
                <label>
                  Label
                  <input value={inviteLabel} onChange={(event) => setInviteLabel(event.target.value)} placeholder={selectedNetwork.name} />
                </label>
                <label>
                  Expires
                  <select value={inviteExpiry} onChange={(event) => setInviteExpiry(event.target.value as ExpiryValue)}>
                    {EXPIRY_OPTIONS.map((option) => (
                      <option key={option.value} value={option.value}>{option.label}</option>
                    ))}
                  </select>
                </label>
                <label className="toggle-field">
                  <input
                    type="checkbox"
                    checked={inviteReusable}
                    onChange={(event) => setInviteReusable(event.target.checked)}
                  />
                  Reusable
                </label>
                <button
                  className="primary-button"
                  type="button"
                  disabled={busyAction === "create-invite"}
                  onClick={() => void handleCreateInvite()}
                >
                  {busyAction === "create-invite" ? <Loader2Icon className="spin" size={16} /> : <UserPlusIcon size={16} />}
                  Create Invite
                </button>
              </div>
            </section>

            {inviteResult ? (
              <div className="invite-result">
                <div>
                  <strong>Invite URL</strong>
                  <code>{inviteResult.url}</code>
                </div>
                <button className="icon-button" type="button" aria-label="Copy invite URL" title="Copy" onClick={() => void copyToClipboard(inviteResult.url)}>
                  <ClipboardIcon size={16} />
                </button>
              </div>
            ) : null}

            <section className="content-section">
              <div className="section-heading">
                <span>Pending</span>
                <small>{topology?.pendingRequests.length ?? 0}</small>
              </div>
              <div className="inline-control">
                <label>
                  Approve for
                  <select value={approvalExpiry} onChange={(event) => setApprovalExpiry(event.target.value as ExpiryValue)}>
                    {EXPIRY_OPTIONS.map((option) => (
                      <option key={option.value} value={option.value}>{option.label}</option>
                    ))}
                  </select>
                </label>
              </div>
              <div className="stack">
                {topology?.pendingRequests.length ? topology.pendingRequests.map((request) => (
                  <PendingRequestRow
                    key={request.recordId}
                    request={request}
                    busyAction={busyAction}
                    onApprove={handleApprove}
                    onReject={handleReject}
                  />
                )) : <EmptyRow icon={<ShieldCheckIcon size={18} />} text="No pending approvals" />}
              </div>
            </section>

            <section className="content-section">
              <div className="section-heading">
                <span>Nodes</span>
                <small>{allNodes.length}</small>
              </div>
              <div className="node-grid">
                {allNodes.length ? allNodes.map(({ node, member }) => (
                  <NodeCard
                    key={node.recordId}
                    node={node}
                    owner={member?.did}
                    busyAction={busyAction}
                    onRemove={handleRemoveNode}
                    onUpdateExpiry={handleUpdateNodeExpiry}
                    onUpdateLabel={handleUpdateNodeLabel}
                  />
                )) : <EmptyRow icon={<ServerIcon size={18} />} text="No nodes" />}
              </div>
            </section>

            <section className="content-section">
              <div className="section-heading">
                <span>Invites</span>
                <small>{topology?.preAuthKeys.length ?? 0}</small>
              </div>
              <div className="stack">
                {topology?.preAuthKeys.length ? topology.preAuthKeys.map((key) => (
                  <InviteRow
                    key={key.recordId}
                    invite={key}
                    busyAction={busyAction}
                    onCopy={handleCopyExistingInvite}
                    onRevoke={handleRevokeInvite}
                  />
                )) : <EmptyRow icon={<UserPlusIcon size={18} />} text="No active invites" />}
              </div>
            </section>
          </>
        )}
      </section>
    </div>
  );
}

function PendingRequestRow({
  request,
  busyAction,
  onApprove,
  onReject
}: {
  request: MeshdNodeRequestSummary;
  busyAction?: string;
  onApprove: (request: MeshdNodeRequestSummary) => Promise<void>;
  onReject: (request: MeshdNodeRequestSummary) => Promise<void>;
}) {
  const approving = busyAction === `approve-${request.recordId}`;
  const rejecting = busyAction === `reject-${request.recordId}`;
  return (
    <article className="data-row">
      <div className="row-main">
        <span className="row-icon"><ServerIcon size={17} /></span>
        <span>
          <strong>{request.label || truncateDid(request.nodeDID)}</strong>
          <small>{request.requestKind === "owner-node" || request.protocolPath === "nodeRequest" ? "Owner request" : "Invite request"}</small>
        </span>
      </div>
      <code title={request.nodeDID}>{truncateDid(request.nodeDID)}</code>
      <div className="row-actions">
        <button className="icon-button success" type="button" aria-label="Approve" title="Approve" disabled={approving || rejecting} onClick={() => void onApprove(request)}>
          {approving ? <Loader2Icon className="spin" size={16} /> : <CheckIcon size={16} />}
        </button>
        <button className="icon-button danger" type="button" aria-label="Reject" title="Reject" disabled={approving || rejecting} onClick={() => void onReject(request)}>
          {rejecting ? <Loader2Icon className="spin" size={16} /> : <XIcon size={16} />}
        </button>
      </div>
    </article>
  );
}

function NodeCard({
  node,
  owner,
  busyAction,
  onRemove,
  onUpdateExpiry,
  onUpdateLabel
}: {
  node: MeshdNodeSummary;
  owner?: string;
  busyAction?: string;
  onRemove: (node: MeshdNodeSummary) => Promise<void>;
  onUpdateExpiry: (node: MeshdNodeSummary, value: ExpiryValue) => Promise<void>;
  onUpdateLabel: (node: MeshdNodeSummary, label: string) => Promise<void>;
}) {
  const removing = busyAction === `remove-${node.recordId}`;
  const updatingLabel = busyAction === `label-${node.recordId}`;
  const updatingExpiry = busyAction === `expiry-${node.recordId}`;
  const [labelValue, setLabelValue] = useState(node.label ?? "");
  const [expiryChoice, setExpiryChoice] = useState<ExpiryValue>("30d");
  const state = expiryState(node.expiresAt);
  const expiryLabel = node.expiresAt
    ? state === "expired"
      ? `Expired ${formatTime(node.expiresAt)}`
      : `Expires ${formatTime(node.expiresAt)}`
    : "No expiry";
  useEffect(() => {
    setLabelValue(node.label ?? "");
  }, [node.label]);
  return (
    <article className={`node-card ${state === "expired" ? "expired" : state === "soon" ? "expiring" : ""}`}>
      <div className="node-card-header">
        <span className="row-icon"><ServerIcon size={17} /></span>
        <strong>{node.label || node.meshIP || truncateDid(node.did, 12, 6)}</strong>
        <button className="icon-button danger small" type="button" aria-label="Remove node" title="Remove" disabled={removing} onClick={() => void onRemove(node)}>
          {removing ? <Loader2Icon className="spin" size={15} /> : <Trash2Icon size={15} />}
        </button>
      </div>
      <dl>
        <div><dt>Mesh IP</dt><dd>{node.meshIP || "unknown"}</dd></div>
        <div><dt>Node</dt><dd title={node.did}>{truncateDid(node.did)}</dd></div>
        {owner ? <div><dt>Owner</dt><dd title={owner}>{truncateDid(owner)}</dd></div> : null}
        <div><dt>Expiry</dt><dd>{expiryLabel}</dd></div>
      </dl>
      <div className="label-editor">
        <label>
          Label
          <input value={labelValue} onChange={(event) => setLabelValue(event.target.value)} placeholder={node.meshIP || "Node label"} />
        </label>
        <button
          className="icon-button"
          type="button"
          aria-label="Apply node label"
          title="Apply label"
          disabled={updatingLabel || removing}
          onClick={() => void onUpdateLabel(node, labelValue)}
        >
          {updatingLabel ? <Loader2Icon className="spin" size={15} /> : <SaveIcon size={15} />}
        </button>
      </div>
      <div className="expiry-editor">
        <select value={expiryChoice} onChange={(event) => setExpiryChoice(event.target.value as ExpiryValue)}>
          {EXPIRY_OPTIONS.map((option) => (
            <option key={option.value} value={option.value}>{option.label}</option>
          ))}
        </select>
        <button
          className="icon-button success"
          type="button"
          aria-label="Apply node expiry"
          title="Apply expiry"
          disabled={updatingExpiry || removing}
          onClick={() => void onUpdateExpiry(node, expiryChoice)}
        >
          {updatingExpiry ? <Loader2Icon className="spin" size={15} /> : <CheckIcon size={15} />}
        </button>
      </div>
    </article>
  );
}

function InviteRow({
  invite,
  busyAction,
  onCopy,
  onRevoke
}: {
  invite: MeshdPreAuthKeySummary;
  busyAction?: string;
  onCopy: (invite: MeshdPreAuthKeySummary) => Promise<void>;
  onRevoke: (invite: MeshdPreAuthKeySummary) => Promise<void>;
}) {
  const revoking = busyAction === `revoke-${invite.recordId}`;
  return (
    <article className="data-row">
      <div className="row-main">
        <span className="row-icon"><UserPlusIcon size={17} /></span>
        <span>
          <strong>{invite.label || truncateDid(invite.recordId, 12, 6)}</strong>
          <small>{invite.expiresAt ? `Expires ${formatTime(invite.expiresAt)}` : "No expiry"}</small>
        </span>
      </div>
      <code>{invite.usedBy.length} used</code>
      <div className="row-actions">
        <button className="icon-button" type="button" aria-label="Copy invite" title="Copy" onClick={() => void onCopy(invite)}>
          <ClipboardIcon size={16} />
        </button>
        <button className="icon-button danger" type="button" aria-label="Revoke invite" title="Revoke" disabled={revoking} onClick={() => void onRevoke(invite)}>
          {revoking ? <Loader2Icon className="spin" size={16} /> : <Trash2Icon size={16} />}
        </button>
      </div>
    </article>
  );
}

function StatePanel({ title, detail, loading }: { title: string; detail: string; loading?: boolean }) {
  return (
    <section className="state-panel">
      {loading ? <Loader2Icon className="spin" size={24} /> : <NetworkIcon size={24} />}
      <h1>{title}</h1>
      <p>{detail}</p>
    </section>
  );
}

function EmptyRow({ icon, text }: { icon: React.ReactNode; text: string }) {
  return (
    <div className="empty-row">
      {icon}
      <span>{text}</span>
    </div>
  );
}
