import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  CheckIcon,
  ClipboardIcon,
  ClockIcon,
  KeyRoundIcon,
  Loader2Icon,
  LogOutIcon,
  NetworkIcon,
  PencilIcon,
  PlusIcon,
  RefreshCwIcon,
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
import { installAndUpCommand } from "./meshd/commands";
import { FirstDevicePanel, FirstNetworkPanel, FirstNodeConnected } from "./onboarding";
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
  updateMeshdInviteDescription,
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
type ExpiryTone = "none" | "active" | "soon" | "expired";

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

function formatDuration(ms: number): string {
  const minutes = Math.round(ms / 60_000);
  if (minutes < 60) return `${Math.max(1, minutes)} min`;
  const hours = Math.round(ms / 3_600_000);
  if (hours < 48) return `${hours} hr`;
  return `${Math.round(ms / 86_400_000)} days`;
}

// A single human-readable expiry descriptor drives both the label text and the
// colour tone, so the node card, invite composer, and invite rows all speak the
// same language ("Expires in 6 days" / "Expired 2 days ago" / "No expiry").
function describeExpiry(value?: string): { label: string; tone: ExpiryTone } {
  if (!value) return { label: "No expiry", tone: "none" };
  const time = new Date(value).getTime();
  if (!Number.isFinite(time)) return { label: value, tone: "none" };
  const diff = time - Date.now();
  if (diff <= 0) return { label: `Expired ${formatDuration(-diff)} ago`, tone: "expired" };
  return { label: `Expires in ${formatDuration(diff)}`, tone: diff <= 24 * 60 * 60 * 1000 ? "soon" : "active" };
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
  const [inviteResults, setInviteResults] = useState<CreateMeshdInviteResult[]>([]);
  const [inviteExpiry, setInviteExpiry] = useState<ExpiryValue>("7d");
  const [inviteReusable, setInviteReusable] = useState(false);
  const [networkName, setNetworkName] = useState("");
  const [networkCIDR, setNetworkCIDR] = useState("10.200.0.0/16");
  // First-run guide: tracks the just-approved first device for the success
  // step, and whether the operator finished or skipped the guide.
  const [firstConnected, setFirstConnected] = useState<{ name?: string; meshIP: string }>();
  const [onboardingDone, setOnboardingDone] = useState(false);
  const [busyAction, setBusyAction] = useState<string>();
  const [topologyRefreshing, setTopologyRefreshing] = useState(false);
  const topologyRefreshInFlight = useRef(false);
  // Records the operator just approved/rejected/removed are dropped from the
  // topology optimistically, then kept suppressed so a topology refetch that
  // still reflects the pre-delete DWN state can't resurrect them until the
  // delete has propagated (approvals used to linger until a later refresh).
  const suppressed = useRef({
    requests: new Set<string>(),
    invites: new Set<string>(),
    nodes: new Set<string>()
  });

  const selectedNetwork = useMemo(() => {
    if (networks.length === 0) return undefined;
    return networks.find((network) => network.recordId === selectedNetworkId) ?? networks[0];
  }, [networks, selectedNetworkId]);

  const applySuppression = useCallback((next: MeshdNetworkTopology): MeshdNetworkTopology => {
    const { requests, invites, nodes } = suppressed.current;
    if (requests.size === 0 && invites.size === 0 && nodes.size === 0) return next;
    return {
      ...next,
      pendingRequests: next.pendingRequests.filter((request) => !requests.has(request.recordId)),
      preAuthKeys: next.preAuthKeys.filter((key) => !invites.has(key.recordId)),
      members: next.members.map((member) => ({
        ...member,
        nodes: member.nodes.filter((node) => !nodes.has(node.recordId))
      })),
      legacyNodes: next.legacyNodes.filter((node) => !nodes.has(node.recordId))
    };
  }, []);

  const patchTopology = useCallback((update: (current: MeshdNetworkTopology) => MeshdNetworkTopology) => {
    setTopology((current) => (current ? update(current) : current));
  }, []);

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
      setTopology(applySuppression(nextTopology));
      setError(undefined);
    } catch (err) {
      if (!options?.silent) {
        setError(err instanceof Error ? err.message : "Could not load network topology.");
      }
    } finally {
      topologyRefreshInFlight.current = false;
      setTopologyRefreshing(false);
    }
  }, [applySuppression, context, did, protocolsInitialized, selectedNetwork, session]);

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

  // Freshly-created invite URLs and optimistic suppressions are scoped to the
  // selected network; reset them when the operator switches networks so nothing
  // carries across.
  useEffect(() => {
    setInviteResults([]);
    setFirstConnected(undefined);
    setOnboardingDone(false);
    suppressed.current = { requests: new Set(), invites: new Set(), nodes: new Set() };
  }, [selectedNetwork?.recordId]);

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

  async function handleCreateNetwork(name: string, cidr: string) {
    if (!session) return;
    await runAction("create-network", async () => {
      const network = await createMeshdNetwork(session, { name, meshCIDR: cidr });
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
        expiresAt: expiryTimestamp(inviteExpiry),
        reusable: inviteReusable
      });
      // Keep every invite created this session pinned and copyable, newest first,
      // so several machines can be invited and copied without losing earlier URLs.
      setInviteResults((prev) => [result, ...prev]);
      toast.success("Invite created");
      await refreshTopology();
    });
  }

  async function handleUpdateInviteDescription(key: MeshdPreAuthKeySummary, description: string) {
    if (!session || !selectedNetwork) return;
    await runAction(`describe-${key.recordId}`, async () => {
      const updated = await updateMeshdInviteDescription(session, selectedNetwork, key, description);
      patchTopology((current) => ({
        ...current,
        preAuthKeys: current.preAuthKeys.map((item) => (item.recordId === updated.recordId ? updated : item))
      }));
      toast.success(description.trim() ? "Invite description saved" : "Invite description cleared");
    });
  }

  async function handleApprove(request: MeshdNodeRequestSummary) {
    if (!session || !selectedNetwork) return;
    const isFirstDevice = !topology?.members.some((member) => member.nodes.length > 0)
      && (topology?.legacyNodes.length ?? 0) === 0;
    await runAction(`approve-${request.recordId}`, async () => {
      const result = await approveMeshdNodeRequest(session, selectedNetwork, request);
      if (isFirstDevice) {
        setFirstConnected({ name: request.label, meshIP: result.meshIP });
      }
      // Drop the approved request now, and drop the single-use invite it consumed,
      // so both disappear immediately instead of lingering until the delete
      // propagates back through a refetch.
      suppressed.current.requests.add(request.recordId);
      const consumedInvite = request.preAuthKeyId
        ? topology?.preAuthKeys.find((key) => key.recordId === request.preAuthKeyId)
        : undefined;
      if (consumedInvite && !consumedInvite.reusable) {
        suppressed.current.invites.add(consumedInvite.recordId);
      }
      patchTopology((current) => ({
        ...current,
        pendingRequests: current.pendingRequests.filter((item) => item.recordId !== request.recordId),
        preAuthKeys: consumedInvite && !consumedInvite.reusable
          ? current.preAuthKeys.filter((key) => key.recordId !== consumedInvite.recordId)
          : current.preAuthKeys
      }));
      toast.success(`Node approved at ${result.meshIP} — a waiting device connects on its own; otherwise run 'meshd up' on it`);
      await refreshTopology({ silent: true });
    });
  }

  async function handleReject(request: MeshdNodeRequestSummary) {
    if (!session) return;
    await runAction(`reject-${request.recordId}`, async () => {
      await rejectMeshdNodeRequest(session, request);
      suppressed.current.requests.add(request.recordId);
      patchTopology((current) => ({
        ...current,
        pendingRequests: current.pendingRequests.filter((item) => item.recordId !== request.recordId)
      }));
      toast.success("Request rejected");
      await refreshTopology({ silent: true });
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
      suppressed.current.invites.add(key.recordId);
      patchTopology((current) => ({
        ...current,
        preAuthKeys: current.preAuthKeys.filter((item) => item.recordId !== key.recordId)
      }));
      toast.success("Invite revoked");
      await refreshTopology({ silent: true });
    });
  }

  async function handleCopyExistingInvite(key: MeshdPreAuthKeySummary) {
    if (!session || !selectedNetwork) return;
    const url = await buildMeshdInviteURL(session, selectedNetwork, key);
    await copyToClipboard(url);
  }

  async function handleCopyExistingInviteCommand(key: MeshdPreAuthKeySummary) {
    if (!session || !selectedNetwork) return;
    const url = await buildMeshdInviteURL(session, selectedNetwork, key);
    await copyToClipboard(installAndUpCommand(url));
  }

  async function handleCopyOwnerSetupCommand() {
    if (!did) return;
    await copyToClipboard(installAndUpCommand(did));
  }

  async function handleRemoveNode(node: MeshdNodeSummary) {
    if (!session || !selectedNetwork) return;
    await runAction(`remove-${node.recordId}`, async () => {
      await removeMeshdNode(session, selectedNetwork, node);
      suppressed.current.nodes.add(node.recordId);
      patchTopology((current) => ({
        ...current,
        members: current.members.map((member) => ({
          ...member,
          nodes: member.nodes.filter((item) => item.recordId !== node.recordId)
        })),
        legacyNodes: current.legacyNodes.filter((item) => item.recordId !== node.recordId)
      }));
      toast.success("Node removed");
      await refreshTopology({ silent: true });
    });
  }

  function dismissInviteResult(tokenId: string) {
    setInviteResults((prev) => prev.filter((result) => result.tokenId !== tokenId));
  }

  if (!ownerMatchesDashboardContext(context, did)) {
    return (
      <StatePanel
        title="Wrong owner wallet"
        detail={`This dashboard URL targets ${context.ownerDID}, but the connected wallet is ${did ?? "unknown"}. Disconnect and connect the owner wallet.`}
      />
    );
  }

  if (!delegateDid) {
    // The dashboard never holds the owner's signing key: every DWN
    // operation must be signed by the wallet session's delegate. A session
    // restored without its delegate cannot sign anything — fail closed
    // here instead of surfacing per-action KMS errors.
    return (
      <StatePanel
        title="Delegated access unavailable"
        detail="This wallet session restored without its delegate identity, so the dashboard cannot sign changes. Disconnect and reconnect your wallet to restore delegated access."
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
  const pendingRequests = topology?.pendingRequests ?? [];
  const expiryLabel = (EXPIRY_OPTIONS.find((option) => option.value === inviteExpiry)?.label ?? inviteExpiry).toLowerCase();
  const inviteHint = inviteExpiry === "never"
    ? `The invite never expires and admits ${inviteReusable ? "any number of devices" : "one device"}.`
    : `The invite is valid for ${expiryLabel} and admits ${inviteReusable ? "any number of devices" : "one device"}.`;

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
          {networks.length === 0 && loadState === "ready" ? (
            <EmptyRow icon={<NetworkIcon size={16} />} text="No networks yet" />
          ) : null}
        </div>

        {networks.length > 0 ? (
          <div className="create-box">
            <div className="section-heading">
              <span>New Network</span>
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
              onClick={() => void handleCreateNetwork(networkName, networkCIDR)}
            >
              {busyAction === "create-network" ? <Loader2Icon className="spin" size={16} /> : <PlusIcon size={16} />}
              Create Network
            </button>
          </div>
        ) : null}
      </aside>

      <section className="main-panel">
        {error ? <div className="error-banner">{error}</div> : null}
        {networks.length === 0 && loadState === "ready" ? (
          <FirstNetworkPanel
            busy={busyAction === "create-network"}
            defaultCIDR="10.200.0.0/16"
            onCreate={(name, cidr) => void handleCreateNetwork(name, cidr)}
          />
        ) : !selectedNetwork ? (
          <StatePanel title="Loading networks" detail="Fetching your mesh networks." loading />
        ) : firstConnected && !onboardingDone ? (
          <FirstNodeConnected
            name={firstConnected.name}
            meshIP={firstConnected.meshIP}
            onAddAnother={() => {
              setOnboardingDone(true);
              void handleCreateInvite();
            }}
            onDismiss={() => setOnboardingDone(true)}
          />
        ) : allNodes.length === 0 && !onboardingDone ? (
          <>
            <FirstDevicePanel
              networkName={selectedNetwork.name}
              command={inviteResults[0] ? installAndUpCommand(inviteResults[0].url) : undefined}
              inviteHint={inviteHint}
              creating={busyAction === "create-invite"}
              pendingCount={pendingRequests.length}
              onCreateInvite={() => void handleCreateInvite()}
              onCopyCommand={copyToClipboard}
            >
              <div className="stack">
                {pendingRequests.map((request) => (
                  <PendingRequestRow
                    key={request.recordId}
                    request={request}
                    busyAction={busyAction}
                    onApprove={handleApprove}
                    onReject={handleReject}
                  />
                ))}
              </div>
            </FirstDevicePanel>
            <button className="text-button skip-guide" type="button" onClick={() => setOnboardingDone(true)}>
              Skip the guided setup
            </button>
          </>
        ) : (
          <>
            <div className="network-header">
              <div>
                <h1>{selectedNetwork.name}</h1>
                <p>{selectedNetwork.meshCIDR} · {allNodes.length} node{allNodes.length === 1 ? "" : "s"}</p>
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

            {pendingRequests.length > 0 ? (
              <section className="content-section pending-section">
                <div className="section-heading">
                  <span>Waiting for approval</span>
                  <small className="count-badge">{pendingRequests.length}</small>
                </div>
                <div className="stack">
                  {pendingRequests.map((request) => (
                    <PendingRequestRow
                      key={request.recordId}
                      request={request}
                      busyAction={busyAction}
                      onApprove={handleApprove}
                      onReject={handleReject}
                    />
                  ))}
                </div>
              </section>
            ) : null}

            <section className="invite-composer">
              <div className="section-heading">
                <span>Invite a device</span>
              </div>
              <div className="invite-fields">
                <label>
                  Access expires
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
              <p className="field-hint">
                The joined device stays valid until the invite expires — set once here, inherited on approval.
                Devices are named by their own hostname; rename them on the node card after they connect.
              </p>
            </section>

            {inviteResults.length > 0 ? (
              <div className="stack">
                {inviteResults.map((result) => (
                  <InviteResultCard key={result.tokenId} result={result} onDismiss={dismissInviteResult} />
                ))}
              </div>
            ) : null}

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
                )) : <EmptyRow icon={<ServerIcon size={18} />} text="No nodes yet — invite a device to get started." />}
              </div>
            </section>

            <section className="content-section">
              <div className="section-heading">
                <span>Active invites</span>
                <small>{topology?.preAuthKeys.length ?? 0}</small>
              </div>
              <div className="stack">
                {topology?.preAuthKeys.length ? topology.preAuthKeys.map((key) => (
                  <InviteRow
                    key={key.recordId}
                    invite={key}
                    busyAction={busyAction}
                    onCopy={handleCopyExistingInvite}
                    onCopyCommand={handleCopyExistingInviteCommand}
                    onSaveDescription={handleUpdateInviteDescription}
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
  const isOwnerRequest = request.requestKind === "owner-node" || request.protocolPath === "nodeRequest";
  return (
    <article className="data-row">
      <div className="row-main">
        <span className="row-icon"><ServerIcon size={17} /></span>
        <span>
          <strong>{request.label || truncateDid(request.nodeDID)}</strong>
          <small>{isOwnerRequest ? "Owner request" : "Joined via invite"}</small>
        </span>
      </div>
      <code title={request.nodeDID}>{truncateDid(request.nodeDID)}</code>
      <div className="row-actions">
        <button className="primary-button small" type="button" disabled={approving || rejecting} onClick={() => void onApprove(request)}>
          {approving ? <Loader2Icon className="spin" size={15} /> : <CheckIcon size={15} />}
          Approve
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
  const [editing, setEditing] = useState(false);
  const [labelValue, setLabelValue] = useState(node.label ?? "");
  const [expiryChoice, setExpiryChoice] = useState<ExpiryValue | "">("");
  const expiry = describeExpiry(node.expiresAt);

  useEffect(() => {
    setLabelValue(node.label ?? "");
  }, [node.label]);

  async function applyLabel() {
    await onUpdateLabel(node, labelValue);
  }

  async function applyExpiry() {
    if (!expiryChoice) return;
    await onUpdateExpiry(node, expiryChoice);
    setExpiryChoice("");
  }

  return (
    <article className={`node-card ${expiry.tone === "expired" ? "expired" : expiry.tone === "soon" ? "expiring" : ""}`}>
      <div className="node-card-header">
        <span className="row-icon"><ServerIcon size={17} /></span>
        <strong>{node.label || node.meshIP || truncateDid(node.did, 12, 6)}</strong>
        <span className={`expiry-pill ${expiry.tone}`} title={node.expiresAt ? formatFullTime(node.expiresAt) : undefined}>
          <ClockIcon size={13} />
          {expiry.label}
        </span>
      </div>
      <dl>
        <div><dt>Mesh IP</dt><dd>{node.meshIP || "unknown"}</dd></div>
        <div><dt>Node</dt><dd title={node.did}>{truncateDid(node.did)}</dd></div>
        {owner ? <div><dt>Owner</dt><dd title={owner}>{truncateDid(owner)}</dd></div> : null}
      </dl>

      {editing ? (
        <div className="node-card-edit">
          <div className="label-editor">
            <label>
              Device name
              <input value={labelValue} onChange={(event) => setLabelValue(event.target.value)} placeholder={node.meshIP || "hostname"} />
            </label>
            <button
              className="icon-button success"
              type="button"
              aria-label="Save device name"
              title="Save name"
              disabled={updatingLabel || removing}
              onClick={() => void applyLabel()}
            >
              {updatingLabel ? <Loader2Icon className="spin" size={15} /> : <CheckIcon size={15} />}
            </button>
          </div>
          <div className="expiry-editor">
            <select value={expiryChoice} onChange={(event) => setExpiryChoice(event.target.value as ExpiryValue)}>
              <option value="" disabled>Change expiry…</option>
              {EXPIRY_OPTIONS.map((option) => (
                <option key={option.value} value={option.value}>{option.label}</option>
              ))}
            </select>
            <button
              className="icon-button success"
              type="button"
              aria-label="Apply node expiry"
              title="Apply expiry"
              disabled={!expiryChoice || updatingExpiry || removing}
              onClick={() => void applyExpiry()}
            >
              {updatingExpiry ? <Loader2Icon className="spin" size={15} /> : <CheckIcon size={15} />}
            </button>
          </div>
        </div>
      ) : null}

      <div className="node-card-actions">
        <button className="text-button" type="button" onClick={() => setEditing((value) => !value)}>
          <PencilIcon size={14} />
          {editing ? "Done" : "Edit"}
        </button>
        <button className="text-button danger" type="button" disabled={removing} onClick={() => void onRemove(node)}>
          {removing ? <Loader2Icon className="spin" size={14} /> : <Trash2Icon size={14} />}
          Remove
        </button>
      </div>
    </article>
  );
}

function InviteResultCard({
  result,
  onDismiss
}: {
  result: CreateMeshdInviteResult;
  onDismiss: (tokenId: string) => void;
}) {
  const expiry = describeExpiry(result.expiresAt);
  const command = installAndUpCommand(result.url);
  return (
    <div className="invite-result">
      <div className="invite-result-body">
        <div className="invite-result-head">
          <strong className="invite-id" title={result.tokenId}>Invite {truncateDid(result.tokenId, 10, 4)}</strong>
          <span className={`expiry-pill ${expiry.tone}`}><ClockIcon size={13} />{expiry.label}</span>
        </div>
        <code>{command}</code>
        <p className="field-hint">
          Run this on the new device: it installs meshd, requests to join, and
          connects on its own once you approve it here. If meshd is already
          installed, copy just the invite URL and run `meshd up &lt;url&gt;` instead.
        </p>
      </div>
      <div className="row-actions">
        <button className="icon-button" type="button" aria-label="Copy install command" title="Copy install command" onClick={() => void copyToClipboard(command)}>
          <TerminalIcon size={16} />
        </button>
        <button className="icon-button" type="button" aria-label="Copy invite URL" title="Copy invite URL" onClick={() => void copyToClipboard(result.url)}>
          <ClipboardIcon size={16} />
        </button>
        <button className="icon-button" type="button" aria-label="Dismiss" title="Dismiss" onClick={() => onDismiss(result.tokenId)}>
          <XIcon size={16} />
        </button>
      </div>
    </div>
  );
}

function InviteRow({
  invite,
  busyAction,
  onCopy,
  onCopyCommand,
  onSaveDescription,
  onRevoke
}: {
  invite: MeshdPreAuthKeySummary;
  busyAction?: string;
  onCopy: (invite: MeshdPreAuthKeySummary) => Promise<void>;
  onCopyCommand: (invite: MeshdPreAuthKeySummary) => Promise<void>;
  onSaveDescription: (invite: MeshdPreAuthKeySummary, description: string) => Promise<void>;
  onRevoke: (invite: MeshdPreAuthKeySummary) => Promise<void>;
}) {
  const revoking = busyAction === `revoke-${invite.recordId}`;
  const saving = busyAction === `describe-${invite.recordId}`;
  const [editing, setEditing] = useState(false);
  const [descriptionValue, setDescriptionValue] = useState(invite.label ?? "");
  const expiry = describeExpiry(invite.expiresAt);

  useEffect(() => {
    setDescriptionValue(invite.label ?? "");
  }, [invite.label]);

  async function saveDescription() {
    await onSaveDescription(invite, descriptionValue);
    setEditing(false);
  }

  return (
    <article className="data-row invite-row">
      <div className="row-main">
        <span className="row-icon"><UserPlusIcon size={17} /></span>
        <span>
          <strong className="invite-id" title={invite.recordId}>Invite {truncateDid(invite.recordId, 10, 4)}</strong>
          <small>
            {invite.label ? `${invite.label} · ` : ""}
            {expiry.label}
            {invite.reusable ? " · reusable" : ""}
            {invite.usedBy.length ? ` · ${invite.usedBy.length} used` : ""}
          </small>
        </span>
      </div>
      <div className="row-actions">
        <button
          className="icon-button"
          type="button"
          aria-label={invite.label ? "Edit invite description" : "Add invite description"}
          title={invite.label ? "Edit description" : "Add description"}
          onClick={() => setEditing((value) => !value)}
        >
          <PencilIcon size={16} />
        </button>
        <button className="icon-button" type="button" aria-label="Copy install command" title="Copy install command" onClick={() => void onCopyCommand(invite)}>
          <TerminalIcon size={16} />
        </button>
        <button className="icon-button" type="button" aria-label="Copy invite URL" title="Copy invite URL" onClick={() => void onCopy(invite)}>
          <ClipboardIcon size={16} />
        </button>
        <button className="icon-button danger" type="button" aria-label="Revoke invite" title="Revoke" disabled={revoking} onClick={() => void onRevoke(invite)}>
          {revoking ? <Loader2Icon className="spin" size={16} /> : <Trash2Icon size={16} />}
        </button>
      </div>
      {editing ? (
        <div className="invite-description-editor">
          <input
            autoFocus
            value={descriptionValue}
            onChange={(event) => setDescriptionValue(event.target.value)}
            placeholder="What is this invite for? (optional)"
            onKeyDown={(event) => {
              if (event.key === "Enter") void saveDescription();
              if (event.key === "Escape") setEditing(false);
            }}
          />
          <button
            className="icon-button success"
            type="button"
            aria-label="Save invite description"
            title="Save description"
            disabled={saving}
            onClick={() => void saveDescription()}
          >
            {saving ? <Loader2Icon className="spin" size={15} /> : <CheckIcon size={15} />}
          </button>
        </div>
      ) : null}
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

function formatFullTime(value: string) {
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) return value;
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short"
  }).format(date);
}
