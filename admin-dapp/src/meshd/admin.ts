import { DwnInterface } from "@enbox/agent";
import { Ed25519 } from "@enbox/crypto";
import { DidJwk } from "@enbox/dids";

import {
  DEFAULT_DWN_ENDPOINT,
  MESHD_PROTOCOL_URI
} from "@/enbox/config";

export type MeshdAdminAgent = {
  permissions?: {
    getPermissionForRequest?: (request: {
      connectedDid: string;
      delegateDid: string;
      protocol?: string;
      delegate?: boolean;
      cached?: boolean;
      messageType: unknown;
    }) => Promise<{ message: unknown; grant?: { id?: string } }>;
  };
  processDwnRequest: (request: Record<string, unknown>) => Promise<{
    reply: {
      status: { code: number; detail?: string };
      entries?: unknown[];
    };
    message?: {
      recordId?: string;
      descriptor?: {
        dateCreated?: string;
      };
    };
    messageCid?: string;
    // Present on a `$role` RecordsWrite: reports whether the agent could deliver the
    // recipient's role-audience key. Best-effort — a failure is reported here, not
    // thrown (see @enbox/agent supplied-key delivery).
    audienceKeyDelivery?: {
      delivered: boolean;
      recipientDid?: string;
      reason?: string;
    };
  }>;
  sync?: {
    sync?: (direction?: "push" | "pull") => Promise<void>;
  };
  dwn?: {
    getDwnEndpointUrlsForTarget?: (targetDid: string) => Promise<string[]>;
  };
};

export type MeshdAdminSession = {
  agent: MeshdAdminAgent;
  ownerDid: string;
  delegateDid?: string;
};

export type MeshdNetworkSummary = {
  recordId: string;
  name: string;
  meshCIDR: string;
  anchorEndpoint?: string;
  createdAt?: string;
  updatedAt?: string;
};

export type MeshdMemberSummary = {
  recordId: string;
  did: string;
  label?: string;
  addedAt?: string;
  createdAt?: string;
  nodes: MeshdNodeSummary[];
};

export type MeshdNodeSummary = {
  recordId: string;
  did: string;
  meshIP?: string;
  allowedIPs?: string[];
  label?: string;
  ownerDID?: string;
  memberDID?: string;
  delegateDID?: string;
  memberRecordId?: string;
  addedAt?: string;
  expiresAt?: string;
  sourceDWN?: string;
  createdAt?: string;
};

// RolePublicKeyJwk is the PUBLIC half of a node's role-path X25519 key, as emitted
// in a node request's `roleKeys` (byte-identical to the `$keyAgreement.publicKeyJwk`
// the node injects at that path). Shape matches @enbox/agent's PublicKeyJwk.
export type RolePublicKeyJwk = {
  kty: string;
  crv: string;
  x: string;
  kid?: string;
};

export type MeshdNodeRequestSummary = {
  recordId: string;
  protocolPath?: string;
  nodeDID: string;
  ownerDID?: string;
  memberDID?: string;
  delegateDID?: string;
  requestedBy?: string;
  nodeProof?: string;
  requestKind?: string;
  networkRecordId?: string;
  networkName?: string;
  label?: string;
  sourceDWN?: string;
  preAuthKeyId?: string;
  preAuthProof?: string;
  requestedAt?: string;
  expiresAt?: string;
  createdAt?: string;
  // roleKeys carries the node's own role-path public keys, keyed by full role path
  // (e.g. "network/member/node"). A DWN-less did:jwk node has no endpoint from which
  // the owner could resolve these, so it supplies them here for key delivery (#187).
  roleKeys?: Record<string, RolePublicKeyJwk>;
};

export type MeshdPreAuthKeySummary = {
  recordId: string;
  key: string;
  createdAt?: string;
  expiresAt?: string;
  reusable?: boolean;
  ephemeral?: boolean;
  label?: string;
  usedBy: string[];
  recordCreatedAt?: string;
};

export type MeshdNetworkTopology = {
  network: MeshdNetworkSummary;
  members: MeshdMemberSummary[];
  legacyNodes: MeshdNodeSummary[];
  pendingRequests: MeshdNodeRequestSummary[];
  preAuthKeys: MeshdPreAuthKeySummary[];
};

export type CreateMeshdInviteResult = {
  url: string;
  tokenId: string;
  secret: string;
  expiresAt?: string;
  label?: string;
};

export type ApproveMeshdNodeRequestResult = {
  memberRecordId: string;
  nodeRecordId: string;
  meshIP: string;
};

type AuthoredRecord = {
  recordId: string;
  dateCreated?: string;
  audienceKeyDelivery?: {
    delivered: boolean;
    recipientDid?: string;
    reason?: string;
  };
};

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function getString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() !== "" ? value.trim() : undefined;
}

function getStringArray(value: unknown): string[] | undefined {
  if (!Array.isArray(value)) return undefined;
  const items = value
    .filter((item): item is string => typeof item === "string" && item.trim() !== "")
    .map((item) => item.trim());
  return items.length ? items : undefined;
}

function base64UrlDecode(value: string): string {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized.padEnd(normalized.length + ((4 - normalized.length % 4) % 4), "=");
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return new TextDecoder().decode(bytes);
}

function base64UrlDecodeBytes(value: string): Uint8Array {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized.padEnd(normalized.length + ((4 - normalized.length % 4) % 4), "=");
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function base64UrlEncodeBytes(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64UrlEncodeJson(value: unknown): string {
  return base64UrlEncodeBytes(new TextEncoder().encode(JSON.stringify(value)));
}

function generateInviteSecret(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return base64UrlEncodeBytes(bytes);
}

function getRecordWrite(rawEntry: unknown): Record<string, unknown> | undefined {
  if (!isObject(rawEntry)) return undefined;
  if (isObject(rawEntry.recordsWrite)) return rawEntry.recordsWrite;
  if (isObject(rawEntry.record)) return rawEntry.record;
  return rawEntry;
}

function getRecordId(
  entry: Record<string, unknown>,
  wrapper: Record<string, unknown>,
  descriptor: Record<string, unknown>
): string | undefined {
  return getString(entry.recordId)
    ?? getString(wrapper.recordId)
    ?? getString(descriptor.recordId)
    ?? getString(wrapper.id);
}

function getRecipient(
  entry: Record<string, unknown>,
  wrapper: Record<string, unknown>,
  descriptor: Record<string, unknown>
): string | undefined {
  return getString(entry.recipient)
    ?? getString(descriptor.recipient)
    ?? getString(wrapper.recipient);
}

function decodeRecordPayload(entry: Record<string, unknown>, wrapper: Record<string, unknown>): unknown {
  if (isObject(wrapper.data)) return wrapper.data;
  if (isObject(entry.data)) return entry.data;
  if (typeof wrapper.encodedData === "string") return JSON.parse(base64UrlDecode(wrapper.encodedData));
  if (typeof entry.encodedData === "string") return JSON.parse(base64UrlDecode(entry.encodedData));
  return undefined;
}

export const DELEGATE_SESSION_REQUIRED_ERROR =
  "This wallet session has no delegate identity, so the dashboard cannot sign DWN messages. "
  + "Disconnect and reconnect your wallet to restore delegated access.";

function delegateGrantMissingError(protocol: string): string {
  return `The wallet session did not grant ${protocol} access to this dashboard. `
    + "Disconnect and reconnect your wallet, approving the requested permissions.";
}

/**
 * Authors a DWN request as the wallet-session delegate, invoking a delegated
 * grant from the connected owner.
 *
 * This fails closed: the dapp never holds the owner's signing key, so a
 * request authored as the owner is guaranteed to die in the agent's KMS
 * ("Unable to get signer for author ... Key not found"). If the session has
 * no delegate, or the wallet session holds no matching delegated grant, we
 * throw a clear, user-facing error instead of ever falling back to
 * author-as-owner.
 */
async function processDwnRequest(
  session: MeshdAdminSession,
  request: Record<string, unknown>,
  protocol: string
) {
  if (!session.delegateDid) {
    throw new Error(DELEGATE_SESSION_REQUIRED_ERROR);
  }

  let permission: { message: unknown } | undefined;
  try {
    permission = await session.agent.permissions?.getPermissionForRequest?.({
      connectedDid: session.ownerDid,
      delegateDid: session.delegateDid,
      protocol,
      delegate: true,
      cached: true,
      messageType: request.messageType
    });
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    throw new Error(`${delegateGrantMissingError(protocol)} (${detail})`);
  }
  if (!permission?.message) {
    throw new Error(delegateGrantMissingError(protocol));
  }

  return session.agent.processDwnRequest({
    ...request,
    messageParams: {
      ...(isObject(request.messageParams) ? request.messageParams : {}),
      delegatedGrant: permission.message
    },
    granteeDid: session.delegateDid
  });
}

/**
 * Best-effort flush of freshly written records to the owner's remote DWN.
 *
 * A delegate session cannot push via owner-authored `sendDwnRequest`
 * (resolving a signer for the owner DID fails — the dapp never holds that
 * key). Remote propagation is the sync engine's job: the auth session
 * registers the owner tenant with the delegate's grants and live sync
 * pushes local writes automatically. This one-shot push only shortens the
 * latency window so the meshd daemon (which polls the owner's remote DWN)
 * sees admin changes sooner. Failures are non-fatal — the records are
 * already accepted locally and sync retries in the background.
 */
async function pushChangesToRemote(session: MeshdAdminSession): Promise<void> {
  const sync = session.agent.sync;
  if (!sync?.sync) {
    return;
  }
  try {
    await sync.sync("push");
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    if (!detail.includes("already in progress")) {
      console.warn("[meshd-admin] Remote DWN push failed (sync will retry):", detail);
    }
  }
}

function recordIdFromMessage(message?: { recordId?: string; descriptor?: { dateCreated?: string } }): string {
  const recordId = message?.recordId;
  if (!recordId) {
    throw new Error("DWN write did not return a record ID.");
  }
  return recordId;
}

async function writeRecord(
  session: MeshdAdminSession,
  protocol: string,
  messageParams: Record<string, unknown>,
  payload: Record<string, unknown>,
  encryption?: true,
  recipientRolePublicKey?: RolePublicKeyJwk
): Promise<AuthoredRecord> {
  const data = new TextEncoder().encode(JSON.stringify(payload));
  const { reply, message, audienceKeyDelivery } = await processDwnRequest(
    session,
    {
      author: session.ownerDid,
      target: session.ownerDid,
      messageType: DwnInterface.RecordsWrite,
      messageParams,
      dataStream: new Blob([data], { type: "application/json" }),
      ...(encryption ? { encryption } : {}),
      // Top-level ProcessDwnRequest field: when writing a $role record with a
      // recipient, the agent wraps the key delivery to this instead of resolving the
      // recipient's role-path key from a DWN it does not have (#187).
      ...(recipientRolePublicKey ? { recipientRolePublicKey } : {})
    },
    protocol
  );

  if (reply.status.code >= 300 || !message) {
    throw new Error(`DWN write failed: ${reply.status.code} ${reply.status.detail ?? ""}`.trim());
  }

  await pushChangesToRemote(session);
  return {
    recordId: recordIdFromMessage(message),
    dateCreated: message.descriptor?.dateCreated,
    ...(audienceKeyDelivery ? { audienceKeyDelivery } : {})
  };
}

async function deleteRecord(
  session: MeshdAdminSession,
  protocol: string,
  recordId: string,
  prune: boolean
): Promise<void> {
  const { reply } = await processDwnRequest(
    session,
    {
      author: session.ownerDid,
      target: session.ownerDid,
      messageType: DwnInterface.RecordsDelete,
      messageParams: { recordId, prune }
    },
    protocol
  );

  if (reply.status.code >= 300) {
    throw new Error(`Could not delete record ${recordId}: ${reply.status.detail ?? reply.status.code}`);
  }
  await pushChangesToRemote(session);
}

async function queryRecords(
  session: MeshdAdminSession,
  protocol: string,
  protocolPath: string,
  contextId?: string,
  extraFilter: Record<string, unknown> = {}
): Promise<unknown[]> {
  const result = await processDwnRequest(
    session,
    {
      author: session.ownerDid,
      target: session.ownerDid,
      messageType: DwnInterface.RecordsQuery,
      messageParams: {
        filter: {
          protocol,
          protocolPath,
          ...(contextId ? { contextId } : {}),
          ...extraFilter
        },
        dateSort: "createdAscending"
      },
      // Mesh records (preAuthKey, member/node payloads) are written with
      // encryption: true. The agent only auto-decrypts reply data when the
      // *query* also carries this flag (maybeDecryptReply early-returns
      // otherwise), so without it encrypted records come back as ciphertext
      // that decodeRecordPayload cannot parse — leaving preAuthKey lookups and
      // the topology invite list silently empty. Plaintext records (e.g.
      // network) are unaffected: decryption only touches entries whose own
      // encryption descriptor is set.
      encryption: true
    },
    protocol
  );

  if (result.reply.status.code !== 200) {
    throw new Error(`Could not fetch ${protocolPath} records: ${result.reply.status.detail ?? result.reply.status.code}`);
  }
  return result.reply.entries ?? [];
}

export function parseMeshdNetworkRecord(rawEntry: unknown): MeshdNetworkSummary | undefined {
  const wrapper = isObject(rawEntry) ? rawEntry : undefined;
  const entry = getRecordWrite(rawEntry);
  if (!entry || !wrapper) return undefined;
  const descriptor = isObject(entry.descriptor) ? entry.descriptor : {};
  const protocolPath = getString(descriptor.protocolPath);
  if (protocolPath && protocolPath !== "network") return undefined;
  const recordId = getRecordId(entry, wrapper, descriptor);
  if (!recordId) return undefined;

  let payload: unknown;
  try {
    payload = decodeRecordPayload(entry, wrapper);
  } catch {
    return undefined;
  }
  if (!isObject(payload)) return undefined;
  const meshCIDR = getString(payload.meshCIDR) ?? getString(payload.meshCidr);
  if (!meshCIDR) return undefined;
  return {
    recordId,
    name: getString(payload.name) ?? "Unnamed mesh",
    meshCIDR,
    anchorEndpoint: getString(payload.anchorEndpoint) ?? getString(payload.endpoint),
    createdAt: getString(descriptor.dateCreated) ?? getString(wrapper.dateCreated),
    updatedAt: getString(descriptor.dateModified) ?? getString(wrapper.dateModified)
  };
}

export function parseMeshdMemberRecord(rawEntry: unknown): Omit<MeshdMemberSummary, "nodes"> | undefined {
  const wrapper = isObject(rawEntry) ? rawEntry : undefined;
  const entry = getRecordWrite(rawEntry);
  if (!entry || !wrapper) return undefined;
  const descriptor = isObject(entry.descriptor) ? entry.descriptor : {};
  const protocolPath = getString(descriptor.protocolPath);
  if (protocolPath && protocolPath !== "network/member") return undefined;
  const recordId = getRecordId(entry, wrapper, descriptor);
  const did = getRecipient(entry, wrapper, descriptor);
  if (!recordId || !did) return undefined;

  let payload: unknown;
  try {
    payload = decodeRecordPayload(entry, wrapper);
  } catch {
    payload = undefined;
  }
  const data = isObject(payload) ? payload : {};
  return {
    recordId,
    did,
    label: getString(data.label),
    addedAt: getString(data.addedAt),
    createdAt: getString(descriptor.dateCreated) ?? getString(wrapper.dateCreated)
  };
}

export function parseMeshdNodeRecord(rawEntry: unknown, memberRecordId?: string): MeshdNodeSummary | undefined {
  const wrapper = isObject(rawEntry) ? rawEntry : undefined;
  const entry = getRecordWrite(rawEntry);
  if (!entry || !wrapper) return undefined;
  const descriptor = isObject(entry.descriptor) ? entry.descriptor : {};
  const protocolPath = getString(descriptor.protocolPath);
  if (protocolPath && protocolPath !== "network/member/node" && protocolPath !== "network/node") return undefined;
  const recordId = getRecordId(entry, wrapper, descriptor);
  const did = getRecipient(entry, wrapper, descriptor);
  if (!recordId || !did) return undefined;

  let payload: unknown;
  try {
    payload = decodeRecordPayload(entry, wrapper);
  } catch {
    payload = undefined;
  }
  const data = isObject(payload) ? payload : {};
  return {
    recordId,
    did,
    meshIP: getString(data.meshIP),
    allowedIPs: getStringArray(data.allowedIPs),
    label: getString(data.label),
    ownerDID: getString(data.ownerDID) ?? getString(data.memberDID),
    memberDID: getString(data.memberDID) ?? getString(data.ownerDID),
    delegateDID: getString(data.delegateDID),
    memberRecordId,
    addedAt: getString(data.addedAt),
    expiresAt: getString(data.expiresAt),
    sourceDWN: getString(data.sourceDWN),
    createdAt: getString(descriptor.dateCreated) ?? getString(wrapper.dateCreated)
  };
}

// parseRoleKeys extracts a node request's `roleKeys` map, keeping only entries whose
// value is a well-formed OKP/X25519 public JWK (kty, crv, x). The SDK re-validates the
// key it is handed; this just keeps malformed payloads out of the summary. Returns
// undefined when nothing usable is present.
function parseRoleKeys(raw: unknown): Record<string, RolePublicKeyJwk> | undefined {
  if (!isObject(raw)) return undefined;
  const keys: Record<string, RolePublicKeyJwk> = {};
  for (const [rolePath, value] of Object.entries(raw)) {
    if (!isObject(value)) continue;
    const kty = getString(value.kty);
    const crv = getString(value.crv);
    const x = getString(value.x);
    if (kty !== "OKP" || crv !== "X25519" || !x) continue;
    const kid = getString(value.kid);
    keys[rolePath] = { kty, crv, x, ...(kid ? { kid } : {}) };
  }
  return Object.keys(keys).length > 0 ? keys : undefined;
}

export function parseMeshdNodeRequestRecord(rawEntry: unknown): MeshdNodeRequestSummary | undefined {
  const wrapper = isObject(rawEntry) ? rawEntry : undefined;
  const entry = getRecordWrite(rawEntry);
  if (!entry || !wrapper) return undefined;
  const descriptor = isObject(entry.descriptor) ? entry.descriptor : {};
  const protocolPath = getString(descriptor.protocolPath);
  if (protocolPath && protocolPath !== "network/nodeRequest" && protocolPath !== "nodeRequest") return undefined;
  const recordId = getRecordId(entry, wrapper, descriptor);
  if (!recordId) return undefined;

  let payload: unknown;
  try {
    payload = decodeRecordPayload(entry, wrapper);
  } catch {
    return undefined;
  }
  if (!isObject(payload)) return undefined;
  const nodeDID = getString(payload.nodeDID);
  if (!nodeDID) return undefined;
  return {
    recordId,
    protocolPath,
    nodeDID,
    ownerDID: getString(payload.ownerDID) ?? getString(payload.memberDID),
    memberDID: getString(payload.memberDID) ?? getString(payload.ownerDID),
    delegateDID: getString(payload.delegateDID),
    requestedBy: getString(payload.requestedBy),
    nodeProof: getString(payload.nodeProof),
    requestKind: getString(payload.requestKind),
    networkRecordId: getString(payload.networkRecordId),
    networkName: getString(payload.networkName),
    label: getString(payload.label),
    sourceDWN: getString(payload.sourceDWN),
    preAuthKeyId: getString(payload.preAuthKeyId),
    preAuthProof: getString(payload.preAuthProof),
    requestedAt: getString(payload.requestedAt),
    expiresAt: getString(payload.expiresAt),
    createdAt: getString(descriptor.dateCreated) ?? getString(wrapper.dateCreated),
    roleKeys: parseRoleKeys(payload.roleKeys)
  };
}

export function parseMeshdPreAuthKeyRecord(rawEntry: unknown): MeshdPreAuthKeySummary | undefined {
  const wrapper = isObject(rawEntry) ? rawEntry : undefined;
  const entry = getRecordWrite(rawEntry);
  if (!entry || !wrapper) return undefined;
  const descriptor = isObject(entry.descriptor) ? entry.descriptor : {};
  const protocolPath = getString(descriptor.protocolPath);
  if (protocolPath && protocolPath !== "network/preAuthKey") return undefined;
  const recordId = getRecordId(entry, wrapper, descriptor);
  if (!recordId) return undefined;

  let payload: unknown;
  try {
    payload = decodeRecordPayload(entry, wrapper);
  } catch {
    return undefined;
  }
  if (!isObject(payload)) return undefined;
  const key = getString(payload.key);
  if (!key) return undefined;
  return {
    recordId,
    key,
    createdAt: getString(payload.createdAt),
    expiresAt: getString(payload.expiresAt),
    reusable: typeof payload.reusable === "boolean" ? payload.reusable : undefined,
    ephemeral: typeof payload.ephemeral === "boolean" ? payload.ephemeral : undefined,
    label: getString(payload.label),
    usedBy: Array.isArray(payload.usedBy)
      ? payload.usedBy.filter((item): item is string => typeof item === "string" && item.trim() !== "")
      : [],
    recordCreatedAt: getString(descriptor.dateCreated) ?? getString(wrapper.dateCreated)
  };
}

export async function fetchMeshdNetworks(session: MeshdAdminSession): Promise<MeshdNetworkSummary[]> {
  const entries = await queryRecords(session, MESHD_PROTOCOL_URI, "network");
  return entries
    .map(parseMeshdNetworkRecord)
    .filter((network): network is MeshdNetworkSummary => Boolean(network))
    .sort((a, b) => (b.createdAt ?? "").localeCompare(a.createdAt ?? ""));
}

export async function fetchMeshdNetworkTopology(
  session: MeshdAdminSession,
  network: MeshdNetworkSummary
): Promise<MeshdNetworkTopology> {
  const memberEntries = await queryRecords(session, MESHD_PROTOCOL_URI, "network/member", network.recordId);
  const memberRecords = memberEntries
    .map(parseMeshdMemberRecord)
    .filter((member): member is Omit<MeshdMemberSummary, "nodes"> => Boolean(member));

  const members = await Promise.all(memberRecords.map(async (member) => {
    const nodeEntries = await queryRecords(
      session,
      MESHD_PROTOCOL_URI,
      "network/member/node",
      `${network.recordId}/${member.recordId}`
    );
    return {
      ...member,
      nodes: nodeEntries
        .map((entry) => parseMeshdNodeRecord(entry, member.recordId))
        .filter((node): node is MeshdNodeSummary => Boolean(node))
    };
  }));

  const legacyNodeEntries = await queryRecords(session, MESHD_PROTOCOL_URI, "network/node", network.recordId);
  const legacyNodes = legacyNodeEntries
    .map((entry) => parseMeshdNodeRecord(entry))
    .filter((node): node is MeshdNodeSummary => Boolean(node));

  const pendingInviteEntries = await queryRecords(session, MESHD_PROTOCOL_URI, "network/nodeRequest", network.recordId);
  const pendingInviteRequests = pendingInviteEntries
    .map(parseMeshdNodeRequestRecord)
    .filter((request): request is MeshdNodeRequestSummary => Boolean(request));

  const ownerRequestEntries = await queryRecords(session, MESHD_PROTOCOL_URI, "nodeRequest");
  const ownerPendingRequests = ownerRequestEntries
    .map(parseMeshdNodeRequestRecord)
    .filter((request): request is MeshdNodeRequestSummary => {
      if (!request) return false;
      return !request.networkRecordId || request.networkRecordId === network.recordId;
    });

  const preAuthEntries = await queryRecords(session, MESHD_PROTOCOL_URI, "network/preAuthKey", network.recordId);
  const preAuthKeys = preAuthEntries
    .map(parseMeshdPreAuthKeyRecord)
    .filter((key): key is MeshdPreAuthKeySummary => Boolean(key));

  return {
    network,
    members,
    legacyNodes,
    pendingRequests: [...ownerPendingRequests, ...pendingInviteRequests],
    preAuthKeys
  };
}

async function ownerDefaultDwnEndpoint(session: MeshdAdminSession): Promise<string> {
  let endpoints: string[] | undefined;
  try {
    endpoints = await session.agent.dwn?.getDwnEndpointUrlsForTarget?.(session.ownerDid);
  } catch {
    endpoints = undefined;
  }
  const endpoint = endpoints?.find((candidate) => candidate.trim() !== "") ?? DEFAULT_DWN_ENDPOINT;
  if (!endpoint) {
    throw new Error("No DWN endpoint is configured for this owner.");
  }
  return endpoint.trim().replace(/\/+$/, "");
}

export async function createMeshdNetwork(
  session: MeshdAdminSession,
  options: { name: string; meshCIDR?: string }
): Promise<MeshdNetworkSummary> {
  const name = options.name.trim();
  if (!name) {
    throw new Error("Network name is required.");
  }
  const meshCIDR = normalizeMeshCIDR(options.meshCIDR?.trim() || "10.200.0.0/16");
  const anchorEndpoint = await ownerDefaultDwnEndpoint(session);
  const record = await writeRecord(
    session,
    MESHD_PROTOCOL_URI,
    {
      protocol: MESHD_PROTOCOL_URI,
      protocolPath: "network",
      schema: "https://enbox.id/schemas/wireguard-mesh/network",
      dataFormat: "application/json"
    },
    { name, meshCIDR, anchorEndpoint }
  );
  return {
    recordId: record.recordId,
    name,
    meshCIDR,
    anchorEndpoint,
    createdAt: record.dateCreated
  };
}

function encodeMeshdInviteURL(
  endpoint: string,
  ownerDid: string,
  network: MeshdNetworkSummary,
  tokenId: string,
  secret: string,
  expiresAt?: string
): string {
  return `meshd://invite/${base64UrlEncodeJson({
    version: 1,
    endpoint,
    anchorDid: ownerDid,
    networkId: network.recordId,
    networkName: network.name,
    tokenId,
    secret,
    ...(expiresAt ? { expiresAt } : {})
  })}`;
}

async function networkAnchorEndpoint(
  session: MeshdAdminSession,
  network: MeshdNetworkSummary
): Promise<string> {
  if (network.anchorEndpoint) {
    return network.anchorEndpoint;
  }
  return ownerDefaultDwnEndpoint(session);
}

export async function buildMeshdInviteURL(
  session: MeshdAdminSession,
  network: MeshdNetworkSummary,
  key: MeshdPreAuthKeySummary
) {
  const endpoint = await networkAnchorEndpoint(session, network);
  return encodeMeshdInviteURL(endpoint, session.ownerDid, network, key.recordId, key.key, key.expiresAt);
}

export async function createMeshdInvite(
  session: MeshdAdminSession,
  network: MeshdNetworkSummary,
  options: { label?: string; expiresAt?: string; reusable?: boolean; ephemeral?: boolean } = {}
): Promise<CreateMeshdInviteResult> {
  const secret = generateInviteSecret();
  const expiresAt = options.expiresAt?.trim();
  const endpoint = await networkAnchorEndpoint(session, network);
  const record = await writeRecord(
    session,
    MESHD_PROTOCOL_URI,
    {
      protocol: MESHD_PROTOCOL_URI,
      protocolPath: "network/preAuthKey",
      schema: "https://enbox.id/schemas/wireguard-mesh/pre-auth-key",
      dataFormat: "application/json",
      parentContextId: network.recordId
    },
    {
      key: secret,
      createdAt: new Date().toISOString(),
      ...(expiresAt ? { expiresAt } : {}),
      ...(options.reusable !== undefined ? { reusable: options.reusable } : {}),
      ...(options.ephemeral !== undefined ? { ephemeral: options.ephemeral } : {}),
      ...(options.label ? { label: options.label } : {}),
      usedBy: []
    },
    true
  );
  return {
    url: encodeMeshdInviteURL(endpoint, session.ownerDid, network, record.recordId, secret, expiresAt),
    tokenId: record.recordId,
    secret,
    ...(expiresAt ? { expiresAt } : {}),
    ...(options.label?.trim() ? { label: options.label.trim() } : {})
  };
}

export async function revokeMeshdInvite(
  session: MeshdAdminSession,
  key: Pick<MeshdPreAuthKeySummary, "recordId">
): Promise<void> {
  await deleteRecord(session, MESHD_PROTOCOL_URI, key.recordId, false);
}

// Rewrites an invite's preAuthKey record with an updated description (stored in
// the record's `label` field), preserving the secret, expiry, reusability, and
// usage list. Invites are referenced by ID; the description is an optional
// operator note added after creation.
export async function updateMeshdInviteDescription(
  session: MeshdAdminSession,
  network: MeshdNetworkSummary,
  invite: MeshdPreAuthKeySummary,
  description?: string
): Promise<MeshdPreAuthKeySummary> {
  const nextDescription = description?.trim();
  await writeRecord(
    session,
    MESHD_PROTOCOL_URI,
    {
      protocol: MESHD_PROTOCOL_URI,
      protocolPath: "network/preAuthKey",
      schema: "https://enbox.id/schemas/wireguard-mesh/pre-auth-key",
      dataFormat: "application/json",
      parentContextId: network.recordId,
      recordId: invite.recordId,
      ...(invite.recordCreatedAt ? { dateCreated: invite.recordCreatedAt } : {})
    },
    {
      key: invite.key,
      ...(invite.createdAt ? { createdAt: invite.createdAt } : {}),
      ...(invite.expiresAt ? { expiresAt: invite.expiresAt } : {}),
      ...(invite.reusable !== undefined ? { reusable: invite.reusable } : {}),
      ...(invite.ephemeral !== undefined ? { ephemeral: invite.ephemeral } : {}),
      ...(nextDescription ? { label: nextDescription } : {}),
      usedBy: invite.usedBy ?? []
    },
    true
  );

  const next = { ...invite };
  if (nextDescription) {
    next.label = nextDescription;
  } else {
    delete next.label;
  }
  return next;
}

function nodeJoinProofMessage(
  networkId: string,
  nodeDID: string,
  ownerDID = nodeDID,
  preAuthKeyId = ""
): Uint8Array {
  return new TextEncoder().encode(
    "meshd node join v1\n"
    + `network=${networkId}\n`
    + `node=${nodeDID}\n`
    + `member=${ownerDID || nodeDID}\n`
    + `preauth=${preAuthKeyId}\n`
  );
}

function ownerNodeRequestProofMessage(
  ownerDID: string,
  nodeDID: string,
  sourceDWN = "",
  requestedAt = ""
): Uint8Array {
  return new TextEncoder().encode(
    "meshd owner node request v1\n"
    + `owner=${ownerDID}\n`
    + `node=${nodeDID}\n`
    + `sourceDWN=${sourceDWN}\n`
    + `requestedAt=${requestedAt}\n`
  );
}

function nodeOwnerDID(request: Pick<MeshdNodeRequestSummary, "nodeDID" | "ownerDID" | "memberDID">): string {
  return request.ownerDID || request.memberDID || request.nodeDID;
}

async function verifyNodeSignature(nodeDid: string, proof: string, data: Uint8Array): Promise<boolean> {
  if (!nodeDid.startsWith("did:jwk:")) {
    return false;
  }
  const resolved = await DidJwk.resolve(nodeDid);
  const key = resolved.didDocument?.verificationMethod?.[0]?.publicKeyJwk;
  if (!key) {
    return false;
  }
  return Ed25519.verify({
    key,
    data,
    signature: base64UrlDecodeBytes(proof)
  });
}

async function verifyNodeJoinProof(request: MeshdNodeRequestSummary, networkId: string): Promise<boolean> {
  if (!request.nodeProof) {
    return false;
  }
  return verifyNodeSignature(
    request.nodeDID,
    request.nodeProof,
    nodeJoinProofMessage(networkId, request.nodeDID, nodeOwnerDID(request), request.preAuthKeyId || "")
  );
}

async function verifyOwnerNodeRequestProof(request: MeshdNodeRequestSummary): Promise<boolean> {
  if (!request.nodeProof || !request.ownerDID || !request.requestedAt) {
    return false;
  }
  return verifyNodeSignature(
    request.nodeDID,
    request.nodeProof,
    ownerNodeRequestProofMessage(request.ownerDID, request.nodeDID, request.sourceDWN || "", request.requestedAt)
  );
}

function isOwnerNodeRequest(request: MeshdNodeRequestSummary): boolean {
  return request.protocolPath === "nodeRequest" || request.requestKind === "owner-node";
}

async function inviteProof(secret: string, networkId: string, nodeDID: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const signature = new Uint8Array(await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(`${networkId}\n${nodeDID}`)
  ));
  return `hmac-sha256:${base64UrlEncodeBytes(signature)}`;
}

function constantTimeEqual(a: string, b: string): boolean {
  let mismatch = a.length ^ b.length;
  const maxLength = Math.max(a.length, b.length);
  for (let i = 0; i < maxLength; i++) {
    mismatch |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  }
  return mismatch === 0;
}

function preAuthKeyAllows(key: MeshdPreAuthKeySummary, nodeDID: string, now: Date = new Date()): boolean {
  if (!key.key || !nodeDID) return false;
  if (key.expiresAt) {
    const expiresMs = new Date(key.expiresAt).getTime();
    if (!Number.isFinite(expiresMs) || now.getTime() > expiresMs) {
      return false;
    }
  }
  if (key.usedBy.includes(nodeDID)) {
    return true;
  }
  return Boolean(key.reusable) || key.usedBy.length === 0;
}

async function verifyInviteProof(
  key: MeshdPreAuthKeySummary,
  networkId: string,
  nodeDID: string,
  proof?: string
): Promise<boolean> {
  if (!proof || !key.key) return false;
  const expected = await inviteProof(key.key, networkId, nodeDID);
  return constantTimeEqual(expected, proof);
}

async function readPreAuthKey(
  session: MeshdAdminSession,
  network: MeshdNetworkSummary,
  request: MeshdNodeRequestSummary
): Promise<MeshdPreAuthKeySummary> {
  if (!request.preAuthKeyId || !request.preAuthProof) {
    throw new Error("The pending invite request is missing preauth data.");
  }
  const entries = await queryRecords(
    session,
    MESHD_PROTOCOL_URI,
    "network/preAuthKey",
    network.recordId,
    { recordId: request.preAuthKeyId }
  );
  const key = entries
    .map(parseMeshdPreAuthKeyRecord)
    .find((entry) => entry?.recordId === request.preAuthKeyId);
  if (!key) {
    throw new Error("The preauth key for this request was not found.");
  }
  if (!preAuthKeyAllows(key, request.nodeDID)) {
    throw new Error("The preauth key for this request is expired or already used.");
  }
  if (!await verifyInviteProof(key, network.recordId, request.nodeDID, request.preAuthProof)) {
    throw new Error("The pending request preauth proof could not be verified.");
  }
  return key;
}

async function markPreAuthKeyUsed(
  session: MeshdAdminSession,
  network: MeshdNetworkSummary,
  key: MeshdPreAuthKeySummary,
  nodeDID: string
): Promise<void> {
  if (key.usedBy.includes(nodeDID)) {
    return;
  }
  // A single-use invite is spent the moment it is consumed, so delete the
  // record instead of leaving a dead "1 used" entry cluttering the admin list.
  // Reusable invites persist and just record the new consumer.
  if (!key.reusable) {
    await deleteRecord(session, MESHD_PROTOCOL_URI, key.recordId, false);
    return;
  }
  await writeRecord(
    session,
    MESHD_PROTOCOL_URI,
    {
      protocol: MESHD_PROTOCOL_URI,
      protocolPath: "network/preAuthKey",
      schema: "https://enbox.id/schemas/wireguard-mesh/pre-auth-key",
      dataFormat: "application/json",
      parentContextId: network.recordId,
      recordId: key.recordId,
      ...(key.recordCreatedAt ? { dateCreated: key.recordCreatedAt } : {})
    },
    {
      key: key.key,
      ...(key.createdAt ? { createdAt: key.createdAt } : {}),
      ...(key.expiresAt ? { expiresAt: key.expiresAt } : {}),
      reusable: true,
      ...(key.ephemeral !== undefined ? { ephemeral: key.ephemeral } : {}),
      ...(key.label ? { label: key.label } : {}),
      usedBy: [...key.usedBy, nodeDID]
    },
    true
  );
}

function ipv4ToInt(ip: string): number {
  const parts = ip.split(".").map((part) => Number.parseInt(part, 10));
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) {
    throw new Error(`Invalid IPv4 address: ${ip}`);
  }
  return (
    ((parts[0] << 24) >>> 0)
    + (parts[1] << 16)
    + (parts[2] << 8)
    + parts[3]
  ) >>> 0;
}

function intToIpv4(value: number): string {
  return [
    (value >>> 24) & 0xff,
    (value >>> 16) & 0xff,
    (value >>> 8) & 0xff,
    value & 0xff
  ].join(".");
}

function normalizeMeshCIDR(cidr: string): string {
  const parts = cidr.split("/");
  if (parts.length !== 2 || !parts[0] || !/^\d+$/.test(parts[1])) {
    throw new Error(`Invalid mesh CIDR: ${cidr}`);
  }

  const address = ipv4ToInt(parts[0]);
  const prefix = Number.parseInt(parts[1], 10);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 30) {
    throw new Error(`Mesh CIDR ${cidr} must be an IPv4 CIDR with at least 2 host bits.`);
  }

  const hostBits = 32 - prefix;
  const mask = prefix === 0 ? 0 : (0xffffffff << hostBits) >>> 0;
  const baseInt = (address & mask) >>> 0;
  return `${intToIpv4(baseInt)}/${prefix}`;
}

async function allocateMeshIp(cidr: string, nodeDID: string): Promise<string> {
  const [ip, prefixText] = cidr.split("/");
  const prefix = Number.parseInt(prefixText, 10);
  if (!ip || !Number.isInteger(prefix) || prefix < 0 || prefix > 30) {
    throw new Error(`Invalid mesh CIDR: ${cidr}`);
  }
  const hostBits = 32 - prefix;
  if (hostBits < 2) {
    throw new Error(`Mesh CIDR ${cidr} has too few host bits.`);
  }
  const mask = prefix === 0 ? 0 : (0xffffffff << hostBits) >>> 0;
  const baseInt = (ipv4ToInt(ip) & mask) >>> 0;
  const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(nodeDID)));
  const hashPrefix = (
    ((hash[0] << 24) >>> 0)
    + (hash[1] << 16)
    + (hash[2] << 8)
    + hash[3]
  ) >>> 0;
  const maxHosts = (2 ** hostBits) - 3;
  return intToIpv4((baseInt + (hashPrefix % maxHosts) + 2) >>> 0);
}

async function ensureMemberRecord(
  session: MeshdAdminSession,
  network: MeshdNetworkSummary,
  nodeOwnerDID: string,
  recipientRolePublicKey: RolePublicKeyJwk,
  label?: string
): Promise<AuthoredRecord> {
  const existingEntries = await queryRecords(
    session,
    MESHD_PROTOCOL_URI,
    "network/member",
    network.recordId,
    { recipient: nodeOwnerDID }
  );
  const existing = existingEntries
    .map(parseMeshdMemberRecord)
    .find((member) => member?.did === nodeOwnerDID);
  if (existing) {
    // The network/member role record — and its network/member `$encryption/delivery`
    // to this recipient — already exists from a prior approval. For a self-owned node
    // the member DID is the node DID, so that delivery already reached the node; nothing
    // to re-provision. (A distinct-human-member layer delivering to a NEW node under an
    // existing member is a separate case — see #192.)
    return {
      recordId: existing.recordId,
      dateCreated: existing.createdAt
    };
  }

  // Peer node records grant can:read to network/member (and network/node); a
  // member-invited did:jwk node authorizes as network/member, so it must recover the
  // network/member audience to decrypt its peers. Writing the network/member role
  // record with the node's supplied network/member role-path key mints that audience
  // and delivers it to the node — the reading-role audience, distinct from the
  // network/member/node role the node merely holds (issue #192).
  const memberRecord = await writeRecord(
    session,
    MESHD_PROTOCOL_URI,
    {
      protocol: MESHD_PROTOCOL_URI,
      protocolPath: "network/member",
      schema: "https://enbox.id/schemas/wireguard-mesh/member",
      dataFormat: "application/json",
      recipient: nodeOwnerDID,
      parentContextId: network.recordId
    },
    {
      addedAt: new Date().toISOString(),
      ...(label ? { label } : {})
    },
    true,
    recipientRolePublicKey
  );

  // Best-effort delivery is reported, not thrown (like the node record). Enforce it and
  // roll back with the dashboard's own delete grant so the operator can retry cleanly —
  // a member without its reading-role audience delivered can never see its peers.
  if (!memberRecord.audienceKeyDelivery?.delivered) {
    const reason = memberRecord.audienceKeyDelivery?.reason ?? "no delivery outcome was reported";
    await deleteRecord(session, MESHD_PROTOCOL_URI, memberRecord.recordId, false);
    throw new Error(
      `Approved node ${nodeOwnerDID} but could not deliver its network/member reading-role ` +
      `audience key (${reason}); the member record was rolled back so you can retry. The node ` +
      "cannot decrypt its peers until this delivery succeeds."
    );
  }

  return memberRecord;
}

export async function approveMeshdNodeRequest(
  session: MeshdAdminSession,
  network: MeshdNetworkSummary,
  request: MeshdNodeRequestSummary,
  options: { expiresAt?: string } = {}
): Promise<ApproveMeshdNodeRequestResult> {
  const ownerScopedRequest = isOwnerNodeRequest(request);
  if (ownerScopedRequest) {
    if (!await verifyOwnerNodeRequestProof(request)) {
      throw new Error("The pending owner request node proof could not be verified.");
    }
  } else if (!await verifyNodeJoinProof(request, network.recordId)) {
    throw new Error("The pending invite request node proof could not be verified.");
  }

  const preAuthKey = ownerScopedRequest ? undefined : await readPreAuthKey(session, network, request);
  const requestOwnerDID = nodeOwnerDID(request);

  // The node is named by what it reports about itself — its hostname, sent as
  // the request label. An invite's description never names a machine: invites
  // are operator annotations referenced by ID, and the joined device's name is
  // editable on the node card after it connects.
  const effectiveLabel = request.label?.trim() || undefined;

  // The node authorizes as network/member and its peer records are encrypted to the
  // network/member audience, so that reading-role audience must be delivered to it. A
  // did:jwk node has no DWN endpoint to resolve its role-path key from, so it supplies
  // the network/member key in its join request (#192); refuse to approve without it —
  // the node would silently never decrypt its peers.
  const MEMBER_ROLE_PATH = "network/member";
  const memberRolePublicKey = request.roleKeys?.[MEMBER_ROLE_PATH];
  if (!memberRolePublicKey) {
    throw new Error(
      `Node ${request.nodeDID} did not include its ${MEMBER_ROLE_PATH} role-audience key, so the ` +
      "reading-role audience its peers are encrypted to cannot be delivered and it would never " +
      "decrypt its peers. Upgrade the meshd node to a build that publishes the network/member " +
      "roleKey in its join request (#192)."
    );
  }
  const member = await ensureMemberRecord(session, network, requestOwnerDID, memberRolePublicKey, effectiveLabel);
  const meshIP = await allocateMeshIp(network.meshCIDR, request.nodeDID);
  // One expiry model: the invite defines the access window and the joined node
  // inherits it, so an operator sets the expiry once (when creating the invite)
  // and never re-picks it at approval time. An explicit options.expiresAt still
  // overrides for tooling that wants to; the fallback covers owner-scoped joins
  // that carry no invite (they may name their own expiry on the request).
  const expiresAt = Object.prototype.hasOwnProperty.call(options, "expiresAt")
    ? options.expiresAt?.trim()
    : preAuthKey?.expiresAt ?? request.expiresAt;

  // Sealed-model key delivery: the node record below is a role record with a
  // recipient, so the agent mints the sealed `$encryption/audience` key during the
  // encrypted write and provisions the `$encryption/delivery` record the joining
  // meshd daemon decrypts its records with. A did:jwk node has no DWN endpoint for
  // the owner to resolve its role-path key from, so it supplies that key in its join
  // request (#187); we hand it to the agent to wrap the delivery. Refuse to approve a
  // node that did not supply it — approving would create a node that silently can
  // never decrypt its peers.
  const NODE_ROLE_PATH = "network/member/node";
  const recipientRolePublicKey = request.roleKeys?.[NODE_ROLE_PATH];
  if (!recipientRolePublicKey) {
    throw new Error(
      `Node ${request.nodeDID} did not include its ${NODE_ROLE_PATH} role-audience key, so its ` +
      "encryption keys cannot be delivered and it would never decrypt its peers. Upgrade the " +
      "meshd node to a build that publishes roleKeys in its join request (#187)."
    );
  }

  const nodeRecord = await writeRecord(
    session,
    MESHD_PROTOCOL_URI,
    {
      protocol: MESHD_PROTOCOL_URI,
      protocolPath: NODE_ROLE_PATH,
      schema: "https://enbox.id/schemas/wireguard-mesh/node",
      dataFormat: "application/json",
      recipient: request.nodeDID,
      parentContextId: `${network.recordId}/${member.recordId}`
    },
    {
      meshIP,
      addedAt: new Date().toISOString(),
      ...(effectiveLabel ? { label: effectiveLabel } : {}),
      ownerDID: requestOwnerDID,
      memberDID: requestOwnerDID,
      ...(request.delegateDID ? { delegateDID: request.delegateDID } : {}),
      ...(expiresAt ? { expiresAt } : {})
    },
    true,
    recipientRolePublicKey
  );

  // Delivery is best-effort in the agent: a failure is reported on
  // `audienceKeyDelivery`, not thrown. Enforce it here — the node is useless without
  // its key. Roll back the just-written role record with the dashboard's own delete
  // grant (which authorizes the delete the agent's write-scoped grant cannot) so the
  // operator can retry cleanly instead of being blocked by a duplicate-role grant.
  if (!nodeRecord.audienceKeyDelivery?.delivered) {
    const reason = nodeRecord.audienceKeyDelivery?.reason ?? "no delivery outcome was reported";
    await deleteRecord(session, MESHD_PROTOCOL_URI, nodeRecord.recordId, false);
    throw new Error(
      `Approved node ${request.nodeDID} but could not deliver its role-audience key (${reason}); ` +
      "the node record was rolled back so you can retry. The node cannot decrypt its peers until " +
      "delivery succeeds."
    );
  }

  if (preAuthKey) {
    await markPreAuthKeyUsed(session, network, preAuthKey, request.nodeDID);
  }

  if (ownerScopedRequest) {
    await writeRecord(
      session,
      MESHD_PROTOCOL_URI,
      {
        protocol: MESHD_PROTOCOL_URI,
        protocolPath: "nodeApproval",
        schema: "https://enbox.id/schemas/wireguard-mesh/node-approval",
        dataFormat: "application/json",
        recipient: request.nodeDID
      },
      {
        ownerDID: session.ownerDid,
        nodeDID: request.nodeDID,
        networkRecordId: network.recordId,
        networkName: network.name,
        meshCIDR: network.meshCIDR,
        meshIP,
        ...(network.anchorEndpoint ? { anchorEndpoint: network.anchorEndpoint } : {}),
        memberRecordId: member.recordId,
        ...(member.dateCreated ? { memberDateCreated: member.dateCreated } : {}),
        nodeRecordId: nodeRecord.recordId,
        ...(nodeRecord.dateCreated ? { nodeDateCreated: nodeRecord.dateCreated } : {}),
        ...(effectiveLabel ? { label: effectiveLabel } : {}),
        ...(expiresAt ? { expiresAt } : {}),
        approvedAt: new Date().toISOString(),
        requestRecordId: request.recordId
      }
    );
  }

  await deleteRecord(session, MESHD_PROTOCOL_URI, request.recordId, false);
  return {
    memberRecordId: member.recordId,
    nodeRecordId: nodeRecord.recordId,
    meshIP
  };
}

export async function rejectMeshdNodeRequest(
  session: MeshdAdminSession,
  request: MeshdNodeRequestSummary
): Promise<void> {
  await deleteRecord(session, MESHD_PROTOCOL_URI, request.recordId, false);
}

export async function updateMeshdNodeExpiry(
  session: MeshdAdminSession,
  network: MeshdNetworkSummary,
  node: MeshdNodeSummary,
  expiresAt?: string
): Promise<MeshdNodeSummary> {
  const nextExpiresAt = expiresAt?.trim();
  const nextNode = await writeUpdatedMeshdNode(session, network, node, { expiresAt: nextExpiresAt });
  await writeNodeApprovalRefresh(session, network, nextNode);
  return nextNode;
}

export async function updateMeshdNodeLabel(
  session: MeshdAdminSession,
  network: MeshdNetworkSummary,
  node: MeshdNodeSummary,
  label?: string
): Promise<MeshdNodeSummary> {
  const nextLabel = label?.trim();
  return writeUpdatedMeshdNode(session, network, node, { label: nextLabel });
}

async function writeUpdatedMeshdNode(
  session: MeshdAdminSession,
  network: MeshdNetworkSummary,
  node: MeshdNodeSummary,
  updates: { expiresAt?: string; label?: string }
): Promise<MeshdNodeSummary> {
  if (!node.meshIP) {
    throw new Error("Cannot update a node without a mesh IP.");
  }

  const hasExpiresAtUpdate = Object.prototype.hasOwnProperty.call(updates, "expiresAt");
  const hasLabelUpdate = Object.prototype.hasOwnProperty.call(updates, "label");
  const nextExpiresAt = hasExpiresAtUpdate ? updates.expiresAt?.trim() : node.expiresAt?.trim();
  const nextLabel = hasLabelUpdate ? updates.label?.trim() : node.label?.trim();

  const protocolPath = node.memberRecordId ? "network/member/node" : "network/node";
  const parentContextId = node.memberRecordId ? `${network.recordId}/${node.memberRecordId}` : network.recordId;
  await writeRecord(
    session,
    MESHD_PROTOCOL_URI,
    {
      protocol: MESHD_PROTOCOL_URI,
      protocolPath,
      schema: "https://enbox.id/schemas/wireguard-mesh/node",
      dataFormat: "application/json",
      recipient: node.did,
      parentContextId,
      recordId: node.recordId,
      ...(node.createdAt ? { dateCreated: node.createdAt } : {})
    },
    {
      meshIP: node.meshIP,
      ...(node.allowedIPs?.length ? { allowedIPs: node.allowedIPs } : {}),
      addedAt: node.addedAt || new Date().toISOString(),
      ...(nextExpiresAt ? { expiresAt: nextExpiresAt } : {}),
      ...(nextLabel ? { label: nextLabel } : {}),
      ...(node.ownerDID ? { ownerDID: node.ownerDID } : {}),
      ...(node.memberDID ? { memberDID: node.memberDID } : {}),
      ...(node.delegateDID ? { delegateDID: node.delegateDID } : {}),
      ...(node.sourceDWN ? { sourceDWN: node.sourceDWN } : {})
    },
    true
  );

  const nextNode = { ...node };
  if (hasExpiresAtUpdate) {
    if (nextExpiresAt) {
      nextNode.expiresAt = nextExpiresAt;
    } else {
      delete nextNode.expiresAt;
    }
  }
  if (hasLabelUpdate) {
    if (nextLabel) {
      nextNode.label = nextLabel;
    } else {
      delete nextNode.label;
    }
  }
  return nextNode;
}

async function writeNodeApprovalRefresh(
  session: MeshdAdminSession,
  network: MeshdNetworkSummary,
  node: MeshdNodeSummary
): Promise<void> {
  if (!node.meshIP) {
    throw new Error("Cannot refresh node approval without a mesh IP.");
  }

  await writeRecord(
    session,
    MESHD_PROTOCOL_URI,
    {
      protocol: MESHD_PROTOCOL_URI,
      protocolPath: "nodeApproval",
      schema: "https://enbox.id/schemas/wireguard-mesh/node-approval",
      dataFormat: "application/json",
      recipient: node.did
    },
    {
      ownerDID: session.ownerDid,
      nodeDID: node.did,
      networkRecordId: network.recordId,
      networkName: network.name,
      meshCIDR: network.meshCIDR,
      meshIP: node.meshIP,
      ...(network.anchorEndpoint ? { anchorEndpoint: network.anchorEndpoint } : {}),
      ...(node.memberRecordId ? { memberRecordId: node.memberRecordId } : {}),
      nodeRecordId: node.recordId,
      ...(node.createdAt ? { nodeDateCreated: node.createdAt } : {}),
      ...(node.label ? { label: node.label } : {}),
      ...(node.expiresAt ? { expiresAt: node.expiresAt } : {}),
      approvedAt: new Date().toISOString()
    }
  );
}

export async function removeMeshdNode(
  session: MeshdAdminSession,
  _network: MeshdNetworkSummary,
  node: MeshdNodeSummary
): Promise<void> {
  await deleteRecord(session, MESHD_PROTOCOL_URI, node.recordId, true);
}
