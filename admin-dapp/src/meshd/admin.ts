import {
  DwnInterface,
  EnboxConnectProtocol,
  writeContextKeyRecord as writeContextKeyRecordWithAgent
} from "@enbox/agent";
import type { DwnMessage } from "@enbox/agent";
import { Ed25519 } from "@enbox/crypto";
import { DidJwk } from "@enbox/dids";
import { Message } from "@enbox/dwn-sdk-js";

import {
  MESHD_KEY_DELIVERY_PROTOCOL_URI,
  MESHD_PROTOCOL_URI
} from "@/enbox/config";
import { MeshNodePermissionRequest } from "@/enbox/protocols";

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
  }>;
  sendDwnRequest?: (request: Record<string, unknown>) => Promise<{
    reply: {
      status: { code: number; detail?: string };
    };
  }>;
  dwn?: {
    getDwnEndpointUrlsForTarget?: (targetDid: string) => Promise<string[]>;
    getProtocolDefinition?: (tenantDid: string, protocolUri: string, granteeDid?: string) => Promise<unknown>;
    exportDelegateContextKeys?: (delegateDid: string) => unknown[];
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
  label?: string;
  ownerDID?: string;
  memberDID?: string;
  delegateDID?: string;
  memberRecordId?: string;
  addedAt?: string;
  expiresAt?: string;
  createdAt?: string;
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
  nodeKeyDelivery?: MeshdNodeKeyDelivery;
  preAuthKeyId?: string;
  preAuthProof?: string;
  requestedAt?: string;
  expiresAt?: string;
  createdAt?: string;
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

export type MeshdNodeKeyDelivery = {
  rootKeyId?: string;
  publicKeyJwk?: {
    kid?: string;
    kty?: string;
    crv?: string;
    x?: string;
    [key: string]: unknown;
  };
};

export type CreateMeshdInviteResult = {
  url: string;
  tokenId: string;
  secret: string;
  expiresAt?: string;
};

export type ApproveMeshdNodeRequestResult = {
  memberRecordId: string;
  nodeRecordId: string;
  meshIP: string;
  deliveredContextKey: boolean;
};

type AuthoredRecord = {
  recordId: string;
  dateCreated?: string;
};

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function getString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() !== "" ? value.trim() : undefined;
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

async function processDwnRequest(
  session: MeshdAdminSession,
  request: Record<string, unknown>,
  protocol?: string
) {
  const next: Record<string, any> = {
    ...request,
    messageParams: {
      ...(isObject(request.messageParams) ? request.messageParams : {})
    }
  };

  if (session.delegateDid && protocol) {
    const permission = await session.agent.permissions?.getPermissionForRequest?.({
      connectedDid: session.ownerDid,
      delegateDid: session.delegateDid,
      protocol,
      delegate: true,
      cached: true,
      messageType: next.messageType
    });
    if (!permission?.message) {
      throw new Error(`The wallet session did not grant ${protocol} access to this dashboard.`);
    }
    next.messageParams = {
      ...next.messageParams,
      delegatedGrant: permission.message
    };
    next.granteeDid = session.delegateDid;
  }

  return session.agent.processDwnRequest(next);
}

async function sendDwnMessage(
  session: MeshdAdminSession,
  messageType: unknown,
  messageCid: string
) {
  if (!session.agent.sendDwnRequest) {
    return;
  }
  const pushed = await session.agent.sendDwnRequest({
    author: session.ownerDid,
    target: session.ownerDid,
    messageType,
    messageCid
  });
  if (pushed.reply.status.code >= 300 && pushed.reply.status.code !== 409) {
    throw new Error(`Remote DWN send failed: ${pushed.reply.status.code} ${pushed.reply.status.detail ?? ""}`.trim());
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
  encryption?: true
): Promise<AuthoredRecord> {
  const data = new TextEncoder().encode(JSON.stringify(payload));
  const { reply, message, messageCid } = await processDwnRequest(
    session,
    {
      author: session.ownerDid,
      target: session.ownerDid,
      messageType: DwnInterface.RecordsWrite,
      messageParams,
      dataStream: new Blob([data], { type: "application/json" }),
      ...(encryption ? { encryption } : {})
    },
    protocol
  );

  if (reply.status.code >= 300 || !message || !messageCid) {
    throw new Error(`DWN write failed: ${reply.status.code} ${reply.status.detail ?? ""}`.trim());
  }

  await sendDwnMessage(session, DwnInterface.RecordsWrite, messageCid);
  return {
    recordId: recordIdFromMessage(message),
    dateCreated: message.descriptor?.dateCreated
  };
}

async function deleteRecord(
  session: MeshdAdminSession,
  protocol: string,
  recordId: string,
  prune: boolean
): Promise<void> {
  const { reply, messageCid } = await processDwnRequest(
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
  if (messageCid) {
    await sendDwnMessage(session, DwnInterface.RecordsDelete, messageCid);
  }
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
      }
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
    label: getString(data.label),
    ownerDID: getString(data.ownerDID) ?? getString(data.memberDID),
    memberDID: getString(data.memberDID) ?? getString(data.ownerDID),
    delegateDID: getString(data.delegateDID),
    memberRecordId,
    addedAt: getString(data.addedAt),
    expiresAt: getString(data.expiresAt),
    createdAt: getString(descriptor.dateCreated) ?? getString(wrapper.dateCreated)
  };
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
    nodeKeyDelivery: isObject(payload.nodeKeyDelivery) ? payload.nodeKeyDelivery as MeshdNodeKeyDelivery : undefined,
    preAuthKeyId: getString(payload.preAuthKeyId),
    preAuthProof: getString(payload.preAuthProof),
    requestedAt: getString(payload.requestedAt),
    expiresAt: getString(payload.expiresAt),
    createdAt: getString(descriptor.dateCreated) ?? getString(wrapper.dateCreated)
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
  const endpoints = await session.agent.dwn?.getDwnEndpointUrlsForTarget?.(session.ownerDid);
  const endpoint = endpoints?.find((candidate) => candidate.trim() !== "");
  if (!endpoint) {
    throw new Error("The owner identity does not publish a DWN endpoint.");
  }
  return endpoint;
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
    ...(expiresAt ? { expiresAt } : {})
  };
}

export async function revokeMeshdInvite(
  session: MeshdAdminSession,
  key: Pick<MeshdPreAuthKeySummary, "recordId">
): Promise<void> {
  await deleteRecord(session, MESHD_PROTOCOL_URI, key.recordId, false);
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
      ...(key.reusable !== undefined ? { reusable: key.reusable } : {}),
      ...(key.ephemeral !== undefined ? { ephemeral: key.ephemeral } : {}),
      ...(key.label ? { label: key.label } : {}),
      usedBy: [...key.usedBy, nodeDID]
    },
    true
  );
}

function validateNodeKeyDelivery(nodeDID: string, key?: MeshdNodeKeyDelivery): MeshdNodeKeyDelivery {
  if (!key) {
    throw new Error("The pending request is missing node key-delivery data. Ask the node to run an updated meshd CLI.");
  }
  const rootKeyId = key.rootKeyId || key.publicKeyJwk?.kid;
  if (!rootKeyId) {
    throw new Error("The pending request is missing node key-delivery rootKeyId.");
  }
  if (rootKeyId !== `${nodeDID}#1`) {
    throw new Error(`The pending request key-delivery rootKeyId does not match node DID ${nodeDID}.`);
  }
  if (key.publicKeyJwk?.kid && key.publicKeyJwk.kid !== rootKeyId) {
    throw new Error("The pending request key-delivery public key id does not match rootKeyId.");
  }
  if (key.publicKeyJwk?.kty !== "OKP" || key.publicKeyJwk?.crv !== "X25519") {
    throw new Error("The pending request key-delivery public key must be an X25519 OKP key.");
  }
  if (!key.publicKeyJwk?.x || base64UrlDecodeBytes(key.publicKeyJwk.x).length !== 32) {
    throw new Error("The pending request node key-delivery public key must be 32 bytes.");
  }
  return key;
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
    return {
      recordId: existing.recordId,
      dateCreated: existing.createdAt
    };
  }

  return writeRecord(
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
    true
  );
}

function exportedContextKeyFor(session: MeshdAdminSession, network: MeshdNetworkSummary) {
  if (!session.delegateDid) {
    return undefined;
  }
  const exported = session.agent.dwn?.exportDelegateContextKeys?.(session.delegateDid) ?? [];
  return exported.find((value): value is { protocol: string; contextId: string; derivedPrivateKey: unknown } => {
    if (!isObject(value)) return false;
    return value.protocol === MESHD_PROTOCOL_URI
      && value.contextId === network.recordId
      && isObject(value.derivedPrivateKey);
  });
}

async function deriveNetworkContextKey(
  session: MeshdAdminSession,
  network: MeshdNetworkSummary
): Promise<unknown> {
  const exported = exportedContextKeyFor(session, network);
  if (exported?.derivedPrivateKey) {
    return exported.derivedPrivateKey;
  }

  const contextKeys = await EnboxConnectProtocol.deriveContextKeysForDelegate(
    session.agent as never,
    session.ownerDid,
    MeshNodePermissionRequest.protocolDefinition as never,
    MeshNodePermissionRequest.permissionScopes as never
  );
  const networkContextKey = (contextKeys as unknown[]).find((value): value is { protocol: string; contextId: string; derivedPrivateKey: unknown } => {
    if (!isObject(value)) return false;
    return value.protocol === MESHD_PROTOCOL_URI
      && value.contextId === network.recordId
      && isObject(value.derivedPrivateKey);
  });
  if (!networkContextKey?.derivedPrivateKey) {
    throw new Error("Could not derive or export the mesh network context key. Reconnect the dashboard wallet session and try again.");
  }
  return networkContextKey.derivedPrivateKey;
}

async function ensureKeyDeliveryReady(session: MeshdAdminSession) {
  const existing = await session.agent.dwn?.getProtocolDefinition?.(
    session.ownerDid,
    MESHD_KEY_DELIVERY_PROTOCOL_URI,
    session.delegateDid
  );
  if (!existing) {
    throw new Error("The key-delivery protocol is not installed for this owner. Reconnect the wallet and approve meshd Admin again.");
  }
}

async function deliverNetworkContextKey(
  session: MeshdAdminSession,
  network: MeshdNetworkSummary,
  request: MeshdNodeRequestSummary,
  nodeKeyDelivery: MeshdNodeKeyDelivery
) {
  const contextKeyData = await deriveNetworkContextKey(session, network);
  await writeContextKeyRecordWithAgent(
    session.agent as never,
    {
      tenantDid: session.ownerDid,
      recipientDid: request.nodeDID,
      contextKeyData: contextKeyData as never,
      sourceProtocol: MESHD_PROTOCOL_URI,
      sourceContextId: network.recordId,
      recipientKeyDeliveryPublicKey: nodeKeyDelivery as never
    },
    (requestParams: Record<string, unknown>) =>
      processDwnRequest(session, requestParams, MESHD_KEY_DELIVERY_PROTOCOL_URI) as never,
    () => ensureKeyDeliveryReady(session),
    async (_tenantDid: string, message: DwnMessage[typeof DwnInterface.RecordsWrite]) => {
      if (!session.agent.sendDwnRequest) {
        return;
      }
      const messageCid = await Message.getCid(message as never);
      await sendDwnMessage(session, DwnInterface.RecordsWrite, messageCid);
    },
    (promise: Promise<void>) => promise
  );
}

export async function approveMeshdNodeRequest(
  session: MeshdAdminSession,
  network: MeshdNetworkSummary,
  request: MeshdNodeRequestSummary
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
  const nodeKeyDelivery = validateNodeKeyDelivery(request.nodeDID, request.nodeKeyDelivery);
  const requestOwnerDID = nodeOwnerDID(request);
  const member = await ensureMemberRecord(session, network, requestOwnerDID, request.label);
  const meshIP = await allocateMeshIp(network.meshCIDR, request.nodeDID);

  const nodeRecord = await writeRecord(
    session,
    MESHD_PROTOCOL_URI,
    {
      protocol: MESHD_PROTOCOL_URI,
      protocolPath: "network/member/node",
      schema: "https://enbox.id/schemas/wireguard-mesh/node",
      dataFormat: "application/json",
      recipient: request.nodeDID,
      parentContextId: `${network.recordId}/${member.recordId}`
    },
    {
      meshIP,
      addedAt: new Date().toISOString(),
      ...(request.label ? { label: request.label } : {}),
      ownerDID: requestOwnerDID,
      memberDID: requestOwnerDID,
      ...(request.delegateDID ? { delegateDID: request.delegateDID } : {}),
      ...(request.expiresAt ? { expiresAt: request.expiresAt } : {}),
      nodeKeyDelivery
    },
    true
  );

  await deliverNetworkContextKey(session, network, request, nodeKeyDelivery);
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
        ...(request.label ? { label: request.label } : {}),
        ...(request.expiresAt ? { expiresAt: request.expiresAt } : {}),
        approvedAt: new Date().toISOString(),
        requestRecordId: request.recordId
      }
    );
  }

  await deleteRecord(session, MESHD_PROTOCOL_URI, request.recordId, false);
  return {
    memberRecordId: member.recordId,
    nodeRecordId: nodeRecord.recordId,
    meshIP,
    deliveredContextKey: true
  };
}

export async function rejectMeshdNodeRequest(
  session: MeshdAdminSession,
  request: MeshdNodeRequestSummary
): Promise<void> {
  await deleteRecord(session, MESHD_PROTOCOL_URI, request.recordId, false);
}

function getRecordIdFromEntry(rawEntry: unknown): string | undefined {
  const wrapper = isObject(rawEntry) ? rawEntry : undefined;
  const entry = getRecordWrite(rawEntry);
  if (!entry || !wrapper) return undefined;
  const descriptor = isObject(entry.descriptor) ? entry.descriptor : {};
  return getRecordId(entry, wrapper, descriptor);
}

export async function removeMeshdNode(
  session: MeshdAdminSession,
  network: MeshdNetworkSummary,
  node: MeshdNodeSummary
): Promise<{ removedContextKeys: number; contextKeyCleanupError?: string }> {
  await deleteRecord(session, MESHD_PROTOCOL_URI, node.recordId, true);
  try {
    const contextKeyEntries = await queryRecords(
      session,
      MESHD_KEY_DELIVERY_PROTOCOL_URI,
      "contextKey",
      undefined,
      {
        recipient: node.did,
        tags: {
          protocol: MESHD_PROTOCOL_URI,
          contextId: network.recordId
        }
      }
    );
    let removedContextKeys = 0;
    for (const entry of contextKeyEntries) {
      const recordId = getRecordIdFromEntry(entry);
      if (!recordId) continue;
      await deleteRecord(session, MESHD_KEY_DELIVERY_PROTOCOL_URI, recordId, false);
      removedContextKeys++;
    }
    return { removedContextKeys };
  } catch (error) {
    return {
      removedContextKeys: 0,
      contextKeyCleanupError: error instanceof Error ? error.message : "Context key cleanup failed"
    };
  }
}
