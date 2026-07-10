import { DwnInterface } from "@enbox/agent";
import { Ed25519 } from "@enbox/crypto";
import { describe, expect, it, vi } from "vitest";

import { DEFAULT_DWN_ENDPOINT, MESHD_PROTOCOL_URI } from "@/enbox/config";

import {
  approveMeshdNodeRequest,
  buildMeshdInviteURL,
  createMeshdInvite,
  createMeshdNetwork,
  DELEGATE_SESSION_REQUIRED_ERROR,
  fetchMeshdNetworks,
  parseMeshdNodeRequestRecord,
  parseMeshdPreAuthKeyRecord,
  rejectMeshdNodeRequest,
  updateMeshdNodeExpiry,
  updateMeshdNodeLabel,
  type MeshdAdminAgent,
  type MeshdAdminSession,
  type MeshdNetworkSummary,
  type MeshdNodeRequestSummary,
  type RolePublicKeyJwk
} from "./admin";

// A structurally valid 32-byte X25519 OKP public key.
const VALID_X25519_KEY: RolePublicKeyJwk = { kty: "OKP", crv: "X25519", x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo" };

function toBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// Builds a real owner-node request signed by a fresh did:jwk so approve's proof check
// passes, letting the tests exercise the roleKeys delivery path end to end.
async function signedOwnerNodeRequest(opts: {
  ownerDID: string;
  roleKeys?: Record<string, RolePublicKeyJwk>;
  requestedAt?: string;
}): Promise<MeshdNodeRequestSummary> {
  const privateKey = await Ed25519.generateKey();
  const publicKey = await Ed25519.computePublicKey({ key: privateKey });
  const nodeDID = `did:jwk:${toBase64Url(new TextEncoder().encode(JSON.stringify(publicKey)))}`;
  const requestedAt = opts.requestedAt ?? "2026-07-10T00:00:00Z";
  const message = new TextEncoder().encode(
    "meshd owner node request v1\n"
    + `owner=${opts.ownerDID}\n`
    + `node=${nodeDID}\n`
    + "sourceDWN=\n"
    + `requestedAt=${requestedAt}\n`
  );
  const signature = await Ed25519.sign({ key: privateKey, data: message });
  return {
    recordId: "req-record",
    protocolPath: "nodeRequest",
    nodeDID,
    ownerDID: opts.ownerDID,
    memberDID: opts.ownerDID,
    requestKind: "owner-node",
    nodeProof: toBase64Url(signature),
    requestedAt,
    ...(opts.roleKeys ? { roleKeys: opts.roleKeys } : {})
  };
}

// Builds a real invite-based (non-owner-scoped) node request signed by a fresh
// did:jwk, with a matching HMAC invite proof, so approve's proof checks pass and
// the tests exercise the preAuthKey consumption + label-carry paths end to end.
async function signedInviteNodeRequest(opts: {
  networkId: string;
  secret: string;
  preAuthKeyId: string;
  ownerDID: string;
  label?: string;
  roleKeys?: Record<string, RolePublicKeyJwk>;
}): Promise<MeshdNodeRequestSummary> {
  const privateKey = await Ed25519.generateKey();
  const publicKey = await Ed25519.computePublicKey({ key: privateKey });
  const nodeDID = `did:jwk:${toBase64Url(new TextEncoder().encode(JSON.stringify(publicKey)))}`;
  const joinMessage = new TextEncoder().encode(
    "meshd node join v1\n"
    + `network=${opts.networkId}\n`
    + `node=${nodeDID}\n`
    + `member=${opts.ownerDID || nodeDID}\n`
    + `preauth=${opts.preAuthKeyId}\n`
  );
  const nodeProof = toBase64Url(await Ed25519.sign({ key: privateKey, data: joinMessage }));
  const hmacKey = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(opts.secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", hmacKey, new TextEncoder().encode(`${opts.networkId}\n${nodeDID}`)));
  return {
    recordId: "req-rec",
    protocolPath: "network/nodeRequest",
    nodeDID,
    ownerDID: opts.ownerDID,
    memberDID: opts.ownerDID,
    preAuthKeyId: opts.preAuthKeyId,
    preAuthProof: `hmac-sha256:${toBase64Url(mac)}`,
    nodeProof,
    ...(opts.label ? { label: opts.label } : {}),
    ...(opts.roleKeys ? { roleKeys: opts.roleKeys } : {})
  };
}

type CapturedRequest = Record<string, any>;

function decodeBase64UrlJson(value: string) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized.padEnd(normalized.length + ((4 - normalized.length % 4) % 4), "=");
  return JSON.parse(atob(padded));
}

async function blobJson(blob: Blob) {
  return JSON.parse(await blob.text());
}

function recordEntry(recordId: string, protocolPath: string, data: Record<string, unknown>, dateCreated = "2026-06-24T00:00:00Z") {
  return {
    recordsWrite: {
      recordId,
      descriptor: {
        protocol: MESHD_PROTOCOL_URI,
        protocolPath,
        dateCreated
      },
      encodedData: btoa(JSON.stringify(data)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
    }
  };
}

function createFakeSession(options: {
  delegate?: boolean;
  grant?: boolean;
  endpoints?: string[];
  queryEntries?: unknown[];
  recordIds?: string[];
  audienceKeyDelivery?: { delivered: boolean; recipientDid?: string; reason?: string };
} = {}) {
  const requests: CapturedRequest[] = [];
  const pushes: Array<string | undefined> = [];
  const recordIds = [...(options.recordIds ?? ["record-1", "record-2", "record-3"])];
  let cid = 0;

  const agent: MeshdAdminAgent = {
    permissions: {
      getPermissionForRequest: vi.fn(async (request) => {
        if (options.grant === false) {
          throw new Error(`CachedPermissions: No permissions found for ${String(request.messageType)}`);
        }
        return {
          message: {
            grant: `${request.protocol}:${String(request.messageType)}`
          }
        };
      })
    },
    dwn: {
      getDwnEndpointUrlsForTarget: vi.fn(async () => options.endpoints ?? ["https://dev.aws.dwn.enbox.id"])
    },
    processDwnRequest: vi.fn(async (request: CapturedRequest) => {
      requests.push(request);
      if (request.messageType === DwnInterface.RecordsQuery) {
        return {
          reply: {
            status: { code: 200, detail: "OK" },
            entries: options.queryEntries ?? []
          }
        };
      }

      const recordId = recordIds.shift() ?? `record-${requests.length}`;
      // The agent only reports audienceKeyDelivery for a $role write carrying a
      // supplied recipient key; default to delivered so unrelated writes are unaffected.
      const audienceKeyDelivery = request.recipientRolePublicKey
        ? (options.audienceKeyDelivery ?? { delivered: true, recipientDid: (request.messageParams as any)?.recipient })
        : undefined;
      return {
        reply: { status: { code: 202, detail: "Accepted" } },
        message: {
          recordId,
          descriptor: { dateCreated: "2026-06-24T00:00:00Z" }
        },
        messageCid: `cid-${++cid}`,
        ...(audienceKeyDelivery ? { audienceKeyDelivery } : {})
      };
    }),
    sync: {
      sync: vi.fn(async (direction?: "push" | "pull") => {
        pushes.push(direction);
      })
    }
  };

  return {
    session: {
      agent,
      ownerDid: "did:example:owner",
      ...(options.delegate === false ? {} : { delegateDid: "did:example:delegate" })
    } satisfies MeshdAdminSession,
    agent,
    requests,
    pushes
  };
}

describe("meshd admin DWN operations", () => {
  it("creates owner-scoped networks with delegated grants and remote push", async () => {
    const { session, agent, requests, pushes } = createFakeSession({
      delegate: true,
      endpoints: ["", "https://dev.aws.dwn.enbox.id"],
      recordIds: ["network-record"]
    });

    const network = await createMeshdNetwork(session, {
      name: "  Home mesh  ",
      meshCIDR: "10.201.0.0/16"
    });

    expect(network).toMatchObject({
      recordId: "network-record",
      name: "Home mesh",
      meshCIDR: "10.201.0.0/16",
      anchorEndpoint: "https://dev.aws.dwn.enbox.id"
    });

    expect(agent.permissions?.getPermissionForRequest).toHaveBeenCalledWith(expect.objectContaining({
      connectedDid: "did:example:owner",
      delegateDid: "did:example:delegate",
      protocol: MESHD_PROTOCOL_URI,
      delegate: true,
      cached: true,
      messageType: DwnInterface.RecordsWrite
    }));
    expect(requests[0]).toMatchObject({
      author: "did:example:owner",
      target: "did:example:owner",
      granteeDid: "did:example:delegate",
      messageType: DwnInterface.RecordsWrite,
      messageParams: {
        protocol: MESHD_PROTOCOL_URI,
        protocolPath: "network",
        schema: "https://enbox.id/schemas/wireguard-mesh/network",
        dataFormat: "application/json",
        delegatedGrant: {
          grant: `${MESHD_PROTOCOL_URI}:${DwnInterface.RecordsWrite}`
        }
      }
    });
    await expect(blobJson(requests[0].dataStream)).resolves.toEqual({
      name: "Home mesh",
      meshCIDR: "10.201.0.0/16",
      anchorEndpoint: "https://dev.aws.dwn.enbox.id"
    });
    // Remote propagation goes through the delegate-aware sync engine —
    // never through an owner-authored sendDwnRequest push.
    expect(pushes).toEqual(["push"]);
  });

  it("requests reply decryption on record queries so encrypted payloads decode", async () => {
    // Mesh records (preAuthKey, member/node) are written encrypted. The agent
    // only auto-decrypts query replies when the query itself carries
    // encryption: true; without it, encrypted payloads return as ciphertext and
    // preAuthKey lookups (approval) and the invite list silently fail.
    const { session, requests } = createFakeSession({ delegate: true });

    await fetchMeshdNetworks(session);

    const query = requests.find((request) => request.messageType === DwnInterface.RecordsQuery);
    expect(query).toBeDefined();
    expect(query).toMatchObject({
      messageType: DwnInterface.RecordsQuery,
      encryption: true
    });
  });

  it("uses the beta DWN endpoint when the owner does not publish one", async () => {
    const { session, requests } = createFakeSession({
      endpoints: ["", "   "],
      recordIds: ["network-record"]
    });

    const network = await createMeshdNetwork(session, {
      name: "Home mesh",
      meshCIDR: "10.200.0.0/16"
    });

    expect(network.anchorEndpoint).toBe(DEFAULT_DWN_ENDPOINT);
    await expect(blobJson(requests[0].dataStream)).resolves.toMatchObject({
      anchorEndpoint: DEFAULT_DWN_ENDPOINT
    });
  });

  it("normalizes and validates network CIDR before writing network records", async () => {
    const valid = createFakeSession({ recordIds: ["network-record"] });

    const network = await createMeshdNetwork(valid.session, {
      name: "Home mesh",
      meshCIDR: "10.201.42.9/16"
    });

    expect(network.meshCIDR).toBe("10.201.0.0/16");
    await expect(blobJson(valid.requests[0].dataStream)).resolves.toMatchObject({
      meshCIDR: "10.201.0.0/16"
    });

    const invalid = createFakeSession();
    await expect(createMeshdNetwork(invalid.session, {
      name: "Bad mesh",
      meshCIDR: "fd00::/64"
    })).rejects.toThrow("Invalid IPv4 address");
    expect(invalid.requests).toHaveLength(0);

    await expect(createMeshdNetwork(invalid.session, {
      name: "Tiny mesh",
      meshCIDR: "10.200.0.0/31"
    })).rejects.toThrow("must be an IPv4 CIDR with at least 2 host bits");
    expect(invalid.requests).toHaveLength(0);
  });

  it("creates invite records and returns CLI-compatible meshd invite URLs", async () => {
    const { session, requests } = createFakeSession({ delegate: true, recordIds: ["invite-record"] });
    const network: MeshdNetworkSummary = {
      recordId: "network-record",
      name: "Home mesh",
      meshCIDR: "10.200.0.0/16",
      anchorEndpoint: "https://owner.dwn.example"
    };

    const result = await createMeshdInvite(session, network, {
      label: "server",
      expiresAt: "2026-06-25T00:00:00Z",
      reusable: false
    });

    expect(result.tokenId).toBe("invite-record");
    expect(result.url.startsWith("meshd://invite/")).toBe(true);
    const payload = decodeBase64UrlJson(result.url.slice("meshd://invite/".length));
    expect(payload).toEqual({
      version: 1,
      endpoint: "https://owner.dwn.example",
      anchorDid: "did:example:owner",
      networkId: "network-record",
      networkName: "Home mesh",
      tokenId: "invite-record",
      secret: result.secret,
      expiresAt: "2026-06-25T00:00:00Z"
    });

    expect(requests[0]).toMatchObject({
      encryption: true,
      messageType: DwnInterface.RecordsWrite,
      messageParams: {
        protocol: MESHD_PROTOCOL_URI,
        protocolPath: "network/preAuthKey",
        schema: "https://enbox.id/schemas/wireguard-mesh/pre-auth-key",
        parentContextId: "network-record"
      }
    });
    await expect(blobJson(requests[0].dataStream)).resolves.toMatchObject({
      key: result.secret,
      expiresAt: "2026-06-25T00:00:00Z",
      reusable: false,
      label: "server",
      usedBy: []
    });
  });

  it("creates reusable invites without expiry when requested", async () => {
    const { session, requests } = createFakeSession({ recordIds: ["invite-record"] });
    const network: MeshdNetworkSummary = {
      recordId: "network-record",
      name: "Home mesh",
      meshCIDR: "10.200.0.0/16",
      anchorEndpoint: "https://owner.dwn.example"
    };

    const result = await createMeshdInvite(session, network, {
      label: "team",
      reusable: true
    });

    const payload = decodeBase64UrlJson(result.url.slice("meshd://invite/".length));
    expect(payload).not.toHaveProperty("expiresAt");
    expect(result).not.toHaveProperty("expiresAt");
    await expect(blobJson(requests[0].dataStream)).resolves.toMatchObject({
      key: result.secret,
      reusable: true,
      label: "team",
      usedBy: []
    });
    await expect(blobJson(requests[0].dataStream)).resolves.not.toHaveProperty("expiresAt");
  });

  it("rebuilds invite URLs from existing preauth records", async () => {
    const { session } = createFakeSession();
    const network: MeshdNetworkSummary = {
      recordId: "network-record",
      name: "Home mesh",
      meshCIDR: "10.200.0.0/16",
      anchorEndpoint: "https://owner.dwn.example"
    };

    const url = await buildMeshdInviteURL(session, network, {
      recordId: "invite-record",
      key: "secret-value",
      expiresAt: "2026-06-25T00:00:00Z",
      usedBy: []
    });

    expect(decodeBase64UrlJson(url.slice("meshd://invite/".length))).toEqual({
      version: 1,
      endpoint: "https://owner.dwn.example",
      anchorDid: "did:example:owner",
      networkId: "network-record",
      networkName: "Home mesh",
      tokenId: "invite-record",
      secret: "secret-value",
      expiresAt: "2026-06-25T00:00:00Z"
    });
  });

  it("rebuilds invite URLs with the beta endpoint when no network endpoint is stored", async () => {
    const { session } = createFakeSession({ endpoints: [] });
    const network: MeshdNetworkSummary = {
      recordId: "network-record",
      name: "Home mesh",
      meshCIDR: "10.200.0.0/16"
    };

    const url = await buildMeshdInviteURL(session, network, {
      recordId: "invite-record",
      key: "secret-value",
      usedBy: []
    });

    expect(decodeBase64UrlJson(url.slice("meshd://invite/".length))).toMatchObject({
      endpoint: DEFAULT_DWN_ENDPOINT,
      anchorDid: "did:example:owner",
      networkId: "network-record"
    });
  });

  it("updates node expiry while preserving the existing node payload and refreshing node approval", async () => {
    const { session, requests } = createFakeSession({ delegate: true, recordIds: ["node-record", "approval-record"] });
    const network: MeshdNetworkSummary = {
      recordId: "network-record",
      name: "Home mesh",
      meshCIDR: "10.200.0.0/16",
      anchorEndpoint: "https://owner.dwn.example"
    };

    const node = await updateMeshdNodeExpiry(session, network, {
      recordId: "node-record",
      did: "did:example:node",
      meshIP: "10.200.0.10",
      allowedIPs: ["10.200.0.10/32", "192.168.1.0/24"],
      label: "server",
      ownerDID: "did:example:owner",
      memberDID: "did:example:owner",
      delegateDID: "did:example:delegate",
      memberRecordId: "member-record",
      addedAt: "2026-06-24T00:00:00Z",
      expiresAt: "2026-06-25T00:00:00Z",
      sourceDWN: "https://node.dwn.example",
      createdAt: "2026-06-24T00:00:00Z"
    }, "2026-07-01T00:00:00Z");

    expect(node.expiresAt).toBe("2026-07-01T00:00:00Z");
    expect(requests[0]).toMatchObject({
      encryption: true,
      messageType: DwnInterface.RecordsWrite,
      messageParams: {
        protocol: MESHD_PROTOCOL_URI,
        protocolPath: "network/member/node",
        schema: "https://enbox.id/schemas/wireguard-mesh/node",
        recipient: "did:example:node",
        parentContextId: "network-record/member-record",
        recordId: "node-record",
        dateCreated: "2026-06-24T00:00:00Z"
      }
    });
    await expect(blobJson(requests[0].dataStream)).resolves.toEqual({
      meshIP: "10.200.0.10",
      allowedIPs: ["10.200.0.10/32", "192.168.1.0/24"],
      addedAt: "2026-06-24T00:00:00Z",
      expiresAt: "2026-07-01T00:00:00Z",
      label: "server",
      ownerDID: "did:example:owner",
      memberDID: "did:example:owner",
      delegateDID: "did:example:delegate",
      sourceDWN: "https://node.dwn.example"
    });
    expect(requests[1]).toMatchObject({
      messageType: DwnInterface.RecordsWrite,
      messageParams: {
        protocol: MESHD_PROTOCOL_URI,
        protocolPath: "nodeApproval",
        schema: "https://enbox.id/schemas/wireguard-mesh/node-approval",
        dataFormat: "application/json",
        recipient: "did:example:node"
      }
    });
    await expect(blobJson(requests[1].dataStream)).resolves.toMatchObject({
      ownerDID: "did:example:owner",
      nodeDID: "did:example:node",
      networkRecordId: "network-record",
      networkName: "Home mesh",
      meshCIDR: "10.200.0.0/16",
      meshIP: "10.200.0.10",
      anchorEndpoint: "https://owner.dwn.example",
      memberRecordId: "member-record",
      nodeRecordId: "node-record",
      nodeDateCreated: "2026-06-24T00:00:00Z",
      label: "server",
      expiresAt: "2026-07-01T00:00:00Z",
      approvedAt: expect.any(String)
    });
  });

  it("clears node expiry when renewing to never and refreshes node approval without expiry", async () => {
    const { session, requests } = createFakeSession({ recordIds: ["node-record", "approval-record"] });
    const network: MeshdNetworkSummary = {
      recordId: "network-record",
      name: "Home mesh",
      meshCIDR: "10.200.0.0/16"
    };

    const node = await updateMeshdNodeExpiry(session, network, {
      recordId: "node-record",
      did: "did:example:node",
      meshIP: "10.200.0.10",
      addedAt: "2026-06-24T00:00:00Z",
      expiresAt: "2026-06-25T00:00:00Z",
      createdAt: "2026-06-24T00:00:00Z"
    });

    expect(node.expiresAt).toBeUndefined();
    expect(requests[0]).toMatchObject({
      messageParams: {
        protocolPath: "network/node",
        parentContextId: "network-record",
        recordId: "node-record"
      }
    });
    await expect(blobJson(requests[0].dataStream)).resolves.not.toHaveProperty("expiresAt");
    await expect(blobJson(requests[1].dataStream)).resolves.toMatchObject({
      ownerDID: "did:example:owner",
      nodeDID: "did:example:node",
      networkRecordId: "network-record",
      networkName: "Home mesh",
      meshCIDR: "10.200.0.0/16",
      meshIP: "10.200.0.10",
      nodeRecordId: "node-record",
      nodeDateCreated: "2026-06-24T00:00:00Z",
      approvedAt: expect.any(String)
    });
    await expect(blobJson(requests[1].dataStream)).resolves.not.toHaveProperty("expiresAt");
  });

  it("updates node label while preserving expiry and membership metadata", async () => {
    const { session, requests } = createFakeSession({ recordIds: ["node-record"] });
    const network: MeshdNetworkSummary = {
      recordId: "network-record",
      name: "Home mesh",
      meshCIDR: "10.200.0.0/16"
    };

    const node = await updateMeshdNodeLabel(session, network, {
      recordId: "node-record",
      did: "did:example:node",
      meshIP: "10.200.0.10",
      allowedIPs: ["10.200.0.10/32"],
      label: "old label",
      ownerDID: "did:example:owner",
      memberDID: "did:example:owner",
      memberRecordId: "member-record",
      addedAt: "2026-06-24T00:00:00Z",
      expiresAt: "2026-06-25T00:00:00Z",
      createdAt: "2026-06-24T00:00:00Z"
    }, "new label");

    expect(node.label).toBe("new label");
    expect(node.expiresAt).toBe("2026-06-25T00:00:00Z");
    expect(requests[0]).toMatchObject({
      messageParams: {
        protocolPath: "network/member/node",
        parentContextId: "network-record/member-record",
        recordId: "node-record",
        dateCreated: "2026-06-24T00:00:00Z"
      }
    });
    await expect(blobJson(requests[0].dataStream)).resolves.toEqual({
      meshIP: "10.200.0.10",
      allowedIPs: ["10.200.0.10/32"],
      addedAt: "2026-06-24T00:00:00Z",
      expiresAt: "2026-06-25T00:00:00Z",
      label: "new label",
      ownerDID: "did:example:owner",
      memberDID: "did:example:owner"
    });
  });

  it("clears node label without clearing expiry", async () => {
    const { session, requests } = createFakeSession({ recordIds: ["node-record"] });
    const network: MeshdNetworkSummary = {
      recordId: "network-record",
      name: "Home mesh",
      meshCIDR: "10.200.0.0/16"
    };

    const node = await updateMeshdNodeLabel(session, network, {
      recordId: "node-record",
      did: "did:example:node",
      meshIP: "10.200.0.10",
      label: "old label",
      addedAt: "2026-06-24T00:00:00Z",
      expiresAt: "2026-06-25T00:00:00Z",
      createdAt: "2026-06-24T00:00:00Z"
    }, "   ");

    expect(node.label).toBeUndefined();
    expect(node.expiresAt).toBe("2026-06-25T00:00:00Z");
    await expect(blobJson(requests[0].dataStream)).resolves.toMatchObject({
      meshIP: "10.200.0.10",
      addedAt: "2026-06-24T00:00:00Z",
      expiresAt: "2026-06-25T00:00:00Z"
    });
    await expect(blobJson(requests[0].dataStream)).resolves.not.toHaveProperty("label");
  });

  it("fails closed when the session has no delegate identity (never authors as owner)", async () => {
    const { session, agent, requests, pushes } = createFakeSession({ delegate: false });

    await expect(createMeshdNetwork(session, {
      name: "Home mesh",
      meshCIDR: "10.200.0.0/16"
    })).rejects.toThrow(DELEGATE_SESSION_REQUIRED_ERROR);

    await expect(fetchMeshdNetworks(session)).rejects.toThrow(DELEGATE_SESSION_REQUIRED_ERROR);

    await expect(rejectMeshdNodeRequest(session, {
      recordId: "request-record",
      nodeDID: "did:example:node"
    })).rejects.toThrow(DELEGATE_SESSION_REQUIRED_ERROR);

    expect(DELEGATE_SESSION_REQUIRED_ERROR).toContain("reconnect your wallet");
    expect(agent.processDwnRequest).not.toHaveBeenCalled();
    expect(requests).toHaveLength(0);
    expect(pushes).toHaveLength(0);
  });

  it("fails closed when the wallet session holds no matching delegated grant", async () => {
    const { session, agent, requests } = createFakeSession({ grant: false });

    await expect(createMeshdNetwork(session, {
      name: "Home mesh",
      meshCIDR: "10.200.0.0/16"
    })).rejects.toThrow(`The wallet session did not grant ${MESHD_PROTOCOL_URI} access to this dashboard.`);

    await expect(fetchMeshdNetworks(session)).rejects.toThrow("reconnect your wallet");

    expect(agent.processDwnRequest).not.toHaveBeenCalled();
    expect(requests).toHaveLength(0);
  });

  it("keeps a failed remote push non-fatal (sync retries in the background)", async () => {
    const { session, agent } = createFakeSession({ recordIds: ["network-record"] });
    (agent.sync!.sync as ReturnType<typeof vi.fn>).mockRejectedValue(
      new Error("SyncEngineLevel: Sync operation is already in progress.")
    );

    const network = await createMeshdNetwork(session, {
      name: "Home mesh",
      meshCIDR: "10.200.0.0/16"
    });

    expect(network.recordId).toBe("network-record");
  });

  it("fetches and sorts network records through delegated records queries", async () => {
    const { session, requests } = createFakeSession({
      delegate: true,
      queryEntries: [
        recordEntry("older", "network", { name: "Older", meshCIDR: "10.200.0.0/16" }, "2026-06-23T00:00:00Z"),
        recordEntry("newer", "network", { name: "Newer", meshCIDR: "10.201.0.0/16" }, "2026-06-24T00:00:00Z"),
        recordEntry("ignored", "network/member", { name: "Member", meshCIDR: "10.202.0.0/16" }, "2026-06-25T00:00:00Z")
      ]
    });

    const networks = await fetchMeshdNetworks(session);

    expect(networks.map((network) => network.recordId)).toEqual(["newer", "older"]);
    expect(requests[0]).toMatchObject({
      granteeDid: "did:example:delegate",
      messageType: DwnInterface.RecordsQuery,
      messageParams: {
        filter: {
          protocol: MESHD_PROTOCOL_URI,
          protocolPath: "network"
        },
        delegatedGrant: {
          grant: `${MESHD_PROTOCOL_URI}:${DwnInterface.RecordsQuery}`
        }
      }
    });
  });
});

describe("meshd node role-audience key delivery (#187)", () => {
  const network: MeshdNetworkSummary = { recordId: "net-1", name: "Test Net", meshCIDR: "10.200.0.0/16" };

  it("parseMeshdNodeRequestRecord surfaces roleKeys and drops malformed entries", () => {
    const raw = recordEntry("req-1", "network/nodeRequest", {
      nodeDID: "did:jwk:node",
      roleKeys: {
        "network/member/node": VALID_X25519_KEY,
        "network/node": VALID_X25519_KEY,
        "network/bad": { kty: "OKP", crv: "Ed25519", x: "abc" }, // wrong curve — dropped
        "network/empty": { kty: "OKP", crv: "X25519" }           // missing x — dropped
      }
    });

    const parsed = parseMeshdNodeRequestRecord(raw);
    expect(parsed?.roleKeys).toEqual({
      "network/member/node": VALID_X25519_KEY,
      "network/node": VALID_X25519_KEY
    });
  });

  it("parseMeshdNodeRequestRecord omits roleKeys when none are present", () => {
    const raw = recordEntry("req-2", "network/nodeRequest", { nodeDID: "did:jwk:node" });
    expect(parseMeshdNodeRequestRecord(raw)?.roleKeys).toBeUndefined();
  });

  it("delivers the network/member reading-role audience to the node and approves", async () => {
    const { session, requests } = createFakeSession({ recordIds: ["member-rec", "node-rec", "approval-rec"] });
    const request = await signedOwnerNodeRequest({
      ownerDID: "did:example:owner",
      roleKeys: { "network/member": VALID_X25519_KEY, "network/member/node": VALID_X25519_KEY }
    });

    const result = await approveMeshdNodeRequest(session, network, request);
    expect(result.nodeRecordId).toBe("node-rec");

    // The network/member role record — the reading-role audience peer records are
    // encrypted to — is written with the node's supplied key so its delivery reaches
    // the node (#192).
    const memberWrite = requests.find(
      (r) => r.messageType === DwnInterface.RecordsWrite && r.messageParams?.protocolPath === "network/member"
    );
    expect(memberWrite).toBeDefined();
    expect(memberWrite!.recipientRolePublicKey).toEqual(VALID_X25519_KEY);

    // The network/member/node role record is still written with its own key.
    const nodeWrite = requests.find(
      (r) => r.messageType === DwnInterface.RecordsWrite && r.messageParams?.protocolPath === "network/member/node"
    );
    expect(nodeWrite).toBeDefined();
    expect(nodeWrite!.recipientRolePublicKey).toEqual(VALID_X25519_KEY);
    expect(nodeWrite!.messageParams.recipient).toBe(request.nodeDID);

    // Neither role record is rolled back on successful delivery (the original
    // nodeRequest record is still cleaned up, so only the role records are checked).
    const roleDeletes = requests.filter(
      (r) => r.messageType === DwnInterface.RecordsDelete &&
        (r.messageParams?.recordId === "member-rec" || r.messageParams?.recordId === "node-rec")
    );
    expect(roleDeletes).toHaveLength(0);
  });

  it("refuses to approve a node that supplied no role keys (fail-fast)", async () => {
    const { session, requests } = createFakeSession();
    const request = await signedOwnerNodeRequest({ ownerDID: "did:example:owner" }); // no roleKeys

    await expect(approveMeshdNodeRequest(session, network, request)).rejects.toThrow(/did not include.*role-audience key/i);

    // No role record is written.
    const roleWrite = requests.find(
      (r) => r.messageType === DwnInterface.RecordsWrite &&
        (r.messageParams?.protocolPath === "network/member" || r.messageParams?.protocolPath === "network/member/node")
    );
    expect(roleWrite).toBeUndefined();
  });

  it("refuses to approve when the network/member reading-role key is missing (fail-fast)", async () => {
    const { session, requests } = createFakeSession();
    // Supplies only the held-role key, not the reading-role key it decrypts peers with.
    const request = await signedOwnerNodeRequest({
      ownerDID: "did:example:owner",
      roleKeys: { "network/member/node": VALID_X25519_KEY }
    });

    await expect(approveMeshdNodeRequest(session, network, request)).rejects.toThrow(/network\/member role-audience key/i);

    const memberWrite = requests.find(
      (r) => r.messageType === DwnInterface.RecordsWrite && r.messageParams?.protocolPath === "network/member"
    );
    expect(memberWrite).toBeUndefined();
  });

  it("rolls back the member record and fails when the reading-role audience could not be delivered", async () => {
    const { session, requests } = createFakeSession({
      recordIds: ["member-rec", "node-rec", "approval-rec"],
      audienceKeyDelivery: { delivered: false, recipientDid: "did:jwk:node", reason: "no seal coverage" }
    });
    const request = await signedOwnerNodeRequest({
      ownerDID: "did:example:owner",
      roleKeys: { "network/member": VALID_X25519_KEY, "network/member/node": VALID_X25519_KEY }
    });

    await expect(approveMeshdNodeRequest(session, network, request)).rejects.toThrow(/could not deliver.*rolled back|no seal coverage/i);

    // The network/member record — written first — is rolled back with the dashboard's
    // own delete grant; the node record write is never reached.
    const memberDeletes = requests.filter(
      (r) => r.messageType === DwnInterface.RecordsDelete && r.messageParams?.recordId === "member-rec"
    );
    expect(memberDeletes).toHaveLength(1);
    const nodeWrite = requests.find(
      (r) => r.messageType === DwnInterface.RecordsWrite && r.messageParams?.protocolPath === "network/member/node"
    );
    expect(nodeWrite).toBeUndefined();
  });
});

describe("meshd invite lifecycle", () => {
  const network: MeshdNetworkSummary = { recordId: "net-1", name: "Test Net", meshCIDR: "10.200.0.0/16" };
  const roleKeys = { "network/member": VALID_X25519_KEY, "network/member/node": VALID_X25519_KEY };
  const secret = "invite-secret";

  function inviteEntry(overrides: Record<string, unknown>) {
    return recordEntry("invite-rec", "network/preAuthKey", {
      key: secret,
      createdAt: "2026-06-24T00:00:00Z",
      usedBy: [],
      ...overrides
    });
  }

  // createMeshdInvite writes the label + expiresAt into the encrypted payload, and
  // parseMeshdPreAuthKeyRecord must read them back — the round-trip that surfaces as
  // the invite row's label and "Expires …" text (guards against silent "No expiry").
  it("round-trips an invite's label and expiry through create and parse", async () => {
    const { session, requests } = createFakeSession({ delegate: true, recordIds: ["invite-rec"] });
    const result = await createMeshdInvite(session, network, {
      label: "laptop-01",
      expiresAt: "2026-06-25T00:00:00Z",
      reusable: false
    });
    expect(result.label).toBe("laptop-01");

    const written = await blobJson(requests[0].dataStream);
    const parsed = parseMeshdPreAuthKeyRecord(recordEntry(result.tokenId, "network/preAuthKey", written));
    expect(parsed?.label).toBe("laptop-01");
    expect(parsed?.expiresAt).toBe("2026-06-25T00:00:00Z");
  });

  it("removes a single-use invite once it is consumed", async () => {
    const { session, requests } = createFakeSession({
      recordIds: ["member-rec", "node-rec"],
      queryEntries: [inviteEntry({ reusable: false })]
    });
    const request = await signedInviteNodeRequest({
      networkId: network.recordId, secret, preAuthKeyId: "invite-rec", ownerDID: "did:example:owner", roleKeys
    });

    await approveMeshdNodeRequest(session, network, request);

    // The spent invite is deleted, not left as a dead "1 used" entry...
    const inviteDeletes = requests.filter(
      (r) => r.messageType === DwnInterface.RecordsDelete && r.messageParams?.recordId === "invite-rec"
    );
    expect(inviteDeletes).toHaveLength(1);
    // ...and never rewritten with a usedBy entry.
    const inviteRewrites = requests.filter(
      (r) => r.messageType === DwnInterface.RecordsWrite && r.messageParams?.protocolPath === "network/preAuthKey"
    );
    expect(inviteRewrites).toHaveLength(0);
  });

  it("keeps a reusable invite and records the new consumer", async () => {
    const { session, requests } = createFakeSession({
      recordIds: ["member-rec", "node-rec"],
      queryEntries: [inviteEntry({ reusable: true })]
    });
    const request = await signedInviteNodeRequest({
      networkId: network.recordId, secret, preAuthKeyId: "invite-rec", ownerDID: "did:example:owner", roleKeys
    });

    await approveMeshdNodeRequest(session, network, request);

    // A reusable invite survives...
    const inviteDeletes = requests.filter(
      (r) => r.messageType === DwnInterface.RecordsDelete && r.messageParams?.recordId === "invite-rec"
    );
    expect(inviteDeletes).toHaveLength(0);
    // ...and records the consumer in usedBy.
    const rewrite = requests.find(
      (r) => r.messageType === DwnInterface.RecordsWrite && r.messageParams?.protocolPath === "network/preAuthKey"
    );
    expect(rewrite).toBeDefined();
    const payload = await blobJson(rewrite!.dataStream);
    expect(payload.reusable).toBe(true);
    expect(payload.usedBy).toEqual([request.nodeDID]);
  });

  it("carries the invite label to the joined node when the request has none", async () => {
    const { session, requests } = createFakeSession({
      recordIds: ["member-rec", "node-rec"],
      queryEntries: [inviteEntry({ reusable: false, label: "laptop-01" })]
    });
    const request = await signedInviteNodeRequest({
      networkId: network.recordId, secret, preAuthKeyId: "invite-rec", ownerDID: "did:example:owner", roleKeys
    });
    expect(request.label).toBeUndefined();

    await approveMeshdNodeRequest(session, network, request);

    const nodeWrite = requests.find(
      (r) => r.messageType === DwnInterface.RecordsWrite && r.messageParams?.protocolPath === "network/member/node"
    );
    expect(nodeWrite).toBeDefined();
    const payload = await blobJson(nodeWrite!.dataStream);
    expect(payload.label).toBe("laptop-01");
  });
});
