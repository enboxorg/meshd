import { DwnInterface } from "@enbox/agent";
import { describe, expect, it, vi } from "vitest";

import { MESHD_PROTOCOL_URI } from "@/enbox/config";

import {
  buildMeshdInviteURL,
  createMeshdInvite,
  createMeshdNetwork,
  fetchMeshdNetworks,
  type MeshdAdminAgent,
  type MeshdAdminSession,
  type MeshdNetworkSummary
} from "./admin";

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
  endpoints?: string[];
  queryEntries?: unknown[];
  recordIds?: string[];
} = {}) {
  const requests: CapturedRequest[] = [];
  const pushes: CapturedRequest[] = [];
  const recordIds = [...(options.recordIds ?? ["record-1", "record-2", "record-3"])];
  let cid = 0;

  const agent: MeshdAdminAgent = {
    permissions: {
      getPermissionForRequest: vi.fn(async (request) => ({
        message: {
          grant: `${request.protocol}:${String(request.messageType)}`
        }
      }))
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
      return {
        reply: { status: { code: 202, detail: "Accepted" } },
        message: {
          recordId,
          descriptor: { dateCreated: "2026-06-24T00:00:00Z" }
        },
        messageCid: `cid-${++cid}`
      };
    }),
    sendDwnRequest: vi.fn(async (request: CapturedRequest) => {
      pushes.push(request);
      return { reply: { status: { code: 202, detail: "Accepted" } } };
    })
  };

  return {
    session: {
      agent,
      ownerDid: "did:example:owner",
      ...(options.delegate ? { delegateDid: "did:example:delegate" } : {})
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
    expect(pushes).toEqual([
      {
        author: "did:example:owner",
        target: "did:example:owner",
        messageType: DwnInterface.RecordsWrite,
        messageCid: "cid-1"
      }
    ]);
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
