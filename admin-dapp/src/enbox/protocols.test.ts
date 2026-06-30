import { normalizeProtocolRequests } from "@enbox/auth";
import type { Enbox } from "@enbox/browser";
import { DwnInterfaceName, DwnMethodName } from "@enbox/dwn-sdk-js";
import { describe, expect, it, vi } from "vitest";

import {
  DAPP_PROTOCOLS,
  MESHD_PROTOCOL_URI,
  MeshProtocolDefinition
} from "./config";
import { ensureProtocolsReady, MeshProtocol } from "./protocols";

type ConfigurableProtocol = {
  protocol: string;
  configure: ReturnType<typeof vi.fn>;
};

function configurableProtocol(protocol: string, definition: unknown, status = { code: 200, detail: "OK" }) {
  return {
    protocol,
    configure: vi.fn().mockResolvedValue({
      status,
      protocol: { definition }
    })
  } satisfies ConfigurableProtocol;
}

function fakeEnbox(mesh: ConfigurableProtocol) {
  return {
    using: vi.fn((protocol: unknown) => {
      if (protocol === MeshProtocol) return mesh;
      throw new Error("unexpected protocol");
    })
  } as unknown as Enbox;
}

describe("meshd admin protocol requests", () => {
  it("asks wallet connect for protocol install plus record grants, not delegated protocol configure", () => {
    const requests = normalizeProtocolRequests(DAPP_PROTOCOLS);

    const protocol = MESHD_PROTOCOL_URI;
    const request = requests.find((item) => item.protocolDefinition.protocol === protocol);
    expect(request).toBeDefined();
    expect(request?.permissionScopes).toEqual(expect.arrayContaining([
      { protocol, interface: DwnInterfaceName.Protocols, method: DwnMethodName.Query },
      { protocol, interface: DwnInterfaceName.Messages, method: DwnMethodName.Read },
      { protocol, interface: DwnInterfaceName.Records, method: DwnMethodName.Read },
      { protocol, interface: DwnInterfaceName.Records, method: DwnMethodName.Write },
      { protocol, interface: DwnInterfaceName.Records, method: DwnMethodName.Delete }
    ]));
    expect(request?.permissionScopes).not.toEqual(expect.arrayContaining([
      expect.objectContaining({
        protocol,
        interface: DwnInterfaceName.Protocols,
        method: DwnMethodName.Configure
      })
    ]));
  });

  it("requests only the mesh protocol (the key-delivery protocol is no longer installed)", () => {
    const requests = normalizeProtocolRequests(DAPP_PROTOCOLS);

    expect(requests.map((item) => item.protocolDefinition.protocol)).toEqual([MESHD_PROTOCOL_URI]);
  });
});

describe("ensureProtocolsReady", () => {
  it("runs the SDK readiness/import step for the mesh protocol", async () => {
    const mesh = configurableProtocol(MESHD_PROTOCOL_URI, MeshProtocolDefinition);

    await expect(ensureProtocolsReady(fakeEnbox(mesh))).resolves.toBeUndefined();

    expect(mesh.configure).toHaveBeenCalledOnce();
  });

  it("fails when the wallet-installed mesh protocol is missing expected types", async () => {
    const staleDefinition = structuredClone(MeshProtocolDefinition) as typeof MeshProtocolDefinition;
    delete (staleDefinition.types as Record<string, unknown>).preAuthKey;

    const mesh = configurableProtocol(MESHD_PROTOCOL_URI, staleDefinition);

    await expect(ensureProtocolsReady(fakeEnbox(mesh))).rejects.toThrow(
      "meshd mesh protocol: wallet protocol is missing types: preAuthKey."
    );
  });

  it("fails when the wallet-installed mesh protocol is missing expected paths", async () => {
    const staleDefinition = structuredClone(MeshProtocolDefinition) as typeof MeshProtocolDefinition;
    delete (staleDefinition.structure.network.member.node as Record<string, unknown>).endpoint;

    const mesh = configurableProtocol(MESHD_PROTOCOL_URI, staleDefinition);

    await expect(ensureProtocolsReady(fakeEnbox(mesh))).rejects.toThrow(
      "meshd mesh protocol: wallet protocol is missing paths: network/member/node/endpoint."
    );
  });

  it("surfaces protocol readiness status failures", async () => {
    const mesh = configurableProtocol(
      MESHD_PROTOCOL_URI,
      MeshProtocolDefinition,
      { code: 401, detail: "missing delegated grant" }
    );

    await expect(ensureProtocolsReady(fakeEnbox(mesh))).rejects.toThrow(
      `${MESHD_PROTOCOL_URI}: 401 missing delegated grant`
    );
  });
});
