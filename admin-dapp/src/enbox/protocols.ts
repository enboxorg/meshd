import { defineProtocol } from "@enbox/browser";
import type { Enbox } from "@enbox/browser";
import type { ConnectPermissionRequest } from "@enbox/agent";

import {
  MESHD_PROTOCOL_URI,
  MeshProtocolDefinition,
  withoutKeyAgreement
} from "./config";

type MeshProtocolSchemaMap = {
  network: Record<string, unknown>;
  member: Record<string, unknown>;
  nodeRequest: Record<string, unknown>;
  nodeApproval: Record<string, unknown>;
  node: Record<string, unknown>;
  nodeInfo: Record<string, unknown>;
  endpoint: Record<string, unknown>;
  aclPolicy: Record<string, unknown>;
  relay: Record<string, unknown>;
  preAuthKey: Record<string, unknown>;
};

type ProtocolDefinition = {
  protocol?: unknown;
  types?: unknown;
  structure?: unknown;
};

type InstalledProtocol = {
  definition?: unknown;
};

export const MeshProtocol = defineProtocol(
  MeshProtocolDefinition as never,
  {} as MeshProtocolSchemaMap
);

export const MeshNodePermissionRequest: ConnectPermissionRequest = {
  protocolDefinition: MeshProtocolDefinition as never,
  permissionScopes: [
    { interface: "Records", method: "Read", protocol: MESHD_PROTOCOL_URI },
    { interface: "Records", method: "Write", protocol: MESHD_PROTOCOL_URI, protocolPath: "network/node/nodeInfo" },
    { interface: "Records", method: "Write", protocol: MESHD_PROTOCOL_URI, protocolPath: "network/node/endpoint" },
    { interface: "Records", method: "Write", protocol: MESHD_PROTOCOL_URI, protocolPath: "network/member/node/nodeInfo" },
    { interface: "Records", method: "Write", protocol: MESHD_PROTOCOL_URI, protocolPath: "network/member/node/endpoint" }
  ] as never
};

export const MeshAdminPermissionRequest: ConnectPermissionRequest = {
  protocolDefinition: MeshProtocolDefinition as never,
  permissionScopes: [
    { interface: "Records", method: "Read", protocol: MESHD_PROTOCOL_URI },
    { interface: "Records", method: "Write", protocol: MESHD_PROTOCOL_URI },
    { interface: "Records", method: "Delete", protocol: MESHD_PROTOCOL_URI }
  ] as never
};

type ConfigurableProtocol = {
  protocol: string;
  configure: () => Promise<{ status: { code: number; detail: string }; protocol?: InstalledProtocol }>;
};

function ensureConfigureStatus(protocol: string, status: { code: number; detail: string }) {
  if ((status.code >= 200 && status.code < 300) || status.code === 409) {
    return;
  }
  throw new Error(`${protocol}: ${status.code} ${status.detail}`);
}

async function configure(protocol: ConfigurableProtocol) {
  const { status, protocol: installed } = await protocol.configure();
  ensureConfigureStatus(protocol.protocol, status);
  return installed;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function protocolDefinition(value: unknown): ProtocolDefinition | undefined {
  return isRecord(value) ? value : undefined;
}

function collectProtocolPaths(structure: unknown, prefix = ""): string[] {
  if (!isRecord(structure)) {
    return [];
  }

  const paths: string[] = [];
  for (const [key, value] of Object.entries(structure)) {
    if (key.startsWith("$") || !isRecord(value)) {
      continue;
    }

    const path = prefix ? `${prefix}/${key}` : key;
    paths.push(path, ...collectProtocolPaths(value, path));
  }
  return paths;
}

function assertExpectedProtocolDefinition(
  label: string,
  expectedDefinition: ProtocolDefinition,
  installedDefinition: unknown
) {
  // The wallet installs the protocol with encryption enabled, so the
  // installed definition carries derived `$keyAgreement: { publicKeyJwk }`
  // blocks at the top level and at every structure path. Those are
  // owner-specific runtime key material, not part of the authored
  // definition — normalize the installed side before comparing.
  const installed = protocolDefinition(
    withoutKeyAgreement(protocolDefinition(installedDefinition))
  );
  const expected = expectedDefinition;
  if (!installed) {
    return;
  }

  if (installed.protocol !== expected.protocol) {
    throw new Error(`${label}: wallet installed an unexpected protocol definition.`);
  }

  const expectedTypes = isRecord(expected.types) ? Object.keys(expected.types) : [];
  const installedTypes = isRecord(installed.types) ? Object.keys(installed.types) : [];
  const missingTypes = expectedTypes.filter((type) => !installedTypes.includes(type));
  if (missingTypes.length > 0) {
    throw new Error(`${label}: wallet protocol is missing types: ${missingTypes.join(", ")}.`);
  }

  const expectedPaths = collectProtocolPaths(expected.structure);
  const installedPaths = collectProtocolPaths(installed.structure);
  const missingPaths = expectedPaths.filter((path) => !installedPaths.includes(path));
  if (missingPaths.length > 0) {
    throw new Error(`${label}: wallet protocol is missing paths: ${missingPaths.join(", ")}.`);
  }
}

export async function ensureProtocolsReady(enbox: Enbox) {
  const mesh = await configure(enbox.using(MeshProtocol) as ConfigurableProtocol);

  assertExpectedProtocolDefinition("meshd mesh protocol", MeshProtocolDefinition as ProtocolDefinition, mesh?.definition);
}
