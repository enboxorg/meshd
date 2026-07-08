import type { AuthManagerOptions, Permission, ProtocolRequest, WalletOption } from "@enbox/browser";

import meshProtocolDefinitionJson from "../../../protocols/wireguard-mesh.json";

export const MESHD_PROTOCOL_URI = "https://enbox.id/protocols/wireguard-mesh";

/**
 * Removes every `$keyAgreement` node from a protocol definition (top level
 * and the whole structure tree) and returns a deep copy.
 *
 * The embedded wireguard-mesh.json (shared with the Go daemon) carries
 * `$keyAgreement` placeholder nodes (`{"rootKeyId": "#dwn-enc",
 * "publicKeyJwk": {}}`). dwn-sdk-js 0.4.8 rejects both keys during
 * ProtocolsConfigure validation (`rootKeyId` is no longer an allowed
 * property and an empty `publicKeyJwk` fails the X25519 JWK schema), and
 * the wallet injects real `{ publicKeyJwk }` blocks itself when it installs
 * the protocol with encryption enabled. The dapp therefore always works
 * with the stripped definition — the TypeScript counterpart of the Go
 * `protocols.MeshProtocolDefinitionForConnect`.
 */
export function stripKeyAgreementPlaceholders<T>(definition: T): T {
  return stripKeyAgreementNodes(structuredClone(definition)) as T;
}

function stripKeyAgreementNodes(value: unknown): unknown {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return value;
  }
  const node = value as Record<string, unknown>;
  delete node["$keyAgreement"];
  for (const [key, child] of Object.entries(node)) {
    if (key.startsWith("$")) {
      continue;
    }
    stripKeyAgreementNodes(child);
  }
  return node;
}

type IdentitySyncProtocols = NonNullable<AuthManagerOptions["identitySyncProtocols"]>;

const ADMIN_PERMISSIONS = ["read", "write", "delete"] satisfies Permission[];

export const DAPP_NAME = import.meta.env.VITE_ENBOX_DAPP_NAME || "meshd Admin";

export const WALLET_OPTIONS = [
  {
    name: "Enbox Wallet",
    url: import.meta.env.VITE_ENBOX_WALLET_URL || "https://enbox-wallet.pages.dev",
    icon: `${import.meta.env.VITE_ENBOX_WALLET_URL || "https://enbox-wallet.pages.dev"}/favicon.ico`,
    description: "Your Enbox identity wallet"
  },
  {
    name: "Blue Enbox Wallet",
    url: import.meta.env.VITE_ENBOX_BLUE_WALLET_URL || "https://blue-enbox-wallet.pages.dev",
    icon: `${import.meta.env.VITE_ENBOX_BLUE_WALLET_URL || "https://blue-enbox-wallet.pages.dev"}/favicon.ico`,
    description: "Your Enbox identity wallet"
  }
] satisfies WalletOption[];

export const DWN_ENDPOINTS = (
  import.meta.env.VITE_ENBOX_DWN_ENDPOINTS || "https://dev.aws.dwn.enbox.id,https://enbox-dwn.fly.dev"
).split(",").map((endpoint: string) => endpoint.trim()).filter(Boolean);
export const DEFAULT_DWN_ENDPOINT = DWN_ENDPOINTS[0] || "https://dev.aws.dwn.enbox.id";

export const MeshProtocolDefinition = stripKeyAgreementPlaceholders(meshProtocolDefinitionJson);

export const DAPP_PROTOCOLS = [
  { definition: MeshProtocolDefinition, permissions: ADMIN_PERMISSIONS }
] as unknown as ProtocolRequest[];

export const IDENTITY_SYNC_PROTOCOLS: IdentitySyncProtocols = [
  MESHD_PROTOCOL_URI
];

export const AUTH_DATA_PATH = "DATA/ENBOX_MESHD_ADMIN_DAPP";
export const AUTH_STORAGE_PREFIX = "enbox:meshd-admin:";
export const VAULT_PASSWORD_STORAGE_KEY = `${AUTH_STORAGE_PREFIX}vault-password`;
