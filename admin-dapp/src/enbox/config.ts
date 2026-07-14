import type { AuthManagerOptions, Permission, ProtocolRequest, WalletOption } from "@enbox/browser";
import { DEFAULT_WALLETS } from "@enbox/browser";

import meshProtocolDefinitionJson from "../../../protocols/wireguard-mesh.json";

export const MESHD_PROTOCOL_URI = "https://enbox.id/protocols/wireguard-mesh";

type IdentitySyncProtocols = NonNullable<AuthManagerOptions["identitySyncProtocols"]>;

const ADMIN_PERMISSIONS = ["read", "write", "delete"] satisfies Permission[];

export const DAPP_NAME = import.meta.env.VITE_ENBOX_DAPP_NAME || "meshd Admin";

// Use the SDK's current DEFAULT_WALLETS (Enbox, Prism, Matcha, Onyx) so the
// standardized connect dialog stays current as the SDK's wallet set evolves.
export const WALLET_OPTIONS: WalletOption[] = DEFAULT_WALLETS;

export const DWN_ENDPOINTS = (
  import.meta.env.VITE_ENBOX_DWN_ENDPOINTS || "https://dev.aws.dwn.enbox.id,https://enbox-dwn.fly.dev"
).split(",").map((endpoint: string) => endpoint.trim()).filter(Boolean);
export const DEFAULT_DWN_ENDPOINT = DWN_ENDPOINTS[0] || "https://dev.aws.dwn.enbox.id";

export const MeshProtocolDefinition = meshProtocolDefinitionJson;

export const DAPP_PROTOCOLS = [
  { definition: MeshProtocolDefinition, permissions: ADMIN_PERMISSIONS }
] as unknown as ProtocolRequest[];

export const IDENTITY_SYNC_PROTOCOLS: IdentitySyncProtocols = [
  MESHD_PROTOCOL_URI
];

export const AUTH_DATA_PATH = "DATA/ENBOX_MESHD_ADMIN_DAPP";
export const AUTH_STORAGE_PREFIX = "enbox:meshd-admin:";
export const VAULT_PASSWORD_STORAGE_KEY = `${AUTH_STORAGE_PREFIX}vault-password`;
