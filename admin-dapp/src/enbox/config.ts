import type { AuthManagerOptions, Permission, ProtocolRequest, WalletOption } from "@enbox/browser";

import meshProtocolDefinition from "../../../protocols/wireguard-mesh.json";
import keyDeliveryProtocolDefinition from "../../../protocols/key-delivery.json";

export const MESHD_PROTOCOL_URI = "https://enbox.id/protocols/wireguard-mesh";
export const MESHD_KEY_DELIVERY_PROTOCOL_URI = "https://identity.foundation/protocols/key-delivery";

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

export const MeshProtocolDefinition = meshProtocolDefinition;
export const KeyDeliveryProtocolDefinition = keyDeliveryProtocolDefinition;

export const DAPP_PROTOCOLS = [
  { definition: MeshProtocolDefinition, permissions: ADMIN_PERMISSIONS },
  { definition: KeyDeliveryProtocolDefinition, permissions: ADMIN_PERMISSIONS }
] as unknown as ProtocolRequest[];

export const IDENTITY_SYNC_PROTOCOLS: IdentitySyncProtocols = [
  MESHD_PROTOCOL_URI,
  MESHD_KEY_DELIVERY_PROTOCOL_URI
];

export const AUTH_DATA_PATH = "DATA/ENBOX_MESHD_ADMIN_DAPP";
export const AUTH_STORAGE_PREFIX = "enbox:meshd-admin:";
export const VAULT_PASSWORD_STORAGE_KEY = `${AUTH_STORAGE_PREFIX}vault-password`;
