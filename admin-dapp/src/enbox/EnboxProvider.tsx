import React, { createContext, useCallback, useEffect, useRef, useState } from "react";

import { AuthManager, BrowserConnectHandler, Enbox } from "@enbox/browser";
import type { AuthManagerOptions, AuthSession } from "@enbox/browser";
import { BrowserStorage } from "@enbox/auth";
import type { ProviderAuthParams, ProviderAuthResult } from "@enbox/auth";

import {
  AUTH_DATA_PATH,
  AUTH_STORAGE_PREFIX,
  DAPP_NAME,
  DAPP_PROTOCOLS,
  DWN_ENDPOINTS,
  IDENTITY_SYNC_PROTOCOLS,
  VAULT_PASSWORD_STORAGE_KEY,
  WALLET_OPTIONS
} from "./config";
import { ensureProtocolsReady } from "./protocols";

type EnboxContextProps = {
  auth: AuthManager | null;
  enbox?: Enbox;
  did?: string;
  delegateDid?: string;
  isConnecting: boolean;
  isConnected: boolean;
  isDelegateSession: boolean;
  protocolsInitialized: boolean;
  protocolSetupError?: string;
  connectWallet: () => Promise<void>;
  disconnect: (options?: { clearStorage?: boolean }) => Promise<void>;
};

export const EnboxContext = createContext<EnboxContextProps>({
  auth: null,
  isConnecting: false,
  isConnected: false,
  isDelegateSession: false,
  protocolsInitialized: false,
  connectWallet: () => Promise.reject(new Error("EnboxProvider not mounted")),
  disconnect: () => Promise.reject(new Error("EnboxProvider not mounted"))
});

function randomHex(byteLength: number) {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function getOrCreateVaultPassword() {
  const existing = localStorage.getItem(VAULT_PASSWORD_STORAGE_KEY);
  if (existing) {
    return existing;
  }
  const created = randomHex(32);
  localStorage.setItem(VAULT_PASSWORD_STORAGE_KEY, created);
  return created;
}

async function resolveProviderAuth(request: ProviderAuthParams): Promise<ProviderAuthResult> {
  const response = await fetch(request.authorizeUrl, { signal: AbortSignal.timeout(30_000) });
  if (!response.ok) {
    throw new Error(`Provider auth failed (${response.status}): ${await response.text()}`);
  }
  const data = await response.json() as ProviderAuthResult;
  if (data.state !== request.state) {
    throw new Error("Provider auth state mismatch");
  }
  return data;
}

async function createAuthManager(password: string) {
  return AuthManager.create({
    dataPath: AUTH_DATA_PATH,
    password,
    storage: new BrowserStorage(AUTH_STORAGE_PREFIX),
    dwnEndpoints: DWN_ENDPOINTS,
    identitySyncProtocols: IDENTITY_SYNC_PROTOCOLS,
    connectHandler: BrowserConnectHandler({
      wallets: WALLET_OPTIONS,
      appName: DAPP_NAME,
      appIcon: `${window.location.origin}/favicon.svg`
    }),
    registration: {
      onSuccess: () => console.info("[meshd-admin] DWN registration complete"),
      onFailure: (error: unknown) => console.warn("[meshd-admin] DWN registration failed:", error),
      persistTokens: true,
      onProviderAuthRequired: resolveProviderAuth
    }
  } satisfies AuthManagerOptions);
}

function isIncorrectVaultPasswordError(error: unknown) {
  return error instanceof Error
    && error.message.includes("Unable to unlock the vault due to an incorrect password");
}

async function deleteIndexedDbByNamePart(namePart: string) {
  const indexedDb = globalThis.indexedDB as (IDBFactory & {
    databases?: () => Promise<Array<{ name?: string | null }>>;
  }) | undefined;
  if (!indexedDb?.databases) {
    return;
  }

  const databases = await indexedDb.databases();
  await Promise.all(databases.map((database) => {
    if (!database.name || !database.name.includes(namePart)) {
      return Promise.resolve();
    }

    return new Promise<void>((resolve, reject) => {
      const request = indexedDb.deleteDatabase(database.name as string);
      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error ?? new Error(`Could not delete ${database.name}`));
      request.onblocked = () => resolve();
    });
  }));
}

async function resetScopedAuthStorage() {
  localStorage.removeItem(VAULT_PASSWORD_STORAGE_KEY);
  for (const key of Object.keys(localStorage)) {
    if (key.startsWith(AUTH_STORAGE_PREFIX)) {
      localStorage.removeItem(key);
    }
  }
  await deleteIndexedDbByNamePart(AUTH_DATA_PATH);
}

export const EnboxProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const authRef = useRef<AuthManager | null>(null);

  const [isConnecting, setIsConnecting] = useState(false);
  const [enbox, setEnbox] = useState<Enbox | undefined>();
  const [did, setDid] = useState<string | undefined>();
  const [delegateDid, setDelegateDid] = useState<string | undefined>();
  const [isDelegateSession, setIsDelegateSession] = useState(false);
  const [protocolsInitialized, setProtocolsInitialized] = useState(false);
  const [protocolSetupError, setProtocolSetupError] = useState<string | undefined>();

  const applySession = useCallback((session: AuthSession) => {
    const api = Enbox.fromSession(session);
    setEnbox(api);
    setDid(session.did);
    setDelegateDid(session.delegateDid);
    setIsDelegateSession(Boolean(session.delegateDid));
    setProtocolsInitialized(false);
    setProtocolSetupError(undefined);
  }, []);

  useEffect(() => {
    let cancelled = false;

    async function init() {
      setIsConnecting(true);
      try {
        const password = getOrCreateVaultPassword();
        const auth = await createAuthManager(password);
        if (cancelled) {
          return;
        }
        authRef.current = auth;
        const session = await auth.restoreSession({ password });
        if (!cancelled && session) {
          applySession(session);
        }
      } catch (error) {
        console.warn("[meshd-admin] Auth restore failed:", error);
      } finally {
        if (!cancelled) {
          setIsConnecting(false);
        }
      }
    }

    void init();
    return () => {
      cancelled = true;
    };
  }, [applySession]);

  useEffect(() => {
    if (!enbox || protocolsInitialized) {
      return;
    }

    let cancelled = false;
    setProtocolSetupError(undefined);

    ensureProtocolsReady(enbox)
      .then(() => {
        if (!cancelled) {
          setProtocolsInitialized(true);
        }
      })
      .catch((error) => {
        if (!cancelled) {
          setProtocolSetupError(error instanceof Error ? error.message : "Protocol setup failed.");
        }
      });

    return () => {
      cancelled = true;
    };
  }, [enbox, protocolsInitialized]);

  const connectWallet = useCallback(async () => {
    let auth = authRef.current;
    if (!auth) {
      throw new Error("AuthManager not ready");
    }

    setIsConnecting(true);
    try {
      try {
        const session = await auth.connect({ protocols: DAPP_PROTOCOLS });
        applySession(session);
      } catch (error) {
        if (!isIncorrectVaultPasswordError(error)) {
          throw error;
        }
        await resetScopedAuthStorage();
        const password = getOrCreateVaultPassword();
        auth = await createAuthManager(password);
        authRef.current = auth;
        const session = await auth.connect({ protocols: DAPP_PROTOCOLS });
        applySession(session);
      }
    } finally {
      setIsConnecting(false);
    }
  }, [applySession]);

  const disconnect = useCallback(async (options?: { clearStorage?: boolean }) => {
    const auth = authRef.current;
    try {
      await enbox?.disconnect();
      await auth?.disconnect({ clearStorage: options?.clearStorage });
    } finally {
      setEnbox(undefined);
      setDid(undefined);
      setDelegateDid(undefined);
      setIsDelegateSession(false);
      setProtocolsInitialized(false);
      setProtocolSetupError(undefined);
      if (options?.clearStorage) {
        await resetScopedAuthStorage();
        window.location.reload();
      }
    }
  }, [enbox]);

  return (
    <EnboxContext.Provider
      value={{
        auth: authRef.current,
        enbox,
        did,
        delegateDid,
        isConnecting,
        isConnected: Boolean(enbox),
        isDelegateSession,
        protocolsInitialized,
        protocolSetupError,
        connectWallet,
        disconnect
      }}
    >
      {children}
    </EnboxContext.Provider>
  );
};
