/**
 * Shared helper for importing @enbox packages from a local checkout of the
 * enbox monorepo (https://github.com/enboxorg/enbox).
 *
 * The monorepo is treated as a read-only import source. Packages are imported
 * by absolute path from their built `dist/esm` entry points so that every
 * script in this directory shares a single, consistent module graph (the same
 * files the packages resolve between themselves through their workspace
 * symlinks).
 *
 * The repo location is taken from the `ENBOX_REPO` environment variable and
 * defaults to `~/src/enboxorg/enbox`.
 */

import { existsSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

/** Resolve and validate the enbox monorepo checkout. */
export function enboxRepoPath(): string {
  const repo = process.env.ENBOX_REPO ?? path.join(os.homedir(), 'src', 'enboxorg', 'enbox');

  if (!existsSync(path.join(repo, 'packages', 'agent', 'package.json'))) {
    throw new Error(
      `enbox monorepo not found at '${repo}'. ` +
      `Clone https://github.com/enboxorg/enbox and/or set ENBOX_REPO to its path.`,
    );
  }

  if (!existsSync(path.join(repo, 'packages', 'agent', 'dist', 'esm', 'index.js'))) {
    throw new Error(
      `enbox monorepo at '${repo}' has no build output. ` +
      `Run: cd ${repo} && bun install && bun run build`,
    );
  }

  return repo;
}

/** Modules needed by the approver (wallet/provider role). */
export type EnboxModules = {
  /** `@enbox/agent` — EnboxUserAgent, EnboxConnectProtocol, DwnInterface, ... */
  agent: any;
  /** `@enbox/dids` — DidJwk, ... */
  dids: any;
  /** `@enbox/crypto` — CryptoUtils, Ed25519, ... */
  crypto: any;
  /** `@enbox/dwn-clients` — DwnRegistrar, ... */
  dwnClients: any;
};

/** Import the monorepo packages used by the approver. */
export async function importEnbox(repo: string): Promise<EnboxModules> {
  const entry = (pkg: string) => path.join(repo, 'packages', pkg, 'dist', 'esm', 'index.js');

  const [agent, dids, crypto, dwnClients] = await Promise.all([
    import(entry('agent')),
    import(entry('dids')),
    import(entry('crypto')),
    import(entry('dwn-clients')),
  ]);

  return { agent, dids, crypto, dwnClients };
}

/** Additional modules used by the selfcheck (app/client role). */
export type EnboxAuthModules = {
  /** `@enbox/auth` — WalletConnect, ... */
  auth: any;
  /** `@enbox/auth` internal `connect/validate-grants` module. */
  validateGrants: any;
};

/** Import the auth-side monorepo modules used by the selfcheck. */
export async function importEnboxAuth(repo: string): Promise<EnboxAuthModules> {
  const [auth, validateGrants] = await Promise.all([
    import(path.join(repo, 'packages', 'auth', 'dist', 'esm', 'index.js')),
    import(path.join(repo, 'packages', 'auth', 'dist', 'esm', 'connect', 'validate-grants.js')),
  ]);

  return { auth, validateGrants };
}
