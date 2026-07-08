#!/usr/bin/env bun
/**
 * Selfcheck for the headless wallet approver.
 *
 * Plays the CLIENT role of the enbox-connect flow using the monorepo's own
 * `WalletConnect.initClient` (packages/auth) with a pre-supplied delegate DID
 * and meshd's wireguard-mesh protocol definition (placeholders included),
 * launches the approver against the real local relay, and asserts:
 *
 *   1. the flow completes: PAR -> wallet URI -> approver -> PIN -> response
 *      JWE decrypts (PIN-bound AAD) and its JWT verifies
 *   2. the returned grants validate (grantee == delegate, scopes are subsets
 *      of the request, revocation grants recognized) via the monorepo's own
 *      `validateConnectResultGrants`
 *   3. every requested scope got a grant; Records grants are `delegated: true`
 *      and carry per-grant session revocations
 *   4. the wireguard-mesh protocol is installed on the REMOTE dwn-server for
 *      the owner tenant with real derived `$keyAgreement` keys everywhere a
 *      type is `encryptionRequired` (placeholders replaced)
 *   5. a SECOND connect round against the same approver data dir approves as
 *      the SAME owner DID (two devices, one owner)
 *
 * Prerequisite: the enbox dev stack must be running:
 *   cd $ENBOX_REPO && bun run dev:ensure     (dwn-server + relay on :3000)
 *
 * Usage:
 *   bun scripts/e2e/selfcheck.ts [--endpoint http://localhost:3000] [--keep]
 */

import { parseArgs } from 'node:util';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { enboxRepoPath, importEnbox, importEnboxAuth } from './enbox-repo.ts';
import { findTypePaths, getStructureNode, isKeyAgreementPlaceholder } from './definition-utils.ts';

const SCRIPT_DIR = import.meta.dir;
const APPROVER = path.join(SCRIPT_DIR, 'approver.ts');
const PROTOCOL_JSON = path.resolve(SCRIPT_DIR, '..', '..', 'protocols', 'wireguard-mesh.json');
const APPROVER_PASSWORD = 'meshd-e2e-selfcheck';

// ─── CLI ────────────────────────────────────────────────────────────

const { values: cli } = parseArgs({
  args    : process.argv.slice(2),
  options : {
    'endpoint' : { type: 'string', default: 'http://localhost:3000' },
    'keep'     : { type: 'boolean', default: false },
  },
});
const endpoint = cli.endpoint!.replace(/\/+$/, '');

// ─── assertion helpers ──────────────────────────────────────────────

let checks = 0;

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) {
    throw new Error(`ASSERTION FAILED: ${message}`);
  }
  checks += 1;
  console.error(`  ok: ${message}`);
}

// ─── approver launcher ──────────────────────────────────────────────

type ApproverRun = { pin: string; ownerDid: string };

/**
 * Run the approver CLI against a wallet URI and parse its stdout contract
 * (`PIN=` / `OWNER_DID=` lines).
 */
async function runApprover(walletUri: string, dataDir: string): Promise<ApproverRun> {
  const pinFile = path.join(dataDir, '..', `pin-${Date.now()}.txt`);
  const proc = Bun.spawn({
    cmd: [
      'bun', APPROVER,
      '--uri', walletUri,
      '--data', dataDir,
      '--password', APPROVER_PASSWORD,
      '--endpoint', endpoint,
      '--pin-file', pinFile,
    ],
    stdout : 'pipe',
    stderr : 'inherit',
    env    : { ...process.env },
  });

  const stdout = await new Response(proc.stdout).text();
  const exitCode = await proc.exited;

  if (exitCode !== 0) {
    throw new Error(`approver exited with code ${exitCode}; stdout:\n${stdout}`);
  }

  const pin = /^PIN=(\d{3,10})$/m.exec(stdout)?.[1];
  const ownerDid = /^OWNER_DID=(\S+)$/m.exec(stdout)?.[1];
  if (!pin || !ownerDid) {
    throw new Error(`approver stdout missing PIN=/OWNER_DID= lines:\n${stdout}`);
  }

  // The --pin-file copy must match the stdout contract.
  const fileContents = await readFile(pinFile, 'utf8');
  assert(
    fileContents === `PIN=${pin}\nOWNER_DID=${ownerDid}\n`,
    'approver --pin-file matches the stdout contract',
  );

  return { pin, ownerDid };
}

// ─── one connect round (client role) ────────────────────────────────

type RoundOutcome = {
  result: any;          // WalletConnect.initClient result
  ownerDid: string;     // owner DID reported by the approver
};

async function runConnectRound(params: {
  WalletConnect: any;
  permissionRequests: any[];
  dataDir: string;
  label: string;
}): Promise<RoundOutcome> {
  const { WalletConnect, permissionRequests, dataDir, label } = params;

  let approverRun: Promise<ApproverRun> | undefined;

  console.error(`--- ${label}: starting connect flow ---`);
  const result = await WalletConnect.initClient({
    displayName          : 'meshd e2e selfcheck',
    clientMetadata       : { origin: 'meshd-e2e-selfcheck' },
    preSupplyDelegateDid : true,
    connectServerUrl     : `${endpoint}/connect`,
    // Only the fragment params matter to the approver; the wallet page itself
    // is never fetched.
    walletUri            : 'https://wallet.invalid/connect/app',
    permissionRequests,
    onWalletUriReady     : (uri: string) => {
      console.error(`${label}: wallet URI ready; launching approver`);
      approverRun = runApprover(uri, dataDir);
      // Surface approver failures immediately instead of waiting for the
      // 3-minute relay poll timeout.
      approverRun.catch(() => {});
    },
    validatePin: async () => {
      const { pin } = await approverRun!;
      console.error(`${label}: approver returned PIN ${pin}`);
      return pin;
    },
    timeoutMs      : 180_000,
    pollIntervalMs : 1_000,
  });

  const { ownerDid } = await approverRun!;
  assert(result !== undefined, `${label}: wallet responded (request not denied / timed out)`);
  return { result, ownerDid };
}

// ─── grant shape assertions ─────────────────────────────────────────

function assertGrantShapes(params: {
  label: string;
  agentPkg: any;
  result: any;
  ownerDid: string;
  permissionRequests: any[];
  protocolUri: string;
}): void {
  const { label, agentPkg, result, ownerDid, permissionRequests, protocolUri } = params;
  const { DwnPermissionGrant } = agentPkg;

  const delegateDid = result.delegatePortableDid.uri;
  assert(
    result.connectedDid === ownerDid,
    `${label}: connectedDid (${result.connectedDid}) == approver OWNER_DID`,
  );
  assert(
    result.delegatePortableDid.privateKeys?.some((k: any) => k.crv === 'Ed25519') &&
    result.delegatePortableDid.privateKeys?.some((k: any) => k.crv === 'X25519'),
    `${label}: pre-supplied delegate portable DID retains Ed25519 + X25519 private keys`,
  );

  const grants = result.delegateGrants.map((message: any) => DwnPermissionGrant.parse(message));

  // Every requested scope must be covered by a grant to the delegate.
  const requestedScopes = permissionRequests.flatMap((request: any) => request.permissionScopes);
  for (const scope of requestedScopes) {
    const match = grants.find((grant: any) =>
      grant.grantee === delegateDid &&
      grant.scope.interface === scope.interface &&
      grant.scope.method === scope.method &&
      grant.scope.protocol === scope.protocol,
    );
    assert(match, `${label}: grant covers requested scope ${scope.interface}.${scope.method}`);
    if (scope.interface === 'Records') {
      assert(
        match.delegated === true,
        `${label}: Records.${scope.method} grant is delegated:true`,
      );
    }
  }

  // Session revocations: the wallet creates one contextId-scoped revocation
  // grant per session grant (i.e. per requested scope).
  assert(
    (result.sessionRevocations?.length ?? 0) === requestedScopes.length,
    `${label}: ${requestedScopes.length} session revocation(s) returned`,
  );
  for (const revocation of result.sessionRevocations ?? []) {
    const revGrant = grants.find((grant: any) => grant.id === revocation.revocationGrantId);
    assert(
      revGrant && revGrant.scope.contextId === revocation.grantId,
      `${label}: revocation grant ${revocation.revocationGrantId.slice(0, 10)}… is contextId-scoped to its grant`,
    );
  }

  // Total: requested scopes + one revocation grant per session grant.
  assert(
    grants.length === requestedScopes.length * 2,
    `${label}: grant count is ${requestedScopes.length} scopes + ${requestedScopes.length} revocations`,
  );

  assert(
    grants.every((grant: any) => grant.grantor === ownerDid),
    `${label}: every grant is authored by the owner`,
  );

  // Sanity: the requested protocol appears in the granted scopes.
  assert(
    grants.some((grant: any) => grant.scope.protocol === protocolUri),
    `${label}: grants reference ${protocolUri}`,
  );
}

// ─── remote protocol install assertions ─────────────────────────────

async function assertRemoteProtocolInstalled(params: {
  label: string;
  ownerDid: string;
  requestedDefinition: any;
}): Promise<void> {
  const { label, ownerDid, requestedDefinition } = params;
  const protocolUri = requestedDefinition.protocol;

  const encoded = Buffer.from(protocolUri, 'utf8').toString('base64url');
  const response = await fetch(`${endpoint}/${ownerDid}/read/protocols/${encoded}`);
  assert(
    response.status === 200,
    `${label}: remote dwn-server has ${protocolUri} installed for the owner tenant`,
  );

  const entry: any = await response.json();
  const installed = entry?.descriptor?.definition;
  assert(installed?.protocol === protocolUri, `${label}: installed definition parses`);

  // Every encryptionRequired type path must carry a REAL derived key.
  for (const [typeName, typeDef] of Object.entries(requestedDefinition.types ?? {})) {
    if (!(typeDef as any)?.encryptionRequired) {
      continue;
    }
    for (const protocolPath of findTypePaths(requestedDefinition.structure, typeName)) {
      const node = getStructureNode(installed.structure, protocolPath);
      assert(
        node?.$keyAgreement !== undefined && !isKeyAgreementPlaceholder(node.$keyAgreement),
        `${label}: installed '${protocolPath}' has a derived $keyAgreement key`,
      );
    }
  }

  // No placeholder (empty publicKeyJwk) $keyAgreement nodes may remain.
  let placeholders = 0;
  const walk = (node: any): void => {
    if (node === null || typeof node !== 'object' || Array.isArray(node)) {
      return;
    }
    if ('$keyAgreement' in node && isKeyAgreementPlaceholder(node.$keyAgreement)) {
      placeholders += 1;
    }
    for (const [key, child] of Object.entries(node)) {
      if (!key.startsWith('$')) {
        walk(child);
      }
    }
  };
  walk(installed.structure);
  assert(placeholders === 0, `${label}: no placeholder $keyAgreement nodes remain on the server`);
}

// ─── main ───────────────────────────────────────────────────────────

async function main(): Promise<void> {
  // 0. Stack reachability.
  let serverInfo: any;
  try {
    const response = await fetch(`${endpoint}/info`, { signal: AbortSignal.timeout(5_000) });
    serverInfo = await response.json();
  } catch {
    throw new Error(
      `no dwn-server reachable at ${endpoint}. ` +
      `Start the enbox dev stack: cd $ENBOX_REPO && bun run dev:ensure ` +
      `(if ports are busy, check: bun run dev:status)`,
    );
  }
  assert(serverInfo?.server === '@enbox/dwn-server', `dev stack is up at ${endpoint} (GET /info)`);

  const repo = enboxRepoPath();
  const { agent: agentPkg } = await importEnbox(repo);
  const { auth, validateGrants } = await importEnboxAuth(repo);
  const { WalletConnect } = auth;

  // Requested protocol: meshd's real wireguard-mesh definition, WITH its
  // $keyAgreement placeholders — proving the approver strips + reinjects.
  const definition = JSON.parse(await readFile(PROTOCOL_JSON, 'utf8'));
  const permissionRequests = [
    WalletConnect.createPermissionRequestForProtocol({
      definition,
      permissions: ['read', 'write', 'delete'],
    }),
  ];

  const tempDir = await mkdtemp(path.join(os.tmpdir(), 'meshd-e2e-selfcheck-'));
  const dataDir = path.join(tempDir, 'approver-data');
  console.error(`selfcheck: approver data dir: ${dataDir}`);

  try {
    // Round 1: fresh owner.
    const round1 = await runConnectRound({
      WalletConnect, permissionRequests, dataDir, label: 'round1',
    });
    validateGrants.validateConnectResultGrants(round1.result, permissionRequests);
    assert(true, 'round1: validateConnectResultGrants (monorepo validator) passed');
    assertGrantShapes({
      label       : 'round1',
      agentPkg,
      result      : round1.result,
      ownerDid    : round1.ownerDid,
      permissionRequests,
      protocolUri : definition.protocol,
    });
    await assertRemoteProtocolInstalled({
      label               : 'round1',
      ownerDid            : round1.ownerDid,
      requestedDefinition : definition,
    });

    // Round 2: same approver data dir — the owner must persist.
    const round2 = await runConnectRound({
      WalletConnect, permissionRequests, dataDir, label: 'round2',
    });
    validateGrants.validateConnectResultGrants(round2.result, permissionRequests);
    assert(true, 'round2: validateConnectResultGrants (monorepo validator) passed');
    assert(
      round2.ownerDid === round1.ownerDid,
      'round2: same owner DID as round1 (persistent owner across invocations)',
    );
    assert(
      round2.result.delegatePortableDid.uri !== round1.result.delegatePortableDid.uri,
      'round2: fresh delegate DID (new device) under the same owner',
    );

    console.error(`\nselfcheck: PASS (${checks} assertions)`);
  } finally {
    if (cli.keep) {
      console.error(`selfcheck: keeping ${tempDir}`);
    } else {
      await rm(tempDir, { recursive: true, force: true });
    }
  }
}

main()
  .then(() => process.exit(0))
  .catch((error: unknown) => {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`\nselfcheck: FAIL: ${message}`);
    if (process.env.DEBUG && error instanceof Error) {
      console.error(error.stack);
    }
    process.exit(1);
  });
