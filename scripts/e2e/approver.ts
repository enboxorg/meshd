#!/usr/bin/env bun
/**
 * Headless wallet approver for meshd's enbox-connect e2e tests.
 *
 * Stands in for the Enbox web wallet: given a wallet URI (containing
 * `request_uri` + `encryption_key`), it fetches the connect request from the
 * relay, approves it as a persistent "owner" identity, and prints the PIN.
 *
 * It replicates the web wallet's approval flow at monorepo HEAD:
 *   1. fetch + decrypt + verify the connect request
 *      (`EnboxConnectProtocol.getConnectRequest`)
 *   2. install every requested protocol definition on the owner tenant —
 *      local agent DWN AND every remote DWN endpoint — with `encryption: true`
 *      when any type declares `encryptionRequired` (wallet `prepareProtocol`)
 *   3. generate a 4-digit PIN (`CryptoUtils.randomPin`)
 *   4. `EnboxConnectProtocol.submitConnectResponse(ownerDid, request, pin,
 *      agent)` — creates the delegated grants + grantKey records + per-grant
 *      revocation grants, fans them out to the owner DWN endpoints, and POSTs
 *      the PIN-bound encrypted response to the relay callback
 *
 * The owner identity is a did:jwk (hermetic: self-resolving, no DHT) with the
 * Ed25519->X25519 converted key imported into the agent KMS so protocol
 * encryption ($keyAgreement derivation, grantKey subtree keys) works. It is
 * persisted in the --data directory, so a second invocation approves as the
 * SAME owner (two devices, one owner).
 *
 * Usage:
 *   bun scripts/e2e/approver.ts --uri '<wallet URI>' \
 *     [--data <dir>] [--password <pw>] [--endpoint <dwn url>] [--pin-file <path>]
 *
 * stdout contract (everything else goes to stderr):
 *   PIN=<4 digits>
 *   OWNER_DID=<did:jwk:...>
 *
 * Exit codes: 0 success, 1 failure, 2 usage error.
 */

import { parseArgs } from 'node:util';
import path from 'node:path';

import { enboxRepoPath, importEnbox } from './enbox-repo.ts';
import {
  definitionsMatch,
  hasEncryptedTypes,
  hasEncryptionKeysInstalled,
  stripKeyAgreementPlaceholders,
} from './definition-utils.ts';

// ─── stdout hygiene ─────────────────────────────────────────────────
//
// The enbox packages log through @enbox/common's logger, which writes to
// console.info/console.log (stdout). Reroute everything to stderr so stdout
// carries only the machine-readable PIN=/OWNER_DID= lines.

const stdoutWrite = process.stdout.write.bind(process.stdout);
for (const method of ['log', 'info', 'debug'] as const) {
  // eslint-disable-next-line no-console
  console[method] = (...args: unknown[]) => console.error(...args);
}

/** Write a machine-readable line to the real stdout. */
function emit(line: string): void {
  stdoutWrite(`${line}\n`);
}

// ─── CLI ────────────────────────────────────────────────────────────

const USAGE = `Usage: bun scripts/e2e/approver.ts --uri '<wallet URI>' [options]

Approves an enbox-connect request as a persistent headless wallet owner.

Options:
  --uri <uri>        Wallet URI containing request_uri + encryption_key (required)
  --data <dir>       Agent data directory (default: .e2e-approver)
  --password <pw>    Vault password (default: meshd-e2e-approver)
  --endpoint <url>   DWN server / relay endpoint (default: http://localhost:3000)
  --pin-file <path>  Also write the PIN=/OWNER_DID= lines to this file
  --owner-name <s>   Identity metadata name for the owner (default: meshd-e2e-owner)
  --help             Show this help

Environment:
  ENBOX_REPO         Path to the enbox monorepo checkout (default: ~/src/enboxorg/enbox)`;

type Cli = {
  uri: string;
  data: string;
  password: string;
  endpoint: string;
  pinFile?: string;
  ownerName: string;
};

function parseCli(argv: string[]): Cli {
  const { values } = parseArgs({
    args    : argv,
    options : {
      'uri'        : { type: 'string' },
      'data'       : { type: 'string', default: '.e2e-approver' },
      'password'   : { type: 'string', default: 'meshd-e2e-approver' },
      'endpoint'   : { type: 'string', default: 'http://localhost:3000' },
      'pin-file'   : { type: 'string' },
      'owner-name' : { type: 'string', default: 'meshd-e2e-owner' },
      'help'       : { type: 'boolean', default: false },
    },
  });

  if (values.help) {
    emit(USAGE);
    process.exit(0);
  }

  if (!values.uri) {
    console.error('approver: missing required --uri\n');
    console.error(USAGE);
    process.exit(2);
  }

  return {
    uri       : values.uri,
    data      : path.resolve(values.data!),
    password  : values.password!,
    endpoint  : values.endpoint!.replace(/\/+$/, ''),
    pinFile   : values['pin-file'],
    ownerName : values['owner-name']!,
  };
}

// ─── wallet URI parsing ─────────────────────────────────────────────

/**
 * Extract `request_uri` and `encryption_key` from a wallet URI. Parses the
 * query string manually so custom schemes (`enbox://connect?...`) work the
 * same as https wallet URLs.
 */
function parseWalletUri(uri: string): { requestUri: string; encryptionKey: string } {
  const queryIndex = uri.indexOf('?');
  if (queryIndex === -1) {
    throw new Error(`wallet URI has no query string: ${uri}`);
  }

  const params = new URLSearchParams(uri.slice(queryIndex + 1));
  const requestUri = params.get('request_uri');
  const encryptionKey = params.get('encryption_key');

  if (!requestUri || !encryptionKey) {
    throw new Error('wallet URI is missing request_uri and/or encryption_key');
  }

  return { requestUri, encryptionKey };
}

// ─── wallet-side protocol install ───────────────────────────────────

/**
 * Ensure the requested protocol is installed on the owner tenant, locally and
 * on every owner DWN endpoint (mirrors the web wallet's `prepareProtocol`).
 *
 * A failure to reach `primaryEndpoint` is fatal — that is the DWN server the
 * meshd client reads from. Other endpoints are best-effort (sync would
 * deliver eventually), matching wallet behavior.
 */
async function prepareProtocol(params: {
  agent: any;
  DwnInterface: any;
  ownerDid: string;
  definition: any;
  primaryEndpoint: string;
}): Promise<void> {
  const { agent, DwnInterface, ownerDid, definition, primaryEndpoint } = params;

  const query = await agent.processDwnRequest({
    author        : ownerDid,
    target        : ownerDid,
    messageType   : DwnInterface.ProtocolsQuery,
    messageParams : { filter: { protocol: definition.protocol } },
  });
  if (query.reply.status.code !== 200) {
    throw new Error(`ProtocolsQuery for '${definition.protocol}' failed: ${query.reply.status.detail}`);
  }

  const installedEntry = query.reply.entries?.[0];
  const installed = installedEntry?.descriptor?.definition;
  const needsEncryption = hasEncryptedTypes(definition);

  const isConfigured = installed !== undefined
    && definitionsMatch(installed, definition)
    && (!needsEncryption || hasEncryptionKeysInstalled(installed, definition));

  let configureMessage: any;
  if (isConfigured) {
    console.error(`approver: protocol already configured: ${definition.protocol}`);
    configureMessage = installedEntry;
  } else {
    console.error(
      `approver: configuring protocol ${definition.protocol}` +
      `${needsEncryption ? ' (with encryption keys)' : ''}`,
    );
    const configure = await agent.processDwnRequest({
      author        : ownerDid,
      target        : ownerDid,
      messageType   : DwnInterface.ProtocolsConfigure,
      messageParams : { definition },
      encryption    : needsEncryption || undefined,
    });
    if (configure.reply.status.code !== 202 && configure.reply.status.code !== 409) {
      throw new Error(
        `ProtocolsConfigure for '${definition.protocol}' failed locally: ${configure.reply.status.detail}`,
      );
    }
    configureMessage = configure.message;
  }

  // Fan out the configure message to every owner DWN endpoint.
  const endpoints: string[] = await agent.dwn.getDwnEndpointUrlsForTarget(ownerDid);
  for (const dwnUrl of endpoints) {
    const isPrimary = dwnUrl.replace(/\/+$/, '') === primaryEndpoint;
    try {
      const reply = await agent.rpc.sendDwnRequest({
        dwnUrl,
        targetDid : ownerDid,
        message   : configureMessage,
      });
      if (reply.status.code !== 202 && reply.status.code !== 409) {
        const detail = `endpoint ${dwnUrl} rejected protocol '${definition.protocol}': ` +
          `${reply.status.code} ${reply.status.detail}`;
        if (isPrimary) {
          throw new Error(detail);
        }
        console.error(`approver: warning: ${detail}`);
      }
    } catch (error) {
      if (isPrimary) {
        throw error;
      }
      console.error(`approver: warning: failed to send protocol to ${dwnUrl}: ${String(error)}`);
    }
  }
}

// ─── owner identity ─────────────────────────────────────────────────

/**
 * Find (by metadata name) or create the persistent owner identity.
 *
 * The owner is a did:jwk — self-resolving, so the local dwn-server can verify
 * its signatures without any DHT/network dependency. did:jwk only carries a
 * single Ed25519 verification method, so the X25519 key needed for DWN
 * encryption is derived via the standard Ed25519->X25519 conversion and
 * imported into the agent KMS alongside the signing key (the same pattern the
 * wallet uses for delegate DIDs).
 */
async function findOrCreateOwner(params: {
  agent: any;
  dids: any;
  crypto: any;
  ownerName: string;
}): Promise<{ ownerDid: string; created: boolean }> {
  const { agent, dids, crypto, ownerName } = params;

  const identities = await agent.identity.list();
  const existing = identities.find(
    (identity: any) => identity.metadata.name === ownerName && !identity.metadata.connectedDid,
  );
  if (existing) {
    return { ownerDid: existing.did.uri, created: false };
  }

  const bearerDid = await dids.DidJwk.create();
  const portableDid = await bearerDid.export();

  const edPrivateKey = portableDid.privateKeys?.[0];
  if (!edPrivateKey) {
    throw new Error('DidJwk.create() returned no private key material');
  }
  const x25519PrivateKey = await crypto.Ed25519.convertPrivateKeyToX25519({ privateKey: edPrivateKey });
  portableDid.privateKeys.push(x25519PrivateKey);

  const identity = await agent.identity.import({
    portableIdentity: {
      portableDid,
      metadata: {
        name   : ownerName,
        uri    : portableDid.uri,
        tenant : agent.agentDid.uri,
      },
    },
  });

  return { ownerDid: identity.did.uri, created: true };
}

// ─── main ───────────────────────────────────────────────────────────

async function main(): Promise<void> {
  const cli = parseCli(process.argv.slice(2));
  const repo = enboxRepoPath();
  const { agent: agentPkg, dids, crypto, dwnClients } = await importEnbox(repo);
  const { EnboxUserAgent, EnboxConnectProtocol, DwnInterface } = agentPkg;

  // 1. Open (or create) the persistent agent.
  const agent = await EnboxUserAgent.create({ dataPath: cli.data });
  try {
    if (await agent.firstLaunch()) {
      console.error(`approver: initializing new agent vault at ${cli.data}`);
      await agent.initialize({ password: cli.password, dwnEndpoints: [cli.endpoint] });
    }
    await agent.start({ password: cli.password });

    // 2. Point the agent's local-DWN discovery at the e2e dwn-server so
    //    owner DWN endpoint resolution returns it (did:jwk documents carry
    //    no #dwn service). Validates the server via GET /info.
    const endpointOk = await agent.dwn.setCachedLocalDwnEndpoint(cli.endpoint);
    if (!endpointOk) {
      throw new Error(
        `no @enbox/dwn-server reachable at ${cli.endpoint} (GET /info failed). ` +
        `Start the enbox dev stack: cd $ENBOX_REPO && bun run dev:ensure`,
      );
    }

    // 3. Find or create the persistent owner identity.
    const { ownerDid, created } = await findOrCreateOwner({
      agent, dids, crypto, ownerName: cli.ownerName,
    });
    console.error(`approver: owner ${created ? 'created' : 'reused'}: ${ownerDid}`);

    // 4. Register the owner tenant on the endpoint when the server requires
    //    it (PoW path). The local dev server is open (no requirements).
    const serverInfo = await agent.rpc.getServerInfo(cli.endpoint);
    if (serverInfo.registrationRequirements?.length > 0) {
      console.error(
        `approver: registering tenant (requirements: ${serverInfo.registrationRequirements.join(', ')})`,
      );
      await dwnClients.DwnRegistrar.registerTenant(cli.endpoint, ownerDid);
    }

    // 5. Fetch, decrypt, and verify the connect request.
    const { requestUri, encryptionKey } = parseWalletUri(cli.uri);
    console.error(`approver: fetching connect request from ${requestUri}`);
    const request = await EnboxConnectProtocol.getConnectRequest(requestUri, encryptionKey);
    console.error(
      `approver: request from app '${request.appName}' (client ${request.clientDid}), ` +
      `${request.permissionRequests.length} protocol(s), delegate ${request.delegateDid ?? '<wallet-minted>'}`,
    );

    // 6. Strip placeholder $keyAgreement nodes from the requested protocol
    //    definitions; the agent injects owner-derived keys during configure.
    for (const permissionRequest of request.permissionRequests) {
      const stripped = stripKeyAgreementPlaceholders(permissionRequest.protocolDefinition);
      if (stripped > 0) {
        console.error(
          `approver: stripped ${stripped} placeholder $keyAgreement node(s) from ` +
          `${permissionRequest.protocolDefinition.protocol}`,
        );
      }
    }

    // 7. Install the requested protocols on the owner tenant (local + remote).
    for (const permissionRequest of request.permissionRequests) {
      await prepareProtocol({
        agent,
        DwnInterface,
        ownerDid,
        definition      : permissionRequest.protocolDefinition,
        primaryEndpoint : cli.endpoint,
      });
    }

    // 8. Approve: grants + grantKey records + revocations + encrypted
    //    response POSTed to the relay callback.
    const pin = crypto.CryptoUtils.randomPin({ length: 4 });
    console.error('approver: submitting connect response...');
    await EnboxConnectProtocol.submitConnectResponse(ownerDid, request, pin, agent);

    // 9. Report.
    const output = `PIN=${pin}\nOWNER_DID=${ownerDid}\n`;
    emit(`PIN=${pin}`);
    emit(`OWNER_DID=${ownerDid}`);
    if (cli.pinFile) {
      await Bun.write(cli.pinFile, output);
    }
    console.error('approver: done');
  } finally {
    await agent.shutdown();
  }
}

main()
  .then(() => process.exit(0))
  .catch((error: unknown) => {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`approver: FAILED: ${message}`);
    if (process.env.DEBUG && error instanceof Error) {
      console.error(error.stack);
    }
    process.exit(1);
  });
