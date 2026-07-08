/**
 * Harness for the meshd crypto-fixture generator.
 *
 * Loads the @enbox monorepo packages by absolute path (env ENBOX_REPO),
 * spins up a REAL in-process DWN (level stores in a throwaway temp dir),
 * and provides:
 *   - did:jwk identity factory (Ed25519 signing + Ed25519→X25519 encryption root,
 *     exactly like the enbox agent treats did:jwk identities)
 *   - a minimal EnboxPlatformAgent stand-in ("mini agent") whose
 *     processDwnRequest/keyManager/did surfaces are backed by the real DWN and
 *     raw keys, so genuine `packages/agent` functions (createAudienceRecord,
 *     createAudienceDeliveryRecord, createGrantKeyRecordsForGrants) run
 *     unmodified and their records are server-validated
 *   - small helpers for protocol install and (encrypted) record writes
 *
 * Run with bun. All fixture records processed through `dwn.processMessage`
 * are genuine, server-validated SDK output.
 */

import { execSync } from 'node:child_process';
import { homedir, tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { mkdtempSync, rmSync } from 'node:fs';

export const ENBOX_REPO = resolve(process.env.ENBOX_REPO ?? join(homedir(), 'src/enboxorg/enbox'));

export type Identity = {
  label: string;
  did: string;
  keyId: string; // fully-qualified verification method id (did:jwk:...#0)
  bearer: any; // BearerDid (for EnboxConnectProtocol.signJwt / deriveSharedKey)
  signer: any; // dwn-sdk-js MessageSigner (EdDSA)
  edPrivateJwk: any; // Ed25519 signing private JWK
  edPublicJwk: any; // Ed25519 signing public JWK
  encPrivateJwk: any; // X25519 encryption ROOT private JWK (Ed25519→X25519 conversion)
  encPublicJwk: any; // X25519 encryption ROOT public JWK
  encKeyThumbprint: string; // RFC 7638 thumbprint of encPublicJwk
};

export type Harness = Awaited<ReturnType<typeof createHarness>>;

export async function createHarness() {
  // ---------------------------------------------------------------------
  // Load monorepo modules by absolute path. Direct imports use the package
  // SOURCE at HEAD; the agent package's own imports of `@enbox/dwn-sdk-js`
  // etc. resolve to the workspace dist builds, so those must be freshly
  // built (see README). We hard-probe a HEAD-only marker symbol below.
  // ---------------------------------------------------------------------
  const sdk = await import(join(ENBOX_REPO, 'packages/dwn-sdk-js/src/index.ts'));
  const level = await import(join(ENBOX_REPO, 'packages/dwn-sdk-js/src/store/level.ts'));
  const dids = await import(join(ENBOX_REPO, 'packages/dids/src/index.ts'));
  const crypto = await import(join(ENBOX_REPO, 'packages/crypto/src/index.ts'));
  const agentEnc = await import(join(ENBOX_REPO, 'packages/agent/src/dwn-encryption.ts'));
  const connect = await import(join(ENBOX_REPO, 'packages/agent/src/enbox-connect-protocol.ts'));

  // Dist freshness probe: WRAPPED_GRANT_KEY_FORMAT only exists at monorepo
  // HEAD (enbox #1189). If the workspace dist is stale, the agent package
  // would silently use outdated wire logic — refuse to generate.
  const distSdk = await import(join(ENBOX_REPO, 'packages/dwn-sdk-js/dist/esm/src/index.js')).catch(() => undefined);
  if (distSdk?.WRAPPED_GRANT_KEY_FORMAT !== sdk.WRAPPED_GRANT_KEY_FORMAT) {
    throw new Error(
      'stale @enbox/dwn-sdk-js dist build detected. Run:\n' +
      `  cd ${ENBOX_REPO} && bunx turbo run build --filter=@enbox/agent\n` +
      'then re-run this generator.'
    );
  }

  const sdkCommit = execSync(`git -C ${ENBOX_REPO} rev-parse HEAD`).toString().trim();

  // ---------------------------------------------------------------------
  // Real in-process DWN over level stores in a throwaway temp dir.
  // One DWN hosts every fixture tenant (tenancy is per processMessage call).
  // ---------------------------------------------------------------------
  const storeDir = mkdtempSync(join(tmpdir(), 'meshd-fixture-dwn-'));
  const wakePublisher = new sdk.EventEmitterWakePublisher();
  const messageStore = new level.MessageStoreLevel({ location: join(storeDir, 'MESSAGESTORE'), wakePublisher });
  const dataStore = new level.DataStoreLevel({ blockstoreLocation: join(storeDir, 'DATASTORE') });
  const resumableTaskStore = new level.ResumableTaskStoreLevel({ location: join(storeDir, 'TASKSTORE') });
  const eventLog = new sdk.DurableEventLog(messageStore, wakePublisher, { idleRedrainIntervalMs: 0 });
  const didResolver = new dids.UniversalResolver({ didResolvers: [dids.DidJwk], cache: new dids.DidResolverCacheMemory() });
  const dwn = await sdk.Dwn.create({ didResolver, messageStore, dataStore, eventLog, resumableTaskStore });

  async function close(): Promise<void> {
    await dwn.close();
    rmSync(storeDir, { recursive: true, force: true });
  }

  // ---------------------------------------------------------------------
  // Identities
  // ---------------------------------------------------------------------
  async function makeIdentity(label: string): Promise<Identity> {
    const bearer = await dids.DidJwk.create(); // Ed25519 by default
    const portable = await bearer.export();
    const edPrivateJwk = portable.privateKeys![0];
    const vm = bearer.document.verificationMethod![0];
    const keyId = vm.id;
    const edPublicJwk = vm.publicKeyJwk;
    // The agent derives a did:jwk identity's encryption root by converting its
    // Ed25519 key to X25519 (packages/agent/src/dwn-encryption.ts getEncryptionKeyInfo).
    const encPrivateJwk = await crypto.Ed25519.convertPrivateKeyToX25519({ privateKey: edPrivateJwk });
    const encPublicJwk = await crypto.X25519.getPublicKey({ key: encPrivateJwk });
    const encKeyThumbprint = await crypto.computeJwkThumbprint({ jwk: encPublicJwk });
    const signer = new sdk.PrivateKeySigner({ privateJwk: edPrivateJwk, keyId, algorithm: 'EdDSA' });
    return {
      label, did: bearer.uri, keyId, bearer, signer,
      edPrivateJwk, edPublicJwk, encPrivateJwk, encPublicJwk, encKeyThumbprint,
    };
  }

  // ---------------------------------------------------------------------
  // Mini agent: the exact surface used by the genuine agent functions
  // (createAudienceRecord / createAudienceDeliveryRecord /
  // createGrantKeyRecordsForGrants), backed by the real DWN + raw keys.
  // Mirrors AgentDwnApi.constructDwnMessage's RecordsWrite handling:
  // compute dataCid/dataSize from the data stream, create with the author's
  // signer, process against the target tenant.
  // ---------------------------------------------------------------------
  function makeMiniAgent(identities: Identity[]) {
    const byDid = new Map(identities.map((identity) => [identity.did, identity]));
    const encRootByKeyUri = new Map(identities.map((identity) => [
      `urn:jwk:${identity.encKeyThumbprint}`, identity.encPrivateJwk,
    ]));

    return {
      did: {
        resolve: (didUri: string) => didResolver.resolve(didUri),
      },
      keyManager: {
        getKeyUri: async ({ key }: { key: any }) => `urn:jwk:${await crypto.computeJwkThumbprint({ jwk: key })}`,
        derivePrivateKeyBytes: async ({ keyUri, derivationPath }: { keyUri: string; derivationPath: string[] }) => {
          const rootPrivateJwk = encRootByKeyUri.get(keyUri);
          if (rootPrivateJwk === undefined) {
            throw new Error(`mini-agent: unknown keyUri '${keyUri}'`);
          }
          const rootBytes = await crypto.X25519.privateKeyToBytes({ privateKey: rootPrivateJwk });
          if (!derivationPath || derivationPath.length === 0) {
            return rootBytes;
          }
          return sdk.HdKey.derivePrivateKeyBytes(rootBytes, derivationPath);
        },
      },
      processDwnRequest: async (request: any) => {
        if (request.messageType !== 'RecordsWrite') {
          throw new Error(`mini-agent: unsupported messageType '${request.messageType}'`);
        }
        const identity = byDid.get(request.author);
        if (identity === undefined) {
          throw new Error(`mini-agent: unknown author '${request.author}'`);
        }
        const params: any = { ...request.messageParams };
        let dataBytes: Uint8Array | undefined;
        if (request.dataStream !== undefined && params.data === undefined) {
          dataBytes = request.dataStream instanceof Blob
            ? new Uint8Array(await request.dataStream.arrayBuffer())
            : await sdk.DataStream.toBytes(request.dataStream);
          params.dataCid ??= await sdk.Cid.computeDagPbCidFromBytes(dataBytes);
          params.dataSize ??= dataBytes.length;
        }
        const recordsWrite = await sdk.RecordsWrite.create({ ...params, signer: identity.signer });
        const reply = await dwn.processMessage(
          request.target,
          recordsWrite.message,
          dataBytes !== undefined ? { dataStream: sdk.DataStream.fromBytes(dataBytes) } : undefined,
        );
        return { reply, message: recordsWrite.message };
      },
    };
  }

  // ---------------------------------------------------------------------
  // Record helpers (direct SDK; every write is processed by the real DWN)
  // ---------------------------------------------------------------------
  function expectStatus(reply: any, expected: number, what: string): void {
    if (reply.status.code !== expected) {
      throw new Error(`${what}: expected ${expected}, got ${reply.status.code} ${reply.status.detail ?? ''}`);
    }
  }

  /** Installs a protocol with $keyAgreement keys injected from the identity's X25519 root. */
  async function installEncryptedProtocol(identity: Identity, definition: any): Promise<any> {
    const injected = await sdk.Protocols.deriveAndInjectPublicEncryptionKeys(
      definition, identity.keyId, identity.encPrivateJwk,
    );
    const protocolsConfigure = await sdk.ProtocolsConfigure.create({ definition: injected, signer: identity.signer });
    const reply = await dwn.processMessage(identity.did, protocolsConfigure.message);
    expectStatus(reply, 202, `ProtocolsConfigure(${definition.protocol}) for ${identity.label}`);
    return injected;
  }

  /** Plaintext RecordsWrite processed by the DWN. */
  async function writePlaintextRecord(identity: Identity, params: any, dataBytes: Uint8Array): Promise<any> {
    const recordsWrite = await sdk.RecordsWrite.create({ ...params, data: dataBytes, signer: identity.signer });
    const reply = await dwn.processMessage(identity.did, recordsWrite.message, {
      dataStream: sdk.DataStream.fromBytes(dataBytes),
    });
    expectStatus(reply, 202, `RecordsWrite(${params.protocolPath}) for ${identity.label}`);
    return recordsWrite.message;
  }

  /**
   * Encrypted RecordsWrite: one protocolPath entry wrapped to the rule set's
   * `$keyAgreement` key plus one roleAudience entry per supplied audience key —
   * the same key-encryption inputs AgentDwnApi builds for `encryption: true`
   * writes (dwn-api.ts constructDwnMessage + getRoleAudienceKeyEncryptionInputs).
   */
  async function writeEncryptedRecord(input: {
    owner: Identity;
    injectedDefinition: any;
    protocolPath: string;
    parentContextId?: string;
    recipient?: string;
    plaintext: Uint8Array;
    roleAudienceKeys?: any[]; // AudienceKeyPayloads from generateAudienceKey
    tags?: Record<string, string>;
  }): Promise<{ message: any; ciphertext: Uint8Array; dek: Uint8Array; iv: Uint8Array }> {
    const ruleSet = sdk.getRuleSetAtPath(input.protocolPath, input.injectedDefinition.structure);
    if (ruleSet?.$keyAgreement?.publicKeyJwk === undefined) {
      throw new Error(`no $keyAgreement at '${input.protocolPath}'`);
    }
    const dek = globalThis.crypto.getRandomValues(new Uint8Array(32));
    const iv = globalThis.crypto.getRandomValues(new Uint8Array(16));
    const keyEncryptionInputs: any[] = [{
      algorithm        : 'X25519-HKDF-SHA256+A256KW',
      keyId            : await sdk.Encryption.getKeyId(ruleSet.$keyAgreement.publicKeyJwk),
      publicKey        : ruleSet.$keyAgreement.publicKeyJwk,
      derivationScheme : 'protocolPath',
    }];
    for (const audienceKey of input.roleAudienceKeys ?? []) {
      keyEncryptionInputs.push({
        algorithm        : 'X25519-HKDF-SHA256+A256KW',
        derivationScheme : 'roleAudience',
        keyId            : audienceKey.keyId,
        protocol         : audienceKey.protocol,
        rolePath         : audienceKey.rolePath,
        publicKey        : audienceKey.keyMaterial.publicKeyJwk,
      });
    }
    const ciphertext = await sdk.Encryption.encrypt('A256CTR', dek, iv, input.plaintext);
    const typeName = input.protocolPath.split('/').pop()!;
    const recordsWrite = await sdk.RecordsWrite.create({
      protocol        : input.injectedDefinition.protocol,
      protocolPath    : input.protocolPath,
      parentContextId : input.parentContextId,
      recipient       : input.recipient,
      schema          : input.injectedDefinition.types[typeName].schema,
      dataFormat      : 'application/json',
      data            : ciphertext,
      tags            : input.tags,
      encryptionInput : { initializationVector: iv, key: dek, keyEncryptionInputs },
      signer          : input.owner.signer,
    });
    const reply = await dwn.processMessage(input.owner.did, recordsWrite.message, {
      dataStream: sdk.DataStream.fromBytes(ciphertext),
    });
    expectStatus(reply, 202, `encrypted RecordsWrite(${input.protocolPath}) for ${input.owner.label}`);
    return { message: recordsWrite.message, ciphertext, dek, iv };
  }

  // ---------------------------------------------------------------------
  // Misc
  // ---------------------------------------------------------------------
  const b64u = (bytes: Uint8Array): string => sdk.Encoder.bytesToBase64Url(bytes);
  const utf8 = (text: string): Uint8Array => new TextEncoder().encode(text);

  /** Derives a descendant X25519 keypair from a root private JWK along an absolute path. */
  async function deriveX25519(rootPrivateJwk: any, fullPath: string[]): Promise<{ privateJwk: any; publicJwk: any; keyId: string }> {
    const rootBytes = await crypto.X25519.privateKeyToBytes({ privateKey: rootPrivateJwk });
    const leafBytes = fullPath.length === 0 ? rootBytes : await sdk.HdKey.derivePrivateKeyBytes(rootBytes, fullPath);
    const privateJwk = await crypto.X25519.bytesToPrivateKey({ privateKeyBytes: leafBytes });
    const publicJwk = await crypto.X25519.getPublicKey({ key: privateJwk });
    const keyId = await crypto.computeJwkThumbprint({ jwk: publicJwk });
    return { privateJwk, publicJwk, keyId };
  }

  function assertEqualBytes(actual: Uint8Array, expected: Uint8Array, what: string): void {
    if (Buffer.compare(Buffer.from(actual), Buffer.from(expected)) !== 0) {
      throw new Error(`verification failed: ${what} bytes differ`);
    }
  }

  return {
    sdk, dids, crypto, agentEnc, connect,
    dwn, didResolver, sdkCommit,
    makeIdentity, makeMiniAgent,
    installEncryptedProtocol, writePlaintextRecord, writeEncryptedRecord,
    expectStatus, b64u, utf8, deriveX25519, assertEqualBytes,
    close,
  };
}
