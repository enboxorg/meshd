/**
 * meshd crypto-fixture generator.
 *
 * Produces GENUINE @enbox SDK fixtures (monorepo at HEAD) for the meshd Go
 * implementation to test against. Every DWN record in the fixtures is
 * processed by a real in-process DWN (server-validated); every encrypted
 * payload is decrypted back in-script with the SDK before the fixture is
 * written (self-proving).
 *
 * Usage: see README.md in this directory. TL;DR:
 *
 *   cd $ENBOX_REPO && bunx turbo run build --filter=@enbox/agent
 *   cd <meshd worktree> && bun scripts/gen-crypto-fixtures/generate.ts
 */

import { join, resolve } from 'node:path';
import { mkdirSync, writeFileSync } from 'node:fs';

import { createHarness, ENBOX_REPO, type Harness, type Identity } from './harness.ts';

const WORKTREE = resolve(import.meta.dir, '../..');
const CRYPTO_TESTDATA = join(WORKTREE, 'internal/dwn/crypto/testdata/v1');
const CONNECT_TESTDATA = join(WORKTREE, 'internal/enboxconnect/testdata');
const MESH_DEF_PATH = join(WORKTREE, 'protocols/wireguard-mesh.json');

const KEK_INFO_DOC = {
  note         : 'HKDF-SHA256 KEK info strings are COMPACT JSON arrays (exact JSON.stringify output, no whitespace); KEK = HKDF-SHA256(ikm=X25519 ECDH shared secret, salt=empty, info, 32 bytes); key wrap = RFC 3394 AES-KW of the raw 32-byte CEK; content encryption = AES-256-CTR with the 16-byte initializationVector as the full counter block.',
  protocolPath : '["X25519-HKDF-SHA256+A256KW","protocolPath","<keyId>"]',
  roleAudience : '["X25519-HKDF-SHA256+A256KW","roleAudience","<protocol>","<rolePath>","<keyId>"]',
  seal         : '["X25519-HKDF-SHA256+A256KW","seal","<protocol>","<rolePath>","<contextId>","<audienceKeyId>"]',
};

function writeFixture(dir: string, name: string, fixture: unknown): void {
  mkdirSync(dir, { recursive: true });
  const path = join(dir, name);
  writeFileSync(path, JSON.stringify(fixture, null, 2) + '\n');
  console.log(`wrote ${path}`);
}

function decodeB64uJson(encoded: string): any {
  return JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));
}

function assertEqualJson(actual: unknown, expected: unknown, what: string): void {
  const left = JSON.stringify(actual);
  const right = JSON.stringify(expected);
  if (left !== right) {
    throw new Error(`verification failed: ${what}\nactual:   ${left}\nexpected: ${right}`);
  }
}

function assertTrue(condition: boolean, what: string): void {
  if (!condition) {
    throw new Error(`verification failed: ${what}`);
  }
}

const h: Harness = await createHarness();
const { sdk, agentEnc, connect } = h;
const rawMeshDefinition = await Bun.file(MESH_DEF_PATH).json();
const MESH = rawMeshDefinition.protocol as string;
const stamp = { generatedAt: new Date().toISOString(), sdkCommit: h.sdkCommit, generator: 'scripts/gen-crypto-fixtures/generate.ts' };

async function decryptWithDecrypter(message: any, decrypter: any, ciphertext: Uint8Array): Promise<Uint8Array> {
  const plainStream = await sdk.Records.decrypt(message, decrypter, sdk.DataStream.fromBytes(ciphertext));
  return sdk.DataStream.toBytes(plainStream);
}

/** Owner-root decrypt through the SDK's DerivedPrivateJwk overload. */
async function decryptAsOwner(owner: Identity, message: any, ciphertext: Uint8Array): Promise<Uint8Array> {
  const rootKey = { rootKeyId: owner.keyId, derivationScheme: 'protocolPath', derivedPrivateKey: owner.encPrivateJwk };
  const plainStream = await sdk.Records.decrypt(message, rootKey, sdk.DataStream.fromBytes(ciphertext));
  return sdk.DataStream.toBytes(plainStream);
}

// ===========================================================================
// Fixture 1 — protocolpath.json
// Encrypted RecordsWrite on wireguard-mesh `network/preAuthKey` (an
// encryptionRequired path with NO read-role rules, so exactly one
// protocolPath keyEncryption entry), decryptable from the owner root key.
// ===========================================================================
async function generateProtocolPathFixture(): Promise<void> {
  const owner = await h.makeIdentity('pp-owner');
  const installedDefinition = await h.installEncryptedProtocol(owner, rawMeshDefinition);

  const networkBytes = h.utf8(JSON.stringify({ name: 'mesh-protocolpath' }));
  const networkMessage = await h.writePlaintextRecord(owner, {
    protocol: MESH, protocolPath: 'network', schema: rawMeshDefinition.types.network.schema, dataFormat: 'application/json',
  }, networkBytes);
  const networkRecordId = networkMessage.recordId;

  const plaintext = h.utf8(JSON.stringify({ secret: 'protocolPath-only', n: 42 }));
  const { message, ciphertext } = await h.writeEncryptedRecord({
    owner,
    injectedDefinition : installedDefinition,
    protocolPath       : 'network/preAuthKey',
    parentContextId    : networkRecordId,
    plaintext,
  });

  // Self-proving: decrypt with ONLY the owner root private key + HD derivation.
  h.assertEqualBytes(await decryptAsOwner(owner, message, ciphertext), plaintext, 'protocolpath owner decrypt');

  const derivationPath = ['protocolPath', MESH, 'network', 'preAuthKey'];
  writeFixture(CRYPTO_TESTDATA, 'protocolpath.json', {
    description: 'encryption v1-sealed protocolPath fixture (wireguard-mesh network/preAuthKey). Decrypt: derive the '
      + 'X25519 leaf private key from readerEncPrivateKeyJwk along derivationPath (HKDF-SHA256 per segment, salt '
      + 'empty, info = utf8(segment)), then for the keyEncryption entry whose derivationScheme === "protocolPath": '
      + 'ECDH(leafPriv, entry.ephemeralPublicKey) -> HKDF-SHA256 KEK (info = compact JSON array, see _scheme) -> '
      + 'AES-KW unwrap entry.encryptedKey -> CEK; AES-256-CTR decrypt ciphertext with '
      + 'recordMessage.encryption.initializationVector.',
    ...stamp,
    _README: 'The record is genuine, server-validated SDK output: the wireguard-mesh protocol (with $keyAgreement '
      + 'keys injected via Protocols.deriveAndInjectPublicEncryptionKeys from the owner root) was installed on a '
      + 'real DWN and the encrypted RecordsWrite passed full protocol authorization including encryption '
      + 'enforcement. network/preAuthKey has no read-role rules, so keyEncryption has exactly one protocolPath entry.',
    _encoding: 'ciphertext_b64 and expectedPlaintext_b64 are STANDARD base64 (legacy field shape). All JWK members '
      + '(x, d) and every field under recordMessage.encryption are base64url, exactly as emitted by the SDK.',
    _scheme: {
      contentEncryption  : 'A256CTR (AES-256-CTR, 16-byte IV used as the full counter block, no authentication tag)',
      keyWrap            : 'X25519-HKDF-SHA256+A256KW (ECDH X25519 -> HKDF-SHA256 -> RFC 3394 AES-KeyWrap)',
      kekHkdf            : 'HKDF-SHA256, salt = empty, length = 32 bytes, info (utf-8) = ' + KEK_INFO_DOC.protocolPath + ' (compact JSON array, no whitespace)',
      encryptionLocation : 'top-level `encryption` field on the RecordsWrite message (NOT inside `descriptor`)',
    },
    protocol               : MESH,
    protocolPath           : 'network/preAuthKey',
    derivationScheme       : 'protocolPath',
    derivationPath,
    rootKeyId              : owner.keyId,
    readerDid              : owner.did,
    readerEncPrivateKeyJwk : owner.encPrivateJwk,
    contextId              : message.contextId,
    networkRecordId,
    recordMessage          : message,
    ciphertext_b64         : Buffer.from(ciphertext).toString('base64'),
    expectedPlaintext_b64  : Buffer.from(plaintext).toString('base64'),
    _fields: {
      readerEncPrivateKeyJwk : 'owner X25519 root private key JWK (did:jwk identity: Ed25519 signing key converted to X25519, as the enbox agent does); `d` is the 32-byte scalar (base64url)',
      rootKeyId              : 'fully-qualified verification-method id of the owner did:jwk key',
      derivationPath         : 'absolute HKDF path from root to the protocol-path leaf key',
      recordMessage          : 'full RecordsWriteMessage; recordMessage.encryption is the encryption envelope',
      ciphertext_b64         : 'the encrypted record DATA bytes (what encryption decrypts to expectedPlaintext)',
      expectedPlaintext_b64  : 'original plaintext bytes BEFORE encryption',
    },
  });
}

// ===========================================================================
// Fixture 2 — sealed_roleaudience.json
// The full v1-sealed role-audience bundle on wireguard-mesh:
// $encryption/audience records (with REAL seals), an encrypted network/node
// source record carrying roleAudience keyEncryption entries, and a
// $encryption/delivery record wrapped to the role holder's own role-path key.
// ===========================================================================
async function generateSealedRoleAudienceFixture(): Promise<void> {
  const owner = await h.makeIdentity('ra-owner');
  const node = await h.makeIdentity('ra-node');
  const miniAgent = h.makeMiniAgent([owner, node]);

  const ownerInstalledDefinition = await h.installEncryptedProtocol(owner, rawMeshDefinition);
  // The role holder installs the protocol on ITS OWN tenant with $keyAgreement
  // injected from ITS root — deliveries wrap to the recipient's own role-path key.
  const recipientInstalledDefinition = await h.installEncryptedProtocol(node, rawMeshDefinition);

  const networkBytes = h.utf8(JSON.stringify({ name: 'mesh-sealed' }));
  const networkMessage = await h.writePlaintextRecord(owner, {
    protocol: MESH, protocolPath: 'network', schema: rawMeshDefinition.types.network.schema, dataFormat: 'application/json',
  }, networkBytes);
  const networkRecordId = networkMessage.recordId;

  // ---- audience records (one per read role of network/node), REAL seals ----
  const readRolePaths = ['network/member', 'network/node']; // read-role rules on network/node, in $actions order
  const audience: Record<string, { audienceKey: any; message: any; payload: any }> = {};
  for (const rolePath of readRolePaths) {
    const audienceKey = await agentEnc.generateAudienceKey({ protocol: MESH, rolePath, contextId: networkRecordId });
    const sealingPublicKey = sdk.getRuleSetAtPath(rolePath, ownerInstalledDefinition.structure).$keyAgreement.publicKeyJwk;
    const created = await agentEnc.createAudienceRecord({
      agent     : miniAgent,
      sourceDid : owner.did,
      authorDid : owner.did,
      protocol  : MESH,
      rolePath,
      contextId : networkRecordId,
      sealingPublicKey,
      audienceKey,
    });
    audience[rolePath] = { audienceKey: created.audienceKey, message: created.message, payload: created.payload };
  }

  // ---- encrypted source record: network/node (recipient = role holder) ----
  const plaintext = h.utf8(JSON.stringify({ hostname: 'node-1', wireguardPublicKey: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=' }));
  const source = await h.writeEncryptedRecord({
    owner,
    injectedDefinition : ownerInstalledDefinition,
    protocolPath       : 'network/node',
    parentContextId    : networkRecordId,
    recipient          : node.did,
    plaintext,
    roleAudienceKeys   : readRolePaths.map((rolePath) => audience[rolePath].audienceKey),
  });

  // The role-audience tuple contextId rule: rolePath depth 2 -> first segment
  // of the source record's contextId, i.e. the network recordId.
  const tupleContextId = sdk.getRoleAudienceContextId('network/node', source.message.contextId);
  assertTrue(tupleContextId === networkRecordId, `tuple contextId (${tupleContextId}) == network recordId`);

  // ---- $encryption/delivery record for the network/node role holder ----
  const recipientRolePublicKey = sdk.getRuleSetAtPath('network/node', recipientInstalledDefinition.structure).$keyAgreement.publicKeyJwk;
  const deliveryMessage = await agentEnc.createAudienceDeliveryRecord({
    agent                  : miniAgent,
    sourceDid              : owner.did,
    authorDid              : owner.did,
    recipientDid           : node.did,
    recipientRolePublicKey,
    audienceKey            : audience['network/node'].audienceKey,
    recipientAuthority     : sdk.EncryptionControlDeliveryRecipientAuthority.RoleHolder,
  });
  const expectedDeliveryPayload = {
    protocol    : MESH,
    rolePath    : 'network/node',
    contextId   : networkRecordId,
    keyId       : audience['network/node'].audienceKey.keyId,
    keyMaterial : audience['network/node'].audienceKey.keyMaterial,
  };

  // -------------------------- verification --------------------------------
  // (a) tenant path: unseal each audience record's sealedPrivateKey with the
  //     owner-derived role-path leaf and compare to the minted private key.
  for (const rolePath of readRolePaths) {
    const sealingLeaf = await h.deriveX25519(owner.encPrivateJwk, ['protocolPath', MESH, ...rolePath.split('/')]);
    const unsealed = await agentEnc.unsealAudienceKey({
      payload           : audience[rolePath].payload,
      sealingPrivateKey : sealingLeaf.privateJwk,
    });
    assertTrue(unsealed.privateKeyJwk.d === audience[rolePath].audienceKey.keyMaterial.privateKeyJwk.d,
      `unsealed audience private key matches for ${rolePath}`);
    // cross-check with the HEAD-source SDK primitive as well
    const unsealedBytes = await sdk.Encryption.unwrapSeal({
      seal                : audience[rolePath].payload.sealedPrivateKey,
      recipientPrivateKey : sealingLeaf.privateJwk,
      protocol            : MESH,
      rolePath,
      contextId           : networkRecordId,
      audienceKeyId       : audience[rolePath].audienceKey.keyId,
    });
    assertTrue(h.b64u(unsealedBytes) === audience[rolePath].audienceKey.keyMaterial.privateKeyJwk.d,
      `src Encryption.unwrapSeal recovers the audience private key for ${rolePath}`);
  }
  // (b) role-audience path: decrypt the source record with each audience key.
  for (const rolePath of readRolePaths) {
    const material = audience[rolePath].audienceKey.keyMaterial;
    const decrypter = agentEnc.buildFixedPrivateKeyDecrypter({
      keyId            : material.keyId,
      derivationScheme : 'roleAudience',
      publicKeyJwk     : material.publicKeyJwk,
      privateKeyJwk    : material.privateKeyJwk,
    });
    h.assertEqualBytes(await decryptWithDecrypter(source.message, decrypter, source.ciphertext), plaintext,
      `source decrypt via roleAudience(${rolePath})`);
  }
  // (c) role-holder path: decrypt the delivery record with the recipient's own
  //     role-path leaf key, verify the payload, then use the delivered
  //     audience private key to decrypt the source record.
  const nodeRoleLeaf = await h.deriveX25519(node.encPrivateJwk, ['protocolPath', MESH, 'network', 'node']);
  assertTrue(nodeRoleLeaf.keyId === deliveryMessage.encryption.keyEncryption[0].keyId,
    'delivery keyEncryption entry targets the recipient role-path key');
  const deliveryDecrypter = agentEnc.buildFixedPrivateKeyDecrypter({
    keyId            : nodeRoleLeaf.keyId,
    derivationScheme : 'protocolPath',
    publicKeyJwk     : nodeRoleLeaf.publicJwk,
    privateKeyJwk    : nodeRoleLeaf.privateJwk,
  });
  const deliveryCiphertext = new Uint8Array(Buffer.from(deliveryMessage.encodedData, 'base64url'));
  const deliveredPayload = JSON.parse(Buffer.from(await decryptWithDecrypter(deliveryMessage, deliveryDecrypter, deliveryCiphertext)).toString('utf8'));
  assertEqualJson(deliveredPayload, expectedDeliveryPayload, 'delivery payload');
  const deliveredDecrypter = agentEnc.buildFixedPrivateKeyDecrypter({
    keyId            : deliveredPayload.keyMaterial.keyId,
    derivationScheme : 'roleAudience',
    publicKeyJwk     : deliveredPayload.keyMaterial.publicKeyJwk,
    privateKeyJwk    : deliveredPayload.keyMaterial.privateKeyJwk,
  });
  h.assertEqualBytes(await decryptWithDecrypter(source.message, deliveredDecrypter, source.ciphertext), plaintext,
    'source decrypt via delivered audience key');
  // (d) owner path: decrypt the source record via the protocolPath entry.
  h.assertEqualBytes(await decryptAsOwner(owner, source.message, source.ciphertext), plaintext, 'source owner decrypt');

  writeFixture(CRYPTO_TESTDATA, 'sealed_roleaudience.json', {
    description: 'encryption v1-sealed role-audience bundle on the real wireguard-mesh protocol. Contains: (1) '
      + 'plaintext $encryption/audience control records for the read roles of network/node (network/member and '
      + 'network/node), each sealing the random audience X25519 PRIVATE key to the tenant role-path $keyAgreement '
      + 'key with the "seal" KEK info; (2) an encrypted network/node source record whose encryption.keyEncryption '
      + 'carries one protocolPath entry plus one roleAudience entry per read role; (3) an encrypted '
      + '$encryption/delivery record addressed to the role-holder DID, wrapped (protocolPath scheme) to the '
      + 'RECIPIENT\'s own role-path key from the recipient\'s installed protocol definition. All records are '
      + 'genuine server-validated SDK output; audience/delivery records were produced by the agent\'s own '
      + 'createAudienceRecord/createAudienceDeliveryRecord.',
    ...stamp,
    _encoding : 'all binary values base64url (JWK members, encryption.* fields, *_b64u fields).',
    _scheme   : KEK_INFO_DOC,
    protocol  : MESH,
    contextIdRule: 'audience tuple contextId for rolePath of depth N = first N-1 segments of the source record '
      + 'contextId (getRoleAudienceContextId); for network/node (depth 2) that is the network recordId. '
      + 'Root-level roles use the empty string.',
    ownerDid                 : owner.did,
    ownerRootKeyId           : owner.keyId,
    ownerEncPrivateKeyJwk    : owner.encPrivateJwk,
    ownerEdPrivateKeyJwk     : owner.edPrivateJwk,
    ownerInstalledDefinition,
    networkRecordId,
    networkRecordMessage     : networkMessage,
    audienceRecords          : readRolePaths.map((rolePath) => ({
      rolePath,
      contextId          : networkRecordId,
      keyId              : audience[rolePath].audienceKey.keyId,
      message            : audience[rolePath].message,
      payload            : audience[rolePath].payload,
      audienceKeyMaterial: audience[rolePath].audienceKey.keyMaterial,
      sealKekInfo        : JSON.stringify(['X25519-HKDF-SHA256+A256KW', 'seal', MESH, rolePath, networkRecordId, audience[rolePath].audienceKey.keyId]),
      sealingKeyDerivationPath: ['protocolPath', MESH, ...rolePath.split('/')],
    })),
    sourceRecord: {
      protocolPath   : 'network/node',
      message        : source.message,
      ciphertext_b64u: h.b64u(source.ciphertext),
      plaintext_b64u : h.b64u(plaintext),
    },
    deliveryRecord: {
      message                : deliveryMessage,
      expectedPayload        : expectedDeliveryPayload,
      recipientRolePublicKeyJwk : recipientRolePublicKey,
      recipientRoleKeyDerivationPath : ['protocolPath', MESH, 'network', 'node'],
      note: 'message.encodedData is the base64url ciphertext of the delivery payload; the single keyEncryption '
        + 'entry (derivationScheme protocolPath) is wrapped to the RECIPIENT\'s role-path key, derived from the '
        + 'recipient\'s OWN X25519 root along recipientRoleKeyDerivationPath.',
    },
    roleHolder: {
      did                   : node.did,
      keyId                 : node.keyId,
      edPrivateKeyJwk       : node.edPrivateJwk,
      encPrivateKeyJwk      : node.encPrivateJwk,
      installedDefinition   : recipientInstalledDefinition,
    },
    _fields: {
      audienceRecords : 'plaintext $encryption/audience RecordsWrite messages (message.encodedData = payload JSON, '
        + 'base64url) + the decoded payload + the full audience key material (incl. private) for verification',
      sourceRecord    : 'the encrypted network/node record; keyEncryption = [protocolPath, roleAudience(network/member), roleAudience(network/node)]',
      deliveryRecord  : 'the encrypted $encryption/delivery record for the network/node role holder',
      roleHolder      : 'the role-holder did:jwk identity: Ed25519 signing key, X25519 root (Ed25519-converted), and '
        + 'ITS OWN installed wireguard-mesh definition with $keyAgreement injected from its root',
    },
  });
}

// ===========================================================================
// Fixture 3 — wrapped_grantkey.json
// Pre-supplied-delegate flow (enbox #1189): a delegated Records.Read grant
// over the whole wireguard-mesh protocol + the PLAINTEXT grantKey record
// carrying a WrappedGrantKeyEnvelope wrapped to the delegate ROOT X25519 key,
// produced by the agent's own createGrantKeyRecordsForGrants ('wrapped' mode).
// ===========================================================================
async function generateWrappedGrantKeyFixture(): Promise<void> {
  const owner = await h.makeIdentity('gk-owner');
  const delegate = await h.makeIdentity('gk-delegate');
  const miniAgent = h.makeMiniAgent([owner]);

  const ownerInstalledDefinition = await h.installEncryptedProtocol(owner, rawMeshDefinition);

  const networkBytes = h.utf8(JSON.stringify({ name: 'mesh-grantkey' }));
  const networkMessage = await h.writePlaintextRecord(owner, {
    protocol: MESH, protocolPath: 'network', schema: rawMeshDefinition.types.network.schema, dataFormat: 'application/json',
  }, networkBytes);
  const networkRecordId = networkMessage.recordId;

  // An owner-encrypted record the delivered subtree key must decrypt
  // (network/preAuthKey: protocolPath entry only).
  const plaintext = h.utf8(JSON.stringify({ preAuthKey: 'pak_5f0c9d2b', expires: '2027-01-01T00:00:00Z' }));
  const encryptedRecord = await h.writeEncryptedRecord({
    owner,
    injectedDefinition : ownerInstalledDefinition,
    protocolPath       : 'network/preAuthKey',
    parentContextId    : networkRecordId,
    plaintext,
  });

  // Delegated Records.Read grant over the whole protocol (grant is
  // server-validated on the owner tenant).
  const grant = await sdk.PermissionsProtocol.createGrant({
    signer      : owner.signer,
    delegated   : true,
    dateExpires : sdk.Time.createOffsetTimestamp({ seconds: 90 * 24 * 60 * 60 }),
    grantedTo   : delegate.did,
    scope       : { interface: 'Records', method: 'Read', protocol: MESH },
    description : 'meshd delegate read (fixture)',
  });
  h.expectStatus(
    await h.dwn.processMessage(owner.did, grant.recordsWrite.message, { dataStream: sdk.DataStream.fromBytes(grant.permissionGrantBytes) }),
    202, 'delegated read grant write',
  );

  // GENUINE agent call — wrapped mode (granteeRootPublicKey only). The record
  // is written to the owner tenant through the mini agent's real DWN.
  const grantKeyRecords = await agentEnc.createGrantKeyRecordsForGrants({
    agent                : miniAgent,
    ownerDid             : owner.did,
    granteeDid           : delegate.did,
    granteeRootPublicKey : delegate.encPublicJwk,
    grantMessages        : [grant.dataEncodedMessage],
    protocolDefinitions  : [ownerInstalledDefinition],
  });
  assertTrue(grantKeyRecords.length === 1, `one grantKey record expected, got ${grantKeyRecords.length}`);
  const grantKeyRecord = grantKeyRecords[0];
  const envelope = decodeB64uJson(grantKeyRecord.encodedData);

  // -------------------------- verification --------------------------------
  assertTrue(envelope.format === sdk.WRAPPED_GRANT_KEY_FORMAT, 'envelope format marker');
  assertTrue(envelope.keyEncryption.keyId === delegate.encKeyThumbprint, 'envelope targets the delegate root X25519 key');
  // Unwrap exactly as a pre-supplied delegate must: protocolPath KEK info with
  // keyId = delegate root thumbprint (the SDK builds the entry with
  // derivationScheme protocolPath, then strips the field from the envelope).
  const dek = await sdk.Encryption.unwrapKey(delegate.encPrivateJwk, { ...envelope.keyEncryption, derivationScheme: 'protocolPath' });
  const payloadBytes = await sdk.Encryption.decrypt(
    envelope.contentEncryption.algorithm,
    dek,
    new Uint8Array(Buffer.from(envelope.contentEncryption.initializationVector, 'base64url')),
    new Uint8Array(Buffer.from(envelope.ciphertext, 'base64url')),
  );
  const grantKeyPayload = JSON.parse(Buffer.from(payloadBytes).toString('utf8'));
  assertTrue(grantKeyPayload.grantId === grant.recordsWrite.message.recordId, 'grantKey payload grantId');
  assertEqualJson(grantKeyPayload.scope, { scheme: 'protocolPath', protocol: MESH }, 'grantKey payload scope');
  assertEqualJson(grantKeyPayload.keyMaterial.derivationPath, ['protocolPath', MESH], 'grantKey derivationPath');
  const expectedSubtree = await h.deriveX25519(owner.encPrivateJwk, ['protocolPath', MESH]);
  assertTrue(grantKeyPayload.keyMaterial.privateKeyJwk.d === expectedSubtree.privateJwk.d, 'delivered subtree key == owner-derived protocol key');

  // The delivered subtree key decrypts the owner's encrypted record.
  const subtreeDecrypter = agentEnc.buildProtocolPathSubtreeDecrypter({
    rootKeyId         : grantKeyPayload.keyMaterial.keyId,
    derivationScheme  : 'protocolPath',
    derivationPath    : grantKeyPayload.keyMaterial.derivationPath,
    derivedPrivateKey : grantKeyPayload.keyMaterial.privateKeyJwk,
  });
  h.assertEqualBytes(
    await decryptWithDecrypter(encryptedRecord.message, subtreeDecrypter, encryptedRecord.ciphertext),
    plaintext, 'delegate subtree decrypt of encrypted record',
  );

  writeFixture(CRYPTO_TESTDATA, 'wrapped_grantkey.json', {
    description: 'pre-supplied-delegate grantKey fixture (enbox #1189, wrapped mode). The wallet grants a delegated '
      + 'Records.Read over the whole wireguard-mesh protocol and writes a PLAINTEXT grantKey record '
      + '(protocol https://identity.foundation/dwn/protocols/encryption, protocolPath grantKey) whose data is a '
      + 'WrappedGrantKeyEnvelope: the GrantKeyPayload JSON (carrying the owner-derived whole-protocol X25519 '
      + 'subtree PRIVATE key) is A256CTR-encrypted with a random DEK, and the DEK is wrapped to the delegate ROOT '
      + 'X25519 key (Ed25519->X25519 conversion of its did:jwk signing key) using the protocolPath KEK info with '
      + 'keyId = the delegate root key RFC 7638 thumbprint. Produced by the agent\'s createGrantKeyRecordsForGrants '
      + 'and server-validated by a real DWN. The included encrypted wireguard-mesh record (network/preAuthKey, '
      + 'protocolPath entry to the owner leaf) is decryptable with the delivered subtree key.',
    ...stamp,
    _encoding : 'all binary values base64url.',
    _scheme   : KEK_INFO_DOC,
    protocol  : MESH,
    ownerDid              : owner.did,
    ownerRootKeyId        : owner.keyId,
    ownerEncPrivateKeyJwk : owner.encPrivateJwk,
    delegate: {
      did                  : delegate.did,
      keyId                : delegate.keyId,
      edPrivateKeyJwk      : delegate.edPrivateJwk,
      encPrivateKeyJwk     : delegate.encPrivateJwk,
      encRootKeyThumbprint : delegate.encKeyThumbprint,
      note                 : 'encPrivateKeyJwk is the Ed25519->X25519 conversion of edPrivateKeyJwk (meshd: internal/did EncryptionPrivateKey)',
    },
    grant: {
      grantId : grant.recordsWrite.message.recordId,
      message : grant.dataEncodedMessage,
      scope   : { interface: 'Records', method: 'Read', protocol: MESH },
    },
    grantKeyRecord: {
      message : grantKeyRecord,
      tags    : grantKeyRecord.descriptor.tags,
      note    : 'plaintext record: descriptor has NO encryption; message.encodedData decodes to wrappedGrantKeyEnvelope JSON',
    },
    wrappedGrantKeyEnvelope : envelope,
    unwrapKekInfo           : JSON.stringify(['X25519-HKDF-SHA256+A256KW', 'protocolPath', delegate.encKeyThumbprint]),
    expectedGrantKeyPayload : grantKeyPayload,
    encryptedRecord: {
      protocolPath    : 'network/preAuthKey',
      message         : encryptedRecord.message,
      ciphertext_b64u : h.b64u(encryptedRecord.ciphertext),
      plaintext_b64u  : h.b64u(plaintext),
      note            : 'decrypt with expectedGrantKeyPayload.keyMaterial: derive the remaining path segments '
        + '(network, preAuthKey) below keyMaterial.derivationPath, unwrap the protocolPath keyEncryption entry.',
    },
    ownerInstalledDefinition,
    networkRecordId,
  });
}

// ===========================================================================
// Fixture 4 — delegated_grant.json
// Delegated-grant invocation: delegated Records.Write / Records.Read grants,
// their CIDs, and delegate-signed RecordsWrite + RecordsQuery messages that
// embed them as authorization.authorDelegatedGrant with delegatedGrantId in
// the signature payload. All server-validated.
// ===========================================================================
async function generateDelegatedGrantFixture(): Promise<void> {
  const owner = await h.makeIdentity('dg-owner');
  const delegate = await h.makeIdentity('dg-delegate');

  await h.installEncryptedProtocol(owner, rawMeshDefinition);

  const dateExpires = sdk.Time.createOffsetTimestamp({ seconds: 90 * 24 * 60 * 60 });
  async function makeDelegatedGrant(method: 'Write' | 'Read'): Promise<any> {
    const grant = await sdk.PermissionsProtocol.createGrant({
      signer      : owner.signer,
      delegated   : true,
      dateExpires,
      grantedTo   : delegate.did,
      scope       : { interface: 'Records', method, protocol: MESH },
      description : `meshd delegated ${method} (fixture)`,
    });
    h.expectStatus(
      await h.dwn.processMessage(owner.did, grant.recordsWrite.message, { dataStream: sdk.DataStream.fromBytes(grant.permissionGrantBytes) }),
      202, `delegated ${method} grant write`,
    );
    return grant;
  }
  const writeGrant = await makeDelegatedGrant('Write');
  const readGrant = await makeDelegatedGrant('Read');

  // Delegate-signed RecordsWrite embedding the Write grant. Logical author
  // becomes the grantor (owner).
  const writeData = h.utf8(JSON.stringify({ requestedBy: 'fixture-node', reason: 'join' }));
  const delegatedWrite = await sdk.RecordsWrite.create({
    signer         : delegate.signer,
    delegatedGrant : writeGrant.dataEncodedMessage,
    protocol       : MESH,
    protocolPath   : 'nodeRequest',
    schema         : rawMeshDefinition.types.nodeRequest.schema,
    dataFormat     : 'application/json',
    data           : writeData,
  });
  h.expectStatus(
    await h.dwn.processMessage(owner.did, delegatedWrite.message, { dataStream: sdk.DataStream.fromBytes(writeData) }),
    202, 'delegated RecordsWrite',
  );

  // Delegate-signed RecordsQuery embedding the Read grant.
  const delegatedQuery = await sdk.RecordsQuery.create({
    signer         : delegate.signer,
    delegatedGrant : readGrant.dataEncodedMessage,
    filter         : { protocol: MESH },
  });
  const queryReply = await h.dwn.processMessage(owner.did, delegatedQuery.message);
  h.expectStatus(queryReply, 200, 'delegated RecordsQuery');

  // -------------------------- verification --------------------------------
  const expectedWriteGrantId = await sdk.Message.getCid(writeGrant.dataEncodedMessage);
  const expectedReadGrantId = await sdk.Message.getCid(readGrant.dataEncodedMessage);
  const writeSignaturePayload = decodeB64uJson(delegatedWrite.message.authorization.signature.payload);
  const querySignaturePayload = decodeB64uJson(delegatedQuery.message.authorization.signature.payload);
  assertTrue(writeSignaturePayload.delegatedGrantId === expectedWriteGrantId, 'write delegatedGrantId == grant CID');
  assertTrue(querySignaturePayload.delegatedGrantId === expectedReadGrantId, 'query delegatedGrantId == grant CID');
  assertTrue(expectedWriteGrantId === await sdk.Message.getCid(delegatedWrite.message.authorization.authorDelegatedGrant),
    'embedded authorDelegatedGrant CID matches (encodedData is INCLUDED in the embedded grant but EXCLUDED from CID computation)');

  writeFixture(CRYPTO_TESTDATA, 'delegated_grant.json', {
    description: 'delegated-grant invocation fixture. Each bundle contains a wallet-style delegated grant '
      + 'RecordsWrite message (with encodedData) plus a delegate-signed message that invokes it: '
      + 'authorization.authorDelegatedGrant = the FULL grant message (including encodedData) and the signature '
      + 'payload carries delegatedGrantId = the DAG-CBOR CID of the grant message COMPUTED WITHOUT encodedData. '
      + 'The delegate signs with its own did:jwk Ed25519 key (deterministic signatures, so Go can byte-verify its '
      + 'own construction against these messages given identical descriptor/payload bytes). Both invocations were '
      + 'accepted by a real DWN (write 202, query 200) with the logical author resolving to the grantor.',
    ...stamp,
    _encoding : 'all binary values base64url.',
    protocol  : MESH,
    ownerDid  : owner.did,
    delegate  : {
      did                  : delegate.did,
      keyId                : delegate.keyId,
      signingPrivateKeyJwk : delegate.edPrivateJwk,
    },
    recordsWrite: {
      delegatedGrant           : writeGrant.dataEncodedMessage,
      expectedDelegatedGrantId : expectedWriteGrantId,
      grantScope               : { interface: 'Records', method: 'Write', protocol: MESH },
      invocation               : delegatedWrite.message,
      decodedSignaturePayload  : writeSignaturePayload,
      data_b64u                : h.b64u(writeData),
    },
    recordsQuery: {
      delegatedGrant           : readGrant.dataEncodedMessage,
      expectedDelegatedGrantId : expectedReadGrantId,
      grantScope               : { interface: 'Records', method: 'Read', protocol: MESH },
      invocation               : delegatedQuery.message,
      decodedSignaturePayload  : querySignaturePayload,
    },
    _fields: {
      'recordsWrite.invocation'              : 'delegate-signed RecordsWrite accepted by the DWN (protocolPath nodeRequest)',
      'recordsQuery.invocation'              : 'delegate-signed RecordsQuery accepted by the DWN (filter.protocol)',
      'recordsWrite.decodedSignaturePayload' : 'decoded JWS payload: { recordId, contextId, descriptorCid, delegatedGrantId }',
      'recordsQuery.decodedSignaturePayload' : 'decoded JWS payload: { descriptorCid, delegatedGrantId }',
    },
  });
}

// ===========================================================================
// Fixture 5 — connect_request.json / connect_response.json
// Genuine Enbox Connect JWEs built with EnboxConnectProtocol's own exported
// crypto functions (signJwt/encryptRequest/encryptResponse/deriveSharedKey).
// The response's delegateGrants are real, DWN-validated grant messages.
// ===========================================================================
async function generateConnectFixtures(): Promise<void> {
  const provider = await h.makeIdentity('cn-provider'); // wallet owner (tenant)
  const delegate = await h.makeIdentity('cn-delegate'); // meshd's pre-supplied delegate
  const client = await h.makeIdentity('cn-client'); // ephemeral connect client
  const responseSigner = await h.makeIdentity('cn-response-signer'); // wallet's ephemeral response DID
  const P = connect.EnboxConnectProtocol;

  const permissionScopes = [
    { protocol: MESH, interface: 'Protocols', method: 'Query' },
    { protocol: MESH, interface: 'Messages', method: 'Read' },
    { protocol: MESH, interface: 'Records', method: 'Write' },
    { protocol: MESH, interface: 'Records', method: 'Read' },
    { protocol: MESH, interface: 'Records', method: 'Delete' },
  ];
  const permissionRequests = [{ protocolDefinition: rawMeshDefinition, permissionScopes }];

  // ---------------------------- request side ------------------------------
  const connectServerUrl = 'https://relay.example.com/connect';
  const request = await P.createConnectRequest({
    clientDid                  : client.did,
    callbackUrl                : `${connectServerUrl}/callback`,
    permissionRequests,
    appName                    : 'meshd',
    requestedSessionTtlSeconds : 86400,
    delegateDid                : delegate.did,
  });
  const requestJwt = await P.signJwt({ did: client.bearer, data: request });
  const encryptionKey = globalThis.crypto.getRandomValues(new Uint8Array(32));
  const requestJwe = await P.encryptRequest({ jwt: requestJwt, encryptionKey });

  // verify round trip with the SDK's own wallet-side function
  const decryptedRequestJwt = await P.decryptRequest({ jwe: requestJwe, encryptionKey: h.b64u(encryptionKey) });
  assertTrue(decryptedRequestJwt === requestJwt, 'request JWE decrypts to the signed JWT');
  const verifiedRequest = await P.verifyJwt({ jwt: requestJwt });
  P.assertConnectRequest(verifiedRequest);
  assertEqualJson(verifiedRequest, request, 'verified request payload');

  const requestProtectedHeaderJson = Buffer.from(requestJwe.split('.')[0], 'base64url').toString('utf8');
  assertTrue(requestProtectedHeaderJson === '{"alg":"dir","cty":"JWT","enc":"XC20P","typ":"JWT"}', 'request protected header exact bytes');

  writeFixture(CONNECT_TESTDATA, 'connect_request.json', {
    description: 'genuine Enbox Connect REQUEST JWE, built exactly the client way (wallet-connect-client initClient '
      + 'flow) with EnboxConnectProtocol.createConnectRequest + signJwt + encryptRequest at monorepo HEAD. '
      + '5-part compact JWE: protected header (exact bytes in protectedHeaderJson) . empty . 24-byte nonce . '
      + 'ciphertext . 16-byte tag; XChaCha20-Poly1305 with the random 32-byte encryptionKey (dir), AAD = the UTF-8 '
      + 'bytes of protectedHeaderJson. The JWT is EdDSA-signed by the ephemeral client did:jwk. Go verifies both '
      + 'directions: decrypt requestJwe with encryptionKey_b64u -> expectedRequestJwt -> expectedRequestPayload; '
      + 'and rebuild the JWE from expectedRequestJwt + encryptionKey + the nonce embedded in requestJwe for a '
      + 'byte-exact match.',
    ...stamp,
    clientDid                  : client.did,
    clientKeyId                : client.keyId,
    clientEdPrivateKeyJwk      : client.edPrivateJwk,
    delegateDid                : delegate.did,
    connectServerUrl,
    encryptionKey_b64u         : h.b64u(encryptionKey),
    protectedHeaderJson        : requestProtectedHeaderJson,
    requestJwe,
    expectedRequestJwt         : requestJwt,
    expectedRequestPayload     : request,
    walletUriExample           : `https://wallet.example.com/connect/app?request_uri=${encodeURIComponent(`${connectServerUrl}/authorize/REQUEST_ID.jwt`)}&encryption_key=${h.b64u(encryptionKey)}`,
    _fields: {
      encryptionKey_b64u     : 'fresh random 32-byte symmetric key; travels to the wallet in the wallet URI query (encryption_key)',
      protectedHeaderJson    : 'EXACT UTF-8 bytes of the JWE protected header; also the AAD',
      expectedRequestPayload : 'the EnboxConnectRequest JWT payload (nonce/state are random base64url(16 bytes))',
    },
  });

  // ---------------------------- response side -----------------------------
  const connectSession = P.createConnectSessionMetadata({
    appName    : 'meshd',
    ttlSeconds : 86400,
    transport  : 'relay',
  });
  const delegateGrants: any[] = [];
  const sessionGrants: any[] = [];
  for (const scope of permissionScopes) {
    const delegated = scope.interface === 'Records'; // wallet: shouldUseDelegatePermission
    const grant = await sdk.PermissionsProtocol.createGrant({
      signer      : provider.signer,
      delegated,
      dateExpires : connectSession.expiresAt,
      grantedTo   : delegate.did,
      scope,
      connectSession,
    });
    h.expectStatus(
      await h.dwn.processMessage(provider.did, grant.recordsWrite.message, { dataStream: sdk.DataStream.fromBytes(grant.permissionGrantBytes) }),
      202, `connect grant (${scope.interface}.${scope.method})`,
    );
    delegateGrants.push(grant.dataEncodedMessage);
    sessionGrants.push(grant.dataEncodedMessage);
  }
  // Per-grant contextId-scoped revocation grants (session self-revocation).
  const sessionRevocations: { grantId: string; revocationGrantId: string }[] = [];
  for (const grantMessage of sessionGrants) {
    const revocationGrant = await sdk.PermissionsProtocol.createGrant({
      signer      : provider.signer,
      delegated   : true,
      dateExpires : connectSession.expiresAt,
      grantedTo   : delegate.did,
      scope       : {
        interface : 'Records',
        method    : 'Write',
        protocol  : sdk.PermissionsProtocol.uri,
        contextId : grantMessage.recordId,
      },
    });
    h.expectStatus(
      await h.dwn.processMessage(provider.did, revocationGrant.recordsWrite.message, { dataStream: sdk.DataStream.fromBytes(revocationGrant.permissionGrantBytes) }),
      202, 'connect revocation grant',
    );
    sessionRevocations.push({ grantId: grantMessage.recordId, revocationGrantId: revocationGrant.recordsWrite.message.recordId });
    delegateGrants.push(revocationGrant.dataEncodedMessage);
  }

  const responseObject = await P.createConnectResponse({
    providerDid : provider.did,
    delegateDid : delegate.did, // pre-supplied: no delegatePortableDid in the response
    aud         : client.did,
    nonce       : request.nonce,
    delegateGrants,
    sessionRevocations,
  });
  const responseJwt = await P.signJwt({ did: responseSigner.bearer, data: responseObject });
  const sharedKey = await P.deriveSharedKey(responseSigner.bearer, client.bearer.document);
  const pin = '1234';
  const responseJwe = await P.encryptResponse({
    jwt                  : responseJwt,
    encryptionKey        : sharedKey,
    delegatePublicKeyJwk : responseSigner.bearer.document.verificationMethod[0].publicKeyJwk,
    pin,
  });

  // verify round trip with the SDK's own client-side function
  const decryptedResponseJwt = await P.decryptResponse(client.bearer, responseJwe, pin);
  assertTrue(decryptedResponseJwt === responseJwt, 'response JWE decrypts to the signed JWT');
  const verifiedResponse = await P.verifyJwt({ jwt: responseJwt });
  P.assertConnectResponse(verifiedResponse);
  assertEqualJson(verifiedResponse, responseObject, 'verified response payload');
  assertTrue((verifiedResponse as any).aud === client.did && (verifiedResponse as any).delegateDid === delegate.did, 'aud/delegateDid checks');

  const responseProtectedHeaderJson = Buffer.from(responseJwe.split('.')[0], 'base64url').toString('utf8');
  const responseAadJson = JSON.stringify({ ...JSON.parse(responseProtectedHeaderJson), pin });
  assertTrue(responseAadJson === responseProtectedHeaderJson.slice(0, -1) + `,"pin":"${pin}"}`,
    'AAD == protected header JSON with ,"pin":"<pin>" spliced before the final }');

  writeFixture(CONNECT_TESTDATA, 'connect_response.json', {
    description: 'genuine Enbox Connect RESPONSE JWE as the wallet produces it for a PRE-SUPPLIED delegate, built '
      + 'with EnboxConnectProtocol.createConnectResponse + signJwt + deriveSharedKey + encryptResponse at monorepo '
      + 'HEAD. The protected header additionally carries epk (minimal Ed25519 public JWK of the wallet\'s ephemeral '
      + 'response did:jwk). sharedKey = HKDF-SHA256(salt=empty, info=empty, 32 bytes) over '
      + 'X25519(convert(client Ed25519 priv), convert(epk Ed25519 pub)). AAD = the decoded protected-header JSON '
      + 'with ,"pin":"<pin>" spliced before the final } (exact bytes in aadJson). XChaCha20-Poly1305, 24-byte '
      + 'nonce, tag = last 16 bytes. The JWT is EdDSA-signed by the response DID. delegateGrants are REAL '
      + 'DWN-validated grant messages: 5 session grants (Protocols.Query + Messages.Read plain; '
      + 'Records.Write/Read/Delete delegated) followed by 5 delegated revocation grants '
      + '(Records.Write on the permissions protocol, contextId = session grantId), mapped by sessionRevocations. '
      + 'delegatePortableDid is ABSENT (pre-supplied delegate).',
    ...stamp,
    providerDid                  : provider.did,
    clientDid                    : client.did,
    clientKeyId                  : client.keyId,
    clientEdPrivateKeyJwk        : client.edPrivateJwk,
    delegateDid                  : delegate.did,
    delegateEdPrivateKeyJwk      : delegate.edPrivateJwk,
    delegateEncPrivateKeyJwk     : delegate.encPrivateJwk,
    responseSignerDid            : responseSigner.did,
    responseSignerEdPrivateKeyJwk: responseSigner.edPrivateJwk,
    pin,
    sharedKey_b64u               : h.b64u(sharedKey),
    protectedHeaderJson          : responseProtectedHeaderJson,
    aadJson                      : responseAadJson,
    responseJwe,
    expectedResponseJwt          : responseJwt,
    expectedResponsePayload      : responseObject,
    requestNonce                 : request.nonce,
    requestedScopes              : permissionScopes,
    _fields: {
      sharedKey_b64u          : 'the derived XChaCha20-Poly1305 key, included so Go can verify its ECDH+HKDF independently of the AEAD',
      protectedHeaderJson     : 'EXACT UTF-8 bytes of the JWE protected header (includes epk)',
      aadJson                 : 'EXACT AAD bytes (header JSON with pin spliced in)',
      expectedResponsePayload : 'the EnboxConnectResponse JWT payload; delegateGrants[0..4] session grants, [5..9] revocation grants',
    },
  });
}

// ===========================================================================
try {
  await generateProtocolPathFixture();
  await generateSealedRoleAudienceFixture();
  await generateWrappedGrantKeyFixture();
  await generateDelegatedGrantFixture();
  await generateConnectFixtures();
  console.log(`\nall fixtures generated and verified (sdkCommit ${h.sdkCommit}, repo ${ENBOX_REPO})`);
} finally {
  await h.close();
}
