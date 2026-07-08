/**
 * Pure helpers for working with DWN protocol definitions, shared by the
 * headless approver and the selfcheck. No enbox imports — plain JSON walking.
 */

/**
 * Strip placeholder `$keyAgreement` nodes (missing or empty `publicKeyJwk`,
 * e.g. `{"rootKeyId": "#dwn-enc", "publicKeyJwk": {}}`) from a protocol
 * definition, in place.
 *
 * Client-authored definitions (meshd's protocols/wireguard-mesh.json) carry
 * such placeholders to mark where the wallet must inject owner-derived
 * X25519 public keys. The agent's ProtocolsConfigure with `encryption: true`
 * derives and injects real keys at every path; stripping the placeholders
 * first keeps the definition valid for any non-encrypted install path and
 * makes the "wallet injects the real keys" contract explicit.
 *
 * @returns the number of placeholder nodes removed.
 */
export function stripKeyAgreementPlaceholders(definition: any): number {
  let stripped = 0;

  const walk = (ruleSet: any): void => {
    if (ruleSet === null || typeof ruleSet !== 'object' || Array.isArray(ruleSet)) {
      return;
    }
    if ('$keyAgreement' in ruleSet && isKeyAgreementPlaceholder(ruleSet.$keyAgreement)) {
      delete ruleSet.$keyAgreement;
      stripped += 1;
    }
    for (const [key, child] of Object.entries(ruleSet)) {
      if (!key.startsWith('$')) {
        walk(child);
      }
    }
  };

  if ('$keyAgreement' in definition && isKeyAgreementPlaceholder(definition.$keyAgreement)) {
    delete definition.$keyAgreement;
    stripped += 1;
  }
  walk(definition.structure);

  return stripped;
}

/** A `$keyAgreement` node without a usable X25519 public key. */
export function isKeyAgreementPlaceholder(node: any): boolean {
  return node !== null && typeof node === 'object' &&
    (node.publicKeyJwk === undefined || node.publicKeyJwk === null ||
      typeof node.publicKeyJwk.x !== 'string' || node.publicKeyJwk.x.length === 0);
}

/** Does any type in the definition declare `encryptionRequired: true`? */
export function hasEncryptedTypes(definition: any): boolean {
  return Object.values(definition.types ?? {}).some((t: any) => t?.encryptionRequired === true);
}

/**
 * Structural comparison of protocol definitions that ignores injected
 * encryption keys (`$keyAgreement`) and undefined entries, mirroring the web
 * wallet's `protocolDefinitionsMatch`.
 */
export function definitionsMatch(installed: any, requested: any): boolean {
  return JSON.stringify(normalizeDefinition(installed)) === JSON.stringify(normalizeDefinition(requested));
}

function normalizeDefinition(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(normalizeDefinition);
  }
  if (value === null || typeof value !== 'object') {
    return value;
  }
  return Object.fromEntries(
    Object.entries(value as Record<string, unknown>)
      .filter(([key, entry]) => key !== '$keyAgreement' && key !== '$encryption' && entry !== undefined)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, entry]) => [key, normalizeDefinition(entry)]),
  );
}

/** Walk `structure` to the rule set at `protocolPath` ('a/b/c'). */
export function getStructureNode(structure: any, protocolPath: string): any {
  let current = structure;
  for (const segment of protocolPath.split('/')) {
    if (current === null || typeof current !== 'object' || !(segment in current)) {
      return undefined;
    }
    current = current[segment];
  }
  return current;
}

/** All structure paths whose leaf segment is `typeName`. */
export function findTypePaths(structure: any, typeName: string): string[] {
  const paths: string[] = [];
  const walk = (node: any, prefix: string[]): void => {
    if (node === null || typeof node !== 'object' || Array.isArray(node)) {
      return;
    }
    for (const [key, child] of Object.entries(node)) {
      if (key.startsWith('$')) {
        continue;
      }
      const current = [...prefix, key];
      if (key === typeName) {
        paths.push(current.join('/'));
      }
      walk(child, current);
    }
  };
  walk(structure, []);
  return paths;
}

/**
 * Every `encryptionRequired` type path in the requested definition must have
 * a real (non-placeholder) `$keyAgreement` key in the installed definition.
 */
export function hasEncryptionKeysInstalled(installed: any, requested: any): boolean {
  for (const [typeName, typeDef] of Object.entries(requested.types ?? {})) {
    if (!(typeDef as any)?.encryptionRequired) {
      continue;
    }
    // Types can appear at multiple structure paths; check every occurrence.
    for (const protocolPath of findTypePaths(requested.structure, typeName)) {
      const node = getStructureNode(installed.structure, protocolPath);
      if (node?.$keyAgreement === undefined || isKeyAgreementPlaceholder(node.$keyAgreement)) {
        return false;
      }
    }
  }
  return true;
}
