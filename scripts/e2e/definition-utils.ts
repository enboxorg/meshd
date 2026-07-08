/**
 * Pure helpers for working with DWN protocol definitions, shared by the
 * headless approver and the selfcheck. No enbox imports — plain JSON walking.
 */

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
