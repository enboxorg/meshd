export function shellQuote(value: string): string {
  return `'${value.replace(/'/g, "'\\''")}'`;
}

export function ownerSetupCommand(ownerDID: string): string {
  const did = ownerDID.trim();
  if (!did) {
    throw new Error("Owner DID is required.");
  }
  return `meshd up --owner ${shellQuote(did)}`;
}
