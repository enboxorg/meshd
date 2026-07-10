export const INSTALL_SCRIPT_URL: string =
  import.meta.env?.VITE_MESHD_INSTALL_URL || "https://meshd.sh/install";

export function shellQuote(value: string): string {
  return `'${value.replace(/'/g, "'\\''")}'`;
}

// installAndUpCommand builds the copy-paste onboarding one-liner: install the
// latest meshd, submit the join request, wait for dashboard approval, and
// start the mesh. `target` is either a meshd://invite URL or an owner DID —
// both are positional arguments to `meshd up`.
export function installAndUpCommand(target: string, installUrl: string = INSTALL_SCRIPT_URL): string {
  const value = target.trim();
  if (!value) {
    throw new Error("An invite URL or owner DID is required.");
  }
  return `curl -fsSL ${installUrl} | bash -s -- up ${shellQuote(value)}`;
}
