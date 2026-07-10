import { useState, type FormEvent, type ReactNode } from "react";
import {
  CheckIcon,
  ClipboardIcon,
  Loader2Icon,
  NetworkIcon,
  PartyPopperIcon,
  ServerIcon,
  UserPlusIcon
} from "lucide-react";

// Guided first-run flow: create the first network, add the first device with
// the install one-liner, approve it live. Purely presentational — state and
// DWN actions stay in App. Rendered instead of the regular dashboard panels
// until the first node is connected.

const STEPS = ["Network", "Device", "Approve"] as const;

export function OnboardingSteps({ current }: { current: 1 | 2 | 3 }) {
  return (
    <ol className="onboarding-steps" aria-label={`Setup step ${current} of ${STEPS.length}`}>
      {STEPS.map((step, index) => {
        const number = index + 1;
        const state = number < current ? "done" : number === current ? "active" : "todo";
        return (
          <li key={step} className={`onboarding-step ${state}`} aria-current={state === "active" ? "step" : undefined}>
            <span className="onboarding-step-dot">{state === "done" ? <CheckIcon size={12} /> : number}</span>
            {step}
          </li>
        );
      })}
    </ol>
  );
}

export function FirstNetworkPanel({
  busy,
  defaultCIDR,
  onCreate
}: {
  busy?: boolean;
  defaultCIDR: string;
  onCreate: (name: string, cidr: string) => void;
}) {
  const [name, setName] = useState("");
  const [cidr, setCidr] = useState(defaultCIDR);
  const [showAdvanced, setShowAdvanced] = useState(false);

  function submit(event: FormEvent) {
    event.preventDefault();
    if (!name.trim() || busy) return;
    onCreate(name.trim(), cidr.trim() || defaultCIDR);
  }

  return (
    <section className="onboarding-panel rise">
      <OnboardingSteps current={1} />
      <span className="panel-icon"><NetworkIcon size={22} /></span>
      <div>
        <h1>Create your first network</h1>
        <p>
          A network is a private mesh your devices join — they reach each other
          directly over encrypted WireGuard tunnels, from anywhere.
        </p>
      </div>
      <form className="onboarding-form" onSubmit={submit}>
        <label>
          Network name
          <input
            autoFocus
            value={name}
            onChange={(event) => setName(event.target.value)}
            placeholder="home"
          />
        </label>
        {showAdvanced ? (
          <label>
            Mesh CIDR
            <input value={cidr} onChange={(event) => setCidr(event.target.value)} />
          </label>
        ) : null}
        <button className="primary-button" type="submit" disabled={busy || name.trim() === ""}>
          {busy ? <Loader2Icon className="spin" size={16} /> : <NetworkIcon size={16} />}
          Create network
        </button>
      </form>
      <button className="text-button" type="button" onClick={() => setShowAdvanced((value) => !value)}>
        {showAdvanced ? "Hide advanced options" : "Advanced options"}
      </button>
    </section>
  );
}

export function FirstDevicePanel({
  networkName,
  command,
  inviteHint,
  creating,
  pendingCount,
  onCreateInvite,
  onCopyCommand,
  children
}: {
  networkName: string;
  command?: string;
  inviteHint: string;
  creating?: boolean;
  pendingCount: number;
  onCreateInvite: () => void;
  onCopyCommand: (command: string) => Promise<void>;
  children?: ReactNode;
}) {
  return (
    <section className="onboarding-panel wide rise">
      <OnboardingSteps current={pendingCount > 0 ? 3 : 2} />
      <span className="panel-icon"><ServerIcon size={22} /></span>
      {!command ? (
        <>
          <div>
            <h1>Add your first device</h1>
            <p>
              An invite lets a device request to join <strong>{networkName}</strong>.
              You approve every request here before it can connect.
            </p>
          </div>
          <button className="primary-button" type="button" disabled={creating} onClick={onCreateInvite}>
            {creating ? <Loader2Icon className="spin" size={16} /> : <UserPlusIcon size={16} />}
            Create an invite
          </button>
          <p className="field-hint">{inviteHint}</p>
        </>
      ) : (
        <>
          <div>
            <h1>Run this on the device</h1>
            <p>
              It installs meshd, asks to join <strong>{networkName}</strong>, and
              connects on its own once you approve the request here.
            </p>
          </div>
          <CommandHero command={command} onCopy={onCopyCommand} />
        </>
      )}
      {/* One persistent live region across all states: swapping its text is
          announced to screen readers, unmounting it would not be. A pending
          request always surfaces here, even when the command was lost (page
          reload) — the device is waiting either way. */}
      <div className="waiting-row" role="status">
        {pendingCount === 0 && command ? <span className="waiting-dot" aria-hidden="true" /> : null}
        {pendingCount > 0
          ? "A device is asking to join — approve it below."
          : command
            ? "Waiting for a device to run the command — this page updates on its own."
            : "Devices appear here as soon as they request to join."}
      </div>
      {pendingCount > 0 ? (
        <div className="onboarding-approve rise">{children}</div>
      ) : null}
    </section>
  );
}

export function CommandHero({ command, onCopy }: { command: string; onCopy: (command: string) => Promise<void> }) {
  const [copied, setCopied] = useState(false);

  async function copy() {
    await onCopy(command);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1800);
  }

  return (
    <div className="command-hero">
      <div className="command-hero-line">
        <span className="command-hero-prompt" aria-hidden="true">$</span>
        <code>{command}</code>
      </div>
      <button
        className={`secondary-button ${copied ? "copied" : ""}`}
        type="button"
        onClick={() => void copy()}
      >
        {copied ? <CheckIcon size={16} /> : <ClipboardIcon size={16} />}
        {copied ? "Copied" : "Copy command"}
      </button>
    </div>
  );
}

export function FirstNodeConnected({
  name,
  meshIP,
  onAddAnother,
  onDismiss
}: {
  name?: string;
  meshIP: string;
  onAddAnother: () => void;
  onDismiss: () => void;
}) {
  return (
    <section className="onboarding-panel rise success">
      <span className="panel-icon success"><PartyPopperIcon size={22} /></span>
      <div>
        <h1>{name || "Your device"} is on the mesh</h1>
        <p>
          It answers at <code className="mesh-ip">{meshIP}</code> from any of your
          other devices. Add the rest of your machines the same way — one command
          each, approved here.
        </p>
      </div>
      <div className="onboarding-actions">
        <button className="primary-button" type="button" onClick={onAddAnother}>
          <UserPlusIcon size={16} />
          Add another device
        </button>
        <button className="secondary-button" type="button" onClick={onDismiss}>
          Go to the dashboard
        </button>
      </div>
    </section>
  );
}
