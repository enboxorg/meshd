import { CheckIcon, ServerIcon, XIcon } from "lucide-react";

import { FirstDevicePanel, FirstNetworkPanel, FirstNodeConnected } from "../onboarding";

// Dev-only visual harness: `bun run dev` then open /?preview to render every
// guided-onboarding state with fixture data, no wallet session required.
// Guarded behind import.meta.env.DEV in main.tsx, so it never ships.

const FIXTURE_COMMAND =
  "curl -fsSL https://meshd.sh/install | bash -s -- up 'meshd://invite/eyJ2ZXJzaW9uIjoxLCJlbmRwb2ludCI6Imh0dHBzOi8vZGV2LmF3cy5kd24uZW5ib3guaWQiLCJhbmNob3JEaWQiOiJkaWQ6ZXhhbXBsZTpvd25lciJ9'";

function FakePendingRow() {
  return (
    <article className="data-row">
      <div className="row-main">
        <span className="row-icon"><ServerIcon size={17} /></span>
        <span>
          <strong>homelab-01</strong>
          <small>Joined via invite</small>
        </span>
      </div>
      <code>did:jwk:eyJrdHkiOiJPS1AiLCJjcnYi...</code>
      <div className="row-actions">
        <button className="primary-button small" type="button"><CheckIcon size={15} />Approve</button>
        <button className="icon-button danger" type="button" aria-label="Reject"><XIcon size={16} /></button>
      </div>
    </article>
  );
}

export function Preview() {
  const noop = () => undefined;
  const noopAsync = async () => undefined;
  return (
    <div className="workspace" style={{ display: "grid", gap: "3rem" }}>
      <PreviewCase title="1 · First network">
        <FirstNetworkPanel defaultCIDR="10.200.0.0/16" onCreate={noop} />
      </PreviewCase>
      <PreviewCase title="2 · Add first device — before invite">
        <FirstDevicePanel
          networkName="home"
          inviteHint="The invite is valid for 7 days and admits one device."
          pendingCount={0}
          onCreateInvite={noop}
          onCopyCommand={noopAsync}
        />
      </PreviewCase>
      <PreviewCase title="3 · Add first device — waiting">
        <FirstDevicePanel
          networkName="home"
          command={FIXTURE_COMMAND}
          inviteHint=""
          pendingCount={0}
          onCreateInvite={noop}
          onCopyCommand={noopAsync}
        />
      </PreviewCase>
      <PreviewCase title="4 · Add first device — request arrived">
        <FirstDevicePanel
          networkName="home"
          command={FIXTURE_COMMAND}
          inviteHint=""
          pendingCount={1}
          onCreateInvite={noop}
          onCopyCommand={noopAsync}
        >
          <div className="stack"><FakePendingRow /></div>
        </FirstDevicePanel>
      </PreviewCase>
      <PreviewCase title="5 · First device connected">
        <FirstNodeConnected name="homelab-01" meshIP="10.200.31.7" onAddAnother={noop} onDismiss={noop} />
      </PreviewCase>
    </div>
  );
}

function PreviewCase({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section style={{ display: "grid", gap: "0.75rem" }}>
      <div className="section-heading"><span>{title}</span></div>
      <div className="main-panel">{children}</div>
    </section>
  );
}
