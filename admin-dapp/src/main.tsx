import React from "react";
import ReactDOM from "react-dom/client";
import { Toaster } from "sonner";

import { App } from "./App";
import { EnboxProvider } from "./enbox/EnboxProvider";
import "./styles.css";

const root = ReactDOM.createRoot(document.getElementById("root")!);

// Dev-only visual harness for the guided onboarding states (no wallet needed):
// `bun run dev` and open /?preview. Excluded from production builds.
if (import.meta.env.DEV && new URLSearchParams(window.location.search).has("preview")) {
  void import("./dev/preview").then(({ Preview }) => {
    root.render(
      <React.StrictMode>
        <Preview />
      </React.StrictMode>
    );
  });
} else {
  root.render(
    <React.StrictMode>
      <EnboxProvider>
        <App />
        <Toaster position="bottom-right" richColors />
      </EnboxProvider>
    </React.StrictMode>
  );
}
