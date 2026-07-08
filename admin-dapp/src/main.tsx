import React from "react";
import ReactDOM from "react-dom/client";
import { Toaster } from "sonner";

import { App } from "./App";
import { PWABadge } from "./PWABadge";
import { EnboxProvider } from "./enbox/EnboxProvider";
import "./styles.css";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <EnboxProvider>
      <App />
      <Toaster position="bottom-right" richColors />
      <PWABadge />
    </EnboxProvider>
  </React.StrictMode>
);
