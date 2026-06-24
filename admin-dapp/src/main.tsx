import React from "react";
import ReactDOM from "react-dom/client";
import { Toaster } from "sonner";

import { App } from "./App";
import { EnboxProvider } from "./enbox/EnboxProvider";
import "./styles.css";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <EnboxProvider>
      <App />
      <Toaster position="bottom-right" richColors />
    </EnboxProvider>
  </React.StrictMode>
);
